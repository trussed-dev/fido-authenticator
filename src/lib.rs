//! Open source reference implementation of FIDO CTAP.
//!
//! The core structure is [`Authenticator`], a Trussed® application.
//!
//! It implements the [`ctap_types::ctap1::Authenticator`] and [`ctap_types::ctap2::Authenticator`] traits,
//! which express the interface defined in the CTAP specification.
//!
//! With feature `dispatch` activated, it also implements the `App` traits
//! of [`apdu_dispatch`] and [`ctaphid_dispatch`].
//!
//! [`apdu_dispatch`]: https://docs.rs/apdu-dispatch
//! [`ctaphid_dispatch`]: https://docs.rs/ctaphid-dispatch

#![cfg_attr(not(test), no_std)]
// #![warn(missing_docs)]

#[macro_use]
extern crate delog;
generate_macros!();

pub use state::migrate;

use core::time::Duration;

use trussed_core::{
    mechanisms, syscall, types::Location, CertificateClient, CryptoClient, FilesystemClient,
    ManagementClient, UiClient,
};
use trussed_fs_info::{FsInfoClient, FsInfoReply};
use trussed_hkdf::HkdfClient;

/// Re-export of `ctap-types` authenticator errors.
pub use ctap_types::Error;

mod ctap1;
mod ctap2;

#[cfg(feature = "dispatch")]
mod dispatch;

pub mod constants;
pub mod credential;
pub mod state;

pub use ctap2::large_blobs::Config as LargeBlobsConfig;

/// Results with our [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Trait bound on our implementation's requirements from a Trussed client.
///
/// - Client is core Trussed client functionality.
/// - Ed25519 and P-256 are the core signature algorithms.
/// - AES-256, SHA-256 and its HMAC are used within the CTAP protocols.
/// - ChaCha8Poly1305 is our AEAD of choice, used e.g. for the key handles.
/// - Some Trussed extensions might be required depending on the activated features, see
///   [`ExtensionRequirements`][].
pub trait TrussedRequirements:
    CertificateClient
    + CryptoClient
    + FilesystemClient
    + ManagementClient
    + UiClient
    + mechanisms::P256
    + mechanisms::Chacha8Poly1305
    + mechanisms::Aes256Cbc
    + mechanisms::Sha256
    + mechanisms::HmacSha256
    + mechanisms::Ed255
    + FsInfoClient
    + HkdfClient
    + ExtensionRequirements
{
}

impl<T> TrussedRequirements for T where
    T: CertificateClient
        + CryptoClient
        + FilesystemClient
        + ManagementClient
        + UiClient
        + mechanisms::P256
        + mechanisms::Chacha8Poly1305
        + mechanisms::Aes256Cbc
        + mechanisms::Sha256
        + mechanisms::HmacSha256
        + mechanisms::Ed255
        + FsInfoClient
        + HkdfClient
        + ExtensionRequirements
{
}

#[cfg(not(feature = "chunked"))]
pub trait ExtensionRequirements {}

#[cfg(not(feature = "chunked"))]
impl<T> ExtensionRequirements for T {}

#[cfg(feature = "chunked")]
pub trait ExtensionRequirements: trussed_chunked::ChunkedClient {}

#[cfg(feature = "chunked")]
impl<T> ExtensionRequirements for T where T: trussed_chunked::ChunkedClient {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Externally defined configuration.
pub struct Config {
    /// Typically determined by surrounding USB-level decoder.
    /// For Solo 2, this is usbd-ctaphid (and its buffer size).
    pub max_msg_size: usize,
    // pub max_creds_in_list: usize,
    // pub max_cred_id_length: usize,
    /// If set, the first Get Assertion or Authenticate request within the specified time after
    /// boot is accepted without additional user presence verification.
    pub skip_up_timeout: Option<Duration>,
    /// The maximum number of resident credentials.
    pub max_resident_credential_count: Option<u32>,
    /// Configuration for the largeBlobKey extension and the largeBlobs command.
    ///
    /// If this is `None`, the extension and the command are disabled.
    pub large_blobs: Option<ctap2::large_blobs::Config>,
    /// Whether the authenticator supports the NFC transport.
    pub nfc_transport: bool,
}

impl Config {
    pub fn supports_large_blobs(&self) -> bool {
        self.large_blobs.is_some()
    }
}

// impl Default for Config {
//     fn default() -> Self {
//         Self {
//             max_message_size: ctap_types::sizes::REALISTIC_MAX_MESSAGE_SIZE,
//             max_credential_count_in_list: ctap_types::sizes::MAX_CREDENTIAL_COUNT_IN_LIST,
//             max_credential_id_length: ctap_types::sizes::MAX_CREDENTIAL_ID_LENGTH,
//         }
//     }
// }

/// Trussed® app implementing a FIDO authenticator.
///
/// It implements the [`ctap_types::ctap1::Authenticator`] and [`ctap_types::ctap2::Authenticator`] traits,
/// which, in turn, express the interfaces defined in the CTAP specification.
///
/// The type parameter `T` selects a Trussed® client implementation, which
/// must meet the [`TrussedRequirements`] in our implementation.
///
/// NB: `T` should be the first parameter, `UP` should default to `Conforming`,
/// and probably `UP` shouldn't be a generic parameter at all, at least not this kind.
pub struct Authenticator<UP, T>
// TODO: changing the order is breaking, but default generic parameters must be trailing.
// pub struct Authenticator<T, UP=Conforming>
where
    UP: UserPresence,
{
    trussed: T,
    state: state::State,
    up: UP,
    config: Config,
}

// EWW.. this is a bit unsafe isn't it
fn format_hex<'a>(data: &[u8], buffer: &'a mut [u8]) -> &'a str {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    assert!(data.len() * 2 >= buffer.len());
    for (idx, byte) in data.iter().enumerate() {
        buffer[idx * 2] = HEX_CHARS[(byte >> 4) as usize];
        buffer[idx * 2 + 1] = HEX_CHARS[(byte & 0xf) as usize];
    }

    // SAFETY: we just added only ascii chars to buffer from 0 to data.len() - 1
    unsafe { core::str::from_utf8_unchecked(&buffer[0..data.len() * 2]) }
}

// NB: to actually use this, replace the constant implementation with the inline assembly.
// Once we move to a new cortex-m release, can use the version from there.
//
// use core::arch::asm;

// #[inline]
// pub fn msp() -> u32 {
//     let r;
//     unsafe { asm!("mrs {}, MSP", out(reg) r, options(nomem, nostack, preserves_flags)) };
//     r
// }

#[inline]
#[allow(dead_code)]
pub(crate) fn msp() -> u32 {
    0x2000_0000
}

/// Currently Ed25519 and P256.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// The Ed25519 signature algorithm.
    Ed25519 = -8,
    /// The NIST P-256 signature algorithm.
    P256 = -7,
    // #[doc(hidden)]
    // Totp = -9,
}

impl core::convert::TryFrom<i32> for SigningAlgorithm {
    type Error = Error;
    fn try_from(alg: i32) -> Result<Self> {
        Ok(match alg {
            -7 => SigningAlgorithm::P256,
            -8 => SigningAlgorithm::Ed25519,
            // -9 => SigningAlgorithm::Totp,
            _ => return Err(Error::UnsupportedAlgorithm),
        })
    }
}

/// Method to check for user presence.
pub trait UserPresence: Copy {
    fn user_present<T: TrussedRequirements>(
        self,
        trussed: &mut T,
        timeout_milliseconds: u32,
    ) -> Result<()>;
}

#[deprecated(note = "use `Silent` directly`")]
#[doc(hidden)]
pub type SilentAuthenticator = Silent;

/// No user presence verification.
#[derive(Copy, Clone)]
pub struct Silent {}

impl UserPresence for Silent {
    fn user_present<T: TrussedRequirements>(self, _: &mut T, _: u32) -> Result<()> {
        Ok(())
    }
}

#[deprecated(note = "use `Conforming` directly")]
#[doc(hidden)]
pub type NonSilentAuthenticator = Conforming;

/// User presence verification via Trussed.
#[derive(Copy, Clone)]
pub struct Conforming {}

impl UserPresence for Conforming {
    fn user_present<T: TrussedRequirements>(
        self,
        trussed: &mut T,
        timeout_milliseconds: u32,
    ) -> Result<()> {
        let result = syscall!(trussed.confirm_user_present(timeout_milliseconds)).result;
        result.map_err(|err| match err {
            trussed_core::types::consent::Error::TimedOut => Error::UserActionTimeout,
            trussed_core::types::consent::Error::Interrupted => Error::KeepaliveCancel,
            _ => Error::OperationDenied,
        })
    }
}

impl<UP, T> Authenticator<UP, T>
where
    UP: UserPresence,
    T: TrussedRequirements,
{
    pub fn new(trussed: T, up: UP, config: Config) -> Self {
        let state = state::State::new();
        Self {
            trussed,
            state,
            up,
            config,
        }
    }

    fn estimate_remaining_inner(info: &FsInfoReply) -> Option<u32> {
        let block_size = info.block_info.as_ref()?.size;
        // 1 block for the directory, 1 for the private key, 400 bytes for a reasonnable key and metadata
        let size_taken = 2 * block_size + 400;
        // Remove 5 block kept as buffer
        Some((info.available_space.saturating_sub(5 * block_size) / size_taken) as u32)
    }

    fn estimate_remaining(&mut self) -> Option<u32> {
        let info = syscall!(self.trussed.fs_info(Location::Internal));
        debug!("Got filesystem info: {info:?}");
        Self::estimate_remaining_inner(&info)
    }

    fn can_fit_inner(info: &FsInfoReply, size: usize) -> Option<bool> {
        let block_size = info.block_info.as_ref()?.size;
        // 1 block for the rp directory, 5 block of margin, 50 bytes for a reasonnable metadata
        let size_taken = 6 * block_size + size + 50;
        Some(size_taken < info.available_space)
    }

    /// Can a credential of size `size` be stored with safe margins
    ///
    /// This assumes that the key has already been generated and is stored.
    fn can_fit(&mut self, size: usize) -> Option<bool> {
        debug!("Can fit for {size} bytes");
        let info = syscall!(self.trussed.fs_info(Location::Internal));
        debug!("Got filesystem info: {info:?}");
        debug!(
            "Available storage: {:?}",
            Self::estimate_remaining_inner(&info)
        );
        Self::can_fit_inner(&info, size)
    }

    fn hash(&mut self, data: &[u8]) -> [u8; 32] {
        let hash = syscall!(self.trussed.hash_sha256(data)).hash;
        hash.as_slice().try_into().expect("hash should fit")
    }

    fn nonce(&mut self) -> [u8; 12] {
        let bytes = syscall!(self.trussed.random_bytes(12)).bytes;
        bytes.as_slice().try_into().expect("hash should fit")
    }

    fn skip_up_check(&mut self) -> bool {
        // If enabled in the configuration, we don't require an additional user presence
        // verification for a certain duration after boot.
        if let Some(timeout) = self.config.skip_up_timeout.take() {
            let uptime = syscall!(self.trussed.uptime()).uptime;
            if uptime < timeout {
                info_now!("skip up check directly after boot");
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hex() {
        let data = [0x01, 0x02, 0xB1, 0xA1];
        let buffer = &mut [0; 8];
        assert_eq!(format_hex(&data, buffer), "0102b1a1");
        assert_eq!(buffer, b"0102b1a1");
    }
}
