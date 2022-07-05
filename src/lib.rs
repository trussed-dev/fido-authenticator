//! Open source reference implementation of FIDO CTAP.
//!
//! The core structure is [`Authenticator`], a Trussed® application.
//!
//! It implements the [`ctap_types::ctap1::Authenticator`] and [`ctap_types::ctap2::Authenticator`] traits,
//! which express the interface defined in the CTAP specification.
//!
//! With feature `dispatch` activated, it also implements the `App` traits
//! of [`apdu_dispatch`] and [`ctaphid_dispatch`].

#![cfg_attr(not(test), no_std)]
// #![warn(missing_docs)]

#[macro_use]
extern crate delog;
generate_macros!();

use core::time::Duration;

use trussed::{client, syscall, types::Message, Client as TrussedClient};

use ctap_types::heapless_bytes::Bytes;

/// Re-export of `ctap-types` authenticator errors.
pub use ctap_types::Error;

mod ctap1;
mod ctap2;

#[cfg(feature = "dispatch")]
mod dispatch;

pub mod constants;
pub mod credential;
pub mod state;

/// Results with our [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Trait bound on our implementation's requirements from a Trussed client.
///
/// - Client is core Trussed client functionality.
/// - Ed25519 and P-256 are the core signature algorithms.
/// - AES-256, SHA-256 and its HMAC are used within the CTAP protocols.
/// - ChaCha8Poly1305 is our AEAD of choice, used e.g. for the key handles.
pub trait TrussedRequirements:
    client::Client
    + client::P256
    + client::Chacha8Poly1305
    + client::Aes256Cbc
    + client::Sha256
    + client::HmacSha256
    + client::Ed255 // + client::Totp
{
}

impl<T> TrussedRequirements for T where
    T: client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::Sha256
        + client::HmacSha256
        + client::Ed255 // + client::Totp
{
}

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
fn format_hex(data: &[u8], mut buffer: &mut [u8]) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    for byte in data.iter() {
        buffer[0] = HEX_CHARS[(byte >> 4) as usize];
        buffer[1] = HEX_CHARS[(byte & 0xf) as usize];
        buffer = &mut buffer[2..];
    }
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
    fn user_present<T: TrussedClient>(
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
    fn user_present<T: TrussedClient>(self, _: &mut T, _: u32) -> Result<()> {
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
    fn user_present<T: TrussedClient>(
        self,
        trussed: &mut T,
        timeout_milliseconds: u32,
    ) -> Result<()> {
        let result = syscall!(trussed.confirm_user_present(timeout_milliseconds)).result;
        result.map_err(|err| match err {
            trussed::types::consent::Error::TimedOut => Error::UserActionTimeout,
            // trussed::types::consent::Error::TimedOut => Error::KeepaliveCancel,
            _ => Error::OperationDenied,
        })
    }
}

fn cbor_serialize_message<T: serde::Serialize>(
    object: &T,
) -> core::result::Result<Message, ctap_types::serde::Error> {
    trussed::cbor_serialize_bytes(object)
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

    fn hash(&mut self, data: &[u8]) -> Bytes<32> {
        let hash = syscall!(self.trussed.hash_sha256(data)).hash;
        hash.to_bytes().expect("hash should fit")
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
mod test {}
