//! Various state of the authenticator.
//!
//! Needs cleanup.

pub mod migrate;

use core::num::NonZeroU32;

use ctap_types::{
    ctap2::AttestationFormatsPreference,
    // 2022-02-27: 10 credentials
    sizes::MAX_CREDENTIAL_COUNT_IN_LIST, // U8 currently
    Error,
    String,
};
use littlefs2_core::{path, Path};
use trussed_core::{
    mechanisms::{Chacha8Poly1305, P256},
    syscall, try_syscall,
    types::{KeyId, Location, Mechanism, Message, PathBuf},
    CertificateClient, CryptoClient, FilesystemClient,
};

use heapless::binary_heap::{BinaryHeap, Max};

use crate::{
    credential::FullCredential,
    ctap2::{self, pin::PinProtocolState},
    Result,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CachedCredential {
    pub timestamp: u32,
    // PathBuf has length 255 + 1, we only need 36 + 1
    // with `rk/<16B rp_id>/<16B cred_id>` = 4 + 2*32
    pub path: String<37>,
}

impl PartialOrd for CachedCredential {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CachedCredential {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CredentialCacheGeneric<const N: usize>(BinaryHeap<CachedCredential, Max, N>);
impl<const N: usize> CredentialCacheGeneric<N> {
    pub fn push(&mut self, item: CachedCredential) {
        if self.0.len() == self.0.capacity() {
            self.0.pop();
        }
        // self.0.push(item).ok();
        self.0.push(item).map_err(drop).unwrap();
    }

    pub fn pop(&mut self) -> Option<CachedCredential> {
        self.0.pop()
    }

    pub fn len(&self) -> u32 {
        self.0.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }
}

pub type CredentialCache = CredentialCacheGeneric<MAX_CREDENTIAL_COUNT_IN_LIST>;

#[derive(Debug)]
pub struct State {
    /// Batch device identity (aaguid, certificate, key).
    pub identity: Identity,
    pub persistent: PersistentState,
    pub runtime: RuntimeState,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    // pub fn new(trussed: &mut TrussedClient) -> Self {
    pub fn new() -> Self {
        // let identity = Identity::get(trussed);
        let identity = Default::default();
        let runtime: RuntimeState = Default::default();
        // let persistent = PersistentState::load_or_reset(trussed);
        let persistent = Default::default();

        Self {
            identity,
            persistent,
            runtime,
        }
    }

    pub fn decrement_retries<T: FilesystemClient>(&mut self, trussed: &mut T) -> Result<()> {
        self.persistent.decrement_retries(trussed)?;
        self.runtime.decrement_retries();
        Ok(())
    }

    pub fn reset_retries<T: FilesystemClient>(&mut self, trussed: &mut T) -> Result<()> {
        self.persistent.reset_retries(trussed)?;
        self.runtime.reset_retries();
        Ok(())
    }

    pub fn pin_blocked(&self) -> Result<()> {
        if self.persistent.pin_blocked() {
            return Err(Error::PinBlocked);
        }
        if self.runtime.pin_blocked() {
            return Err(Error::PinAuthBlocked);
        }

        Ok(())
    }
}

/// Batch device identity (aaguid, certificate, key).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Identity {
    // can this be [u8; 16] or need Bytes for serialization?
    // aaguid: Option<Bytes<consts::U16>>,
    attestation_key: Option<KeyId>,
}

pub type Aaguid = [u8; 16];
pub type Certificate = trussed_core::types::Message;

impl Identity {
    // Attempt to yank out the aaguid of a certificate.
    fn yank_aaguid(&mut self, der: &[u8]) -> Option<[u8; 16]> {
        let aaguid_start_sequence = [
            // OBJECT IDENTIFIER 1.3.6.1.4.1.45724.1.1.4 (AAGUID)
            0x06u8, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x01, 0x01, 0x04,
            // Sequence, 16 bytes
            0x04, 0x12, 0x04, 0x10,
        ];

        // Scan for the beginning sequence for AAGUID.
        let mut cert_reader = der;

        while !cert_reader.is_empty() {
            if cert_reader.starts_with(&aaguid_start_sequence) {
                info_now!("found aaguid");
                break;
            }
            cert_reader = &cert_reader[1..];
        }
        if cert_reader.is_empty() {
            return None;
        }

        cert_reader = &cert_reader[aaguid_start_sequence.len()..];

        let mut aaguid = [0u8; 16];
        aaguid[..16].clone_from_slice(&cert_reader[..16]);
        Some(aaguid)
    }

    /// Lookup batch key and certificate, together with AAUGID.
    pub fn attestation<T: CryptoClient + CertificateClient>(
        &mut self,
        trussed: &mut T,
    ) -> (Option<(KeyId, Certificate)>, Aaguid) {
        let key = crate::constants::ATTESTATION_KEY_ID;
        let attestation_key_exists = syscall!(trussed.exists(Mechanism::P256, key)).exists;
        if attestation_key_exists {
            // Will panic if certificate does not exist.
            let cert =
                syscall!(trussed.read_certificate(crate::constants::ATTESTATION_CERT_ID)).der;

            let mut aaguid = self.yank_aaguid(cert.as_slice());

            if aaguid.is_none() {
                // Provide a default
                aaguid = Some(*b"AAGUID0123456789");
            }

            (Some((key, cert)), aaguid.unwrap())
        } else {
            info_now!("attestation key does not exist");
            (None, *b"AAGUID0123456789")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialManagementEnumerateRps {
    pub remaining: NonZeroU32,
    pub rp_id_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialManagementEnumerateCredentials {
    pub remaining: u32,
    pub prev_filename: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct ActiveGetAssertionData {
    pub rp_id_hash: [u8; 32],
    pub client_data_hash: [u8; 32],
    pub uv_performed: bool,
    pub up_performed: bool,
    pub multiple_credentials: bool,
    pub extensions: Option<ctap_types::ctap2::get_assertion::ExtensionsInput>,
    pub attestation_formats_preference: Option<AttestationFormatsPreference>,
}

#[derive(Debug, Default)]
pub struct RuntimeState {
    pin_protocol: Option<PinProtocolState>,
    consecutive_pin_mismatches: u8,

    // both of these are a cache for previous Get{Next,}Assertion call
    cached_credentials: CredentialCache,
    pub active_get_assertion: Option<ActiveGetAssertionData>,
    pub cached_rp: Option<CredentialManagementEnumerateRps>,
    pub cached_rk: Option<CredentialManagementEnumerateCredentials>,

    // largeBlob command
    pub large_blobs: ctap2::large_blobs::State,
}

// TODO: Plan towards future extensibility
//
// - if we set all fields as optional, and annotate with `skip_serializing if None`,
// then, missing fields in older fw versions should not cause problems with newer fw
// versions that potentially add new fields.
//
// - empirically, the implementation of Deserialize doesn't seem to mind moving around
// the order of fields, which is already nice
//
// - adding new non-optional fields definitely doesn't parse (but maybe it could?)
// - same for removing a field
// Currently, this causes the entire authnr to reset state. Maybe it should even reformat disk
//
// - An alternative would be `heapless::Map`, but I'd prefer something more typed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, Default)]
pub struct PersistentState {
    #[serde(skip)]
    // TODO: there has to be a better way than.. this
    // Pro-tip: it should involve types ^^
    //
    // We could alternatively make all methods take a TrussedClient as parameter
    initialised: bool,

    key_encryption_key: Option<KeyId>,
    key_wrapping_key: Option<KeyId>,
    consecutive_pin_mismatches: u8,
    /// PIN hash. Always serialized as a CBOR byte string (major type 2) —
    /// the shape used since `fido-authenticator 0.2.0`. Devices upgrading
    /// from `0.1.1` carry blobs that encode the field as a 16-element CBOR
    /// array (major type 4); cbor-smol's `deserialize_bytes` is permissive
    /// enough to accept both shapes (it routes major type 4 to `visit_seq`),
    /// so the legacy format deserializes cleanly via the `serde_bytes`
    /// helper, and the next `save` normalises the on-disk format. There is
    /// a regression test for the 0.1.1 shape in `state::tests::deser`.
    #[serde(default, with = "serde_bytes")]
    pin_hash: Option<[u8; 16]>,
    // Ideally, we'd dogfood a "Monotonic Counter" from trussed.
    // TODO: Add per-key counters for resident keys.
    // counter: Option<CounterId>,
    timestamp: u32,

    /// Configured minimum PIN length (CTAP 2.1 `setMinPINLength`, §6.11.4
    /// subcmd 0x03). `0` means "no override; use the spec default of 4".
    #[serde(default)]
    min_pin_length: u8,

    /// RP IDs that should automatically receive the `minPinLength` extension
    /// output without explicit request (CTAP 2.1 `setMinPINLength`).
    #[serde(default)]
    min_pin_length_rp_ids: heapless::Vec<heapless::String<256>, 4>,

    /// `forcePINChange` (CTAP 2.1 §6.4 0x0C). When `true`, the authenticator
    /// rejects every operation that requires `clientPin` until the platform
    /// successfully calls `clientPin.changePIN`.
    #[serde(default)]
    force_pin_change: bool,

    /// `alwaysUv` (CTAP 2.1 §6.11.3). When `true`, every MakeCredential and
    /// GetAssertion must carry a valid `pinUvAuthParam`; ops without UV are
    /// rejected with `PinRequired`.
    #[serde(default)]
    always_uv: bool,
}

impl PersistentState {
    const RESET_RETRIES: u8 = 8;
    const FILENAME: &'static Path = path!("persistent-state.cbor");

    /// Default minimum PIN length (CTAP 2.1 §6.11.4: spec floor is 4).
    pub const DEFAULT_MIN_PIN_LENGTH: u8 = 4;
    /// Maximum number of RP IDs that can be auto-receivers of the
    /// `minPinLength` extension.
    pub const MAX_MIN_PIN_LENGTH_RP_IDS: usize = 4;

    /// Load persistent state from disk.
    ///
    /// Returns `Ok(None)` when no state file is present (fresh / wiped
    /// device), `Ok(Some(state))` on a successful load, and `Err(_)` when a
    /// state file is present but cannot be deserialized. The two paths must
    /// stay distinct so [`Self::load_if_not_initialised`] can refuse to start
    /// the authenticator on a corrupt blob instead of silently re-initialising
    /// (which would destroy every credential).
    pub fn load<T: FilesystemClient>(trussed: &mut T) -> Result<Option<Self>> {
        // Trussed's read syscall conflates "file does not exist" and
        // "read failure" into a single `FilesystemReadFailure`. Either way,
        // this is a fresh authenticator from our perspective.
        let data = match try_syscall!(
            trussed.read_file(Location::Internal, PathBuf::from(Self::FILENAME))
        ) {
            Ok(reply) => reply.data,
            Err(_) => return Ok(None),
        };

        let state: Self = cbor_smol::cbor_deserialize(&data).map_err(|_err| {
            info!("err deser'ing: {_err:?}",);
            info!("{}", hex_str!(&data));
            Error::Other
        })?;

        debug!("Loaded state: {state:#?}");

        Ok(Some(state))
    }

    pub fn save<T: FilesystemClient>(&self, trussed: &mut T) -> Result<()> {
        let mut data = Message::new();
        cbor_smol::cbor_serialize_to(self, &mut data).unwrap();

        syscall!(trussed.write_file(
            Location::Internal,
            PathBuf::from(Self::FILENAME),
            data,
            None,
        ));
        Ok(())
    }

    pub fn reset<T: CryptoClient + FilesystemClient>(&mut self, trussed: &mut T) -> Result<()> {
        if let Some(key) = self.key_encryption_key {
            syscall!(trussed.delete(key));
        }
        if let Some(key) = self.key_wrapping_key {
            syscall!(trussed.delete(key));
        }
        self.key_encryption_key = None;
        self.key_wrapping_key = None;
        self.consecutive_pin_mismatches = 0;
        self.pin_hash = None;
        self.timestamp = 0;
        self.save(trussed)
    }

    pub fn load_if_not_initialised<T: FilesystemClient>(&mut self, trussed: &mut T) {
        if !self.initialised {
            match Self::load(trussed) {
                Ok(Some(previous_self)) => {
                    info!("loaded previous state!");
                    *self = previous_self;
                }
                Ok(None) => {
                    // No state on disk — fresh authenticator. Leave defaults.
                    info!("no previous state, starting fresh");
                }
                Err(_err) => {
                    // State file is present but unparseable. Silently
                    // resetting here would silently destroy the user's PIN,
                    // KEK, and every credential. Refuse to start instead.
                    // The failure is at least visible in the RTT log; the
                    // user can recover via JLink/bootloader.
                    error_now!("PERSISTENT STATE LOAD FAILED: {:?}", _err);
                    panic!("fido-authenticator: corrupt persistent state");
                }
            }
            self.initialised = true;
        }
    }

    pub fn timestamp<T: FilesystemClient>(&mut self, trussed: &mut T) -> Result<u32> {
        let now = self.timestamp;
        self.timestamp += 1;
        self.save(trussed)?;
        Ok(now)
    }

    pub fn key_encryption_key<T: CryptoClient + Chacha8Poly1305 + FilesystemClient>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        match self.key_encryption_key {
            Some(key) => Ok(key),
            None => self.rotate_key_encryption_key(trussed),
        }
    }

    pub fn rotate_key_encryption_key<T: CryptoClient + Chacha8Poly1305 + FilesystemClient>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        if let Some(key) = self.key_encryption_key {
            syscall!(trussed.delete(key));
        }
        let key = syscall!(trussed.generate_chacha8poly1305_key(Location::Internal)).key;
        self.key_encryption_key = Some(key);
        self.save(trussed)?;
        Ok(key)
    }

    pub fn key_wrapping_key<T: CryptoClient + Chacha8Poly1305 + FilesystemClient>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        match self.key_wrapping_key {
            Some(key) => Ok(key),
            None => self.rotate_key_wrapping_key(trussed),
        }
    }

    pub fn rotate_key_wrapping_key<T: CryptoClient + Chacha8Poly1305 + FilesystemClient>(
        &mut self,
        trussed: &mut T,
    ) -> Result<KeyId> {
        self.load_if_not_initialised(trussed);
        if let Some(key) = self.key_wrapping_key {
            syscall!(trussed.delete(key));
        }
        let key = syscall!(trussed.generate_chacha8poly1305_key(Location::Internal)).key;
        self.key_wrapping_key = Some(key);
        self.save(trussed)?;
        Ok(key)
    }

    pub fn pin_is_set(&self) -> bool {
        self.pin_hash.is_some()
    }

    pub fn retries(&self) -> u8 {
        Self::RESET_RETRIES.saturating_sub(self.consecutive_pin_mismatches)
    }

    pub fn pin_blocked(&self) -> bool {
        self.consecutive_pin_mismatches >= Self::RESET_RETRIES
    }

    fn reset_retries<T: FilesystemClient>(&mut self, trussed: &mut T) -> Result<()> {
        if self.consecutive_pin_mismatches > 0 {
            self.consecutive_pin_mismatches = 0;
            self.save(trussed)?;
        }
        Ok(())
    }

    fn decrement_retries<T: FilesystemClient>(&mut self, trussed: &mut T) -> Result<()> {
        // error to call before initialization
        if self.consecutive_pin_mismatches < Self::RESET_RETRIES {
            self.consecutive_pin_mismatches += 1;
            self.save(trussed)?;
            if self.consecutive_pin_mismatches == 0 {
                return Err(Error::PinBlocked);
            }
        }
        Ok(())
    }

    pub fn pin_hash(&self) -> Option<[u8; 16]> {
        self.pin_hash
    }

    pub fn set_pin_hash<T: FilesystemClient>(
        &mut self,
        trussed: &mut T,
        pin_hash: [u8; 16],
    ) -> Result<()> {
        self.pin_hash = Some(pin_hash);
        // Successfully (re)setting the PIN clears any pending forcePINChange
        // request — the platform has just complied (CTAP 2.1 §6.5.5.7).
        self.force_pin_change = false;
        self.save(trussed)?;
        Ok(())
    }

    /// Configured minimum PIN length, never less than the CTAP 2.1 floor.
    pub fn min_pin_length(&self) -> u8 {
        core::cmp::max(self.min_pin_length, Self::DEFAULT_MIN_PIN_LENGTH)
    }

    pub fn set_min_pin_length<T: FilesystemClient>(
        &mut self,
        trussed: &mut T,
        new_value: u8,
    ) -> Result<()> {
        // Spec: setMinPINLength may only raise the value, never lower it.
        if new_value <= self.min_pin_length() {
            return Err(Error::PinPolicyViolation);
        }
        self.min_pin_length = new_value;
        // Spec §6.11.4 step 7: if the existing PIN is shorter than the new
        // floor, force the platform to change it. We can't measure the
        // existing PIN length here (only its hash is stored), so we set the
        // flag unconditionally on any tightening.
        if self.pin_hash.is_some() {
            self.force_pin_change = true;
        }
        self.save(trussed)?;
        Ok(())
    }

    pub fn min_pin_length_rp_ids(&self) -> &[heapless::String<256>] {
        &self.min_pin_length_rp_ids
    }

    pub fn set_min_pin_length_rp_ids<T: FilesystemClient>(
        &mut self,
        trussed: &mut T,
        rp_ids: heapless::Vec<heapless::String<256>, { Self::MAX_MIN_PIN_LENGTH_RP_IDS }>,
    ) -> Result<()> {
        self.min_pin_length_rp_ids = rp_ids;
        self.save(trussed)?;
        Ok(())
    }

    pub fn force_pin_change(&self) -> bool {
        self.force_pin_change
    }

    pub fn always_uv(&self) -> bool {
        self.always_uv
    }

    pub fn toggle_always_uv<T: FilesystemClient>(&mut self, trussed: &mut T) -> Result<()> {
        self.always_uv = !self.always_uv;
        self.save(trussed)
    }
}

impl RuntimeState {
    const POWERCYCLE_RETRIES: u8 = 3;

    fn decrement_retries(&mut self) {
        if self.consecutive_pin_mismatches < Self::POWERCYCLE_RETRIES {
            self.consecutive_pin_mismatches += 1;
        }
    }

    fn reset_retries(&mut self) {
        self.consecutive_pin_mismatches = 0;
    }

    pub fn pin_blocked(&self) -> bool {
        self.consecutive_pin_mismatches >= Self::POWERCYCLE_RETRIES
    }

    // pub fn cached_credentials(&mut self) -> &mut CredentialCache {
    //     &mut self.cached_credentials
    //     // if let Some(cache) = self.cached_credentials.as_mut() {
    //     //     return cache
    //     // }
    //     // self.cached_credentials.insert(CredentialCache::new())
    // }

    pub fn clear_credential_cache(&mut self) {
        self.cached_credentials.clear()
    }

    pub fn push_credential(&mut self, credential: CachedCredential) {
        self.cached_credentials.push(credential);
    }

    pub fn pop_credential<T: FilesystemClient>(
        &mut self,
        trussed: &mut T,
    ) -> Option<FullCredential> {
        let cached_credential = self.cached_credentials.pop()?;

        let credential_data = syscall!(trussed.read_file(
            Location::Internal,
            PathBuf::try_from(cached_credential.path.as_str()).unwrap(),
        ))
        .data;

        FullCredential::deserialize(&credential_data).ok()
    }

    pub fn remaining_credentials(&self) -> u32 {
        self.cached_credentials.len() as _
    }

    pub fn pin_protocol<T: P256>(&mut self, trussed: &mut T) -> &mut PinProtocolState {
        self.pin_protocol
            .get_or_insert_with(|| PinProtocolState::new(trussed))
    }

    pub fn reset<T: CryptoClient + P256>(&mut self, trussed: &mut T) {
        // Could use `free_credential_heap`, but since we're deleting everything here, this is quicker.
        syscall!(trussed.delete_all(Location::Volatile));
        self.clear_credential_cache();
        self.active_get_assertion = None;

        // Clear any in-flight credMgmt enumeration cursors. Otherwise a
        // `next_relying_party`/`next_credential` call straight after
        // `authenticatorReset` succeeds with stale data instead of
        // returning `NotAllowed` (caught by fido2-tests
        // test_rpnext_without_rpbegin).
        self.cached_rp = None;
        self.cached_rk = None;

        // The per-power-cycle pinAuthFailedAttempts counter is runtime
        // state and lives here. `authenticatorReset` removes the PIN
        // entirely (caller resets the persistent retries counter via
        // `PersistentState::reset`), so the per-power-cycle counter
        // should drop with it.
        self.consecutive_pin_mismatches = 0;

        if let Some(pin_protocol) = self.pin_protocol.take() {
            pin_protocol.reset(trussed);
        }
        // to speed up future operations, we already generate the key agreement key
        self.pin_protocol = Some(PinProtocolState::new(trussed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn deser() {
        let _state: PersistentState = trussed::cbor_deserialize(&hex!(
            "
            a5726b65795f656e6372797074696f6e5f6b657950b19a5a2845e5ec71e3
            2a1b890892376c706b65795f7772617070696e675f6b6579f6781a636f6e
            73656375746976655f70696e5f6d69736d617463686573006870696e5f68
            6173689018ef1879187c1881181818f0182d18fb186418960718dd185d18
            3f188c18766974696d657374616d7009
        "
        ))
        .unwrap();
    }
}
