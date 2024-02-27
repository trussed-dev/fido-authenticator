use crate::{cbor_serialize_message, TrussedRequirements};
use ctap_types::{cose::EcdhEsHkdf256PublicKey, Error, Result};
use trussed::{
    cbor_deserialize,
    client::{Aes256Cbc, CryptoClient, HmacSha256, P256},
    syscall, try_syscall,
    types::{Bytes, KeyId, KeySerialization, Location, Mechanism, StorageAttributes},
};

const PIN_TOKEN_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug)]
pub enum PinProtocolVersion {
    V1,
}

#[derive(Debug)]
pub struct PinProtocolState {
    key_agreement_key: KeyId,
    // only used to delete the old shared secret from VFS when generating a new one.  ideally, the
    // SharedSecret struct would clean up after itself.
    shared_secret: Option<KeyId>,

    // for protocol version 1
    pin_token_v1: KeyId,
}

impl PinProtocolState {
    // in spec: initialize(...)
    pub fn new<T: TrussedRequirements>(trussed: &mut T) -> Self {
        Self {
            key_agreement_key: generate_key_agreement_key(trussed),
            shared_secret: None,
            pin_token_v1: generate_pin_token(trussed),
        }
    }

    pub fn reset<T: TrussedRequirements>(self, trussed: &mut T) {
        syscall!(trussed.delete(self.pin_token_v1));
        syscall!(trussed.delete(self.key_agreement_key));
        if let Some(shared_secret) = self.shared_secret {
            syscall!(trussed.delete(shared_secret));
        }
    }
}

#[derive(Debug)]
pub struct PinProtocol<'a, T: TrussedRequirements> {
    trussed: &'a mut T,
    state: &'a mut PinProtocolState,
    version: PinProtocolVersion,
}

impl<'a, T: TrussedRequirements> PinProtocol<'a, T> {
    pub fn new(
        trussed: &'a mut T,
        state: &'a mut PinProtocolState,
        version: PinProtocolVersion,
    ) -> Self {
        Self {
            trussed,
            state,
            version,
        }
    }

    fn pin_token(&self) -> KeyId {
        match self.version {
            PinProtocolVersion::V1 => self.state.pin_token_v1,
        }
    }

    fn set_pin_token(&mut self, pin_token: KeyId) {
        match self.version {
            PinProtocolVersion::V1 => self.state.pin_token_v1 = pin_token,
        }
    }

    pub fn regenerate(&mut self) {
        syscall!(self.trussed.delete(self.state.key_agreement_key));
        if let Some(shared_secret) = self.state.shared_secret.take() {
            syscall!(self.trussed.delete(shared_secret));
        }
        self.state.key_agreement_key = generate_key_agreement_key(self.trussed);
    }

    // in spec: resetPinUvAuthToken()
    pub fn reset_pin_token(&mut self) {
        syscall!(self.trussed.delete(self.pin_token()));
        let pin_token = generate_pin_token(self.trussed);
        self.set_pin_token(pin_token);
    }

    // in spec: getPublicKey
    #[must_use]
    pub fn key_agreement_key(&mut self) -> EcdhEsHkdf256PublicKey {
        let public_key = syscall!(self
            .trussed
            .derive_p256_public_key(self.state.key_agreement_key, Location::Volatile))
        .key;
        let serialized_cose_key = syscall!(self.trussed.serialize_key(
            Mechanism::P256,
            public_key,
            KeySerialization::EcdhEsHkdf256
        ))
        .serialized_key;
        let cose_key = cbor_deserialize(&serialized_cose_key).unwrap();
        syscall!(self.trussed.delete(public_key));
        cose_key
    }

    // in spec: verify(pinUvAuthToken, ...)
    #[must_use]
    pub fn verify_pin_token(&mut self, data: &[u8], signature: &[u8]) -> bool {
        // TODO: check if pin token is in use
        verify(self.trussed, self.pin_token(), data, signature)
    }

    // in spec: resetPinUvAuthToken() + encrypt(..., pinUvAuthToken)
    pub fn reset_and_encrypt_pin_token(
        &mut self,
        shared_secret: &SharedSecret,
    ) -> Result<Bytes<32>> {
        self.reset_pin_token();
        self.encrypt_pin_token(shared_secret)
    }

    // in spec: encrypt(..., pinUvAuthToken)
    fn encrypt_pin_token(&mut self, shared_secret: &SharedSecret) -> Result<Bytes<32>> {
        let token = syscall!(self
            .trussed
            .wrap_key_aes256cbc(shared_secret.key_id, self.pin_token()))
        .wrapped_key;
        Bytes::from_slice(&token).map_err(|_| Error::Other)
    }

    // in spec: decapsulate(...) = ecdh(...)
    // The returned key ID is valid until the next call of shared_secret or regenerate.  The caller
    // has to delete the key from the VFS after end of use.  Ideally, this should be enforced by
    // the compiler, for example by using a callback.
    pub fn shared_secret(&mut self, peer_key: &EcdhEsHkdf256PublicKey) -> Result<SharedSecret> {
        self.shared_secret_impl(peer_key)
            .ok_or(Error::InvalidParameter)
    }

    fn shared_secret_impl(&mut self, peer_key: &EcdhEsHkdf256PublicKey) -> Option<SharedSecret> {
        let serialized_peer_key = cbor_serialize_message(peer_key).ok()?;
        let peer_key = try_syscall!(self.trussed.deserialize_p256_key(
            &serialized_peer_key,
            KeySerialization::EcdhEsHkdf256,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .ok()?
        .key;

        let result = try_syscall!(self.trussed.agree(
            Mechanism::P256,
            self.state.key_agreement_key,
            peer_key,
            StorageAttributes::new().set_persistence(Location::Volatile),
        ));
        syscall!(self.trussed.delete(peer_key));
        let pre_shared_secret = result.ok()?.shared_secret;

        if let Some(shared_secret) = self.state.shared_secret {
            syscall!(self.trussed.delete(shared_secret));
        }

        let shared_secret = self.kdf(pre_shared_secret);
        self.state.shared_secret = Some(shared_secret);
        syscall!(self.trussed.delete(pre_shared_secret));

        Some(SharedSecret {
            key_id: shared_secret,
        })
    }

    fn kdf(&mut self, input: KeyId) -> KeyId {
        syscall!(self.trussed.derive_key(
            Mechanism::Sha256,
            input,
            None,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .key
    }
}

pub struct SharedSecret {
    key_id: KeyId,
}

impl SharedSecret {
    pub fn verify_pin_auth<T: HmacSha256>(
        &self,
        trussed: &mut T,
        data: &[u8],
        pin_auth: &Bytes<16>,
    ) -> Result<()> {
        if verify(trussed, self.key_id, data, pin_auth) {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    #[must_use]
    pub fn encrypt<T: CryptoClient>(&self, trussed: &mut T, data: &[u8]) -> Bytes<1024> {
        syscall!(trussed.encrypt(Mechanism::Aes256Cbc, self.key_id, data, b"", None)).ciphertext
    }

    #[must_use]
    pub fn decrypt<T: Aes256Cbc>(&self, trussed: &mut T, data: &[u8]) -> Option<Bytes<1024>> {
        decrypt(trussed, self.key_id, data)
    }

    pub fn delete<T: CryptoClient>(self, trussed: &mut T) {
        syscall!(trussed.delete(self.key_id));
    }
}

#[must_use]
fn verify<T: HmacSha256>(trussed: &mut T, key: KeyId, data: &[u8], signature: &[u8]) -> bool {
    let actual_signature = syscall!(trussed.sign_hmacsha256(key, data)).signature;
    &actual_signature[..16] == signature
}

#[must_use]
fn decrypt<T: Aes256Cbc>(trussed: &mut T, key: KeyId, data: &[u8]) -> Option<Bytes<1024>> {
    try_syscall!(trussed.decrypt_aes256cbc(key, data))
        .ok()
        .and_then(|response| response.plaintext)
}

fn generate_pin_token<T: HmacSha256>(trussed: &mut T) -> KeyId {
    syscall!(trussed.generate_secret_key(PIN_TOKEN_LENGTH, Location::Volatile)).key
}

fn generate_key_agreement_key<T: P256>(trussed: &mut T) -> KeyId {
    syscall!(trussed.generate_p256_private_key(Location::Volatile)).key
}
