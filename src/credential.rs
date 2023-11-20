//! Internal `Credential` and external `CredentialId` ("keyhandle").

use core::cmp::Ordering;

use serde::Serialize;
use trussed::{client, syscall, try_syscall, types::KeyId};

pub(crate) use ctap_types::{
    // authenticator::{ctap1, ctap2, Error, Request, Response},
    ctap2::credential_management::CredentialProtectionPolicy,
    sizes::*,
    webauthn::{PublicKeyCredentialDescriptor, PublicKeyCredentialDescriptorRef},
    Bytes,
    String,
};

use crate::{Authenticator, Error, Result, UserPresence};

/// As signaled in `get_info`.
///
/// Eventual goal is full support for the CTAP2.1 specification.
#[derive(Copy, Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum CtapVersion {
    U2fV2,
    Fido20,
    Fido21Pre,
}

/// External ID of a credential, commonly known as "keyhandle".
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CredentialId(pub Bytes<MAX_CREDENTIAL_ID_LENGTH>);

impl CredentialId {
    fn new<T: client::Chacha8Poly1305 + client::Sha256, C: Serialize>(
        trussed: &mut T,
        credential: &C,
        key_encryption_key: KeyId,
        rp_id_hash: &Bytes<32>,
        nonce: &Bytes<12>,
    ) -> Result<Self> {
        let serialized_credential: SerializedCredential =
            trussed::cbor_serialize_bytes(credential).map_err(|_| Error::Other)?;
        let message = &serialized_credential;
        // info!("serialized cred = {:?}", message).ok();
        let associated_data = &rp_id_hash[..];
        let nonce: [u8; 12] = nonce.as_slice().try_into().unwrap();
        let encrypted_serialized_credential = syscall!(trussed.encrypt_chacha8poly1305(
            key_encryption_key,
            message,
            associated_data,
            Some(&nonce)
        ));
        EncryptedSerializedCredential(encrypted_serialized_credential)
            .try_into()
            .map_err(|_| Error::RequestTooLarge)
    }
}

// TODO: how to determine necessary size?
// pub type SerializedCredential = Bytes<512>;
// pub type SerializedCredential = Bytes<256>;
pub(crate) type SerializedCredential = trussed::types::Message;

#[derive(Clone, Debug)]
struct EncryptedSerializedCredential(pub trussed::api::reply::Encrypt);

impl TryFrom<EncryptedSerializedCredential> for CredentialId {
    type Error = Error;

    fn try_from(esc: EncryptedSerializedCredential) -> Result<CredentialId> {
        Ok(CredentialId(
            trussed::cbor_serialize_bytes(&esc.0).map_err(|_| Error::Other)?,
        ))
    }
}

impl TryFrom<CredentialId> for EncryptedSerializedCredential {
    // tag = 16B
    // nonce = 12B
    type Error = Error;

    fn try_from(cid: CredentialId) -> Result<EncryptedSerializedCredential> {
        let encrypted_serialized_credential = EncryptedSerializedCredential(
            ctap_types::serde::cbor_deserialize(&cid.0).map_err(|_| Error::InvalidCredential)?,
        );
        Ok(encrypted_serialized_credential)
    }
}

/// Credential keys can either be "discoverable" or not.
///
/// The FIDO Alliance likes to refer to "resident keys" as "(client-side) discoverable public key
/// credential sources" now ;)
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum Key {
    ResidentKey(KeyId),
    // THIS USED TO BE 92 NOW IT'S 96 or 97 or so... waddup?
    WrappedKey(Bytes<128>),
}

/// A credential that is managed by the authenticator.
///
/// The authenticator uses two credential representations:
/// - [`FullCredential`][] contains all data available for a credential and is used for resident
///   credentials that are stored on the filesystem.  Older versions of this app used this
///   reprensentation for non-resident credentials too.
/// - [`StrippedCredential`][] contains the minimal data required for non-resident credentials.  As
///   the data for these credentials is encoded in the credential ID, we try to keep it as small as
///   possible.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Credential {
    Full(FullCredential),
    Stripped(StrippedCredential),
}

impl Credential {
    pub fn try_from<UP: UserPresence, T: client::Client + client::Chacha8Poly1305>(
        authnr: &mut Authenticator<UP, T>,
        rp_id_hash: &Bytes<32>,
        descriptor: &PublicKeyCredentialDescriptorRef,
    ) -> Result<Self> {
        Self::try_from_bytes(authnr, rp_id_hash, descriptor.id)
    }

    pub fn try_from_bytes<UP: UserPresence, T: client::Client + client::Chacha8Poly1305>(
        authnr: &mut Authenticator<UP, T>,
        rp_id_hash: &Bytes<32>,
        id: &[u8],
    ) -> Result<Self> {
        let mut cred: Bytes<MAX_CREDENTIAL_ID_LENGTH> = Bytes::new();
        cred.extend_from_slice(id)
            .map_err(|_| Error::InvalidCredential)?;

        let encrypted_serialized = EncryptedSerializedCredential::try_from(CredentialId(cred))?;

        let kek = authnr
            .state
            .persistent
            .key_encryption_key(&mut authnr.trussed)?;

        let serialized = try_syscall!(authnr.trussed.decrypt_chacha8poly1305(
            kek,
            &encrypted_serialized.0.ciphertext,
            &rp_id_hash[..],
            &encrypted_serialized.0.nonce,
            &encrypted_serialized.0.tag,
        ))
        .map_err(|_| Error::InvalidCredential)?
        .plaintext
        .ok_or(Error::InvalidCredential)?;

        // In older versions of this app, we serialized the full credential.  Now we only serialize
        // the stripped credential.  For compatibility, we have to try both.
        FullCredential::deserialize(&serialized)
            .map(Self::Full)
            .or_else(|_| StrippedCredential::deserialize(&serialized).map(Self::Stripped))
            .map_err(|_| Error::InvalidCredential)
    }

    pub fn id<T: client::Chacha8Poly1305 + client::Sha256>(
        &self,
        trussed: &mut T,
        key_encryption_key: KeyId,
        rp_id_hash: &Bytes<32>,
    ) -> Result<CredentialId> {
        match self {
            Self::Full(credential) => credential.id(trussed, key_encryption_key, Some(rp_id_hash)),
            Self::Stripped(credential) => CredentialId::new(
                trussed,
                credential,
                key_encryption_key,
                rp_id_hash,
                &credential.nonce,
            ),
        }
    }

    pub fn algorithm(&self) -> i32 {
        match self {
            Self::Full(credential) => credential.algorithm,
            Self::Stripped(credential) => credential.algorithm,
        }
    }

    pub fn cred_protect(&self) -> Option<CredentialProtectionPolicy> {
        match self {
            Self::Full(credential) => credential.cred_protect,
            Self::Stripped(credential) => credential.cred_protect,
        }
    }

    pub fn key(&self) -> &Key {
        match self {
            Self::Full(credential) => &credential.key,
            Self::Stripped(credential) => &credential.key,
        }
    }
}

/// The main content of a `FullCredential`.
#[derive(
    Clone, Debug, PartialEq, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed,
)]
pub struct CredentialData {
    // id, name, url
    pub rp: ctap_types::webauthn::PublicKeyCredentialRpEntity,
    // id, icon, name, display_name
    pub user: ctap_types::webauthn::PublicKeyCredentialUserEntity,

    // can be just a counter, need to be able to determine "latest"
    pub creation_time: u32,
    // for stateless deterministic keys, it seems CTAP2 (but not CTAP1) makes signature counters optional
    use_counter: bool,
    // P256 or Ed25519
    pub algorithm: i32,
    // for RK in non-deterministic mode: refers to actual key
    // TODO(implement enums in cbor-deser): for all others, is a wrapped key
    // --> use above Key enum
    // #[serde(skip_serializing_if = "Option::is_none")]
    // key_id: Option<KeyId>,
    pub key: Key,

    // extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<Bytes<32>>,
    // TODO: add `sig_counter: Option<CounterId>`,
    // and grant RKs a per-credential sig-counter.

    // In older app versions, we serialized the full credential to determine the credential ID.  In
    // newer app versions, we strip unnecessary fields to generate a shorter credential ID.  To
    // make sure that the credential ID does not change for an existing credential, this field is
    // used as a marker for new credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    use_short_id: Option<bool>,
}

// TODO: figure out sizes
// We may or may not follow https://github.com/satoshilabs/slips/blob/master/slip-0022.md
/// The core structure this authenticator creates and uses.
#[derive(Clone, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
pub struct FullCredential {
    ctap: CtapVersion,
    pub data: CredentialData,
    nonce: Bytes<12>,
}

// Alas... it would be more symmetrical to have Credential { meta, data },
// but let's not break binary compatibility for this.
//
// struct Metadata {
//     ctap: CtapVersion,
//     nonce: Bytes<12>,
// }

impl core::ops::Deref for FullCredential {
    type Target = CredentialData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// Compare credentials based on key + timestamp.
///
/// Likely comparison based on timestamp would be good enough?
impl PartialEq for FullCredential {
    fn eq(&self, other: &Self) -> bool {
        (self.creation_time == other.creation_time) && (self.key == other.key)
    }
}

impl PartialEq<&FullCredential> for FullCredential {
    fn eq(&self, other: &&Self) -> bool {
        self == *other
    }
}

impl Eq for FullCredential {}

impl Ord for FullCredential {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.creation_time.cmp(&other.data.creation_time)
    }
}

/// Order by timestamp of creation.
impl PartialOrd for FullCredential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<&FullCredential> for FullCredential {
    fn partial_cmp(&self, other: &&Self) -> Option<Ordering> {
        Some(self.cmp(*other))
    }
}

// Bad idea - huge stack
// pub(crate) type CredentialList = Vec<Credential, {ctap_types::sizes::MAX_CREDENTIAL_COUNT_IN_LIST}>;

impl From<CredentialId> for PublicKeyCredentialDescriptor {
    fn from(id: CredentialId) -> PublicKeyCredentialDescriptor {
        PublicKeyCredentialDescriptor {
            id: id.0,
            key_type: {
                let mut key_type = String::new();
                key_type.push_str("public-key").unwrap();
                key_type
            },
        }
    }
}

impl FullCredential {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctap: CtapVersion,
        // parameters: &ctap2::make_credential::Parameters,
        rp: &ctap_types::webauthn::PublicKeyCredentialRpEntity,
        user: &ctap_types::webauthn::PublicKeyCredentialUserEntity,
        algorithm: i32,
        key: Key,
        timestamp: u32,
        hmac_secret: Option<bool>,
        cred_protect: Option<CredentialProtectionPolicy>,
        large_blob_key: Option<Bytes<32>>,
        nonce: [u8; 12],
    ) -> Self {
        info!("credential for algorithm {}", algorithm);
        let data = CredentialData {
            rp: rp.clone(),
            user: user.clone(),

            creation_time: timestamp,
            use_counter: true,
            algorithm,
            key,

            hmac_secret,
            cred_protect,
            large_blob_key,

            use_short_id: Some(true),
        };

        FullCredential {
            ctap,
            data,
            nonce: Bytes::from_slice(&nonce).unwrap(),
        }
    }

    // ID (or "keyhandle") for the credential.
    //
    // Originally, the entire data was serialized, and its encryption
    // (binding RP as associated data) used as a keyhandle.
    //
    // However, this leads to problems with relying parties. According to the old U2F
    // spec, the length of a keyhandle is encoded as one byte, whereas this procedure would
    // generate keyhandles of length ~320 bytes.
    //
    // Therefore, inessential metadata is stripped before serialization, ensuring
    // the ID will stay below 255 bytes.
    //
    // Existing keyhandles can still be decoded
    pub fn id<T: client::Chacha8Poly1305 + client::Sha256>(
        &self,
        trussed: &mut T,
        key_encryption_key: KeyId,
        rp_id_hash: Option<&Bytes<32>>,
    ) -> Result<CredentialId> {
        let rp_id_hash: Bytes<32> = if let Some(hash) = rp_id_hash {
            hash.clone()
        } else {
            syscall!(trussed.hash_sha256(self.rp.id.as_ref()))
                .hash
                .to_bytes()
                .map_err(|_| Error::Other)?
        };
        if self.use_short_id.unwrap_or_default() {
            StrippedCredential::from(self).id(trussed, key_encryption_key, &rp_id_hash)
        } else {
            let stripped_credential = self.strip();
            CredentialId::new(
                trussed,
                &stripped_credential,
                key_encryption_key,
                &rp_id_hash,
                &self.nonce,
            )
        }
    }

    pub fn serialize(&self) -> Result<SerializedCredential> {
        trussed::cbor_serialize_bytes(self).map_err(|_| Error::Other)
    }

    pub fn deserialize(bytes: &SerializedCredential) -> Result<Self> {
        match ctap_types::serde::cbor_deserialize(bytes) {
            Ok(s) => Ok(s),
            Err(_) => {
                info_now!("could not deserialize {:?}", bytes);
                Err(Error::Other)
            }
        }
    }

    // This method is only kept for compatibility.  To strip new credentials, use
    // `StrippedCredential`.
    #[must_use]
    fn strip(&self) -> Self {
        info_now!(":: stripping ID");
        let mut stripped = self.clone();
        let data = &mut stripped.data;

        data.rp.name = None;
        data.rp.icon = None;

        data.user.icon = None;
        data.user.name = None;
        data.user.display_name = None;

        // data.hmac_secret = None;
        // data.cred_protect = None;

        stripped
    }
}

/// A reduced version of `FullCredential` that is used for non-resident credentials.
///
/// As the credential data is encodeded in the credential ID, we only want to include necessary
/// data to keep the credential ID as short as possible.
#[derive(Clone, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
pub struct StrippedCredential {
    pub ctap: CtapVersion,
    pub creation_time: u32,
    pub use_counter: bool,
    pub algorithm: i32,
    pub key: Key,
    pub nonce: Bytes<12>,
    // extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
}

impl StrippedCredential {
    fn deserialize(bytes: &SerializedCredential) -> Result<Self> {
        match ctap_types::serde::cbor_deserialize(bytes) {
            Ok(s) => Ok(s),
            Err(_) => {
                info_now!("could not deserialize {:?}", bytes);
                Err(Error::Other)
            }
        }
    }

    pub fn id<T: client::Chacha8Poly1305 + client::Sha256>(
        &self,
        trussed: &mut T,
        key_encryption_key: KeyId,
        rp_id_hash: &Bytes<32>,
    ) -> Result<CredentialId> {
        CredentialId::new(trussed, self, key_encryption_key, rp_id_hash, &self.nonce)
    }
}

impl From<&FullCredential> for StrippedCredential {
    fn from(credential: &FullCredential) -> Self {
        Self {
            ctap: credential.ctap,
            creation_time: credential.data.creation_time,
            use_counter: credential.data.use_counter,
            algorithm: credential.data.algorithm,
            key: credential.data.key.clone(),
            nonce: credential.nonce.clone(),
            hmac_secret: credential.data.hmac_secret,
            cred_protect: credential.data.cred_protect,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ctap_types::webauthn::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};
    use trussed::{
        client::{Chacha8Poly1305, Sha256},
        types::Location,
    };

    fn credential_data() -> CredentialData {
        CredentialData {
            rp: PublicKeyCredentialRpEntity {
                id: String::from("John Doe"),
                name: None,
                icon: None,
            },
            user: PublicKeyCredentialUserEntity {
                id: Bytes::from_slice(&[1, 2, 3]).unwrap(),
                icon: None,
                name: None,
                display_name: None,
            },
            creation_time: 123,
            use_counter: false,
            algorithm: -7,
            key: Key::WrappedKey(Bytes::from_slice(&[1, 2, 3]).unwrap()),
            hmac_secret: Some(false),
            cred_protect: None,
            use_short_id: Some(true),
        }
    }

    fn random_bytes<const N: usize>() -> Bytes<N> {
        use rand::{
            distributions::{Distribution, Uniform},
            rngs::OsRng,
            RngCore,
        };
        let mut bytes = Bytes::default();

        let between = Uniform::from(0..(N + 1));
        let n = between.sample(&mut OsRng);

        bytes.resize_default(n).unwrap();

        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    #[allow(dead_code)]
    fn maybe_random_bytes<const N: usize>() -> Option<Bytes<N>> {
        use rand::{rngs::OsRng, RngCore};
        if OsRng.next_u32() & 1 != 0 {
            Some(random_bytes())
        } else {
            None
        }
    }

    fn random_string<const N: usize>() -> String<N> {
        use rand::{
            distributions::{Alphanumeric, Distribution, Uniform},
            rngs::OsRng,
            Rng,
        };
        use std::str::FromStr;

        let between = Uniform::from(0..(N + 1));
        let n = between.sample(&mut OsRng);

        let std_string: std::string::String = OsRng
            .sample_iter(&Alphanumeric)
            .take(n)
            .map(char::from)
            .collect();
        String::from_str(&std_string).unwrap()
    }

    fn maybe_random_string<const N: usize>() -> Option<String<N>> {
        use rand::{rngs::OsRng, RngCore};
        if OsRng.next_u32() & 1 != 0 {
            Some(random_string())
        } else {
            None
        }
    }

    fn random_credential_data() -> CredentialData {
        CredentialData {
            rp: PublicKeyCredentialRpEntity {
                id: random_string(),
                name: maybe_random_string(),
                icon: None,
            },
            user: PublicKeyCredentialUserEntity {
                id: random_bytes(), //Bytes::from_slice(&[1,2,3]).unwrap(),
                icon: maybe_random_string(),
                name: maybe_random_string(),
                display_name: maybe_random_string(),
            },
            creation_time: 123,
            use_counter: false,
            algorithm: -7,
            key: Key::WrappedKey(random_bytes()),
            hmac_secret: Some(false),
            cred_protect: None,
            use_short_id: Some(true),
        }
    }

    #[test]
    fn skip_credential_data_options() {
        use trussed::{cbor_deserialize as deserialize, cbor_serialize_bytes as serialize};

        let credential_data = credential_data();
        let serialization: Bytes<1024> = serialize(&credential_data).unwrap();
        let deserialized: CredentialData = deserialize(&serialization).unwrap();

        assert_eq!(credential_data, deserialized);

        let credential_data = random_credential_data();
        let serialization: Bytes<1024> = serialize(&credential_data).unwrap();
        let deserialized: CredentialData = deserialize(&serialization).unwrap();

        assert_eq!(credential_data, deserialized);
    }

    #[test]
    fn credential_ids() {
        trussed::virt::with_ram_client("fido", |mut client| {
            let kek = syscall!(client.generate_chacha8poly1305_key(Location::Internal)).key;
            let mut nonce = Bytes::new();
            nonce.extend_from_slice(&[0; 12]).unwrap();
            let data = credential_data();
            let mut full_credential = FullCredential {
                ctap: CtapVersion::Fido21Pre,
                data,
                nonce,
            };
            let rp_id_hash = syscall!(client.hash_sha256(full_credential.rp.id.as_ref()))
                .hash
                .to_bytes()
                .unwrap();

            // Case 1: credential with use_short_id = Some(true) uses new (short) format
            full_credential.data.use_short_id = Some(true);
            let stripped_credential = StrippedCredential::from(&full_credential);
            let full_id = full_credential
                .id(&mut client, kek, Some(&rp_id_hash))
                .unwrap();
            let short_id = stripped_credential
                .id(&mut client, kek, &rp_id_hash)
                .unwrap();
            assert_eq!(full_id.0, short_id.0);

            // Case 2: credential with use_short_id = None uses old (long) format
            full_credential.data.use_short_id = None;
            let stripped_credential = full_credential.strip();
            let full_id = full_credential
                .id(&mut client, kek, Some(&rp_id_hash))
                .unwrap();
            let long_id = CredentialId::new(
                &mut client,
                &stripped_credential,
                kek,
                &rp_id_hash,
                &full_credential.nonce,
            )
            .unwrap();
            assert_eq!(full_id.0, long_id.0);

            assert!(short_id.0.len() < long_id.0.len());
        });
    }

    #[test]
    fn max_credential_id() {
        let rp_id: String<256> = core::iter::repeat('?').take(256).collect();
        let key = Bytes::from_slice(&[u8::MAX; 128]).unwrap();
        let credential = StrippedCredential {
            ctap: CtapVersion::Fido21Pre,
            creation_time: u32::MAX,
            use_counter: true,
            algorithm: i32::MAX,
            key: Key::WrappedKey(key),
            nonce: Bytes::from_slice(&[u8::MAX; 12]).unwrap(),
            hmac_secret: Some(true),
            cred_protect: Some(CredentialProtectionPolicy::Required),
        };
        trussed::virt::with_ram_client("fido", |mut client| {
            let kek = syscall!(client.generate_chacha8poly1305_key(Location::Internal)).key;
            let rp_id_hash = syscall!(client.hash_sha256(rp_id.as_ref()))
                .hash
                .to_bytes()
                .unwrap();
            let id = credential.id(&mut client, kek, &rp_id_hash).unwrap();
            assert_eq!(id.0.len(), 204);
        });
    }

    // use quickcheck::TestResult;
    // quickcheck::quickcheck! {
    //   fn prop(
    //       rp_id: std::string::String,
    //       rp_name: Option<std::string::String>,
    //       rp_url: Option<std::string::String>,
    //       user_id: std::vec::Vec<u8>,
    //       user_name: Option<std::string::String>,
    //       creation_time: u32,
    //       use_counter: bool,
    //       algorithm: i32
    //     ) -> TestResult {
    //     use std::str::FromStr;
    //     use ctap_types::webauthn::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};
    //     use trussed::{cbor_deserialize as deserialize, cbor_serialize_bytes as serialize};

    //     let rp_name = &rp_name.as_ref().map(|string| string.as_str());
    //     let rp_url = &rp_url.as_ref().map(|string| string.as_str());
    //     let user_name = &user_name.as_ref().map(|string| string.as_str());
    //     let discard = [
    //         rp_id.len() > 256,
    //         rp_name.unwrap_or(&"").len() > 64,
    //         rp_url.unwrap_or(&"").len() > 64,
    //         user_id.len() > 64,
    //         user_name.unwrap_or(&"").len() > 64,

    //     ];
    //     if discard.iter().any(|&x| x) {
    //         return TestResult::discard();
    //     }

    //     let credential_data = CredentialData {
    //         rp: PublicKeyCredentialRpEntity {
    //             id: String::from_str(&rp_id).unwrap(),
    //             name: rp_name.map(|rp_name| String::from_str(rp_name).unwrap()),
    //             url: rp_url.map(|rp_url| String::from_str(rp_url).unwrap()),
    //         },
    //         user: PublicKeyCredentialUserEntity {
    //             id: Bytes::from_slice(&user_id).unwrap(),
    //             icon: maybe_random_string(),
    //             name: user_name.map(|user_name| String::from_str(user_name).unwrap()),
    //             display_name: maybe_random_string(),
    //         },
    //         creation_time,
    //         use_counter,
    //         algorithm,
    //         key: Key::WrappedKey(random_bytes()),
    //         hmac_secret: Some(false),
    //         cred_protect: None,
    //     };

    //     let serialization: Bytes<1024> = serialize(&credential_data).unwrap();
    //     let deserialized: CredentialData = deserialize(&serialization).unwrap();

    //     TestResult::from_bool(credential_data == deserialized)
    // }
    // }
}
