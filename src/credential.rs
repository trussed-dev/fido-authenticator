//! Internal `Credential` and external `CredentialId` ("keyhandle").

use core::cmp::Ordering;

use serde::Serialize;
use serde_bytes::ByteArray;
use trussed_core::{
    mechanisms::{Chacha8Poly1305, Sha256},
    syscall, try_syscall,
    types::{EncryptedData, KeyId},
    CryptoClient, FilesystemClient,
};

pub(crate) use ctap_types::{
    // authenticator::{ctap1, ctap2, Error, Request, Response},
    ctap2::credential_management::CredentialProtectionPolicy,
    sizes::*,
    webauthn::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialDescriptorRef,
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    },
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
    fn new<T: Chacha8Poly1305, C: Serialize>(
        trussed: &mut T,
        credential: &C,
        key_encryption_key: KeyId,
        rp_id_hash: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Self> {
        let mut serialized_credential = SerializedCredential::new();
        cbor_smol::cbor_serialize_to(credential, &mut serialized_credential)
            .map_err(|_| Error::Other)?;
        let message = &serialized_credential;
        // info!("serialized cred = {:?}", message).ok();
        let associated_data = &rp_id_hash[..];
        let encrypted_serialized_credential = syscall!(trussed.encrypt_chacha8poly1305(
            key_encryption_key,
            message,
            associated_data,
            Some(nonce)
        ));
        let mut credential_id = Bytes::new();
        cbor_smol::cbor_serialize_to(
            &EncryptedData::from(encrypted_serialized_credential),
            &mut credential_id,
        )
        .map_err(|_| Error::RequestTooLarge)?;
        Ok(Self(credential_id))
    }
}

struct CredentialIdRef<'a>(&'a [u8]);

impl CredentialIdRef<'_> {
    fn deserialize(&self) -> Result<EncryptedData> {
        cbor_smol::cbor_deserialize(self.0).map_err(|_| Error::InvalidCredential)
    }
}

// TODO: how to determine necessary size?
// pub type SerializedCredential = Bytes<512>;
// pub type SerializedCredential = Bytes<256>;
pub(crate) type SerializedCredential = trussed_core::types::Message;

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
    pub fn try_from<UP: UserPresence, T: CryptoClient + Chacha8Poly1305 + FilesystemClient>(
        authnr: &mut Authenticator<UP, T>,
        rp_id_hash: &[u8; 32],
        descriptor: &PublicKeyCredentialDescriptorRef,
    ) -> Result<Self> {
        Self::try_from_bytes(authnr, rp_id_hash, descriptor.id)
    }

    pub fn try_from_bytes<
        UP: UserPresence,
        T: CryptoClient + Chacha8Poly1305 + FilesystemClient,
    >(
        authnr: &mut Authenticator<UP, T>,
        rp_id_hash: &[u8; 32],
        id: &[u8],
    ) -> Result<Self> {
        let encrypted_serialized = CredentialIdRef(id).deserialize()?;

        let kek = authnr
            .state
            .persistent
            .key_encryption_key(&mut authnr.trussed)?;

        let serialized = try_syscall!(authnr.trussed.decrypt_chacha8poly1305(
            kek,
            &encrypted_serialized.ciphertext,
            &rp_id_hash[..],
            &encrypted_serialized.nonce,
            &encrypted_serialized.tag,
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

    pub fn id<T: Chacha8Poly1305 + Sha256>(
        &self,
        trussed: &mut T,
        key_encryption_key: KeyId,
        rp_id_hash: &[u8; 32],
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

    pub fn third_party_payment(&self) -> Option<bool> {
        match self {
            Self::Full(credential) => credential.data.third_party_payment,
            Self::Stripped(credential) => credential.third_party_payment,
        }
    }
}

fn deserialize_bytes<E: serde::de::Error, const N: usize>(
    s: &[u8],
) -> core::result::Result<Bytes<N>, E> {
    Bytes::from_slice(s).map_err(|_| E::invalid_length(s.len(), &"a fixed-size sequence of bytes"))
}

fn deserialize_str<E: serde::de::Error, const N: usize>(
    s: &str,
) -> core::result::Result<String<N>, E> {
    Ok(s.into())
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SerializationFormat {
    Short,
    Long,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Rp {
    format: SerializationFormat,
    inner: PublicKeyCredentialRpEntity,
}

impl Rp {
    fn new(inner: PublicKeyCredentialRpEntity) -> Self {
        Self {
            format: SerializationFormat::Short,
            inner,
        }
    }

    fn raw(&self) -> RawRp<'_> {
        let mut raw = RawRp::default();
        match self.format {
            SerializationFormat::Short => {
                raw.i = Some(&self.inner.id);
                raw.n = self.inner.name.as_deref();
            }
            SerializationFormat::Long => {
                raw.id = Some(&self.inner.id);
                raw.name = self.inner.name.as_deref();
            }
        }
        raw
    }

    pub fn id(&self) -> &str {
        &self.inner.id
    }
}

impl AsRef<PublicKeyCredentialRpEntity> for Rp {
    fn as_ref(&self) -> &PublicKeyCredentialRpEntity {
        &self.inner
    }
}

impl AsMut<PublicKeyCredentialRpEntity> for Rp {
    fn as_mut(&mut self) -> &mut PublicKeyCredentialRpEntity {
        &mut self.inner
    }
}

impl<'de> serde::Deserialize<'de> for Rp {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let r = RawRp::deserialize(deserializer)?;

        if r.i.is_some() && r.id.is_some() {
            return Err(D::Error::duplicate_field("i"));
        }

        let (format, id, name) = if let Some(i) = r.i {
            if r.name.is_some() {
                return Err(D::Error::unknown_field("name", &["i", "n"]));
            }
            (SerializationFormat::Short, i, r.n)
        } else if let Some(id) = r.id {
            if r.n.is_some() {
                return Err(D::Error::unknown_field("n", &["id", "name"]));
            }
            (SerializationFormat::Long, id, r.name)
        } else {
            return Err(D::Error::missing_field("i"));
        };

        let inner = PublicKeyCredentialRpEntity {
            id: deserialize_str(id)?,
            name: name.map(deserialize_str).transpose()?,
            icon: None,
        };
        Ok(Self { format, inner })
    }
}

impl serde::Serialize for Rp {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        self.raw().serialize(serializer)
    }
}

impl From<Rp> for PublicKeyCredentialRpEntity {
    fn from(rp: Rp) -> PublicKeyCredentialRpEntity {
        rp.inner
    }
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct RawRp<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    i: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct User {
    format: SerializationFormat,
    inner: PublicKeyCredentialUserEntity,
}

impl User {
    fn new(inner: PublicKeyCredentialUserEntity) -> Self {
        Self {
            format: SerializationFormat::Short,
            inner,
        }
    }

    fn raw(&self) -> RawUser<'_> {
        let mut raw = RawUser::default();
        match self.format {
            SerializationFormat::Short => {
                raw.i = Some(self.inner.id.as_slice().into());
                raw.ii = self.inner.icon.as_deref();
                raw.n = self.inner.name.as_deref();
                raw.d = self.inner.display_name.as_deref();
            }
            SerializationFormat::Long => {
                raw.id = Some(self.inner.id.as_slice().into());
                raw.icon = self.inner.icon.as_deref();
                raw.name = self.inner.name.as_deref();
                raw.display_name = self.inner.display_name.as_deref();
            }
        }
        raw
    }

    pub fn id(&self) -> &Bytes<64> {
        &self.inner.id
    }
}

impl AsRef<PublicKeyCredentialUserEntity> for User {
    fn as_ref(&self) -> &PublicKeyCredentialUserEntity {
        &self.inner
    }
}

impl AsMut<PublicKeyCredentialUserEntity> for User {
    fn as_mut(&mut self) -> &mut PublicKeyCredentialUserEntity {
        &mut self.inner
    }
}

impl<'de> serde::Deserialize<'de> for User {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let u = RawUser::deserialize(deserializer)?;

        if u.i.is_some() && u.id.is_some() {
            return Err(D::Error::duplicate_field("i"));
        }

        let (format, id, icon, name, display_name) = if let Some(i) = u.i {
            // short format
            let fields = &["i", "I", "n", "d"];
            if u.icon.is_some() {
                return Err(D::Error::unknown_field("icon", fields));
            }
            if u.name.is_some() {
                return Err(D::Error::unknown_field("name", fields));
            }
            if u.display_name.is_some() {
                return Err(D::Error::unknown_field("display_name", fields));
            }

            (SerializationFormat::Short, i, u.ii, u.n, u.d)
        } else if let Some(id) = u.id {
            // long format
            let fields = &["id", "icon", "name", "display_name"];
            if u.ii.is_some() {
                return Err(D::Error::unknown_field("ii", fields));
            }
            if u.n.is_some() {
                return Err(D::Error::unknown_field("n", fields));
            }
            if u.d.is_some() {
                return Err(D::Error::unknown_field("d", fields));
            }

            (
                SerializationFormat::Long,
                id,
                u.icon,
                u.name,
                u.display_name,
            )
        } else {
            // ID is missing
            return Err(D::Error::missing_field("i"));
        };

        let inner = PublicKeyCredentialUserEntity {
            id: deserialize_bytes(id)?,
            icon: icon.map(deserialize_str).transpose()?,
            name: name.map(deserialize_str).transpose()?,
            display_name: display_name.map(deserialize_str).transpose()?,
        };
        Ok(Self { format, inner })
    }
}

impl serde::Serialize for User {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        self.raw().serialize(serializer)
    }
}

impl From<User> for PublicKeyCredentialUserEntity {
    fn from(user: User) -> PublicKeyCredentialUserEntity {
        user.inner
    }
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct RawUser<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    i: Option<&'a serde_bytes::Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a serde_bytes::Bytes>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "I")]
    ii: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "displayName")]
    display_name: Option<&'a str>,
}

/// The main content of a `FullCredential`.
#[derive(
    Clone, Debug, PartialEq, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed,
)]
pub struct CredentialData {
    // id, name, url
    pub rp: Rp,
    // id, icon, name, display_name
    pub user: User,

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
    // TODO: add `sig_counter: Option<CounterId>`,
    // and grant RKs a per-credential sig-counter.

    // In older app versions, we serialized the full credential to determine the credential ID.  In
    // newer app versions, we strip unnecessary fields to generate a shorter credential ID.  To
    // make sure that the credential ID does not change for an existing credential, this field is
    // used as a marker for new credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    use_short_id: Option<bool>,

    // extensions (cont. -- we can only append new options due to index-based deserialization)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteArray<32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_payment: Option<bool>,
}

// TODO: figure out sizes
// We may or may not follow https://github.com/satoshilabs/slips/blob/master/slip-0022.md
/// The core structure this authenticator creates and uses.
#[derive(Clone, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
pub struct FullCredential {
    ctap: CtapVersion,
    pub data: CredentialData,
    nonce: ByteArray<12>,
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
        large_blob_key: Option<ByteArray<32>>,
        third_party_payment: Option<bool>,
        nonce: [u8; 12],
    ) -> Self {
        info!("credential for algorithm {}", algorithm);
        let data = CredentialData {
            rp: Rp::new(rp.clone()),
            user: User::new(user.clone()),

            creation_time: timestamp,
            use_counter: true,
            algorithm,
            key,

            hmac_secret,
            cred_protect,
            large_blob_key,
            third_party_payment,

            use_short_id: Some(true),
        };

        FullCredential {
            ctap,
            data,
            nonce: ByteArray::new(nonce),
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
    pub fn id<T: Chacha8Poly1305 + Sha256>(
        &self,
        trussed: &mut T,
        key_encryption_key: KeyId,
        rp_id_hash: Option<&[u8; 32]>,
    ) -> Result<CredentialId> {
        let rp_id_hash: [u8; 32] = if let Some(hash) = rp_id_hash {
            *hash
        } else {
            syscall!(trussed.hash_sha256(self.rp.id().as_ref()))
                .hash
                .as_slice()
                .try_into()
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
        let mut serialized_credential = SerializedCredential::new();
        cbor_smol::cbor_serialize_to(self, &mut serialized_credential).map_err(|_| Error::Other)?;
        Ok(serialized_credential)
    }

    pub fn deserialize(bytes: &SerializedCredential) -> Result<Self> {
        match cbor_smol::cbor_deserialize(bytes) {
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
        let rp = stripped.data.rp.as_mut();
        rp.name = None;
        let user = stripped.data.user.as_mut();
        user.icon = None;
        user.name = None;
        user.display_name = None;
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
    pub nonce: ByteArray<12>,
    // extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
    // TODO: HACK -- remove
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteArray<32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_payment: Option<bool>,
}

impl StrippedCredential {
    fn deserialize(bytes: &SerializedCredential) -> Result<Self> {
        match cbor_smol::cbor_deserialize(bytes) {
            Ok(s) => Ok(s),
            Err(_) => {
                info_now!("could not deserialize {:?}", bytes);
                Err(Error::Other)
            }
        }
    }

    pub fn id<T: Chacha8Poly1305>(
        &self,
        trussed: &mut T,
        key_encryption_key: KeyId,
        rp_id_hash: &[u8; 32],
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
            nonce: credential.nonce,
            hmac_secret: credential.data.hmac_secret,
            cred_protect: credential.data.cred_protect,
            large_blob_key: credential.data.large_blob_key,
            third_party_payment: credential.data.third_party_payment,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use littlefs2_core::path;
    use rand::SeedableRng as _;
    use rand_chacha::ChaCha8Rng;
    use serde_test::{assert_de_tokens, assert_tokens, Token};
    use trussed::{
        client::{Chacha8Poly1305, Sha256},
        key::{Kind, Secrecy},
        store::keystore::{ClientKeystore, Keystore as _},
        types::Location,
        virt::{self, StoreConfig},
        Platform as _,
    };

    fn credential_data() -> CredentialData {
        CredentialData {
            rp: Rp::new(PublicKeyCredentialRpEntity {
                id: String::from("John Doe"),
                name: None,
                icon: None,
            }),
            user: User::new(PublicKeyCredentialUserEntity {
                id: Bytes::from_slice(&[1, 2, 3]).unwrap(),
                icon: None,
                name: None,
                display_name: None,
            }),
            creation_time: 123,
            use_counter: false,
            algorithm: -7,
            key: Key::WrappedKey(Bytes::from_slice(&[1, 2, 3]).unwrap()),
            hmac_secret: Some(false),
            cred_protect: None,
            use_short_id: Some(true),
            large_blob_key: Some(ByteArray::new([0xff; 32])),
            third_party_payment: Some(true),
        }
    }

    fn old_credential_data() -> CredentialData {
        CredentialData {
            rp: Rp {
                format: SerializationFormat::Long,
                inner: PublicKeyCredentialRpEntity {
                    id: String::from("John Doe"),
                    name: None,
                    icon: None,
                },
            },
            user: User {
                format: SerializationFormat::Long,
                inner: PublicKeyCredentialUserEntity {
                    id: Bytes::from_slice(&[1, 2, 3]).unwrap(),
                    icon: None,
                    name: None,
                    display_name: None,
                },
            },
            creation_time: 123,
            use_counter: false,
            algorithm: -7,
            key: Key::WrappedKey(Bytes::from_slice(&[1, 2, 3]).unwrap()),
            hmac_secret: Some(false),
            cred_protect: None,
            use_short_id: None,
            large_blob_key: None,
            third_party_payment: None,
        }
    }

    fn random_byte_array<const N: usize>() -> ByteArray<N> {
        use rand::{rngs::OsRng, RngCore};
        let mut bytes = [0; N];
        OsRng.fill_bytes(&mut bytes);
        ByteArray::new(bytes)
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
            rp: Rp::new(PublicKeyCredentialRpEntity {
                id: random_string(),
                name: maybe_random_string(),
                icon: None,
            }),
            user: User::new(PublicKeyCredentialUserEntity {
                id: random_bytes(), //Bytes::from_slice(&[1,2,3]).unwrap(),
                icon: maybe_random_string(),
                name: maybe_random_string(),
                display_name: maybe_random_string(),
            }),
            creation_time: 123,
            use_counter: false,
            algorithm: -7,
            key: Key::WrappedKey(random_bytes()),
            hmac_secret: Some(false),
            cred_protect: None,
            use_short_id: Some(true),
            large_blob_key: Some(random_byte_array()),
            third_party_payment: Some(false),
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
    fn old_credential_id() {
        // generated with v0.1.1-nitrokey.4 (NK3 firmware version v1.4.0)
        const OLD_ID: &[u8] = &hex!("A300583A71AEF80C4DA56033D66EB3266E9ACB8D84923D13F89BCBCE9FF30D8CD77ED968A436CA3D39C49999EC0F69A289CB2A65A08ABF251DEB21BB4B56014C00000000000000000000000002504DF499ABDAE80F5615C870985B74A799");
        const SERIALIZED_DATA: &[u8] = &hex!(
            "A700A1626964684A6F686E20446F6501A16269644301020302187B03F404260582014301020306F4"
        );
        const SERIALIZED_CREDENTIAL: &[u8] = &hex!("A3000201A700A1626964684A6F686E20446F6501A16269644301020302187B03F404260582014301020306F4024C000000000000000000000000");

        virt::with_platform(StoreConfig::ram(), |mut platform| {
            let kek = [0; 44];
            let client_id = path!("fido");
            let kek = {
                let rng = ChaCha8Rng::from_rng(platform.rng()).unwrap();
                let mut keystore = ClientKeystore::new(client_id.into(), rng, platform.store());
                keystore
                    .store_key(
                        Location::Internal,
                        Secrecy::Secret,
                        Kind::Symmetric32Nonce(12),
                        &kek,
                    )
                    .unwrap()
            };
            platform.run_client(client_id.as_str(), |mut client| {
                let data = old_credential_data();
                let rp_id_hash = syscall!(client.hash_sha256(data.rp.id().as_ref())).hash;
                let encrypted_serialized = CredentialIdRef(OLD_ID).deserialize().unwrap();
                let serialized = syscall!(client.decrypt_chacha8poly1305(
                    kek,
                    &encrypted_serialized.ciphertext,
                    &rp_id_hash,
                    &encrypted_serialized.nonce,
                    &encrypted_serialized.tag,
                ))
                .plaintext
                .unwrap();

                let full = FullCredential::deserialize(&serialized).unwrap();
                assert_eq!(
                    full,
                    FullCredential {
                        ctap: CtapVersion::Fido21Pre,
                        data,
                        nonce: [0; 12].into(),
                    }
                );

                let stripped_credential = full.strip();

                let serialized_data: Bytes<1024> =
                    trussed::cbor_serialize_bytes(&stripped_credential.data).unwrap();
                assert_eq!(
                    delog::hexstr!(&serialized_data).to_string(),
                    delog::hexstr!(SERIALIZED_DATA).to_string()
                );

                let serialized_credential: Bytes<1024> =
                    trussed::cbor_serialize_bytes(&stripped_credential).unwrap();
                assert_eq!(
                    delog::hexstr!(&serialized_credential).to_string(),
                    delog::hexstr!(SERIALIZED_CREDENTIAL).to_string()
                );

                let credential = Credential::Full(full);
                let id = credential
                    .id(&mut client, kek, rp_id_hash.as_ref().try_into().unwrap())
                    .unwrap()
                    .0;
                assert_eq!(
                    delog::hexstr!(&id).to_string(),
                    delog::hexstr!(OLD_ID).to_string()
                );
            });
        });
    }

    #[test]
    fn credential_ids() {
        trussed::virt::with_client(StoreConfig::ram(), "fido", |mut client| {
            let kek = syscall!(client.generate_chacha8poly1305_key(Location::Internal)).key;
            let nonce = ByteArray::new([0; 12]);
            let data = credential_data();
            let mut full_credential = FullCredential {
                ctap: CtapVersion::Fido21Pre,
                data,
                nonce,
            };
            let rp_id_hash = syscall!(client.hash_sha256(full_credential.rp.id().as_ref()))
                .hash
                .as_slice()
                .try_into()
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
        let rp_id: String<256> = core::iter::repeat_n('?', 256).collect();
        let key = Bytes::from_slice(&[u8::MAX; 128]).unwrap();
        let credential = StrippedCredential {
            ctap: CtapVersion::Fido21Pre,
            creation_time: u32::MAX,
            use_counter: true,
            algorithm: i32::MAX,
            key: Key::WrappedKey(key),
            nonce: ByteArray::new([u8::MAX; 12]),
            hmac_secret: Some(true),
            cred_protect: Some(CredentialProtectionPolicy::Required),
            large_blob_key: Some(ByteArray::new([0xff; 32])),
            third_party_payment: Some(true),
        };
        trussed::virt::with_client(StoreConfig::ram(), "fido", |mut client| {
            let kek = syscall!(client.generate_chacha8poly1305_key(Location::Internal)).key;
            let rp_id_hash = syscall!(client.hash_sha256(rp_id.as_ref()))
                .hash
                .as_slice()
                .try_into()
                .unwrap();
            let id = credential.id(&mut client, kek, &rp_id_hash).unwrap();
            assert_eq!(id.0.len(), 241);
        });
    }

    fn test_serde<T>(item: &T, name: &'static str, fields: &[(&'static str, Token)])
    where
        for<'a> T: core::fmt::Debug + PartialEq + serde::Deserialize<'a> + serde::Serialize,
    {
        let len = fields.len();

        let mut struct_tokens = vec![Token::Struct { name, len }];
        let mut map_tokens = vec![Token::Map { len: Some(len) }];
        for (key, value) in fields {
            struct_tokens.push(Token::Str(key));
            struct_tokens.push(Token::Some);
            struct_tokens.push(*value);

            map_tokens.push(Token::Str(key));
            map_tokens.push(Token::Some);
            map_tokens.push(*value);
        }
        struct_tokens.push(Token::StructEnd);
        map_tokens.push(Token::MapEnd);

        assert_tokens(item, &struct_tokens);
        assert_de_tokens(item, &map_tokens);
    }

    struct RpValues {
        id: &'static str,
        name: Option<&'static str>,
    }

    impl RpValues {
        fn test(&self) {
            for format in [SerializationFormat::Short, SerializationFormat::Long] {
                self.test_format(format);
            }
        }

        fn test_format(&self, format: SerializationFormat) {
            let (id_field, name_field) = match format {
                SerializationFormat::Short => ("i", "n"),
                SerializationFormat::Long => ("id", "name"),
            };
            let rp = Rp {
                format,
                inner: self.inner(),
            };

            let mut fields = vec![(id_field, Token::BorrowedStr(self.id))];
            if let Some(name) = self.name {
                fields.push((name_field, Token::BorrowedStr(name)));
            }

            test_serde(&rp, "RawRp", &fields);
        }

        fn inner(&self) -> PublicKeyCredentialRpEntity {
            PublicKeyCredentialRpEntity {
                id: self.id.into(),
                name: self.name.map(From::from),
                icon: None,
            }
        }
    }

    #[test]
    fn serde_rp_name_none() {
        RpValues {
            id: "Testing rp id",
            name: None,
        }
        .test()
    }

    #[test]
    fn serde_rp_name_some() {
        RpValues {
            id: "Testing rp id",
            name: Some("Testing rp name"),
        }
        .test()
    }

    struct UserValues {
        id: &'static [u8],
        icon: Option<&'static str>,
        name: Option<&'static str>,
        display_name: Option<&'static str>,
    }

    impl UserValues {
        fn test(&self) {
            for format in [SerializationFormat::Short, SerializationFormat::Long] {
                self.test_format(format);
            }
        }

        fn test_format(&self, format: SerializationFormat) {
            let (id_field, icon_field, name_field, display_name_field) = match format {
                SerializationFormat::Short => ("i", "I", "n", "d"),
                SerializationFormat::Long => ("id", "icon", "name", "displayName"),
            };
            let user = User {
                format,
                inner: self.inner(),
            };

            let mut fields = vec![(id_field, Token::BorrowedBytes(self.id))];
            if let Some(icon) = self.icon {
                fields.push((icon_field, Token::BorrowedStr(icon)));
            }
            if let Some(name) = self.name {
                fields.push((name_field, Token::BorrowedStr(name)));
            }
            if let Some(display_name) = self.display_name {
                fields.push((display_name_field, Token::BorrowedStr(display_name)));
            }

            test_serde(&user, "RawUser", &fields);
        }

        fn inner(&self) -> PublicKeyCredentialUserEntity {
            PublicKeyCredentialUserEntity {
                id: Bytes::from_slice(self.id).unwrap(),
                icon: self.icon.map(From::from),
                name: self.name.map(From::from),
                display_name: self.display_name.map(From::from),
            }
        }
    }

    #[test]
    fn serde_user_full() {
        UserValues {
            id: b"Testing user id",
            icon: Some("Testing user icon"),
            name: Some("Testing user name"),
            display_name: Some("Testing user display_name"),
        }
        .test();
    }

    #[test]
    fn serde_user_display_name() {
        UserValues {
            id: b"Testing user id",
            icon: None,
            name: None,
            display_name: Some("Testing user display_name"),
        }
        .test();
    }

    #[test]
    fn serde_user_icon_display_name() {
        UserValues {
            id: b"Testing user id",
            icon: Some("Testing user icon"),
            name: None,
            display_name: Some("Testing user display_name"),
        }
        .test();
    }

    #[test]
    fn serde_user_icon() {
        UserValues {
            id: b"Testing user id",
            icon: Some("Testing user icon"),
            name: None,
            display_name: None,
        }
        .test();
    }

    #[test]
    fn serde_user_empty() {
        UserValues {
            id: b"Testing user id",
            icon: None,
            name: None,
            display_name: None,
        }
        .test();
    }

    // Test credentials that were serialized before the migration to shorter field names for serialization
    #[test]
    fn legacy_full_credential() {
        use hex_literal::hex;
        let data = hex!(
            "
            a3000201a700a16269646b776562617574686e2e696f01a2626964476447
            567a644445646e616d65657465737431020003f504260582005037635754
            c9882b21565a9f8a47b0ece408f5024cf62ca01ed181a3d03d561fc7
        "
        );

        let credential = FullCredential::deserialize(&Bytes::from_slice(&data).unwrap()).unwrap();
        assert!(matches!(credential.ctap, CtapVersion::Fido21Pre));
        assert_eq!(credential.nonce, &hex!("F62CA01ED181A3D03D561FC7"));
        assert_eq!(
            credential.data,
            CredentialData {
                rp: Rp {
                    format: SerializationFormat::Long,
                    inner: PublicKeyCredentialRpEntity {
                        id: "webauthn.io".into(),
                        name: None,
                        icon: None,
                    },
                },
                user: User {
                    format: SerializationFormat::Long,
                    inner: PublicKeyCredentialUserEntity {
                        id: Bytes::from_slice(&hex!("6447567A644445")).unwrap(),
                        icon: None,
                        name: Some("test1".into()),
                        display_name: None,
                    },
                },
                creation_time: 0,
                use_counter: true,
                algorithm: -7,
                key: Key::ResidentKey(KeyId::from_value(0x37635754C9882B21565A9F8A47B0ECE4)),
                hmac_secret: None,
                cred_protect: None,
                use_short_id: Some(true),
                large_blob_key: None,
                third_party_payment: None,
            },
        );
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
