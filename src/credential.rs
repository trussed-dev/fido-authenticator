use core::convert::{TryFrom, TryInto};

use trussed::{
    client, syscall, try_syscall,
    types::KeyId,
};

pub(crate) use ctap_types::{
    Bytes, Bytes32, String, Vec,
    // authenticator::{ctap1, ctap2, Error, Request, Response},
    ctap2::credential_management::CredentialProtectionPolicy,
    sizes::*,
    webauthn::PublicKeyCredentialDescriptor,
};

use crate::{
    Authenticator,
    Error,
    Result,
    UserPresence,
};


#[derive(Copy, Clone, Debug, serde::Deserialize, serde::Serialize)]
// #[derive(Copy, Clone, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
pub enum CtapVersion {
    U2fV2,
    Fido20,
    Fido21Pre,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CredentialId(pub Bytes<MAX_CREDENTIAL_ID_LENGTH>);

// TODO: how to determine necessary size?
// pub type SerializedCredential = Bytes<512>;
// pub type SerializedCredential = Bytes<256>;
pub type SerializedCredential = trussed::types::Message;

#[derive(Clone, Debug)]
pub struct EncryptedSerializedCredential(pub trussed::api::reply::Encrypt);

impl TryFrom<EncryptedSerializedCredential> for CredentialId {
    type Error = Error;

    fn try_from(esc: EncryptedSerializedCredential) -> Result<CredentialId> {
        Ok(CredentialId(trussed::cbor_serialize_bytes(&esc.0).map_err(|_| Error::Other)?))
    }
}

impl TryFrom<CredentialId> for EncryptedSerializedCredential {
    // tag = 16B
    // nonce = 12B
    type Error = Error;

    fn try_from(cid: CredentialId) -> Result<EncryptedSerializedCredential> {
        let encrypted_serialized_credential = EncryptedSerializedCredential(
            ctap_types::serde::cbor_deserialize(&cid.0).map_err(|_| Error::InvalidCredential)?
        );
        Ok(encrypted_serialized_credential)
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum Key {
    ResidentKey(KeyId),
    // THIS USED TO BE 92 NOW IT'S 96 or 97 or so... waddup?
    WrappedKey(Bytes<128>),
}

#[derive(Clone, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
pub struct CredentialData {
    // id, name, url
    pub rp: ctap_types::webauthn::PublicKeyCredentialRpEntity,
    // id, name, display_name
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

    // TODO: add `sig_counter: Option<CounterId>`,
    // and grant RKs a per-credential sig-counter.
}

// TODO: figure out sizes
// We may or may not follow https://github.com/satoshilabs/slips/blob/master/slip-0022.md
#[derive(Clone, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
// #[serde_indexed(offset = 1)]
pub struct Credential {
    ctap: CtapVersion,
    pub data: CredentialData,
    nonce: Bytes<12>,
}

impl core::ops::Deref for Credential {
    type Target = CredentialData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

pub type CredentialList = Vec<Credential, {ctap_types::sizes::MAX_CREDENTIAL_COUNT_IN_LIST}>;

impl Into<PublicKeyCredentialDescriptor> for CredentialId {
    fn into(self) -> PublicKeyCredentialDescriptor {
        PublicKeyCredentialDescriptor {
            id: self.0,
            key_type: {
                let mut key_type = String::new();
                key_type.push_str("public-key").unwrap();
                key_type
            }
        }
    }
}

impl Credential {
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
        nonce: [u8; 12],
    )
        -> Self
    {
        info!("credential for algorithm {}", algorithm);
        let data = CredentialData {
            rp: rp.clone(),
            user: user.clone(),

            creation_time: timestamp,
            use_counter: true,
            algorithm: algorithm,
            key,

            hmac_secret,
            cred_protect,
        };

        Credential {
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
    pub fn id<'a, T: client::Chacha8Poly1305 + client::Sha256>(
        &self,
        trussed: &mut T,
        key_encryption_key: KeyId,
        rp_id_hash: Option<&Bytes32>,
    )
        -> Result<CredentialId>
    {
        let serialized_credential = self.strip().serialize()?;
        let message = &serialized_credential;
        // info!("serialized cred = {:?}", message).ok();

        let rp_id_hash: Bytes32 = if let Some(hash) = rp_id_hash {
            hash.clone()
        } else {
            syscall!(trussed.hash_sha256(&self.rp.id.as_ref()))
                .hash
                .to_bytes().map_err(|_| Error::Other)?
        };

        let associated_data = &rp_id_hash[..];
        let nonce: [u8; 12] = self.nonce.as_slice().try_into().unwrap();
        let encrypted_serialized_credential = EncryptedSerializedCredential(
            syscall!(trussed.encrypt_chacha8poly1305(
                    key_encryption_key, message, associated_data, Some(&nonce))));
        let credential_id: CredentialId = encrypted_serialized_credential.try_into().unwrap();

        Ok(credential_id)
    }

    pub fn serialize(&self) -> Result<SerializedCredential> {
        Ok(trussed::cbor_serialize_bytes(self).map_err(|_| Error::Other)?)
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

    pub fn try_from<UP: UserPresence, T: client::Client + client::Chacha8Poly1305>(
        authnr: &mut Authenticator<UP,T>,
        rp_id_hash: &Bytes<32>,
        descriptor: &PublicKeyCredentialDescriptor,
    )
        -> Result<Self>
    {
        Self::try_from_bytes(authnr, rp_id_hash, &descriptor.id)
    }

    pub fn try_from_bytes<UP: UserPresence, T: client::Client + client::Chacha8Poly1305>(
        authnr: &mut Authenticator<UP, T>,
        rp_id_hash: &Bytes<32>,
        id: &[u8],
    )
        -> Result<Self>
    {

        let mut cred: Bytes<MAX_CREDENTIAL_ID_LENGTH> = Bytes::new();
        cred.extend_from_slice(id).map_err(|_| Error::InvalidCredential)?;

        let encrypted_serialized = EncryptedSerializedCredential::try_from(
            CredentialId(cred)
        )?;

        let kek = authnr.state.persistent.key_encryption_key(&mut authnr.trussed)?;

        let serialized = try_syscall!(authnr.trussed.decrypt_chacha8poly1305(
            // TODO: use RpId as associated data here?
            kek,
            &encrypted_serialized.0.ciphertext,
            &rp_id_hash[..],
            &encrypted_serialized.0.nonce,
            &encrypted_serialized.0.tag,
        ))
            .map_err(|_| Error::InvalidCredential)?.plaintext
            .ok_or(Error::InvalidCredential)?;

        let credential = Credential::deserialize(&serialized)
            .map_err(|_| Error::InvalidCredential)?;

        Ok(credential)
    }

    // Remove inessential metadata from credential.
    //
    // Called by the `id` method, see its documentation.
    pub fn strip(&self) -> Self {
        let mut stripped = self.clone();
        let data = &mut stripped.data;

        data.rp.name = None;
        data.rp.url = None;

        data.user.icon = None;
        data.user.name = None;
        data.user.display_name = None;

        // data.hmac_secret = None;
        // data.cred_protect = None;

        stripped
    }
}
