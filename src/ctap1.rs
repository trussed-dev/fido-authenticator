//! The `ctap1::Authenticator` trait and its implementation.

use ctap_types::{
    Bytes,
    ctap1::{
        self,
        Command as Request,
        Response,
        Result,
        Error,
    },
};

use trussed::{
    syscall,
    types::{
        KeySerialization,
        Mechanism,
        SignatureSerialization,
        Location,
    },
};

use crate::{
    credential::{
        self,
        Credential,
        Key,
    },
    constants,
    SigningAlgorithm,
    TrussedRequirements,
    UserPresence,
};

/// CTAP1 (U2F) authenticator API
///
/// Ahh... life could be so simple!
//
// TODO: Lift into ctap-types?
pub trait Authenticator {
    /// Register a U2F credential.
    fn register(&mut self, request: &ctap1::Register) -> Result<ctap1::RegisterResponse>;
    /// Authenticate with a U2F credential.
    fn authenticate(&mut self, request: &ctap1::Authenticate) -> Result<ctap1::AuthenticateResponse>;
    /// Supported U2F version.
    fn version() -> [u8; 6] {
        *b"U2F_V2"
    }
}

impl<UP, T> crate::Authenticator<UP, T>
where UP: UserPresence,
      T: TrussedRequirements,
{
    /// Dispatches the enum of possible requests into the ctap1 [`Authenticator`] trait methods.
    pub fn call_ctap1(&mut self, request: &Request) -> Result<Response> {
        info!("called ctap1");
        self.state.persistent.load_if_not_initialised(&mut self.trussed);

        match request {
            Request::Register(reg) =>
                Ok(Response::Register(self.register(reg)?)),

            Request::Authenticate(auth) =>
                Ok(Response::Authenticate(self.authenticate(auth)?)),

            Request::Version =>
                Ok(ctap1::Response::Version(Self::version())),

        }
    }

    // #[deprecated(note="please use `call_ctap1` instead")]
    /// Alias of `call_ctap1`, may be deprecated in the future.
    pub fn call_u2f(&mut self, request: &Request) -> Result<Response> {
        self.call_ctap1(request)
    }

}

type Commitment = Bytes::<324>;

/// Implement `ctap1::Authenticator` for our Authenticator.
impl<UP: UserPresence, T: TrussedRequirements> Authenticator for crate::Authenticator<UP, T>
{
    fn register(&mut self, reg: &ctap1::Register) -> Result<ctap1::RegisterResponse> {
        self.up.user_present(&mut self.trussed, constants::U2F_UP_TIMEOUT)
            .map_err(|_| Error::ConditionsOfUseNotSatisfied)?;

        // Generate a new P256 key pair.
        let private_key = syscall!(self.trussed.generate_p256_private_key(Location::Volatile)).key;
        let public_key = syscall!(self.trussed.derive_p256_public_key(private_key, Location::Volatile)).key;

        let serialized_cose_public_key = syscall!(self.trussed.serialize_p256_key(
            public_key, KeySerialization::EcdhEsHkdf256
        )).serialized_key;
        let cose_key: ctap_types::cose::EcdhEsHkdf256PublicKey
            = trussed::cbor_deserialize(&serialized_cose_public_key).unwrap();

        let wrapping_key = self.state.persistent.key_wrapping_key(&mut self.trussed)
            .map_err(|_| Error::UnspecifiedCheckingError)?;
        debug!("wrapping u2f private key");
        let wrapped_key = syscall!(self.trussed.wrap_key_chacha8poly1305(
            wrapping_key,
            private_key,
            &reg.app_id,
        )).wrapped_key;
        // debug!("wrapped_key = {:?}", &wrapped_key);

        let key = Key::WrappedKey(wrapped_key.to_bytes().map_err(|_| Error::UnspecifiedCheckingError)?);
        let nonce = syscall!(self.trussed.random_bytes(12)).bytes.as_slice().try_into().unwrap();

        let mut rp_id = heapless::String::new();

        // We do not know the rpId string in U2F.  Just using placeholder.
        rp_id.push_str("u2f").ok();
        let rp = ctap_types::webauthn::PublicKeyCredentialRpEntity{
            id: rp_id,
            name: None,
            url: None,
        };

        let user = ctap_types::webauthn::PublicKeyCredentialUserEntity {
            id: Bytes::from_slice(&[0u8; 8]).unwrap(),
            icon: None,
            name: None,
            display_name: None,
        };

        let credential = Credential::new(
            credential::CtapVersion::U2fV2,
            &rp,
            &user,

            SigningAlgorithm::P256 as i32,
            key,
            self.state.persistent.timestamp(&mut self.trussed).map_err(|_| Error::NotEnoughMemory)?,
            None,
            None,
            nonce,
        );

        // info!("made credential {:?}", &credential);

        // 12.b generate credential ID { = AEAD(Serialize(Credential)) }
        let kek = self.state.persistent.key_encryption_key(&mut self.trussed).map_err(|_| Error::NotEnoughMemory)?;
        let credential_id = credential.id(&mut self.trussed, kek, Some(&reg.app_id)).map_err(|_| Error::NotEnoughMemory)?;
        syscall!(self.trussed.delete(public_key));
        syscall!(self.trussed.delete(private_key));

        let mut commitment = Commitment::new();

        commitment.push(0).unwrap();     // reserve byte
        commitment.extend_from_slice(&reg.app_id).unwrap();
        commitment.extend_from_slice(&reg.challenge).unwrap();

        commitment.extend_from_slice(&credential_id.0).unwrap();

        commitment.push(0x04).unwrap();  // public key uncompressed byte
        commitment.extend_from_slice(&cose_key.x).unwrap();
        commitment.extend_from_slice(&cose_key.y).unwrap();

        let attestation = self.state.identity.attestation(&mut self.trussed);

        let (signature, cert) = match attestation {
            (Some((key, cert)), _aaguid) => {
                info!("aaguid: {}", hex_str!(&_aaguid));
                (
                    syscall!(
                        self.trussed.sign(Mechanism::P256,
                        key,
                        &commitment,
                        SignatureSerialization::Asn1Der
                    )).signature.to_bytes().unwrap(),
                    cert
                )
            },
            _ => {
                info!("Not provisioned with attestation key!");
                return Err(Error::KeyReferenceNotFound);
            }
        };


        Ok(ctap1::RegisterResponse::new(
            0x05,
            &cose_key,
            &credential_id.0,
            signature,
            &cert,
        ))
    }

    fn authenticate(&mut self, auth: &ctap1::Authenticate) -> Result<ctap1::AuthenticateResponse> {
        let cred = Credential::try_from_bytes(self, &auth.app_id, &auth.key_handle);

        let user_presence_byte = match auth.control_byte {
            ctap1::ControlByte::CheckOnly => {
                // if the control byte is set to 0x07 by the FIDO Client,
                // the U2F token is supposed to simply check whether the
                // provided key handle was originally created by this token
                return if cred.is_ok() {
                    Err(Error::ConditionsOfUseNotSatisfied)
                } else {
                    Err(Error::IncorrectDataParameter)
                };
            },
            ctap1::ControlByte::EnforceUserPresenceAndSign => {
                self.up.user_present(&mut self.trussed, constants::U2F_UP_TIMEOUT)
                    .map_err(|_| Error::ConditionsOfUseNotSatisfied)?;
                0x01
            },
            ctap1::ControlByte::DontEnforceUserPresenceAndSign => 0x00,
        };

        let cred = cred.map_err(|_| Error::IncorrectDataParameter)?;

        let key = match &cred.key {
            Key::WrappedKey(bytes) => {
                let wrapping_key = self.state.persistent.key_wrapping_key(&mut self.trussed)
                    .map_err(|_| Error::IncorrectDataParameter)?;
                let key_result = syscall!(self.trussed.unwrap_key_chacha8poly1305(
                    wrapping_key,
                    bytes,
                    b"",
                    Location::Volatile,
                )).key;
                match key_result {
                    Some(key) => {
                        info!("loaded u2f key!");
                        key
                    }
                    None => {
                        info!("issue with unwrapping credential id key");
                        return Err(Error::IncorrectDataParameter);
                    }
                }
            }
            _ => return Err(Error::IncorrectDataParameter),
        };

        if cred.algorithm != -7 {
            info!("Unexpected mechanism for u2f");
            return Err(Error::IncorrectDataParameter);
        }

        let sig_count = self.state.persistent.timestamp(&mut self.trussed).
            map_err(|_| Error::UnspecifiedNonpersistentExecutionError)?;

        let mut commitment = Commitment::new();

        commitment.extend_from_slice(&auth.app_id).unwrap();
        commitment.push(user_presence_byte).unwrap();
        commitment.extend_from_slice(&sig_count.to_be_bytes()).unwrap();
        commitment.extend_from_slice(&auth.challenge).unwrap();

        let signature = syscall!(
            self.trussed.sign(Mechanism::P256,
            key,
            &commitment,
            SignatureSerialization::Asn1Der
        )).signature.to_bytes().unwrap();

        Ok(ctap1::AuthenticateResponse::new(
            user_presence_byte,
            sig_count,
            signature,
        ))
    }

}

