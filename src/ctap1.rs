//! The `ctap_types::ctap1::Authenticator` implementation.

use ctap_types::{
    ctap1::{authenticate, register, Authenticator, ControlByte, Error, Result},
    heapless_bytes::Bytes,
};

use trussed::{
    syscall,
    types::{KeySerialization, Location, Mechanism, SignatureSerialization},
};

use crate::{
    constants,
    credential::{self, Credential, Key},
    SigningAlgorithm, TrussedRequirements, UserPresence,
};

type Commitment = Bytes<324>;

/// Implement `ctap1::Authenticator` for our Authenticator.
///
/// ## References
/// The "proposed standard" of U2F V1.2 applies to CTAP1.
/// - [Message formats](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html)
/// - [App ID](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-appid-and-facets-v1.2-ps-20170411.html)
impl<UP: UserPresence, T: TrussedRequirements> Authenticator for crate::Authenticator<UP, T> {
    /// Register a new credential, this always uses P-256 keys.
    ///
    /// Note that attestation is mandatory in CTAP1/U2F, so if the state
    /// is not provisioned with a key/cert, this method will fail.
    /// <https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-request-message---u2f_register>
    ///
    /// Also note that CTAP1 credentials should be assertable over CTAP2. I believe this is
    /// currently not the case.
    fn register(&mut self, reg: &register::Request) -> Result<register::Response> {
        self.up
            .user_present(&mut self.trussed, constants::U2F_UP_TIMEOUT)
            .map_err(|_| Error::ConditionsOfUseNotSatisfied)?;

        // Generate a new P256 key pair.
        let private_key = syscall!(self.trussed.generate_p256_private_key(Location::Volatile)).key;
        let public_key = syscall!(self
            .trussed
            .derive_p256_public_key(private_key, Location::Volatile))
        .key;

        let serialized_cose_public_key = syscall!(self
            .trussed
            .serialize_p256_key(public_key, KeySerialization::EcdhEsHkdf256))
        .serialized_key;
        syscall!(self.trussed.delete(public_key));
        let cose_key: ctap_types::cose::EcdhEsHkdf256PublicKey =
            trussed::cbor_deserialize(&serialized_cose_public_key).unwrap();

        let wrapping_key = self
            .state
            .persistent
            .key_wrapping_key(&mut self.trussed)
            .map_err(|_| Error::UnspecifiedCheckingError)?;
        // debug!("wrapping u2f private key");

        let wrapped_key =
            syscall!(self
                .trussed
                .wrap_key_chacha8poly1305(wrapping_key, private_key, &reg.app_id,))
            .wrapped_key;
        // debug!("wrapped_key = {:?}", &wrapped_key);

        syscall!(self.trussed.delete(private_key));

        let key = Key::WrappedKey(
            wrapped_key
                .to_bytes()
                .map_err(|_| Error::UnspecifiedCheckingError)?,
        );
        let nonce = syscall!(self.trussed.random_bytes(12))
            .bytes
            .as_slice()
            .try_into()
            .unwrap();

        let mut rp_id = heapless::String::new();

        // We do not know the rpId string in U2F.  Just using placeholder.
        // TODO: Is this true?
        // <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#cross-version-credentials>
        rp_id.push_str("u2f").ok();
        let rp = ctap_types::webauthn::PublicKeyCredentialRpEntity {
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
            self.state
                .persistent
                .timestamp(&mut self.trussed)
                .map_err(|_| Error::NotEnoughMemory)?,
            None,
            None,
            nonce,
        );

        // info!("made credential {:?}", &credential);

        // 12.b generate credential ID { = AEAD(Serialize(Credential)) }
        let kek = self
            .state
            .persistent
            .key_encryption_key(&mut self.trussed)
            .map_err(|_| Error::NotEnoughMemory)?;
        let credential_id = credential
            .id(&mut self.trussed, kek, Some(&reg.app_id))
            .map_err(|_| Error::NotEnoughMemory)?;

        let mut commitment = Commitment::new();

        commitment.push(0).unwrap(); // reserve byte
        commitment.extend_from_slice(&reg.app_id).unwrap();
        commitment.extend_from_slice(&reg.challenge).unwrap();

        commitment.extend_from_slice(&credential_id.0).unwrap();

        commitment.push(0x04).unwrap(); // public key uncompressed byte
        commitment.extend_from_slice(&cose_key.x).unwrap();
        commitment.extend_from_slice(&cose_key.y).unwrap();

        let attestation = self.state.identity.attestation(&mut self.trussed);

        let (signature, cert) = match attestation {
            (Some((key, cert)), _aaguid) => {
                info!("aaguid: {}", hex_str!(&_aaguid));
                (
                    syscall!(self.trussed.sign(
                        Mechanism::P256,
                        key,
                        &commitment,
                        SignatureSerialization::Asn1Der
                    ))
                    .signature
                    .to_bytes()
                    .unwrap(),
                    cert,
                )
            }
            _ => {
                info!("Not provisioned with attestation key!");
                return Err(Error::KeyReferenceNotFound);
            }
        };

        Ok(register::Response::new(
            0x05,
            &cose_key,
            &credential_id.0,
            signature,
            &cert,
        ))
    }

    fn authenticate(&mut self, auth: &authenticate::Request) -> Result<authenticate::Response> {
        let cred = Credential::try_from_bytes(self, &auth.app_id, &auth.key_handle);

        let user_presence_byte = match auth.control_byte {
            ControlByte::CheckOnly => {
                // if the control byte is set to 0x07 by the FIDO Client,
                // the U2F token is supposed to simply check whether the
                // provided key handle was originally created by this token
                return if cred.is_ok() {
                    Err(Error::ConditionsOfUseNotSatisfied)
                } else {
                    Err(Error::IncorrectDataParameter)
                };
            }
            ControlByte::EnforceUserPresenceAndSign => {
                if !self.skip_up_check() {
                    self.up
                        .user_present(&mut self.trussed, constants::U2F_UP_TIMEOUT)
                        .map_err(|_| Error::ConditionsOfUseNotSatisfied)?;
                }
                0x01
            }
            ControlByte::DontEnforceUserPresenceAndSign => 0x00,
        };

        let cred = cred.map_err(|_| Error::IncorrectDataParameter)?;

        let key = match &cred.key {
            Key::WrappedKey(bytes) => {
                let wrapping_key = self
                    .state
                    .persistent
                    .key_wrapping_key(&mut self.trussed)
                    .map_err(|_| Error::IncorrectDataParameter)?;
                let key_result = syscall!(self.trussed.unwrap_key_chacha8poly1305(
                    wrapping_key,
                    bytes,
                    b"",
                    Location::Volatile,
                ))
                .key;
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

        let sig_count = self
            .state
            .persistent
            .timestamp(&mut self.trussed)
            .map_err(|_| Error::UnspecifiedNonpersistentExecutionError)?;

        let mut commitment = Commitment::new();

        commitment.extend_from_slice(&auth.app_id).unwrap();
        commitment.push(user_presence_byte).unwrap();
        commitment
            .extend_from_slice(&sig_count.to_be_bytes())
            .unwrap();
        commitment.extend_from_slice(&auth.challenge).unwrap();

        let signature = syscall!(self.trussed.sign(
            Mechanism::P256,
            key,
            &commitment,
            SignatureSerialization::Asn1Der
        ))
        .signature
        .to_bytes()
        .unwrap();

        Ok(authenticate::Response {
            user_presence: user_presence_byte,
            count: sig_count,
            signature,
        })
    }
}
