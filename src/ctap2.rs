//! The `ctap_types::ctap2::Authenticator` implementation.

use ctap_types::{
    ctap2::{
        self, client_pin::Permissions, AttestationFormatsPreference, AttestationStatement,
        AttestationStatementFormat, Authenticator, NoneAttestationStatement,
        PackedAttestationStatement, VendorOperation,
    },
    heapless::{String, Vec},
    heapless_bytes::Bytes,
    sizes, ByteArray, Error,
};
use sha2::{Digest as _, Sha256};

use trussed::{
    syscall, try_syscall,
    types::{
        KeyId, KeySerialization, Location, Mechanism, MediumData, Message, Path, PathBuf,
        SignatureSerialization,
    },
};

use crate::{
    constants,
    credential::{self, Credential, FullCredential, Key, StrippedCredential},
    format_hex,
    state::{
        self,
        // // (2022-02-27): 9288 bytes
        // MinCredentialHeap,
    },
    Result, SigningAlgorithm, TrussedRequirements, UserPresence,
};

#[allow(unused_imports)]
use crate::msp;

pub mod credential_management;
pub mod large_blobs;
pub mod pin;

use pin::{PinProtocol, PinProtocolVersion, RpScope, SharedSecret};

/// Implement `ctap2::Authenticator` for our Authenticator.
impl<UP: UserPresence, T: TrussedRequirements> Authenticator for crate::Authenticator<UP, T> {
    #[inline(never)]
    fn get_info(&mut self) -> ctap2::get_info::Response {
        use ctap2::get_info::{Extension, Transport, Version};

        debug_now!("remaining stack size: {} bytes", msp() - 0x2000_0000);

        let mut versions = Vec::new();
        versions.push(Version::U2fV2).unwrap();
        versions.push(Version::Fido2_0).unwrap();
        versions.push(Version::Fido2_1).unwrap();

        let mut extensions = Vec::new();
        extensions.push(Extension::CredProtect).unwrap();
        extensions.push(Extension::HmacSecret).unwrap();
        if self.config.supports_large_blobs() {
            extensions.push(Extension::LargeBlobKey).unwrap();
        }
        extensions.push(Extension::ThirdPartyPayment).unwrap();

        let mut pin_protocols = Vec::new();
        for pin_protocol in self.pin_protocols() {
            pin_protocols.push(u8::from(*pin_protocol)).unwrap();
        }

        let mut options = ctap2::get_info::CtapOptions::default();
        options.rk = true;
        options.up = true;
        options.plat = Some(false);
        options.cred_mgmt = Some(true);
        options.client_pin = match self.state.persistent.pin_is_set() {
            true => Some(true),
            false => Some(false),
        };
        options.large_blobs = Some(self.config.supports_large_blobs());
        options.pin_uv_auth_token = Some(true);

        let mut transports = Vec::new();
        if self.config.nfc_transport {
            transports.push(Transport::Nfc).unwrap();
        }
        transports.push(Transport::Usb).unwrap();

        let (_, aaguid) = self.state.identity.attestation(&mut self.trussed);

        let mut response = ctap2::get_info::Response::default();
        response.versions = versions;
        response.extensions = Some(extensions);
        response.aaguid = Bytes::from_slice(&aaguid).unwrap();
        response.options = Some(options);
        response.transports = Some(transports);
        // 1200
        response.max_msg_size = Some(self.config.max_msg_size);
        response.pin_protocols = Some(pin_protocols);
        response.max_creds_in_list = Some(ctap_types::sizes::MAX_CREDENTIAL_COUNT_IN_LIST);
        response.max_cred_id_length = Some(ctap_types::sizes::MAX_CREDENTIAL_ID_LENGTH);
        response
    }

    #[inline(never)]
    fn get_next_assertion(&mut self) -> Result<ctap2::get_assertion::Response> {
        // 3. previous GA/GNA >30s ago -> discard stat
        // this is optional over NFC
        if false {
            self.state.runtime.clear_credential_cache();
            self.state.runtime.active_get_assertion = None;
            return Err(Error::NotAllowed);
        }
        //
        // 1./2. don't remember / don't have left any credentials
        // 4. select credential
        // let data = syscall!(self.trussed.read_file(
        //     timestamp_hash.location,
        //     timestamp_hash.path,
        // )).data;
        if self.state.runtime.active_get_assertion.is_none() {
            return Err(Error::NotAllowed);
        }
        let credential = self
            .state
            .runtime
            .pop_credential(&mut self.trussed)
            .ok_or(Error::NotAllowed)?;

        // 5. suppress PII if no UV was performed in original GA

        // 6. sign
        // 7. reset timer
        // 8. increment credential counter (not applicable)

        self.assert_with_credential(None, Credential::Full(credential))
    }

    #[inline(never)]
    fn make_credential(
        &mut self,
        parameters: &ctap2::make_credential::Request,
    ) -> Result<ctap2::make_credential::Response> {
        let rp_id_hash = self.hash(parameters.rp.id.as_ref());

        // 1-4.
        if let Some(options) = parameters.options.as_ref() {
            // up option is not valid for make_credential
            if options.up.is_some() {
                return Err(Error::InvalidOption);
            }
        }
        if parameters.enterprise_attestation.is_some() {
            return Err(Error::InvalidParameter);
        }
        let uv_performed = self.pin_prechecks(
            &parameters.options,
            parameters.pin_auth.map(AsRef::as_ref),
            parameters.pin_protocol,
            parameters.client_data_hash.as_ref(),
            Permissions::MAKE_CREDENTIAL,
            &parameters.rp.id,
        )?;

        // 5. "persist credProtect value for this credential"
        // --> seems out of place here, see 9.

        // 6. excludeList present, contains credential ID on this authenticator bound to RP?
        // --> wait for UP, error CredentialExcluded
        if let Some(exclude_list) = &parameters.exclude_list {
            for descriptor in exclude_list.iter() {
                let result = Credential::try_from(self, &rp_id_hash, descriptor);
                if let Ok(excluded_cred) = result {
                    use credential::CredentialProtectionPolicy;
                    // If UV is not performed, than CredProtectRequired credentials should not be visibile.
                    if !(excluded_cred.cred_protect() == Some(CredentialProtectionPolicy::Required))
                        || uv_performed
                    {
                        info_now!("Excluded!");
                        self.up
                            .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;
                        return Err(Error::CredentialExcluded);
                    }
                }
            }
        }

        // 7. check pubKeyCredParams algorithm is valid + supported COSE identifier

        let mut algorithm: Option<SigningAlgorithm> = None;
        for param in parameters.pub_key_cred_params.0.iter() {
            match param.alg {
                -7 => {
                    if algorithm.is_none() {
                        algorithm = Some(SigningAlgorithm::P256);
                    }
                }
                -8 => {
                    algorithm = Some(SigningAlgorithm::Ed25519);
                }
                // -9 => { algorithm = Some(SigningAlgorithm::Totp); }
                _ => {}
            }
        }
        let algorithm = algorithm.ok_or(Error::UnsupportedAlgorithm)?;
        info_now!("algo: {:?}", algorithm as i32);

        // 8. process options; on known but unsupported error UnsupportedOption

        let mut rk_requested = false;
        // TODO: why is this unused?
        let mut _uv_requested = false;
        let _up_requested = true; // can't be toggled

        info_now!("MC options: {:?}", &parameters.options);
        if let Some(ref options) = &parameters.options {
            if Some(true) == options.rk {
                rk_requested = true;
            }
            if Some(true) == options.uv {
                _uv_requested = true;
            }
        }

        // 9. process extensions
        let mut hmac_secret_requested = None;
        // let mut cred_protect_requested = CredentialProtectionPolicy::Optional;
        let mut cred_protect_requested = None;
        let mut large_blob_key_requested = false;
        let mut third_party_payment_requested = false;
        if let Some(extensions) = &parameters.extensions {
            hmac_secret_requested = extensions.hmac_secret;

            if let Some(policy) = &extensions.cred_protect {
                cred_protect_requested =
                    Some(credential::CredentialProtectionPolicy::try_from(*policy)?);
            }

            if self.config.supports_large_blobs() {
                if let Some(large_blob_key) = extensions.large_blob_key {
                    if large_blob_key {
                        if !rk_requested {
                            // the largeBlobKey extension is only available for resident keys
                            return Err(Error::InvalidOption);
                        }
                        large_blob_key_requested = true;
                    } else {
                        // large_blob_key must be Some(true) or omitted, Some(false) is invalid
                        return Err(Error::InvalidOption);
                    }
                }
            }

            third_party_payment_requested = extensions.third_party_payment.unwrap_or_default();
        }

        // debug_now!("hmac-secret = {:?}, credProtect = {:?}", hmac_secret_requested, cred_protect_requested);

        // 10. get UP, if denied error OperationDenied
        self.up
            .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;

        // 11. generate credential keypair
        let location = match rk_requested {
            true => Location::Internal,
            false => Location::Volatile,
        };

        let private_key: KeyId;
        let public_key: KeyId;
        let cose_public_key;
        match algorithm {
            SigningAlgorithm::P256 => {
                private_key = syscall!(self.trussed.generate_p256_private_key(location)).key;
                public_key = syscall!(self
                    .trussed
                    .derive_p256_public_key(private_key, Location::Volatile))
                .key;
                cose_public_key = syscall!(self.trussed.serialize_key(
                    Mechanism::P256,
                    public_key,
                    KeySerialization::Cose
                ))
                .serialized_key;
                let _success = syscall!(self.trussed.delete(public_key)).success;
                info_now!("deleted public P256 key: {}", _success);
            }
            SigningAlgorithm::Ed25519 => {
                private_key = syscall!(self.trussed.generate_ed255_private_key(location)).key;
                public_key = syscall!(self
                    .trussed
                    .derive_ed255_public_key(private_key, Location::Volatile))
                .key;
                cose_public_key = syscall!(self.trussed.serialize_key(
                    Mechanism::Ed255,
                    public_key,
                    KeySerialization::Cose
                ))
                .serialized_key;
                let _success = syscall!(self.trussed.delete(public_key)).success;
                info_now!("deleted public Ed25519 key: {}", _success);
            } // SigningAlgorithm::Totp => {
              //     if parameters.client_data_hash.len() != 32 {
              //         return Err(Error::InvalidParameter);
              //     }
              //     // b'TOTP---W\x0e\xf1\xe0\xd7\x83\xfe\t\xd1\xc1U\xbf\x08T_\x07v\xb2\xc6--TOTP'
              //     let totp_secret: [u8; 20] = parameters.client_data_hash[6..26].try_into().unwrap();
              //     private_key = syscall!(self.trussed.unsafe_inject_shared_key(
              //         &totp_secret, Location::Internal)).key;
              //     // info_now!("totes injected");
              //     let fake_cose_pk = ctap_types::cose::TotpPublicKey {};
              //     let fake_serialized_cose_pk = trussed::cbor_serialize_bytes(&fake_cose_pk)
              //         .map_err(|_| Error::NotAllowed)?;
              //     cose_public_key = fake_serialized_cose_pk; // Bytes::from_slice(&[0u8; 20]).unwrap();
              // }
        }

        // 12. if `rk` is set, store or overwrite key pair, if full error KeyStoreFull

        // 12.a generate credential
        let key_parameter = match rk_requested {
            true => Key::ResidentKey(private_key),
            false => {
                // WrappedKey version
                let wrapping_key = self.state.persistent.key_wrapping_key(&mut self.trussed)?;
                let wrapped_key = syscall!(self.trussed.wrap_key_chacha8poly1305(
                    wrapping_key,
                    private_key,
                    &[],
                    None
                ))
                .wrapped_key;

                // 32B key, 12B nonce, 16B tag + some info on algorithm (P256/Ed25519)
                // Turns out it's size 92 (enum serialization not optimized yet...)
                // let mut wrapped_key = Bytes::<60>::new();
                // wrapped_key.extend_from_slice(&wrapped_key_msg).unwrap();
                Key::WrappedKey(wrapped_key.to_bytes().map_err(|_| Error::Other)?)
            }
        };

        // injecting this is a bit mehhh..
        let nonce = self.nonce();
        info_now!("nonce = {:?}", &nonce);

        // 12.b generate credential ID { = AEAD(Serialize(Credential)) }
        let kek = self
            .state
            .persistent
            .key_encryption_key(&mut self.trussed)?;

        // store it.
        // TODO: overwrite, error handling with KeyStoreFull

        let large_blob_key = if large_blob_key_requested {
            let key = syscall!(self.trussed.random_bytes(32)).bytes;
            Some(ByteArray::new(key.as_slice().try_into().unwrap()))
        } else {
            None
        };

        let credential = FullCredential::new(
            credential::CtapVersion::Fido21Pre,
            &parameters.rp,
            &parameters.user,
            algorithm as i32,
            key_parameter,
            self.state.persistent.timestamp(&mut self.trussed)?,
            hmac_secret_requested,
            cred_protect_requested,
            large_blob_key,
            third_party_payment_requested.then_some(true),
            nonce,
        );

        // note that this does the "stripping" of OptionalUI etc.
        let credential_id =
            StrippedCredential::from(&credential).id(&mut self.trussed, kek, &rp_id_hash)?;

        if rk_requested {
            // serialization with all metadata
            let serialized_credential = credential.serialize()?;

            // first delete any other RK cred with same RP + UserId if there is one.
            self.delete_resident_key_by_user_id(&rp_id_hash, &credential.user.id)
                .ok();

            let mut key_store_full = false;

            // then check the maximum number of RK credentials
            if let Some(max_count) = self.config.max_resident_credential_count {
                let mut cm = credential_management::CredentialManagement::new(self);
                let metadata = cm.get_creds_metadata();
                let count = metadata
                    .existing_resident_credentials_count
                    .unwrap_or(max_count);
                debug!("resident cred count: {} (max: {})", count, max_count);
                if count >= max_count {
                    error!("maximum resident credential count reached");
                    key_store_full = true;
                }
            }

            if !key_store_full {
                // then store key, making it resident
                let credential_id_hash = self.hash(credential_id.0.as_ref());
                let result = try_syscall!(self.trussed.write_file(
                    Location::Internal,
                    rk_path(&rp_id_hash, &credential_id_hash),
                    serialized_credential,
                    // user attribute for later easy lookup
                    // Some(rp_id_hash.clone()),
                    None,
                ));
                key_store_full = result.is_err();
            }

            if key_store_full {
                // If we previously deleted an existing cred with the same RP + UserId but then
                // failed to store the new cred, the RP directory could now be empty.  This is not
                // a valid state so we have to delete it.
                let rp_dir = rp_rk_dir(&rp_id_hash);
                self.delete_rp_dir_if_empty(rp_dir);
                return Err(Error::KeyStoreFull);
            }
        }

        // 13. generate and return attestation statement using clientDataHash

        // 13.a AuthenticatorData and its serialization
        use ctap2::AuthenticatorDataFlags as Flags;
        info_now!("MC created cred id");

        let (attestation_maybe, aaguid) = self.state.identity.attestation(&mut self.trussed);

        let authenticator_data = ctap2::make_credential::AuthenticatorData {
            rp_id_hash: &rp_id_hash,

            flags: {
                let mut flags = Flags::USER_PRESENCE;
                if uv_performed {
                    flags |= Flags::USER_VERIFIED;
                }
                if true {
                    flags |= Flags::ATTESTED_CREDENTIAL_DATA;
                }
                if hmac_secret_requested.is_some() || cred_protect_requested.is_some() {
                    flags |= Flags::EXTENSION_DATA;
                }
                flags
            },

            sign_count: self.state.persistent.timestamp(&mut self.trussed)?,

            attested_credential_data: {
                // debug_now!("acd in, cid len {}, pk len {}", credential_id.0.len(), cose_public_key.len());
                let attested_credential_data = ctap2::make_credential::AttestedCredentialData {
                    aaguid: &aaguid,
                    credential_id: &credential_id.0,
                    credential_public_key: &cose_public_key,
                };
                // debug_now!("cose PK = {:?}", &attested_credential_data.credential_public_key);
                Some(attested_credential_data)
            },

            extensions: {
                if hmac_secret_requested.is_some() || cred_protect_requested.is_some() {
                    let mut extensions = ctap2::make_credential::Extensions::default();
                    extensions.cred_protect = parameters.extensions.as_ref().unwrap().cred_protect;
                    extensions.hmac_secret = parameters.extensions.as_ref().unwrap().hmac_secret;
                    Some(extensions)
                } else {
                    None
                }
            },
        };
        // debug_now!("authData = {:?}", &authenticator_data);

        let serialized_auth_data = authenticator_data.serialize()?;

        let att_stmt_fmt =
            SupportedAttestationFormat::select(parameters.attestation_formats_preference.as_ref());
        let att_stmt = if let Some(format) = att_stmt_fmt {
            match format {
                SupportedAttestationFormat::None => {
                    Some(AttestationStatement::None(NoneAttestationStatement {}))
                }
                SupportedAttestationFormat::Packed => {
                    let mut commitment = Bytes::<1024>::new();
                    commitment
                        .extend_from_slice(&serialized_auth_data)
                        .map_err(|_| Error::Other)?;
                    commitment
                        .extend_from_slice(parameters.client_data_hash)
                        .map_err(|_| Error::Other)?;

                    let (signature, attestation_algorithm) = {
                        if let Some(attestation) = attestation_maybe.as_ref() {
                            let signature = syscall!(self.trussed.sign_p256(
                                attestation.0,
                                &commitment,
                                SignatureSerialization::Asn1Der,
                            ))
                            .signature;
                            (signature.to_bytes().map_err(|_| Error::Other)?, -7)
                        } else {
                            match algorithm {
                                SigningAlgorithm::Ed25519 => {
                                    let signature =
                                        syscall!(self.trussed.sign_ed255(private_key, &commitment))
                                            .signature;
                                    (signature.to_bytes().map_err(|_| Error::Other)?, -8)
                                }

                                SigningAlgorithm::P256 => {
                                    // DO NOT prehash here, `trussed` does that
                                    let der_signature = syscall!(self.trussed.sign_p256(
                                        private_key,
                                        &commitment,
                                        SignatureSerialization::Asn1Der
                                    ))
                                    .signature;
                                    (der_signature.to_bytes().map_err(|_| Error::Other)?, -7)
                                }
                            }
                        }
                    };
                    let packed = PackedAttestationStatement {
                        alg: attestation_algorithm,
                        sig: signature,
                        x5c: attestation_maybe.as_ref().map(|attestation| {
                            // See: https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
                            let cert = attestation.1.clone();
                            let mut x5c = Vec::new();
                            x5c.push(cert).ok();
                            x5c
                        }),
                    };
                    Some(AttestationStatement::Packed(packed))
                }
            }
        } else {
            None
        };

        if !rk_requested {
            let _success = syscall!(self.trussed.delete(private_key)).success;
            info_now!("deleted private credential key: {}", _success);
        }

        let mut attestation_object = ctap2::make_credential::ResponseBuilder {
            fmt: att_stmt_fmt
                .map(From::from)
                .unwrap_or(AttestationStatementFormat::None),
            auth_data: serialized_auth_data,
        }
        .build();
        attestation_object.att_stmt = att_stmt;
        attestation_object.large_blob_key = large_blob_key;
        Ok(attestation_object)
    }

    #[inline(never)]
    fn reset(&mut self) -> Result<()> {
        // 1. >10s after bootup -> NotAllowed
        let uptime = syscall!(self.trussed.uptime()).uptime;
        debug_now!("uptime: {:?}", uptime);
        if uptime.as_secs() > 10 {
            #[cfg(not(feature = "disable-reset-time-window"))]
            return Err(Error::NotAllowed);
        }
        // 2. check for user presence
        // denied -> OperationDenied
        // timeout -> UserActionTimeout
        self.up
            .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;

        // Delete resident keys
        syscall!(self.trussed.delete_all(Location::Internal));
        syscall!(self
            .trussed
            .remove_dir_all(Location::Internal, PathBuf::from("rk"),));

        // Delete large-blob array
        large_blobs::reset(&mut self.trussed);

        // b. delete persistent state
        self.state.persistent.reset(&mut self.trussed)?;

        // c. Reset runtime state
        self.state.runtime.reset(&mut self.trussed);

        Ok(())
    }

    fn selection(&mut self) -> Result<()> {
        self.up
            .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)
    }

    #[inline(never)]
    fn client_pin(
        &mut self,
        parameters: &ctap2::client_pin::Request<'_>,
    ) -> Result<ctap2::client_pin::Response> {
        use ctap2::client_pin::PinV1Subcommand as Subcommand;
        debug_now!("CTAP2.PIN...");
        // info_now!("{:?}", parameters);

        let pin_protocol = self.parse_pin_protocol(parameters.pin_protocol)?;
        let mut response = ctap2::client_pin::Response::default();

        match parameters.sub_command {
            Subcommand::GetRetries => {
                debug_now!("CTAP2.Pin.GetRetries");

                response.retries = Some(self.state.persistent.retries());
            }

            Subcommand::GetKeyAgreement => {
                debug_now!("CTAP2.Pin.GetKeyAgreement");

                response.key_agreement = Some(self.pin_protocol(pin_protocol).key_agreement_key());
            }

            Subcommand::SetPin => {
                debug_now!("CTAP2.Pin.SetPin");
                // 1. check mandatory parameters
                let platform_kek = match parameters.key_agreement.as_ref() {
                    Some(key) => key,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let new_pin_enc = match parameters.new_pin_enc.as_ref() {
                    Some(pin) => pin,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let pin_auth = match parameters.pin_auth.as_ref() {
                    Some(auth) => auth,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };

                // 2. is pin already set
                if self.state.persistent.pin_is_set() {
                    return Err(Error::NotAllowed);
                }

                // 3. generate shared secret
                let mut pin_protocol = self.pin_protocol(pin_protocol);
                let shared_secret = pin_protocol.shared_secret(platform_kek)?;

                // TODO: there are moar early returns!!
                // - implement Drop?
                // - do garbage collection outside of this?

                // 4. verify pinAuth
                pin_protocol.verify_pin_auth(&shared_secret, new_pin_enc, pin_auth)?;

                // 5. decrypt and verify new PIN
                let new_pin = self.decrypt_pin_check_length(&shared_secret, new_pin_enc)?;

                shared_secret.delete(&mut self.trussed);

                // 6. store LEFT(SHA-256(newPin), 16), set retries to 8
                self.hash_store_pin(&new_pin)?;
                self.state
                    .reset_retries(&mut self.trussed)
                    .map_err(|_| Error::Other)?;
            }

            Subcommand::ChangePin => {
                debug_now!("CTAP2.Pin.ChangePin");

                // 1. check mandatory parameters
                let platform_kek = match parameters.key_agreement.as_ref() {
                    Some(key) => key,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let pin_hash_enc = match parameters.pin_hash_enc.as_ref() {
                    Some(hash) => hash,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let new_pin_enc = match parameters.new_pin_enc.as_ref() {
                    Some(pin) => pin,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let pin_auth = match parameters.pin_auth.as_ref() {
                    Some(auth) => auth,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };

                // 2. fail if no retries left
                self.state.pin_blocked()?;

                // 3. generate shared secret
                let mut pin_protocol_impl = self.pin_protocol(pin_protocol);
                let shared_secret = pin_protocol_impl.shared_secret(platform_kek)?;

                // 4. verify pinAuth
                let mut data = MediumData::new();
                data.extend_from_slice(new_pin_enc)
                    .map_err(|_| Error::InvalidParameter)?;
                data.extend_from_slice(pin_hash_enc)
                    .map_err(|_| Error::InvalidParameter)?;
                pin_protocol_impl.verify_pin_auth(&shared_secret, &data, pin_auth)?;

                // 5. decrement retries
                self.state.decrement_retries(&mut self.trussed)?;

                // 6. decrypt pinHashEnc, compare with stored
                self.decrypt_pin_hash_and_maybe_escalate(
                    pin_protocol,
                    &shared_secret,
                    pin_hash_enc,
                )?;

                // 7. reset retries
                self.state.reset_retries(&mut self.trussed)?;

                // 8. decrypt and verify new PIN
                let new_pin = self.decrypt_pin_check_length(&shared_secret, new_pin_enc)?;

                shared_secret.delete(&mut self.trussed);

                // 9. store hashed PIN
                self.hash_store_pin(&new_pin)?;

                self.pin_protocol(pin_protocol).reset_pin_tokens();
            }

            // § 6.5.5.7.1 No 4
            Subcommand::GetPinToken => {
                debug_now!("CTAP2.Pin.GetPinToken");

                // 1. Check mandatory parameters
                let key_agreement = parameters
                    .key_agreement
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;
                let pin_hash_enc = parameters
                    .pin_hash_enc
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;

                // 2. Check PIN protocol
                let pin_protocol = self.parse_pin_protocol(parameters.pin_protocol)?;

                // 3. + 4. Check invalid parameters
                if parameters.permissions.is_some() || parameters.rp_id.is_some() {
                    return Err(Error::InvalidParameter);
                }

                // 5. Check PIN retries
                self.state.pin_blocked()?;

                // 6. Obtain shared secret
                let shared_secret = self
                    .pin_protocol(pin_protocol)
                    .shared_secret(key_agreement)?;

                // 7. Request user consent using display -- skipped

                // 8. Decrement PIN retries
                self.state.decrement_retries(&mut self.trussed)?;

                // 9. Check PIN
                self.decrypt_pin_hash_and_maybe_escalate(
                    pin_protocol,
                    &shared_secret,
                    pin_hash_enc,
                )?;

                // 10. Reset PIN retries
                self.state.reset_retries(&mut self.trussed)?;

                // 11. Check forcePINChange -- skipped

                // 12. Reset all PIN tokens
                // 13. Call beginUsingPinUvAuthToken
                let mut pin_protocol = self.pin_protocol(pin_protocol);
                let mut pin_token = pin_protocol.reset_and_begin_using_pin_token(false);

                // 14. Assign the default permissions
                let mut permissions = Permissions::empty();
                permissions.insert(Permissions::MAKE_CREDENTIAL);
                permissions.insert(Permissions::GET_ASSERTION);
                pin_token.restrict(permissions, None);

                // 15. Return PIN token
                response.pin_token = Some(pin_token.encrypt(&shared_secret)?);

                shared_secret.delete(&mut self.trussed);
            }

            // § 6.5.5.7.2 No 4
            Subcommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                debug_now!("CTAP2.Pin.GetPinUvAuthTokenUsingPinWithPermissions");

                // 1. Check mandatory parameters
                let key_agreement = parameters
                    .key_agreement
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;
                let pin_hash_enc = parameters
                    .pin_hash_enc
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;
                let permissions = parameters.permissions.ok_or(Error::MissingParameter)?;

                // 2. Check PIN protocol
                let pin_protocol = self.parse_pin_protocol(parameters.pin_protocol)?;

                // 3. Check that permissions are not empty
                let permissions = Permissions::from_bits_truncate(permissions);
                if permissions.is_empty() {
                    return Err(Error::InvalidParameter);
                }

                // 4. Check that all requested permissions are supported
                let mut unauthorized_permissions = Permissions::empty();
                unauthorized_permissions.insert(Permissions::BIO_ENROLLMENT);
                if !self.config.supports_large_blobs() {
                    unauthorized_permissions.insert(Permissions::LARGE_BLOB_WRITE);
                }
                unauthorized_permissions.insert(Permissions::AUTHENTICATOR_CONFIGURATION);
                if permissions.intersects(unauthorized_permissions) {
                    return Err(Error::UnauthorizedPermission);
                }

                // 5. Check PIN retries
                self.state.pin_blocked()?;

                // 6. Obtain shared secret
                let shared_secret = self
                    .pin_protocol(pin_protocol)
                    .shared_secret(key_agreement)?;

                // 7. Request user consent using display -- skipped

                // 8. Decrement PIN retries
                self.state.decrement_retries(&mut self.trussed)?;

                // 9. Check PIN
                self.decrypt_pin_hash_and_maybe_escalate(
                    pin_protocol,
                    &shared_secret,
                    pin_hash_enc,
                )?;

                // 10. Reset PIN retries
                self.state.reset_retries(&mut self.trussed)?;

                // 11. Check forcePINChange -- skipped

                // 12. Reset all PIN tokens
                // 13. Call beginUsingPinUvAuthToken
                let mut pin_protocol = self.pin_protocol(pin_protocol);
                let mut pin_token = pin_protocol.reset_and_begin_using_pin_token(false);

                // 14. Assign the requested permissions
                // 15. Assign the requested RP id
                let rp_id = parameters
                    .rp_id
                    .map(TryInto::try_into)
                    .transpose()
                    .map_err(|_| Error::InvalidParameter)?;
                pin_token.restrict(permissions, rp_id);

                // 16. Return PIN token
                response.pin_token = Some(pin_token.encrypt(&shared_secret)?);

                shared_secret.delete(&mut self.trussed);
            }

            Subcommand::GetPinUvAuthTokenUsingUvWithPermissions | Subcommand::GetUVRetries => {
                // todo!("not implemented yet")
                return Err(Error::InvalidParameter);
            }

            _ => {
                return Err(Error::InvalidParameter);
            }
        }

        Ok(response)
    }

    #[inline(never)]
    fn credential_management(
        &mut self,
        parameters: &ctap2::credential_management::Request<'_>,
    ) -> Result<ctap2::credential_management::Response> {
        use credential_management as cm;
        use ctap2::credential_management::Subcommand;

        self.verify_credential_management_pin_auth(parameters)?;

        let mut cred_mgmt = cm::CredentialManagement::new(self);
        let sub_parameters = &parameters.sub_command_params;
        // TODO: use custom enum of known commands
        match parameters.sub_command {
            // 0x1
            Subcommand::GetCredsMetadata => Ok(cred_mgmt.get_creds_metadata()),

            // 0x2
            Subcommand::EnumerateRpsBegin => cred_mgmt.first_relying_party(),

            // 0x3
            Subcommand::EnumerateRpsGetNextRp => cred_mgmt.next_relying_party(),

            // 0x4
            Subcommand::EnumerateCredentialsBegin => {
                let sub_parameters = sub_parameters.as_ref().ok_or(Error::MissingParameter)?;

                cred_mgmt.first_credential(
                    sub_parameters
                        .rp_id_hash
                        .as_ref()
                        .ok_or(Error::MissingParameter)?,
                )
            }

            // 0x5
            Subcommand::EnumerateCredentialsGetNextCredential => cred_mgmt.next_credential(),

            // 0x6
            Subcommand::DeleteCredential => {
                let sub_parameters = sub_parameters.as_ref().ok_or(Error::MissingParameter)?;

                cred_mgmt.delete_credential(
                    sub_parameters
                        .credential_id
                        .as_ref()
                        .ok_or(Error::MissingParameter)?,
                )
            }

            // 0x7
            Subcommand::UpdateUserInformation => {
                let sub_parameters = sub_parameters.as_ref().ok_or(Error::MissingParameter)?;
                let credential_id = sub_parameters
                    .credential_id
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;
                let user = sub_parameters
                    .user
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;

                cred_mgmt.update_user_information(credential_id, user)
            }

            _ => Err(Error::InvalidParameter),
        }
    }

    #[inline(never)]
    fn vendor(&mut self, op: VendorOperation) -> Result<()> {
        info_now!("hello VO {:?}", &op);
        match op.into() {
            0x79 => syscall!(self.trussed.debug_dump_store()),
            _ => return Err(Error::InvalidCommand),
        };

        Ok(())
    }

    #[inline(never)]
    fn get_assertion(
        &mut self,
        parameters: &ctap2::get_assertion::Request,
    ) -> Result<ctap2::get_assertion::Response> {
        debug_now!("remaining stack size: {} bytes", msp() - 0x2000_0000);

        let rp_id_hash = self.hash(parameters.rp_id.as_ref());

        // 1-4.
        let uv_performed = match self.pin_prechecks(
            &parameters.options,
            parameters.pin_auth.map(AsRef::as_ref),
            parameters.pin_protocol,
            parameters.client_data_hash.as_ref(),
            Permissions::GET_ASSERTION,
            parameters.rp_id,
        ) {
            Ok(b) => b,
            Err(Error::PinRequired) => {
                // UV is optional for get_assertion
                false
            }
            Err(err) => return Err(err),
        };

        // 5. Locate eligible credentials
        //
        // Note: If allowList is passed, credential is Some(credential)
        // If no allowList is passed, credential is None and the retrieved credentials
        // are stored in state.runtime.credential_heap
        let (credential, num_credentials) = self
            .prepare_credentials(&rp_id_hash, &parameters.allow_list, uv_performed)
            .ok_or(Error::NoCredentials)?;

        info_now!("found {:?} applicable credentials", num_credentials);
        info_now!("{:?}", &credential);

        // 6. process any options present

        // RK is not supported in get_assertion
        if parameters
            .options
            .as_ref()
            .and_then(|options| options.rk)
            .is_some()
        {
            return Err(Error::InvalidOption);
        }

        // UP occurs by default, but option could specify not to.
        let do_up = if let Some(options) = parameters.options.as_ref() {
            options.up.unwrap_or(true)
        } else {
            true
        };

        // 7. collect user presence
        let up_performed = if do_up {
            if !self.skip_up_check() {
                info_now!("asking for up");
                self.up
                    .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;
            }
            true
        } else {
            info_now!("not asking for up");
            false
        };

        let multiple_credentials = num_credentials > 1;
        self.state.runtime.active_get_assertion = Some(state::ActiveGetAssertionData {
            rp_id_hash: {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&rp_id_hash);
                buf
            },
            client_data_hash: {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(parameters.client_data_hash);
                buf
            },
            uv_performed,
            up_performed,
            multiple_credentials,
            extensions: parameters.extensions.clone(),
        });

        let num_credentials = match num_credentials {
            1 => None,
            n => Some(n),
        };

        self.assert_with_credential(num_credentials, credential)
    }

    #[inline(never)]
    fn large_blobs(
        &mut self,
        request: &ctap2::large_blobs::Request,
    ) -> Result<ctap2::large_blobs::Response> {
        let Some(config) = self.config.large_blobs else {
            return Err(Error::InvalidCommand);
        };

        // 1. offset is validated by serde

        // 2.-3. Exactly one of get or set must be present
        match (request.get, request.set) {
            (None, None) | (Some(_), Some(_)) => Err(Error::InvalidParameter),
            // 4. Implement get subcommand
            (Some(get), None) => self.large_blobs_get(request, config, get),
            // 5. Implement set subcommand
            (None, Some(set)) => self.large_blobs_set(request, config, set),
        }
    }
}

// impl<UP: UserPresence, T: TrussedRequirements> Authenticator for crate::Authenticator<UP, T>
impl<UP: UserPresence, T: TrussedRequirements> crate::Authenticator<UP, T> {
    fn parse_pin_protocol(&self, version: impl TryInto<u8>) -> Result<PinProtocolVersion> {
        if let Ok(version) = version.try_into() {
            for pin_protocol in self.pin_protocols() {
                if u8::from(*pin_protocol) == version {
                    return Ok(*pin_protocol);
                }
            }
        }
        Err(Error::InvalidParameter)
    }

    // This is the single source of truth for the supported PIN protocols.
    fn pin_protocols(&self) -> &'static [PinProtocolVersion] {
        &[PinProtocolVersion::V2, PinProtocolVersion::V1]
    }

    fn pin_protocol(&mut self, pin_protocol: PinProtocolVersion) -> PinProtocol<'_, T> {
        let state = self.state.runtime.pin_protocol(&mut self.trussed);
        PinProtocol::new(&mut self.trussed, state, pin_protocol)
    }

    #[inline(never)]
    fn check_credential_applicable(
        &mut self,
        credential: &Credential,
        allowlist_passed: bool,
        uv_performed: bool,
    ) -> bool {
        if !self.check_key_exists(credential.algorithm(), credential.key()) {
            return false;
        }

        if !{
            use credential::CredentialProtectionPolicy as Policy;
            debug_now!("CredentialProtectionPolicy {:?}", credential.cred_protect());
            match credential.cred_protect() {
                None | Some(Policy::Optional) => true,
                Some(Policy::OptionalWithCredentialIdList) => allowlist_passed || uv_performed,
                Some(Policy::Required) => uv_performed,
            }
        } {
            return false;
        }
        true
    }

    #[inline(never)]
    fn prepare_credentials(
        &mut self,
        rp_id_hash: &[u8; 32],
        allow_list: &Option<ctap2::get_assertion::AllowList>,
        uv_performed: bool,
    ) -> Option<(Credential, u32)> {
        debug_now!("remaining stack size: {} bytes", msp() - 0x2000_0000);

        self.state.runtime.clear_credential_cache();
        self.state.runtime.active_get_assertion = None;

        // NB: CTAP 2.1 specifies to return the first applicable credential, and set
        // numberOfCredentials to None.
        // However, CTAP 2.0 says to send numberOfCredentials that are applicable,
        // which implies we'd have to respond to GetNextAssertion.
        //
        // We are using CTAP 2.1 behaviour here, as it allows us not to cache the (length)
        // credential IDs. Presumably, most clients use this to just get any old signatures,
        // but we did change the github.com/solokeys/fido2-tests to accommodate this change
        // of behaviour.
        if let Some(allow_list) = allow_list {
            debug_now!("Allowlist of len {} passed, filtering", allow_list.len());
            // we will have at most one credential, and an empty cache.

            // client is not supposed to send Some(empty list):
            // <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#:~:text=A%20platform%20MUST%20NOT%20send%20an%20empty%20allowList%E2%80%94if%20it%20would%20be%20empty%20it%20MUST%20be%20omitted>
            // but some still do (and CTAP 2.0 does not rule it out).
            // they probably meant to send None.
            if !allow_list.is_empty() {
                for credential_id in allow_list {
                    let credential = match Credential::try_from(self, rp_id_hash, credential_id) {
                        Ok(credential) => credential,
                        _ => continue,
                    };

                    if !self.check_credential_applicable(&credential, true, uv_performed) {
                        continue;
                    }

                    return Some((credential, 1));
                }

                // we don't recognize any credentials in the allowlist
                return None;
            }
        }

        // we are only dealing with discoverable credentials.
        debug_now!("Allowlist not passed, fetching RKs");

        let mut maybe_path =
            syscall!(self
                .trussed
                .read_dir_first(Location::Internal, rp_rk_dir(rp_id_hash), None,))
            .entry
            .map(|entry| PathBuf::from(entry.path()));

        use crate::state::CachedCredential;
        use core::str::FromStr;

        while let Some(path) = maybe_path {
            let credential_data =
                syscall!(self.trussed.read_file(Location::Internal, path.clone(),)).data;

            let credential = FullCredential::deserialize(&credential_data).ok()?;
            let timestamp = credential.creation_time;
            let credential = Credential::Full(credential);

            if self.check_credential_applicable(&credential, false, uv_performed) {
                self.state.runtime.push_credential(CachedCredential {
                    timestamp,
                    path: String::from_str(path.as_str_ref_with_trailing_nul()).ok()?,
                });
            }

            maybe_path = syscall!(self.trussed.read_dir_next())
                .entry
                .map(|entry| PathBuf::from(entry.path()));
        }

        let num_credentials = self.state.runtime.remaining_credentials();
        let credential = self.state.runtime.pop_credential(&mut self.trussed);
        credential.map(|credential| (Credential::Full(credential), num_credentials))
    }

    fn decrypt_pin_hash_and_maybe_escalate(
        &mut self,
        pin_protocol: PinProtocolVersion,
        shared_secret: &SharedSecret,
        pin_hash_enc: &[u8],
    ) -> Result<()> {
        let pin_hash = shared_secret
            .decrypt(&mut self.trussed, pin_hash_enc)
            .ok_or(Error::Other)?;

        let stored_pin_hash = match self.state.persistent.pin_hash() {
            Some(hash) => hash,
            None => {
                return Err(Error::PinNotSet);
            }
        };

        if pin_hash != stored_pin_hash {
            // I) generate new KEK
            self.pin_protocol(pin_protocol).regenerate();
            self.state.pin_blocked()?;
            return Err(Error::PinInvalid);
        }

        Ok(())
    }

    fn hash_store_pin(&mut self, pin: &Message) -> Result<()> {
        let pin_hash_32 = syscall!(self.trussed.hash_sha256(pin)).hash;
        let pin_hash: [u8; 16] = pin_hash_32[..16].try_into().unwrap();
        self.state
            .persistent
            .set_pin_hash(&mut self.trussed, pin_hash)
            .unwrap();

        Ok(())
    }

    fn decrypt_pin_check_length(
        &mut self,
        shared_secret: &SharedSecret,
        pin_enc: &[u8],
    ) -> Result<Message> {
        // pin is expected to be filled with null bytes to length at least 64
        if pin_enc.len() < 64 {
            // correct error?
            return Err(Error::PinPolicyViolation);
        }

        let mut pin = shared_secret
            .decrypt(&mut self.trussed, pin_enc)
            .ok_or(Error::Other)?;

        // // temp
        // let pin_length = pin.iter().position(|&b| b == b'\0').unwrap_or(pin.len());
        // info_now!("pin.len() = {}, pin_length = {}, = {:?}",
        //           pin.len(), pin_length, &pin);
        // chop off null bytes
        let pin_length = pin.iter().position(|&b| b == b'\0').unwrap_or(pin.len());
        if !(4..64).contains(&pin_length) {
            return Err(Error::PinPolicyViolation);
        }

        pin.resize_default(pin_length).unwrap();

        Ok(pin)
    }

    fn verify_credential_management_pin_auth(
        &mut self,
        parameters: &ctap2::credential_management::Request,
    ) -> Result<()> {
        use ctap2::credential_management::Subcommand;
        let rp_scope = match parameters.sub_command {
            Subcommand::EnumerateCredentialsBegin => {
                let rp_id_hash = parameters
                    .sub_command_params
                    .as_ref()
                    .and_then(|subparams| subparams.rp_id_hash)
                    .ok_or(Error::MissingParameter)?;
                RpScope::RpIdHash(rp_id_hash)
            }
            Subcommand::DeleteCredential | Subcommand::UpdateUserInformation => {
                // TODO: determine RP ID from credential ID
                RpScope::All
            }
            _ => RpScope::All,
        };
        match parameters.sub_command {
            Subcommand::GetCredsMetadata
            | Subcommand::EnumerateRpsBegin
            | Subcommand::EnumerateCredentialsBegin
            | Subcommand::DeleteCredential
            | Subcommand::UpdateUserInformation => {
                // check pinProtocol
                let pin_protocol = parameters.pin_protocol.ok_or(Error::MissingParameter)?;
                let pin_protocol = self.parse_pin_protocol(pin_protocol)?;

                // check pinAuth
                let mut data: Bytes<{ sizes::MAX_CREDENTIAL_ID_LENGTH_PLUS_256 }> =
                    Bytes::from_slice(&[parameters.sub_command as u8]).unwrap();
                let len = 1 + match parameters.sub_command {
                    Subcommand::EnumerateCredentialsBegin
                    | Subcommand::DeleteCredential
                    | Subcommand::UpdateUserInformation => {
                        data.resize_to_capacity();
                        // ble, need to reserialize
                        ctap_types::serde::cbor_serialize(
                            &parameters
                                .sub_command_params
                                .as_ref()
                                .ok_or(Error::MissingParameter)?,
                            &mut data[1..],
                        )
                        .map_err(|_| Error::LimitExceeded)?
                        .len()
                    }
                    _ => 0,
                };

                let pin_auth = parameters
                    .pin_auth
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;

                let mut pin_protocol = self.pin_protocol(pin_protocol);
                if let Ok(pin_token) = pin_protocol.verify_pin_token(&data[..len], pin_auth) {
                    info_now!("passed pinauth");
                    pin_token.require_permissions(Permissions::CREDENTIAL_MANAGEMENT)?;
                    pin_token.require_valid_for_rp(rp_scope)?;
                    Ok(())
                } else {
                    info_now!("failed pinauth!");
                    self.state.decrement_retries(&mut self.trussed)?;
                    let maybe_blocked = self.state.pin_blocked();
                    if maybe_blocked.is_err() {
                        info_now!("blocked");
                        maybe_blocked
                    } else {
                        info_now!("pinAuthInvalid");
                        Err(Error::PinAuthInvalid)
                    }
                }
            }

            // don't need the PIN auth, they're continuations
            // of already checked CredMgmt subcommands
            Subcommand::EnumerateRpsGetNextRp
            | Subcommand::EnumerateCredentialsGetNextCredential => Ok(()),

            _ => Err(Error::InvalidParameter),
        }
    }

    /// Returns whether UV was performed.
    fn pin_prechecks(
        &mut self,
        options: &Option<ctap2::AuthenticatorOptions>,
        pin_auth: Option<&[u8]>,
        pin_protocol: Option<u32>,
        data: &[u8],
        permissions: Permissions,
        rp_id: &str,
    ) -> Result<bool> {
        // 1. pinAuth zero length -> wait for user touch, then
        // return PinNotSet if not set, PinInvalid if set
        //
        // the idea is for multi-authnr scenario where platform
        // wants to enforce PIN and needs to figure out which authnrs support PIN
        if let Some(pin_auth) = pin_auth {
            if pin_auth.is_empty() {
                self.up
                    .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;
                if !self.state.persistent.pin_is_set() {
                    return Err(Error::PinNotSet);
                } else {
                    return Err(Error::PinAuthInvalid);
                }
            }
        }

        // 2. check PIN protocol is 1 if pinAuth was sent
        let pin_protocol = if pin_auth.is_some() {
            let pin_protocol = pin_protocol.ok_or(Error::MissingParameter)?;
            let pin_protocol = self.parse_pin_protocol(pin_protocol)?;
            Some(pin_protocol)
        } else {
            None
        };

        // 3. if no PIN is set (we have no other form of UV),
        // and platform sent `uv` or `pinAuth`, return InvalidOption
        if !self.state.persistent.pin_is_set() {
            if let Some(ref options) = &options {
                if Some(true) == options.uv {
                    return Err(Error::InvalidOption);
                }
            }
            if pin_auth.is_some() {
                return Err(Error::InvalidOption);
            }
        }

        // 4. If authenticator is protected by som form of user verification, do it
        //
        // TODO: Should we should fail if `uv` is passed?
        // Current thinking: no
        if self.state.persistent.pin_is_set() {
            // let mut uv_performed = false;
            if let Some(pin_auth) = pin_auth {
                // seems a bit redundant to check here in light of 2.
                // I guess the CTAP spec writers aren't implementers :D
                if let Some(pin_protocol) = pin_protocol {
                    // 5. if pinAuth is present and pinProtocol = 1, verify
                    // success --> set uv = 1
                    // error --> PinAuthInvalid
                    let mut pin_protocol = self.pin_protocol(pin_protocol);
                    let pin_token = pin_protocol.verify_pin_token(data, pin_auth)?;
                    pin_token.require_permissions(permissions)?;
                    pin_token.require_valid_for_rp(RpScope::RpId(rp_id))?;

                    return Ok(true);
                } else {
                    // 7. pinAuth present + pinProtocol != 1 --> error PinAuthInvalid
                    return Err(Error::PinAuthInvalid);
                }
            } else {
                // 6. pinAuth not present + clientPin set --> error PinRequired
                if self.state.persistent.pin_is_set() {
                    return Err(Error::PinRequired);
                }
            }
        }

        Ok(false)
    }

    #[inline(never)]
    fn check_key_exists(&mut self, alg: i32, key: &Key) -> bool {
        match key {
            // TODO: should check if wrapped key is valid AEAD
            // On the other hand, we already decrypted a valid AEAD
            Key::WrappedKey(_) => true,
            Key::ResidentKey(key) => {
                debug_now!("checking if ResidentKey {:?} exists", key);
                match alg {
                    -7 => syscall!(self.trussed.exists(Mechanism::P256, *key)).exists,
                    -8 => syscall!(self.trussed.exists(Mechanism::Ed255, *key)).exists,
                    // -9 => {
                    //     let exists = syscall!(self.trussed.exists(Mechanism::Totp, key)).exists;
                    //     info_now!("found it");
                    //     exists
                    // }
                    _ => false,
                }
            }
        }
    }

    #[inline(never)]
    fn process_assertion_extensions(
        &mut self,
        get_assertion_state: &state::ActiveGetAssertionData,
        extensions: &ctap2::get_assertion::ExtensionsInput,
        credential: &Credential,
        credential_key: KeyId,
    ) -> Result<Option<ctap2::get_assertion::ExtensionsOutput>> {
        let mut output = ctap2::get_assertion::ExtensionsOutput::default();

        if let Some(hmac_secret) = &extensions.hmac_secret {
            let pin_protocol = hmac_secret
                .pin_protocol
                .map(|i| self.parse_pin_protocol(i))
                .transpose()?
                .unwrap_or(PinProtocolVersion::V1);

            // We derive credRandom as an hmac of the existing private key.
            // UV is used as input data since credRandom should depend UV
            // i.e. credRandom = HMAC(private_key, uv)
            let cred_random = syscall!(self.trussed.derive_key(
                Mechanism::HmacSha256,
                credential_key,
                Some(Bytes::from_slice(&[get_assertion_state.uv_performed as u8]).unwrap()),
                trussed::types::StorageAttributes::new().set_persistence(Location::Volatile)
            ))
            .key;

            // Verify the auth tag, which uses the same process as the pinAuth
            let mut pin_protocol = self.pin_protocol(pin_protocol);
            let shared_secret = pin_protocol.shared_secret(&hmac_secret.key_agreement)?;
            pin_protocol.verify_pin_auth(
                &shared_secret,
                &hmac_secret.salt_enc,
                &hmac_secret.salt_auth,
            )?;

            // decrypt input salt_enc to get salt1 or (salt1 || salt2)
            let salts = shared_secret
                .decrypt(&mut self.trussed, &hmac_secret.salt_enc)
                .ok_or(Error::InvalidOption)?;

            if salts.len() != 32 && salts.len() != 64 {
                debug_now!("invalid hmac-secret length");
                return Err(Error::InvalidLength);
            }

            let mut salt_output: Bytes<64> = Bytes::new();

            // output1 = hmac_sha256(credRandom, salt1)
            let output1 =
                syscall!(self.trussed.sign_hmacsha256(cred_random, &salts[0..32])).signature;

            salt_output.extend_from_slice(&output1).unwrap();

            if salts.len() == 64 {
                // output2 = hmac_sha256(credRandom, salt2)
                let output2 =
                    syscall!(self.trussed.sign_hmacsha256(cred_random, &salts[32..64])).signature;

                salt_output.extend_from_slice(&output2).unwrap();
            }

            syscall!(self.trussed.delete(cred_random));

            // output_enc = aes256-cbc(sharedSecret, IV=0, output1 || output2)
            let output_enc = shared_secret.encrypt(&mut self.trussed, &salt_output);

            shared_secret.delete(&mut self.trussed);

            output.hmac_secret = Some(Bytes::from_slice(&output_enc).unwrap());
        }

        if extensions.third_party_payment.unwrap_or_default() {
            output.third_party_payment = Some(credential.third_party_payment().unwrap_or_default());
        }

        Ok(output.is_set().then_some(output))
    }

    #[inline(never)]
    fn assert_with_credential(
        &mut self,
        num_credentials: Option<u32>,
        credential: Credential,
    ) -> Result<ctap2::get_assertion::Response> {
        let data = self.state.runtime.active_get_assertion.clone().unwrap();
        let rp_id_hash = &data.rp_id_hash;

        let (key, is_rk) = match credential.key().clone() {
            Key::ResidentKey(key) => (key, true),
            Key::WrappedKey(bytes) => {
                let wrapping_key = self.state.persistent.key_wrapping_key(&mut self.trussed)?;
                // info_now!("unwrapping {:?} with wrapping key {:?}", &bytes, &wrapping_key);
                let key_result = syscall!(self.trussed.unwrap_key_chacha8poly1305(
                    wrapping_key,
                    &bytes,
                    &[],
                    Location::Volatile,
                ))
                .key;
                // debug_now!("key result: {:?}", &key_result);
                info_now!("key result");
                match key_result {
                    Some(key) => (key, false),
                    None => {
                        return Err(Error::Other);
                    }
                }
            }
        };

        // 8. process any extensions present
        let mut large_blob_key_requested = false;
        let extensions_output = if let Some(extensions) = &data.extensions {
            if self.config.supports_large_blobs() {
                if extensions.large_blob_key == Some(false) {
                    // large_blob_key must be Some(true) or omitted
                    return Err(Error::InvalidOption);
                }
                large_blob_key_requested = extensions.large_blob_key == Some(true);
            }
            self.process_assertion_extensions(&data, extensions, &credential, key)?
        } else {
            None
        };

        // 9./10. sign clientDataHash || authData with "first" credential

        // info_now!("signing with credential {:?}", &credential);
        let kek = self
            .state
            .persistent
            .key_encryption_key(&mut self.trussed)?;
        let credential_id = credential.id(&mut self.trussed, kek, rp_id_hash)?;

        use ctap2::AuthenticatorDataFlags as Flags;

        let sig_count = self.state.persistent.timestamp(&mut self.trussed)?;

        let authenticator_data = ctap2::get_assertion::AuthenticatorData {
            rp_id_hash,

            flags: {
                let mut flags = Flags::empty();
                if data.up_performed {
                    flags |= Flags::USER_PRESENCE;
                }
                if data.uv_performed {
                    flags |= Flags::USER_VERIFIED;
                }
                if extensions_output.is_some() {
                    flags |= Flags::EXTENSION_DATA;
                }
                flags
            },

            sign_count: sig_count,
            attested_credential_data: None,
            extensions: extensions_output,
        };

        let serialized_auth_data = authenticator_data.serialize()?;

        let mut commitment = Bytes::<1024>::new();
        commitment
            .extend_from_slice(&serialized_auth_data)
            .map_err(|_| Error::Other)?;
        commitment
            .extend_from_slice(&data.client_data_hash)
            .map_err(|_| Error::Other)?;

        let (mechanism, serialization) = match credential.algorithm() {
            -7 => (Mechanism::P256, SignatureSerialization::Asn1Der),
            -8 => (Mechanism::Ed255, SignatureSerialization::Raw),
            // -9 => (Mechanism::Totp, SignatureSerialization::Raw),
            _ => {
                return Err(Error::Other);
            }
        };

        debug_now!("signing with {:?}, {:?}", &mechanism, &serialization);
        let signature = syscall!(self
            .trussed
            .sign(mechanism, key, &commitment, serialization))
        .signature
        .to_bytes()
        .unwrap();

        if !is_rk {
            syscall!(self.trussed.delete(key));
        }

        let mut response = ctap2::get_assertion::ResponseBuilder {
            credential: credential_id.into(),
            auth_data: serialized_auth_data,
            signature,
        }
        .build();
        response.number_of_credentials = num_credentials;

        // User with empty IDs are ignored for compatibility
        if is_rk {
            if let Credential::Full(credential) = &credential {
                if !credential.user.id.is_empty() {
                    let mut user = credential.user.clone();
                    // User identifiable information (name, DisplayName, icon) MUST not
                    // be returned if user verification is not done by the authenticator.
                    // For single account per RP case, authenticator returns "id" field.
                    if !data.uv_performed || !data.multiple_credentials {
                        user.icon = None;
                        user.name = None;
                        user.display_name = None;
                    }
                    response.user = Some(user);
                }
            }

            if large_blob_key_requested {
                debug!("Sending largeBlobKey in getAssertion");
                response.large_blob_key = match credential {
                    Credential::Stripped(stripped) => stripped.large_blob_key,
                    Credential::Full(full) => full.data.large_blob_key,
                };
            }
        }

        Ok(response)
    }

    #[inline(never)]
    fn delete_resident_key_by_user_id(
        &mut self,
        rp_id_hash: &[u8; 32],
        user_id: &Bytes<64>,
    ) -> Result<()> {
        // Prepare to iterate over all credentials associated to RP.
        let rp_path = rp_rk_dir(rp_id_hash);
        let mut entry = syscall!(self
            .trussed
            .read_dir_first(Location::Internal, rp_path, None,))
        .entry;

        loop {
            info_now!("this may be an RK: {:?}", &entry);
            let rk_path = match entry {
                // no more RKs left
                // break breaks inner loop here
                None => break,
                Some(entry) => PathBuf::from(entry.path()),
            };

            info_now!("checking RK {:?} for userId ", &rk_path);
            let credential_data =
                syscall!(self.trussed.read_file(Location::Internal, rk_path.clone(),)).data;
            let credential_maybe = FullCredential::deserialize(&credential_data);

            if let Ok(old_credential) = credential_maybe {
                if old_credential.user.id == user_id {
                    match old_credential.key {
                        credential::Key::ResidentKey(key) => {
                            info_now!(":: deleting resident key");
                            syscall!(self.trussed.delete(key));
                        }
                        _ => {
                            warn_now!(":: WARNING: unexpected server credential in rk.");
                        }
                    }
                    syscall!(self.trussed.remove_file(Location::Internal, rk_path,));

                    info_now!("Overwriting previous rk tied to this userId.");
                    break;
                }
            } else {
                warn_now!("WARNING: Could not read RK.");
            }

            // prepare for next loop iteration
            entry = syscall!(self.trussed.read_dir_next()).entry;
        }

        Ok(())
    }

    #[inline(never)]
    pub(crate) fn delete_resident_key_by_path(&mut self, rk_path: &Path) -> Result<()> {
        info_now!("deleting RK {:?}", &rk_path);
        let credential_data = syscall!(self
            .trussed
            .read_file(Location::Internal, PathBuf::from(rk_path),))
        .data;
        let credential_maybe = FullCredential::deserialize(&credential_data);
        // info_now!("deleting credential {:?}", &credential);

        if let Ok(credential) = credential_maybe {
            match credential.key {
                credential::Key::ResidentKey(key) => {
                    info_now!(":: deleting resident key");
                    syscall!(self.trussed.delete(key));
                }
                credential::Key::WrappedKey(_) => {}
            }
        } else {
            // If for some reason there becomes a corrupt credential,
            // we can still at least orphan the key rather then crash.
            info_now!("Warning!  Orpaning a key.");
        }

        info_now!(":: deleting RK file {:?} itself", &rk_path);
        syscall!(self
            .trussed
            .remove_file(Location::Internal, PathBuf::from(rk_path),));

        Ok(())
    }

    pub(crate) fn delete_rp_dir_if_empty(&mut self, rp_path: PathBuf) {
        let maybe_first_remaining_rk =
            syscall!(self
                .trussed
                .read_dir_first(Location::Internal, rp_path.clone(), None,))
            .entry;

        if let Some(_first_remaining_rk) = maybe_first_remaining_rk {
            info!(
                "not deleting deleting parent {:?} as there is {:?}",
                &rp_path,
                &_first_remaining_rk.path(),
            );
        } else {
            info!("deleting parent {:?} as this was its last RK", &rp_path);
            syscall!(self.trussed.remove_dir(Location::Internal, rp_path,));
        }
    }

    fn large_blobs_get(
        &mut self,
        request: &ctap2::large_blobs::Request,
        config: large_blobs::Config,
        length: u32,
    ) -> Result<ctap2::large_blobs::Response> {
        debug!(
            "large_blobs_get: length = {length}, offset = {}",
            request.offset
        );
        // 1.-2. Validate parameters
        if request.length.is_some()
            || request.pin_uv_auth_param.is_some()
            || request.pin_uv_auth_protocol.is_some()
        {
            error!("length/pin set");
            return Err(Error::InvalidParameter);
        }
        // 3. Validate length
        let Ok(length) = usize::try_from(length) else {
            return Err(Error::InvalidLength);
        };
        if length > self.config.max_msg_size.saturating_sub(64) {
            return Err(Error::InvalidLength);
        }
        // 4. Validate offset
        let Ok(offset) = usize::try_from(request.offset) else {
            error!("offset too large");
            return Err(Error::InvalidParameter);
        };
        let stored_length = large_blobs::size(&mut self.trussed, config.location)?;
        if offset > stored_length {
            error!("offset: {offset}, stored_length: {stored_length}");
            return Err(Error::InvalidParameter);
        };
        // 5. Return requested data
        info!("Reading large-blob array from offset {offset}");
        let data = large_blobs::read_chunk(&mut self.trussed, config.location, offset, length)?;
        let mut response = ctap2::large_blobs::Response::default();
        response.config = Some(data);
        Ok(response)
    }

    fn large_blobs_set(
        &mut self,
        request: &ctap2::large_blobs::Request,
        config: large_blobs::Config,
        data: &[u8],
    ) -> Result<ctap2::large_blobs::Response> {
        debug!(
            "large_blobs_set: |data| = {}, offset = {}, length = {:?}",
            data.len(),
            request.offset,
            request.length
        );
        // 1. Validate data
        if data.len() > self.config.max_msg_size.saturating_sub(64) {
            return Err(Error::InvalidLength);
        }
        if request.offset == 0 {
            // 2. Calculate expected length and offset
            // 2.1. Require length
            let Some(length) = request.length else {
                return Err(Error::InvalidParameter);
            };
            // 2.2. Check that length is not too big
            let Ok(length) = usize::try_from(length) else {
                return Err(Error::LargeBlobStorageFull);
            };
            if length > config.max_size() {
                return Err(Error::LargeBlobStorageFull);
            }
            // 2.3. Check that length is not too small
            if length < large_blobs::MIN_SIZE {
                return Err(Error::InvalidParameter);
            }
            // 2.4-5. Set expected length and offset
            self.state.runtime.large_blobs.expected_length = length;
            self.state.runtime.large_blobs.expected_next_offset = 0;
        } else {
            // 3. Validate parameters
            if request.length.is_some() {
                return Err(Error::InvalidParameter);
            }
        }

        // 4. Validate offset
        let Ok(offset) = usize::try_from(request.offset) else {
            return Err(Error::InvalidSeq);
        };
        if offset != self.state.runtime.large_blobs.expected_next_offset {
            return Err(Error::InvalidSeq);
        }

        // 5. Perform uv
        // TODO: support alwaysUv
        if self.state.persistent.pin_is_set() {
            let Some(pin_uv_auth_param) = request.pin_uv_auth_param else {
                return Err(Error::PinRequired);
            };
            let Some(pin_uv_auth_protocol) = request.pin_uv_auth_protocol else {
                return Err(Error::PinRequired);
            };
            if pin_uv_auth_protocol != 1 {
                return Err(Error::PinAuthInvalid);
            }
            let pin_protocol = self.parse_pin_protocol(pin_uv_auth_protocol)?;
            // TODO: check pinUvAuthToken
            let pin_auth: [u8; 16] = pin_uv_auth_param
                .as_ref()
                .try_into()
                .map_err(|_| Error::PinAuthInvalid)?;

            let mut auth_data: Bytes<70> = Bytes::new();
            // 32x 0xff
            auth_data.resize(32, 0xff).unwrap();
            // h'0c00'
            auth_data.push(0x0c).unwrap();
            auth_data.push(0x00).unwrap();
            // uint32LittleEndian(offset)
            auth_data
                .extend_from_slice(&request.offset.to_le_bytes())
                .unwrap();
            // SHA-256(data)
            auth_data.extend_from_slice(&Sha256::digest(data)).unwrap();

            let mut pin_protocol = self.pin_protocol(pin_protocol);
            let pin_token = pin_protocol.verify_pin_token(&pin_auth, &auth_data)?;
            pin_token.require_permissions(Permissions::LARGE_BLOB_WRITE)?;
        }

        // 6. Validate data length
        if offset + data.len() > self.state.runtime.large_blobs.expected_length {
            return Err(Error::InvalidParameter);
        }

        // 7.-11. Write the buffer
        info!("Writing large-blob array to offset {offset}");
        large_blobs::write_chunk(
            &mut self.trussed,
            &mut self.state.runtime.large_blobs,
            config.location,
            data,
        )?;

        Ok(ctap2::large_blobs::Response::default())
    }
}

#[derive(Clone, Copy, Debug)]
enum SupportedAttestationFormat {
    None,
    Packed,
}

impl SupportedAttestationFormat {
    fn select(preference: Option<&AttestationFormatsPreference>) -> Option<Self> {
        let Some(preference) = preference else {
            // no preference, default to packed format
            return Some(Self::Packed);
        };
        if preference.known_formats() == [AttestationStatementFormat::None]
            && !preference.includes_unknown_formats()
        {
            // platform requested only None --> omit attestation statement
            return None;
        }
        // use first known and supported format, or default to packed format
        let format = preference
            .known_formats()
            .iter()
            .copied()
            .flat_map(Self::try_from)
            .next()
            .unwrap_or(Self::Packed);
        Some(format)
    }
}

impl From<SupportedAttestationFormat> for AttestationStatementFormat {
    fn from(format: SupportedAttestationFormat) -> Self {
        match format {
            SupportedAttestationFormat::None => Self::None,
            SupportedAttestationFormat::Packed => Self::Packed,
        }
    }
}

impl TryFrom<AttestationStatementFormat> for SupportedAttestationFormat {
    type Error = Error;

    fn try_from(format: AttestationStatementFormat) -> core::result::Result<Self, Self::Error> {
        match format {
            AttestationStatementFormat::None => Ok(Self::None),
            AttestationStatementFormat::Packed => Ok(Self::Packed),
            _ => Err(Error::Other),
        }
    }
}

fn rp_rk_dir(rp_id_hash: &[u8; 32]) -> PathBuf {
    // uses only first 8 bytes of hash, which should be "good enough"
    let mut hex = [b'0'; 16];
    format_hex(&rp_id_hash[..8], &mut hex);

    let mut dir = PathBuf::from(b"rk");
    dir.push(&PathBuf::from(&hex));

    dir
}

fn rk_path(rp_id_hash: &[u8; 32], credential_id_hash: &[u8; 32]) -> PathBuf {
    let mut path = rp_rk_dir(rp_id_hash);

    let mut hex = [0u8; 16];
    format_hex(&credential_id_hash[..8], &mut hex);
    path.push(&PathBuf::from(&hex));

    path
}
