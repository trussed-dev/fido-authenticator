//! The `ctap_types::ctap2::Authenticator` implementation.

use ctap_types::{
    ctap2::{self, Authenticator, VendorOperation},
    heapless::{String, Vec},
    heapless_bytes::Bytes,
    sizes, Error,
};

use littlefs2::path::Path;

use trussed::{
    syscall, try_syscall,
    types::{
        KeyId, KeySerialization, Location, Mechanism, MediumData, Message, PathBuf,
        SignatureSerialization,
    },
};

use crate::{
    constants,
    credential::{
        self,
        Credential,
        // CredentialList,
        Key,
    },
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
// pub mod pin;

/// Implement `ctap2::Authenticator` for our Authenticator.
impl<UP: UserPresence, T: TrussedRequirements> Authenticator for crate::Authenticator<UP, T> {
    #[inline(never)]
    fn get_info(&mut self) -> ctap2::get_info::Response {
        debug_now!("remaining stack size: {} bytes", msp() - 0x2000_0000);

        use core::str::FromStr;
        let mut versions = Vec::<String<12>, 4>::new();
        versions.push(String::from_str("U2F_V2").unwrap()).unwrap();
        versions
            .push(String::from_str("FIDO_2_0").unwrap())
            .unwrap();
        // #[cfg(feature = "enable-fido-pre")]
        versions
            .push(String::from_str("FIDO_2_1_PRE").unwrap())
            .unwrap();

        let mut extensions = Vec::<String<11>, 4>::new();
        // extensions.push(String::from_str("credProtect").unwrap()).unwrap();
        extensions
            .push(String::from_str("credProtect").unwrap())
            .unwrap();
        extensions
            .push(String::from_str("hmac-secret").unwrap())
            .unwrap();

        let mut pin_protocols = Vec::<u8, 1>::new();
        pin_protocols.push(1).unwrap();

        let options = ctap2::get_info::CtapOptions {
            ep: None,
            rk: true,
            up: true,
            uv: None,
            plat: Some(false),
            cred_mgmt: Some(true),
            client_pin: match self.state.persistent.pin_is_set() {
                true => Some(true),
                false => Some(false),
            },
            credential_mgmt_preview: Some(true),
            ..Default::default()
        };
        // options.rk = true;
        // options.up = true;
        // options.uv = None; // "uv" here refers to "in itself", e.g. biometric
        // options.plat = Some(false);
        // options.cred_mgmt = Some(true);
        // options.credential_mgmt_preview = Some(true);
        // // options.client_pin = None; // not capable of PIN
        // options.client_pin = match self.state.persistent.pin_is_set() {
        //     true => Some(true),
        //     false => Some(false),
        // };

        let mut transports = Vec::new();
        transports.push(String::from("nfc")).unwrap();
        transports.push(String::from("usb")).unwrap();

        let (_, aaguid) = self.state.identity.attestation(&mut self.trussed);

        ctap2::get_info::Response {
            versions,
            extensions: Some(extensions),
            aaguid: Bytes::from_slice(&aaguid).unwrap(),
            options: Some(options),
            transports: Some(transports),
            // 1200
            max_msg_size: Some(self.config.max_msg_size),
            pin_protocols: Some(pin_protocols),
            max_creds_in_list: Some(ctap_types::sizes::MAX_CREDENTIAL_COUNT_IN_LIST),
            max_cred_id_length: Some(ctap_types::sizes::MAX_CREDENTIAL_ID_LENGTH),
            ..ctap2::get_info::Response::default()
        }
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

        self.assert_with_credential(None, credential)
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
        let uv_performed = self.pin_prechecks(
            &parameters.options,
            &parameters.pin_auth,
            &parameters.pin_protocol,
            parameters.client_data_hash.as_ref(),
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
                    if !(excluded_cred.cred_protect == Some(CredentialProtectionPolicy::Required))
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
        for param in parameters.pub_key_cred_params.iter() {
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
        let algorithm = match algorithm {
            Some(algorithm) => {
                info_now!("algo: {:?}", algorithm as i32);
                algorithm
            }
            None => {
                return Err(Error::UnsupportedAlgorithm);
            }
        };

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
        if let Some(extensions) = &parameters.extensions {
            hmac_secret_requested = extensions.hmac_secret;

            if let Some(policy) = &extensions.cred_protect {
                cred_protect_requested =
                    Some(credential::CredentialProtectionPolicy::try_from(*policy)?);
            }
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
                    &rp_id_hash,
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
        let nonce = syscall!(self.trussed.random_bytes(12))
            .bytes
            .as_slice()
            .try_into()
            .unwrap();
        info_now!("nonce = {:?}", &nonce);

        // 12.b generate credential ID { = AEAD(Serialize(Credential)) }
        let kek = self
            .state
            .persistent
            .key_encryption_key(&mut self.trussed)?;

        // store it.
        // TODO: overwrite, error handling with KeyStoreFull

        let credential = Credential::new(
            credential::CtapVersion::Fido21Pre,
            &parameters.rp,
            &parameters.user,
            algorithm as i32,
            key_parameter,
            self.state.persistent.timestamp(&mut self.trussed)?,
            hmac_secret_requested,
            cred_protect_requested,
            nonce,
        );

        // note that this does the "stripping" of OptionalUI etc.
        let credential_id = credential.id(&mut self.trussed, kek, Some(&rp_id_hash))?;

        if rk_requested {
            // serialization with all metadata
            let serialized_credential = credential.serialize()?;

            // first delete any other RK cred with same RP + UserId if there is one.
            self.delete_resident_key_by_user_id(&rp_id_hash, &credential.user.id)
                .ok();

            // then store key, making it resident
            let credential_id_hash = self.hash(credential_id.0.as_ref());
            try_syscall!(self.trussed.write_file(
                Location::Internal,
                rk_path(&rp_id_hash, &credential_id_hash),
                serialized_credential,
                // user attribute for later easy lookup
                // Some(rp_id_hash.clone()),
                None,
            ))
            .map_err(|_| Error::KeyStoreFull)?;
        }

        // 13. generate and return attestation statement using clientDataHash

        // 13.a AuthenticatorData and its serialization
        use ctap2::AuthenticatorDataFlags as Flags;
        info_now!("MC created cred id");

        let (attestation_maybe, aaguid) = self.state.identity.attestation(&mut self.trussed);

        let authenticator_data = ctap2::make_credential::AuthenticatorData {
            rp_id_hash: rp_id_hash.to_bytes().map_err(|_| Error::Other)?,

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
                    aaguid: Bytes::from_slice(&aaguid).unwrap(),
                    credential_id: credential_id.0.to_bytes().unwrap(),
                    credential_public_key: cose_public_key.to_bytes().unwrap(),
                };
                // debug_now!("cose PK = {:?}", &attested_credential_data.credential_public_key);
                Some(attested_credential_data)
            },

            extensions: {
                if hmac_secret_requested.is_some() || cred_protect_requested.is_some() {
                    Some(ctap2::make_credential::Extensions {
                        cred_protect: parameters.extensions.as_ref().unwrap().cred_protect,
                        hmac_secret: parameters.extensions.as_ref().unwrap().hmac_secret,
                    })
                } else {
                    None
                }
            },
        };
        // debug_now!("authData = {:?}", &authenticator_data);

        let serialized_auth_data = authenticator_data.serialize();

        // 13.b The Signature

        // can we write Sum<M, N> somehow?
        // debug_now!("seeking commitment, {} + {}", serialized_auth_data.len(), parameters.client_data_hash.len());
        let mut commitment = Bytes::<1024>::new();
        commitment
            .extend_from_slice(&serialized_auth_data)
            .map_err(|_| Error::Other)?;
        // debug_now!("serialized_auth_data ={:?}", &serialized_auth_data);
        commitment
            .extend_from_slice(&parameters.client_data_hash)
            .map_err(|_| Error::Other)?;
        // debug_now!("client_data_hash = {:?}", &parameters.client_data_hash);
        // debug_now!("commitment = {:?}", &commitment);

        // NB: the other/normal one is called "basic" or "batch" attestation,
        // because it attests the authenticator is part of a batch: the model
        // specified by AAGUID.
        // "self signed" is also called "surrogate basic".
        //
        // we should also directly support "none" format, it's a bit weird
        // how browsers firefox this

        let (signature, attestation_algorithm) = {
            if attestation_maybe.is_none() {
                match algorithm {
                    SigningAlgorithm::Ed25519 => {
                        let signature =
                            syscall!(self.trussed.sign_ed255(private_key, &commitment)).signature;
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
                    } // SigningAlgorithm::Totp => {
                      //     // maybe we can fake it here too, but seems kinda weird
                      //     // return Err(Error::UnsupportedAlgorithm);
                      //     // micro-ecc is borked. let's self-sign anyway
                      //     let hash = syscall!(self.trussed.hash_sha256(&commitment.as_ref())).hash;
                      //     let tmp_key = syscall!(self.trussed
                      //         .generate_p256_private_key(Location::Volatile))
                      //         .key;

                      //     let signature = syscall!(self.trussed.sign_p256(
                      //         tmp_key,
                      //         &hash,
                      //         SignatureSerialization::Asn1Der,
                      //     )).signature;
                      //     (signature.to_bytes().map_err(|_| Error::Other)?, -7)
                      // }
                }
            } else {
                let signature = syscall!(self.trussed.sign_p256(
                    attestation_maybe.as_ref().unwrap().0,
                    &commitment,
                    SignatureSerialization::Asn1Der,
                ))
                .signature;
                (signature.to_bytes().map_err(|_| Error::Other)?, -7)
            }
        };
        // debug_now!("SIG = {:?}", &signature);

        if !rk_requested {
            let _success = syscall!(self.trussed.delete(private_key)).success;
            info_now!("deleted private credential key: {}", _success);
        }

        let packed_attn_stmt = ctap2::make_credential::PackedAttestationStatement {
            alg: attestation_algorithm,
            sig: signature,
            x5c: match attestation_maybe.is_some() {
                false => None,
                true => {
                    // See: https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
                    let cert = attestation_maybe.as_ref().unwrap().1.clone();
                    let mut x5c = Vec::new();
                    x5c.push(cert).ok();
                    Some(x5c)
                }
            },
        };

        let fmt = String::<32>::from("packed");
        let att_stmt = ctap2::make_credential::AttestationStatement::Packed(packed_attn_stmt);

        let attestation_object = ctap2::make_credential::Response {
            fmt,
            auth_data: serialized_auth_data,
            att_stmt,
        };

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
        parameters: &ctap2::client_pin::Request,
    ) -> Result<ctap2::client_pin::Response> {
        use ctap2::client_pin::PinV1Subcommand as Subcommand;
        debug_now!("CTAP2.PIN...");
        // info_now!("{:?}", parameters);

        // TODO: Handle pin protocol V2
        if parameters.pin_protocol != 1 {
            return Err(Error::InvalidParameter);
        }

        Ok(match parameters.sub_command {
            Subcommand::GetRetries => {
                debug_now!("CTAP2.Pin.GetRetries");

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: None,
                    retries: Some(self.state.persistent.retries()),
                }
            }

            Subcommand::GetKeyAgreement => {
                debug_now!("CTAP2.Pin.GetKeyAgreement");

                let private_key = self.state.runtime.key_agreement_key(&mut self.trussed);
                let public_key = syscall!(self
                    .trussed
                    .derive_p256_public_key(private_key, Location::Volatile))
                .key;
                let serialized_cose_key = syscall!(self.trussed.serialize_key(
                    Mechanism::P256,
                    public_key,
                    KeySerialization::EcdhEsHkdf256
                ))
                .serialized_key;
                let cose_key = trussed::cbor_deserialize(&serialized_cose_key).unwrap();

                syscall!(self.trussed.delete(public_key));

                ctap2::client_pin::Response {
                    key_agreement: cose_key,
                    pin_token: None,
                    retries: None,
                }
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
                let shared_secret = self
                    .state
                    .runtime
                    .generate_shared_secret(&mut self.trussed, platform_kek)?;

                // TODO: there are moar early returns!!
                // - implement Drop?
                // - do garbage collection outside of this?

                // 4. verify pinAuth
                self.verify_pin_auth(shared_secret, new_pin_enc, pin_auth)?;

                // 5. decrypt and verify new PIN
                let new_pin = self.decrypt_pin_check_length(shared_secret, new_pin_enc)?;

                syscall!(self.trussed.delete(shared_secret));

                // 6. store LEFT(SHA-256(newPin), 16), set retries to 8
                self.hash_store_pin(&new_pin)?;
                self.state
                    .reset_retries(&mut self.trussed)
                    .map_err(|_| Error::Other)?;

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: None,
                    retries: None,
                }
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
                let shared_secret = self
                    .state
                    .runtime
                    .generate_shared_secret(&mut self.trussed, platform_kek)?;

                // 4. verify pinAuth
                let mut data = MediumData::new();
                data.extend_from_slice(new_pin_enc)
                    .map_err(|_| Error::InvalidParameter)?;
                data.extend_from_slice(pin_hash_enc)
                    .map_err(|_| Error::InvalidParameter)?;
                self.verify_pin_auth(shared_secret, &data, pin_auth)?;

                // 5. decrement retries
                self.state.decrement_retries(&mut self.trussed)?;

                // 6. decrypt pinHashEnc, compare with stored
                self.decrypt_pin_hash_and_maybe_escalate(shared_secret, pin_hash_enc)?;

                // 7. reset retries
                self.state.reset_retries(&mut self.trussed)?;

                // 8. decrypt and verify new PIN
                let new_pin = self.decrypt_pin_check_length(shared_secret, new_pin_enc)?;

                syscall!(self.trussed.delete(shared_secret));

                // 9. store hashed PIN
                self.hash_store_pin(&new_pin)?;

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: None,
                    retries: None,
                }
            }

            Subcommand::GetPinToken => {
                debug_now!("CTAP2.Pin.GetPinToken");

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

                // 2. fail if no retries left
                self.state.pin_blocked()?;

                // 3. generate shared secret
                let shared_secret = self
                    .state
                    .runtime
                    .generate_shared_secret(&mut self.trussed, platform_kek)?;

                // 4. decrement retires
                self.state.decrement_retries(&mut self.trussed)?;

                // 5. decrypt and verify pinHashEnc
                self.decrypt_pin_hash_and_maybe_escalate(shared_secret, pin_hash_enc)?;

                // 6. reset retries
                self.state.reset_retries(&mut self.trussed)?;

                // 7. return encrypted pinToken
                let pin_token = self.state.runtime.pin_token(&mut self.trussed);
                debug_now!("wrapping pin token");
                // info_now!("exists? {}", syscall!(self.trussed.exists(shared_secret)).exists);
                let pin_token_enc =
                    syscall!(self.trussed.wrap_key_aes256cbc(shared_secret, pin_token)).wrapped_key;

                syscall!(self.trussed.delete(shared_secret));

                // ble...
                if pin_token_enc.len() != 16 {
                    return Err(Error::Other);
                }
                let pin_token_enc_32 = Bytes::from_slice(&pin_token_enc).unwrap();

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: Some(pin_token_enc_32),
                    retries: None,
                }
            }

            Subcommand::GetPinUvAuthTokenUsingUvWithPermissions
            | Subcommand::GetUVRetries
            | Subcommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                // todo!("not implemented yet")
                return Err(Error::InvalidParameter);
            }
        })
    }

    #[inline(never)]
    fn credential_management(
        &mut self,
        parameters: &ctap2::credential_management::Request,
    ) -> Result<ctap2::credential_management::Response> {
        use credential_management as cm;
        use ctap2::credential_management::Subcommand;

        // TODO: I see "failed pinauth" output, but then still continuation...
        self.verify_pin_auth_using_token(parameters)?;

        let mut cred_mgmt = cm::CredentialManagement::new(self);
        let sub_parameters = &parameters.sub_command_params;
        match parameters.sub_command {
            // 0x1
            Subcommand::GetCredsMetadata => cred_mgmt.get_creds_metadata(),

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
            &parameters.pin_auth,
            &parameters.pin_protocol,
            parameters.client_data_hash.as_ref(),
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

        // UP occurs by default, but option could specify not to.
        let do_up = if parameters.options.is_some() {
            parameters.options.as_ref().unwrap().up.unwrap_or(true)
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
                buf.copy_from_slice(&parameters.client_data_hash);
                buf
            },
            uv_performed,
            up_performed,
            multiple_credentials,
            extensions: parameters.extensions.clone(),
        });

        let num_credentials = match num_credentials {
            1 => None,
            n => Some(n as u32),
        };

        self.assert_with_credential(num_credentials, credential)
    }
}

// impl<UP: UserPresence, T: TrussedRequirements> Authenticator for crate::Authenticator<UP, T>
impl<UP: UserPresence, T: TrussedRequirements> crate::Authenticator<UP, T> {
    #[inline(never)]
    fn check_credential_applicable(
        &mut self,
        credential: &Credential,
        allowlist_passed: bool,
        uv_performed: bool,
    ) -> bool {
        if !self.check_key_exists(credential.algorithm, &credential.key) {
            return false;
        }

        if !{
            use credential::CredentialProtectionPolicy as Policy;
            debug_now!("CredentialProtectionPolicy {:?}", &credential.cred_protect);
            match credential.cred_protect {
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
        rp_id_hash: &Bytes<32>,
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
            .map(|entry| PathBuf::try_from(entry.path()).unwrap());

        use crate::state::CachedCredential;
        use core::str::FromStr;

        while let Some(path) = maybe_path {
            let credential_data =
                syscall!(self.trussed.read_file(Location::Internal, path.clone(),)).data;

            let credential = Credential::deserialize(&credential_data).ok()?;

            if self.check_credential_applicable(&credential, false, uv_performed) {
                self.state.runtime.push_credential(CachedCredential {
                    timestamp: credential.creation_time,
                    path: String::from_str(path.as_str_ref_with_trailing_nul()).ok()?,
                });
            }

            maybe_path = syscall!(self.trussed.read_dir_next())
                .entry
                .map(|entry| PathBuf::try_from(entry.path()).unwrap());
        }

        let num_credentials = self.state.runtime.remaining_credentials();
        let credential = self.state.runtime.pop_credential(&mut self.trussed);
        credential.map(|credential| (credential, num_credentials))
    }

    fn decrypt_pin_hash_and_maybe_escalate(
        &mut self,
        shared_secret: KeyId,
        pin_hash_enc: &Bytes<64>,
    ) -> Result<()> {
        let pin_hash = syscall!(self.trussed.decrypt_aes256cbc(shared_secret, pin_hash_enc))
            .plaintext
            .ok_or(Error::Other)?;

        let stored_pin_hash = match self.state.persistent.pin_hash() {
            Some(hash) => hash,
            None => {
                return Err(Error::PinNotSet);
            }
        };

        if pin_hash != stored_pin_hash {
            // I) generate new KEK
            self.state
                .runtime
                .rotate_key_agreement_key(&mut self.trussed);
            if self.state.persistent.retries() == 0 {
                return Err(Error::PinBlocked);
            }
            if self.state.persistent.pin_blocked() {
                return Err(Error::PinAuthBlocked);
            }
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
        shared_secret: KeyId,
        pin_enc: &[u8],
    ) -> Result<Message> {
        // pin is expected to be filled with null bytes to length at least 64
        if pin_enc.len() < 64 {
            // correct error?
            return Err(Error::PinPolicyViolation);
        }

        let mut pin = syscall!(self.trussed.decrypt_aes256cbc(shared_secret, pin_enc))
            .plaintext
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

    // fn verify_pin(&mut self, pin_auth: &Bytes<16>, client_data_hash: &Bytes<32>) -> bool {
    fn verify_pin(&mut self, pin_auth: &[u8; 16], data: &[u8]) -> Result<()> {
        let key = self.state.runtime.pin_token(&mut self.trussed);
        let tag = syscall!(self.trussed.sign_hmacsha256(key, data)).signature;
        if pin_auth == &tag[..16] {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    fn verify_pin_auth(
        &mut self,
        shared_secret: KeyId,
        data: &[u8],
        pin_auth: &Bytes<16>,
    ) -> Result<()> {
        let expected_pin_auth =
            syscall!(self.trussed.sign_hmacsha256(shared_secret, data)).signature;

        if expected_pin_auth[..16] == pin_auth[..] {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    // fn verify_pin_auth_using_token(&mut self, data: &[u8], pin_auth: &Bytes<16>)
    fn verify_pin_auth_using_token(
        &mut self,
        parameters: &ctap2::credential_management::Request,
    ) -> Result<()> {
        // info_now!("CM params: {:?}", parameters);
        use ctap2::credential_management::Subcommand;
        match parameters.sub_command {
            // are we Haskell yet lol
            sub_command @ Subcommand::GetCredsMetadata
            | sub_command @ Subcommand::EnumerateRpsBegin
            | sub_command @ Subcommand::EnumerateCredentialsBegin
            | sub_command @ Subcommand::DeleteCredential => {
                // check pinProtocol
                let pin_protocol = parameters
                    // .sub_command_params.as_ref().ok_or(Error::MissingParameter)?
                    .pin_protocol
                    .ok_or(Error::MissingParameter)?;
                if pin_protocol != 1 {
                    return Err(Error::InvalidParameter);
                }

                // check pinAuth
                let pin_token = self.state.runtime.pin_token(&mut self.trussed);
                let mut data: Bytes<{ sizes::MAX_CREDENTIAL_ID_LENGTH_PLUS_256 }> =
                    Bytes::from_slice(&[sub_command as u8]).unwrap();
                let len = 1 + match sub_command {
                    Subcommand::EnumerateCredentialsBegin | Subcommand::DeleteCredential => {
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

                // info_now!("input to hmacsha256: {:?}", &data[..len]);
                let expected_pin_auth =
                    syscall!(self.trussed.sign_hmacsha256(pin_token, &data[..len],)).signature;

                let pin_auth = parameters
                    .pin_auth
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;

                if expected_pin_auth[..16] == pin_auth[..] {
                    info_now!("passed pinauth");
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
        }
    }

    /// Returns whether UV was performed.
    fn pin_prechecks(
        &mut self,
        options: &Option<ctap2::AuthenticatorOptions>,
        pin_auth: &Option<ctap2::PinAuth>,
        pin_protocol: &Option<u32>,
        data: &[u8],
    ) -> Result<bool> {
        // 1. pinAuth zero length -> wait for user touch, then
        // return PinNotSet if not set, PinInvalid if set
        //
        // the idea is for multi-authnr scenario where platform
        // wants to enforce PIN and needs to figure out which authnrs support PIN
        if let Some(pin_auth) = pin_auth.as_ref() {
            if pin_auth.len() == 0 {
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
        if let Some(ref _pin_auth) = pin_auth {
            if let Some(1) = pin_protocol {
            } else {
                return Err(Error::PinAuthInvalid);
            }
        }

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
            if let Some(ref pin_auth) = pin_auth {
                if pin_auth.len() != 16 {
                    return Err(Error::InvalidParameter);
                }
                // seems a bit redundant to check here in light of 2.
                // I guess the CTAP spec writers aren't implementers :D
                if let Some(1) = pin_protocol {
                    // 5. if pinAuth is present and pinProtocol = 1, verify
                    // success --> set uv = 1
                    // error --> PinAuthInvalid
                    self.verify_pin(
                        // unwrap panic ruled out above
                        pin_auth.as_slice().try_into().unwrap(),
                        data,
                    )?;

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
        _credential: &Credential,
        credential_key: KeyId,
    ) -> Result<Option<ctap2::get_assertion::ExtensionsOutput>> {
        if let Some(hmac_secret) = &extensions.hmac_secret {
            if let Some(pin_protocol) = hmac_secret.pin_protocol {
                if pin_protocol != 1 {
                    return Err(Error::InvalidParameter);
                }
            }

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
            let kek = self
                .state
                .runtime
                .generate_shared_secret(&mut self.trussed, &hmac_secret.key_agreement)?;
            self.verify_pin_auth(kek, &hmac_secret.salt_enc, &hmac_secret.salt_auth)
                .map_err(|_| Error::ExtensionFirst)?;

            if hmac_secret.salt_enc.len() != 32 && hmac_secret.salt_enc.len() != 64 {
                debug_now!("invalid hmac-secret length");
                return Err(Error::InvalidLength);
            }

            // decrypt input salt_enc to get salt1 or (salt1 || salt2)
            let salts = syscall!(self.trussed.decrypt(
                Mechanism::Aes256Cbc,
                kek,
                &hmac_secret.salt_enc,
                b"",
                b"",
                b""
            ))
            .plaintext
            .ok_or(Error::InvalidOption)?;

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
            let output_enc =
                syscall!(self
                    .trussed
                    .encrypt(Mechanism::Aes256Cbc, kek, &salt_output, b"", None))
                .ciphertext;

            Ok(Some(ctap2::get_assertion::ExtensionsOutput {
                hmac_secret: Some(Bytes::from_slice(&output_enc).unwrap()),
            }))
        } else {
            Ok(None)
        }
    }

    #[inline(never)]
    fn assert_with_credential(
        &mut self,
        num_credentials: Option<u32>,
        credential: Credential,
    ) -> Result<ctap2::get_assertion::Response> {
        let data = self.state.runtime.active_get_assertion.clone().unwrap();
        let rp_id_hash = Bytes::from_slice(&data.rp_id_hash).unwrap();

        let (key, is_rk) = match credential.key.clone() {
            Key::ResidentKey(key) => (key, true),
            Key::WrappedKey(bytes) => {
                let wrapping_key = self.state.persistent.key_wrapping_key(&mut self.trussed)?;
                // info_now!("unwrapping {:?} with wrapping key {:?}", &bytes, &wrapping_key);
                let key_result = syscall!(self.trussed.unwrap_key_chacha8poly1305(
                    wrapping_key,
                    &bytes,
                    b"",
                    // &rp_id_hash,
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
        let extensions_output = if let Some(extensions) = &data.extensions {
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
        let credential_id = credential.id(&mut self.trussed, kek, Some(&rp_id_hash))?;

        use ctap2::AuthenticatorDataFlags as Flags;

        let sig_count = self.state.persistent.timestamp(&mut self.trussed)?;

        let authenticator_data = ctap2::get_assertion::AuthenticatorData {
            rp_id_hash,

            flags: {
                let mut flags = Flags::EMPTY;
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

        let serialized_auth_data = authenticator_data.serialize();

        let mut commitment = Bytes::<1024>::new();
        commitment
            .extend_from_slice(&serialized_auth_data)
            .map_err(|_| Error::Other)?;
        commitment
            .extend_from_slice(&data.client_data_hash)
            .map_err(|_| Error::Other)?;

        let (mechanism, serialization) = match credential.algorithm {
            -7 => (Mechanism::P256, SignatureSerialization::Asn1Der),
            -8 => (Mechanism::Ed255, SignatureSerialization::Raw),
            // -9 => (Mechanism::Totp, SignatureSerialization::Raw),
            _ => {
                return Err(Error::Other);
            }
        };

        debug_now!("signing with {:?}, {:?}", &mechanism, &serialization);
        let signature = match mechanism {
            // Mechanism::Totp => {
            //     let timestamp = u64::from_le_bytes(data.client_data_hash[..8].try_into().unwrap());
            //     info_now!("TOTP with timestamp {:?}", &timestamp);
            //     syscall!(self.trussed.sign_totp(key, timestamp)).signature.to_bytes().unwrap()
            // }
            _ => syscall!(self
                .trussed
                .sign(mechanism, key, &commitment, serialization))
            .signature
            .to_bytes()
            .unwrap(),
        };

        if !is_rk {
            syscall!(self.trussed.delete(key));
        }

        let mut response = ctap2::get_assertion::Response {
            credential: Some(credential_id.into()),
            auth_data: Bytes::from_slice(&serialized_auth_data).map_err(|_| Error::Other)?,
            signature,
            user: None,
            number_of_credentials: num_credentials,
        };

        if is_rk {
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

        Ok(response)
    }

    #[inline(never)]
    fn delete_resident_key_by_user_id(
        &mut self,
        rp_id_hash: &Bytes<32>,
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
            let credential_maybe = Credential::deserialize(&credential_data);

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
        let credential_maybe = Credential::deserialize(&credential_data);
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
}

fn rp_rk_dir(rp_id_hash: &Bytes<32>) -> PathBuf {
    // uses only first 8 bytes of hash, which should be "good enough"
    let mut hex = [b'0'; 16];
    format_hex(&rp_id_hash[..8], &mut hex);

    let mut dir = PathBuf::from(b"rk");
    dir.push(&PathBuf::from(&hex));

    dir
}

fn rk_path(rp_id_hash: &Bytes<32>, credential_id_hash: &Bytes<32>) -> PathBuf {
    let mut path = rp_rk_dir(rp_id_hash);

    let mut hex = [0u8; 16];
    format_hex(&credential_id_hash[..8], &mut hex);
    path.push(&PathBuf::from(&hex));

    path
}
