use sha2::{Digest as _, Sha256};

use super::{
    virt::{Ctap2, Ctap2Error},
    webauthn::{
        AttStmtFormat, ClientPin, CredentialData, CredentialManagement, CredentialManagementParams,
        KeyAgreementKey, MakeCredential, MakeCredentialOptions, PinToken, PubKeyCredDescriptor,
        PubKeyCredParam, PublicKey, Rp, SharedSecret, User,
    },
};

pub struct Authenticator<'a, P: PinState> {
    ctap2: Ctap2<'a>,
    key_agreement_key: KeyAgreementKey,
    shared_secret: Option<SharedSecret>,
    pin: P,
}

impl<'a> Authenticator<'a, NoPin> {
    pub fn new(ctap2: Ctap2<'a>) -> Self {
        Self {
            ctap2,
            key_agreement_key: KeyAgreementKey::generate(),
            shared_secret: None,
            pin: NoPin,
        }
    }

    pub fn set_pin(mut self, pin: &[u8]) -> Authenticator<'a, Pin> {
        let shared_secret = self.shared_secret();
        let mut padded_pin = [0; 64];
        padded_pin[..pin.len()].copy_from_slice(pin);
        let pin_enc = shared_secret.encrypt(&padded_pin);
        let pin_auth = shared_secret.authenticate(&pin_enc);
        let mut request = ClientPin::new(2, 3);
        request.key_agreement = Some(self.key_agreement_key.public_key());
        request.new_pin_enc = Some(pin_enc);
        request.pin_auth = Some(pin_auth);
        self.ctap2.exec(request).unwrap();
        Authenticator {
            ctap2: self.ctap2,
            key_agreement_key: self.key_agreement_key,
            shared_secret: self.shared_secret,
            pin: Pin(pin.into()),
        }
    }
}

impl<P: PinState> Authenticator<'_, P> {
    fn shared_secret(&mut self) -> &SharedSecret {
        self.shared_secret.get_or_insert_with(|| {
            let reply = self.ctap2.exec(ClientPin::new(2, 2)).unwrap();
            let authenticator_key_agreement: PublicKey = reply.key_agreement.unwrap().into();
            self.key_agreement_key
                .shared_secret(&authenticator_key_agreement)
        })
    }
}

impl Authenticator<'_, Pin> {
    fn get_pin_token(&mut self, permissions: u8, rp_id: Option<String>) -> PinToken {
        let mut hasher = Sha256::new();
        hasher.update(&self.pin.0);
        let pin_hash = hasher.finalize();
        let pin_hash_enc = self.shared_secret().encrypt(&pin_hash[..16]);
        let mut request = ClientPin::new(2, 9);
        request.key_agreement = Some(self.key_agreement_key.public_key());
        request.pin_hash_enc = Some(pin_hash_enc);
        request.permissions = Some(permissions);
        request.rp_id = rp_id;
        let reply = self.ctap2.exec(request).unwrap();
        let encrypted_pin_token = reply.pin_token.as_ref().unwrap().as_bytes().unwrap();
        self.shared_secret().decrypt_pin_token(encrypted_pin_token)
    }

    pub fn make_credential(&mut self, rp: Rp, user: User) -> Result<CredentialData, Ctap2Error> {
        let pin_token = self.get_pin_token(0x01, None);
        // TODO: client data
        let client_data_hash = b"";
        let pin_auth = pin_token.authenticate(client_data_hash);
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
        request.options = Some(MakeCredentialOptions::default().rk(true));
        request.pin_auth = Some(pin_auth);
        request.pin_protocol = Some(2);
        let reply = self.ctap2.exec(request)?;
        assert_eq!(
            reply.auth_data.flags & 0b1,
            0b1,
            "up flag not set in auth_data: 0b{:b}",
            reply.auth_data.flags
        );
        assert_eq!(
            reply.auth_data.flags & 0b100,
            0b100,
            "uv flag not set in auth_data: 0b{:b}",
            reply.auth_data.flags
        );
        let format = AttStmtFormat::Packed;
        assert_eq!(reply.fmt, format.as_str());
        reply.att_stmt.unwrap().validate(format, &reply.auth_data);
        Ok(reply.auth_data.credential.unwrap())
    }

    fn credential_management(&mut self, subcommand: u8) -> CredentialManagement {
        let pin_token = self.get_pin_token(0x04, None);
        let pin_auth = pin_token.authenticate(&[subcommand]);
        CredentialManagement {
            subcommand,
            subcommand_params: None,
            pin_protocol: Some(2),
            pin_auth: Some(pin_auth),
        }
    }

    pub fn credentials_metadata(&mut self) -> CredentialsMetadata {
        let request = self.credential_management(0x01);
        let reply = self.ctap2.exec(request).unwrap();
        CredentialsMetadata {
            existing: reply.existing_resident_credentials_count.unwrap(),
            remaining: reply
                .max_possible_remaining_resident_credentials_count
                .unwrap(),
        }
    }

    pub fn list_rps(&mut self) -> Vec<Rp> {
        let request = self.credential_management(0x02);
        let reply = self.ctap2.exec(request).unwrap();
        // TODO: check RP ID hash
        let total_rps = reply.total_rps.unwrap();
        let mut rps = Vec::with_capacity(total_rps);
        rps.push(reply.rp.unwrap().into());

        for _ in 1..total_rps {
            let request = CredentialManagement::new(0x03);
            let reply = self.ctap2.exec(request).unwrap();
            // TODO: check RP ID hash
            rps.push(reply.rp.unwrap().into());
        }

        rps
    }

    pub fn list_credentials(&mut self, rp_id: &str) -> Vec<(User, PubKeyCredDescriptor)> {
        let rp_id_hash = rp_id_hash(rp_id);
        let pin_token = self.get_pin_token(0x04, Some(rp_id.to_owned()));
        let params = CredentialManagementParams {
            rp_id_hash: Some(rp_id_hash.to_vec()),
            ..Default::default()
        };
        let mut pin_auth_param = vec![0x04];
        pin_auth_param.extend_from_slice(&params.serialized());
        let pin_auth = pin_token.authenticate(&pin_auth_param);
        let request = CredentialManagement {
            subcommand: 0x04,
            subcommand_params: Some(params),
            pin_protocol: Some(2),
            pin_auth: Some(pin_auth),
        };
        let reply = self.ctap2.exec(request).unwrap();
        // TODO: check other fields
        let total_credentials = reply.total_credentials.unwrap();
        let mut credentials = Vec::with_capacity(total_credentials);
        credentials.push((reply.user.unwrap().into(), reply.credential_id.unwrap()));

        for _ in 1..total_credentials {
            let request = CredentialManagement::new(0x05);
            let reply = self.ctap2.exec(request).unwrap();
            // TODO: check other fields
            credentials.push((reply.user.unwrap().into(), reply.credential_id.unwrap()));
        }

        credentials
    }

    pub fn delete_credential(&mut self, id: &[u8]) {
        let pin_token = self.get_pin_token(0x04, None);
        let params = CredentialManagementParams {
            credential_id: Some(PubKeyCredDescriptor::new("public-key", id)),
            ..Default::default()
        };
        let mut pin_auth_param = vec![0x06];
        pin_auth_param.extend_from_slice(&params.serialized());
        let pin_auth = pin_token.authenticate(&pin_auth_param);
        let request = CredentialManagement {
            subcommand: 0x06,
            subcommand_params: Some(params),
            pin_protocol: Some(2),
            pin_auth: Some(pin_auth),
        };
        self.ctap2.exec(request).unwrap();
    }

    pub fn update_user(&mut self, id: &[u8], user: User) -> Result<(), Ctap2Error> {
        let pin_token = self.get_pin_token(0x04, None);
        let params = CredentialManagementParams {
            credential_id: Some(PubKeyCredDescriptor::new("public-key", id)),
            user: Some(user),
            ..Default::default()
        };
        let mut pin_auth_param = vec![0x07];
        pin_auth_param.extend_from_slice(&params.serialized());
        let pin_auth = pin_token.authenticate(&pin_auth_param);
        let request = CredentialManagement {
            subcommand: 0x07,
            subcommand_params: Some(params),
            pin_protocol: Some(2),
            pin_auth: Some(pin_auth),
        };
        self.ctap2.exec(request).map(|_| ())
    }
}

pub struct CredentialsMetadata {
    pub existing: usize,
    pub remaining: usize,
}

pub trait PinState {}

pub struct NoPin;

impl PinState for NoPin {}

pub struct Pin(Vec<u8>);

impl PinState for Pin {}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rp_id);
    hasher.finalize().into()
}
