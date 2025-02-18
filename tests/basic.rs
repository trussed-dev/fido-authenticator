#![cfg(feature = "dispatch")]

pub mod virt;
pub mod webauthn;

use std::{collections::BTreeMap, fmt::Debug};

use ciborium::Value;
use exhaustive::Exhaustive;
use hex_literal::hex;

use virt::{Ctap2, Ctap2Error};
use webauthn::{
    AttStmtFormat, ClientPin, CredentialManagement, CredentialManagementParams, ExtensionsInput,
    GetAssertion, GetAssertionOptions, GetInfo, KeyAgreementKey, MakeCredential,
    MakeCredentialOptions, PinToken, PubKeyCredDescriptor, PubKeyCredParam, PublicKey, Rp,
    SharedSecret, User,
};

trait Test: Debug {
    fn test(&self);

    fn run(&self) {
        println!("{}", "=".repeat(80));
        println!("Running test:");
        println!("{self:#?}");
        println!();

        self.test();
    }

    fn run_all()
    where
        Self: Exhaustive,
    {
        for test in Self::iter_exhaustive(None) {
            test.run();
        }
    }
}

#[test]
fn test_ping() {
    virt::run_ctaphid(|device| {
        device.ping(&[0xf1, 0xd0]).unwrap();
    });
}

#[test]
fn test_get_info() {
    virt::run_ctap2(|device| {
        let reply = device.exec(GetInfo).unwrap();
        assert!(reply.versions.contains(&"FIDO_2_0".to_owned()));
        assert!(reply.versions.contains(&"FIDO_2_1".to_owned()));
        assert_eq!(
            reply.aaguid.as_bytes().unwrap(),
            &hex!("8BC5496807B14D5FB249607F5D527DA2")
        );
        assert_eq!(reply.pin_protocols, Some(vec![2, 1]));
        assert_eq!(
            reply.attestation_formats,
            Some(vec!["packed".to_owned(), "none".to_owned()])
        );
    });
}

fn get_shared_secret(device: &Ctap2, platform_key_agreement: &KeyAgreementKey) -> SharedSecret {
    let reply = device.exec(ClientPin::new(2, 2)).unwrap();
    let authenticator_key_agreement: PublicKey = reply.key_agreement.unwrap().into();
    platform_key_agreement.shared_secret(&authenticator_key_agreement)
}

fn set_pin(
    device: &Ctap2,
    key_agreement_key: &KeyAgreementKey,
    shared_secret: &SharedSecret,
    pin: &[u8],
) {
    let mut padded_pin = [0; 64];
    padded_pin[..pin.len()].copy_from_slice(pin);
    let pin_enc = shared_secret.encrypt(&padded_pin);
    let pin_auth = shared_secret.authenticate(&pin_enc);
    let mut request = ClientPin::new(2, 3);
    request.key_agreement = Some(key_agreement_key.public_key());
    request.new_pin_enc = Some(pin_enc);
    request.pin_auth = Some(pin_auth);
    device.exec(request).unwrap();
}

#[test]
fn test_set_pin() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, b"123456");
    })
}

fn get_pin_token(
    device: &Ctap2,
    key_agreement_key: &KeyAgreementKey,
    shared_secret: &SharedSecret,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<String>,
) -> PinToken {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(pin);
    let pin_hash = hasher.finalize();
    let pin_hash_enc = shared_secret.encrypt(&pin_hash[..16]);
    let mut request = ClientPin::new(2, 9);
    request.key_agreement = Some(key_agreement_key.public_key());
    request.pin_hash_enc = Some(pin_hash_enc);
    request.permissions = Some(permissions);
    request.rp_id = rp_id;
    let reply = device.exec(request).unwrap();
    let encrypted_pin_token = reply.pin_token.as_ref().unwrap().as_bytes().unwrap();
    shared_secret.decrypt_pin_token(encrypted_pin_token)
}

#[test]
fn test_get_pin_token() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin);
        get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None);
    })
}

#[derive(Clone, Debug, Exhaustive)]
enum RequestPinToken {
    InvalidPermissions,
    InvalidRpId,
    NoRpId,
    ValidRpId,
}

impl RequestPinToken {
    fn permissions(&self, valid: u8, invalid: u8) -> u8 {
        if matches!(self, Self::InvalidPermissions) {
            invalid
        } else {
            valid
        }
    }

    fn rp_id(&self, valid: &str, invalid: &str) -> Option<String> {
        match self {
            Self::InvalidPermissions => None,
            Self::InvalidRpId => Some(invalid.to_owned()),
            Self::NoRpId => None,
            Self::ValidRpId => Some(valid.to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, Exhaustive)]
enum AttestationFormatsPreference {
    Empty,
    None,
    Packed,
    NonePacked,
    PackedNone,
    OtherNonePacked,
    MultiOtherNonePacked,
}

impl AttestationFormatsPreference {
    fn format(&self) -> Option<AttStmtFormat> {
        match self {
            Self::Empty | Self::Packed | Self::PackedNone => Some(AttStmtFormat::Packed),
            Self::NonePacked | Self::OtherNonePacked | Self::MultiOtherNonePacked => {
                Some(AttStmtFormat::None)
            }
            Self::None => None,
        }
    }
}

impl From<AttestationFormatsPreference> for Vec<&'static str> {
    fn from(preference: AttestationFormatsPreference) -> Self {
        let mut vec = Vec::new();
        match preference {
            AttestationFormatsPreference::Empty => {}
            AttestationFormatsPreference::None => {
                vec.push("none");
            }
            AttestationFormatsPreference::Packed => {
                vec.push("packed");
            }
            AttestationFormatsPreference::NonePacked => {
                vec.push("none");
                vec.push("packed");
            }
            AttestationFormatsPreference::PackedNone => {
                vec.push("packed");
                vec.push("none");
            }
            AttestationFormatsPreference::OtherNonePacked => {
                vec.push("tpm");
                vec.push("none");
                vec.push("packed");
            }
            AttestationFormatsPreference::MultiOtherNonePacked => {
                vec.resize(100, "tpm");
                vec.push("none");
                vec.push("packed");
            }
        }
        vec
    }
}

#[derive(Debug, Exhaustive)]
enum PinAuth {
    NoPin,
    PinNoToken,
    PinToken(RequestPinToken),
}

#[derive(Debug, Exhaustive)]
struct TestMakeCredential {
    pin_auth: PinAuth,
    options: Option<MakeCredentialOptions>,
    valid_pub_key_alg: bool,
    attestation_formats_preference: Option<AttestationFormatsPreference>,
    hmac_secret: bool,
}

impl TestMakeCredential {
    fn expected_error(&self) -> Option<u8> {
        if let Some(options) = self.options {
            // TODO: this is the current implementation, but the spec allows Some(true)
            if options.up.is_some() {
                return Some(0x2c);
            }
        }
        match &self.pin_auth {
            PinAuth::PinToken(
                RequestPinToken::InvalidPermissions | RequestPinToken::InvalidRpId,
            ) => {
                return Some(0x33);
            }
            PinAuth::PinNoToken => {
                return Some(0x36);
            }
            _ => {}
        }
        if let Some(options) = self.options {
            // TODO: review if uv should be always rejected due to the lack of built-in uv
            if !matches!(self.pin_auth, PinAuth::PinToken(_)) && options.uv == Some(true) {
                return Some(0x2c);
            }
        }
        if !self.valid_pub_key_alg {
            return Some(0x26);
        }
        None
    }
}

impl Test for TestMakeCredential {
    fn test(&self) {
        let pin = b"123456";
        let rp_id = "example.com";
        let invalid_rp_id = "test.com";
        // TODO: client data
        let client_data_hash = b"";

        virt::run_ctap2(|device| {
            let mut pin_auth = None;
            match &self.pin_auth {
                PinAuth::NoPin => {}
                PinAuth::PinNoToken => {
                    let key_agreement_key = KeyAgreementKey::generate();
                    let shared_secret = get_shared_secret(&device, &key_agreement_key);
                    set_pin(&device, &key_agreement_key, &shared_secret, pin);
                }
                PinAuth::PinToken(pin_token) => {
                    let key_agreement_key = KeyAgreementKey::generate();
                    let shared_secret = get_shared_secret(&device, &key_agreement_key);
                    set_pin(&device, &key_agreement_key, &shared_secret, pin);
                    let pin_token = get_pin_token(
                        &device,
                        &key_agreement_key,
                        &shared_secret,
                        pin,
                        pin_token.permissions(0x01, 0x04),
                        pin_token.rp_id(rp_id, invalid_rp_id),
                    );
                    pin_auth = Some(pin_token.authenticate(client_data_hash));
                }
            }

            let rp = Rp::new(rp_id);
            let user = User::new(b"id123")
                .name("john.doe")
                .display_name("John Doe");
            let pub_key_alg = if self.valid_pub_key_alg { -7 } else { -11 };
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", pub_key_alg)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            request.options = self.options;
            if let Some(pin_auth) = pin_auth {
                request.pin_auth = Some(pin_auth);
                request.pin_protocol = Some(2);
            }
            request.attestation_formats_preference =
                self.attestation_formats_preference.map(From::from);
            // TODO: test other extensions and permutations
            if self.hmac_secret {
                request.extensions = Some(ExtensionsInput {
                    hmac_secret: Some(true),
                    ..Default::default()
                });
            }

            let result = device.exec(request);
            if let Some(error) = self.expected_error() {
                assert_eq!(result, Err(Ctap2Error(error)));
            } else {
                let reply = result.unwrap();
                assert!(reply.auth_data.credential.is_some());
                assert!(reply.auth_data.up_flag());
                // TODO: review conditions
                assert_eq!(
                    reply.auth_data.uv_flag(),
                    self.options.and_then(|options| options.uv).unwrap_or(false)
                        || matches!(self.pin_auth, PinAuth::PinToken(_))
                );
                assert!(reply.auth_data.at_flag());
                assert_eq!(reply.auth_data.ed_flag(), self.hmac_secret);
                let format = self
                    .attestation_formats_preference
                    .unwrap_or(AttestationFormatsPreference::Packed)
                    .format();
                if let Some(format) = format {
                    assert_eq!(reply.fmt, format.as_str());
                    reply.att_stmt.unwrap().validate(format, &reply.auth_data);
                } else {
                    assert_eq!(reply.fmt, AttStmtFormat::None.as_str());
                    assert!(reply.att_stmt.is_none());
                }
                if self.hmac_secret {
                    let extensions = reply.auth_data.extensions.unwrap();
                    assert_eq!(extensions.get("hmac-secret"), Some(&Value::from(true)));
                } else {
                    assert_eq!(reply.auth_data.extensions, None);
                }
            }
        });
    }
}

#[test]
fn test_make_credential() {
    TestMakeCredential::run_all();
}

#[derive(Debug, Exhaustive)]
struct TestGetAssertion {
    rk: bool,
    allow_list: bool,
    options: Option<GetAssertionOptions>,
    mc_third_party_payment: Option<bool>,
    ga_third_party_payment: Option<bool>,
}

impl TestGetAssertion {
    fn expected_error(&self) -> Option<u8> {
        if let Some(options) = self.options {
            if options.uv == Some(true) {
                return Some(0x2c);
            }
        }
        if !self.rk && !self.allow_list {
            return Some(0x2e);
        }
        None
    }
}

impl Test for TestGetAssertion {
    fn test(&self) {
        let rp_id = "example.com";
        // TODO: client data
        let client_data_hash = &[0; 32];

        // TODO: test with PIN
        virt::run_ctap2(|device| {
            let rp = Rp::new(rp_id);
            let user = User::new(b"id123")
                .name("john.doe")
                .display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            if self.rk {
                request.options = Some(MakeCredentialOptions::default().rk(true));
            }
            if let Some(third_party_payment) = self.mc_third_party_payment {
                request.extensions = Some(ExtensionsInput {
                    third_party_payment: Some(third_party_payment),
                    ..Default::default()
                });
            }
            let response = device.exec(request).unwrap();
            let credential = response.auth_data.credential.unwrap();

            let mut request = GetAssertion::new(rp_id, client_data_hash);
            // TODO: test more cases:
            // - multiple credentials in allow list
            // - invalid allow list
            if self.allow_list {
                request.allow_list = Some(vec![PubKeyCredDescriptor::new(
                    "public-key",
                    credential.id.clone(),
                )]);
            }
            if let Some(third_party_payment) = self.ga_third_party_payment {
                request.extensions = Some(ExtensionsInput {
                    third_party_payment: Some(third_party_payment),
                    ..Default::default()
                });
            }
            request.options = self.options;
            let result = device.exec(request);
            if let Some(error) = self.expected_error() {
                assert_eq!(result, Err(Ctap2Error(error)));
                return;
            }
            let response = result.unwrap();
            assert_eq!(response.credential.ty, "public-key");
            assert_eq!(response.credential.id, credential.id);
            assert_eq!(response.auth_data.credential, None);
            assert_eq!(
                response.auth_data.up_flag(),
                self.options.and_then(|options| options.up).unwrap_or(true)
            );
            assert!(!response.auth_data.uv_flag());
            assert!(!response.auth_data.at_flag());
            assert_eq!(
                response.auth_data.ed_flag(),
                self.ga_third_party_payment.unwrap_or_default()
            );
            credential.verify_assertion(&response.auth_data, client_data_hash, &response.signature);
            if self.ga_third_party_payment.unwrap_or_default() {
                let extensions = response.auth_data.extensions.unwrap();
                assert_eq!(
                    extensions.get("thirdPartyPayment"),
                    Some(&Value::from(
                        self.mc_third_party_payment.unwrap_or_default()
                    ))
                );
            } else {
                assert!(response.auth_data.extensions.is_none());
            }
        });
    }
}

#[test]
fn test_get_assertion() {
    TestGetAssertion::run_all();
}

#[derive(Debug, Exhaustive)]
struct TestListCredentials {
    pin_token_rp_id: bool,
    third_party_payment: Option<bool>,
}

impl Test for TestListCredentials {
    fn test(&self) {
        let key_agreement_key = KeyAgreementKey::generate();
        let pin = b"123456";
        let rp_id = "example.com";
        let user_id = b"id123";
        virt::run_ctap2(|device| {
            let shared_secret = get_shared_secret(&device, &key_agreement_key);
            set_pin(&device, &key_agreement_key, &shared_secret, pin);

            let pin_token =
                get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None);
            // TODO: client data
            let client_data_hash = b"";
            let pin_auth = pin_token.authenticate(client_data_hash);

            let rp = Rp::new(rp_id);
            let user = User::new(user_id).name("john.doe").display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            request.options = Some(MakeCredentialOptions::default().rk(true));
            request.pin_auth = Some(pin_auth);
            request.pin_protocol = Some(2);
            if let Some(third_party_payment) = self.third_party_payment {
                request.extensions = Some(ExtensionsInput {
                    third_party_payment: Some(third_party_payment),
                    ..Default::default()
                });
            }
            let reply = device.exec(request).unwrap();
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

            let pin_token =
                get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x04, None);
            let pin_auth = pin_token.authenticate(&[0x02]);
            let request = CredentialManagement {
                subcommand: 0x02,
                subcommand_params: None,
                pin_protocol: Some(2),
                pin_auth: Some(pin_auth),
            };
            let reply = device.exec(request).unwrap();
            let rp: BTreeMap<String, Value> = reply.rp.unwrap().deserialized().unwrap();
            // TODO: check rp ID hash
            assert!(reply.rp_id_hash.is_some());
            assert_eq!(reply.total_rps, Some(1));
            assert_eq!(rp.get("id").unwrap(), &Value::from(rp_id));

            let pin_token_rp_id = self.pin_token_rp_id.then(|| rp_id.to_owned());
            let pin_token = get_pin_token(
                &device,
                &key_agreement_key,
                &shared_secret,
                pin,
                0x04,
                pin_token_rp_id,
            );
            let params = CredentialManagementParams {
                rp_id_hash: Some(reply.rp_id_hash.unwrap().as_bytes().unwrap().to_owned()),
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
            let reply = device.exec(request).unwrap();
            let user: BTreeMap<String, Value> = reply.user.unwrap().deserialized().unwrap();
            assert_eq!(reply.total_credentials, Some(1));
            assert_eq!(user.get("id").unwrap(), &Value::from(user_id.as_slice()));
            assert_eq!(
                reply.third_party_payment,
                Some(self.third_party_payment.unwrap_or_default())
            );
        });
    }
}

#[test]
fn test_list_credentials() {
    TestListCredentials::run_all();
}
