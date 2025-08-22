#![cfg(feature = "dispatch")]

pub mod fs;
pub mod virt;
pub mod webauthn;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

use ciborium::Value;
use hex_literal::hex;
use itertools::iproduct;
use rand::RngCore as _;

use fs::list_fs;
use virt::{Ctap2, Ctap2Error, Options};
use webauthn::{
    exhaustive_struct, AttStmtFormat, ClientPin, CredentialManagement, CredentialManagementParams,
    Exhaustive, GetAssertion, GetAssertionExtensionsInput, GetAssertionOptions, GetInfo,
    GetNextAssertion, HmacSecretInput, KeyAgreementKey, MakeCredential,
    MakeCredentialExtensionsInput, MakeCredentialOptions, PinToken, PubKeyCredDescriptor,
    PubKeyCredParam, PublicKey, Rp, SharedSecret, User,
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
        for test in Self::iter_exhaustive() {
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
    let options = Options {
        inspect_ifs: Some(Box::new(|ifs| {
            let mut files = list_fs(ifs);
            files.remove_standard();
            files.assert_empty();
        })),
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
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
) -> Result<(), Ctap2Error> {
    let mut padded_pin = [0; 64];
    padded_pin[..pin.len()].copy_from_slice(pin);
    let pin_enc = shared_secret.encrypt(&padded_pin);
    let pin_auth = shared_secret.authenticate(&pin_enc);
    let mut request = ClientPin::new(2, 3);
    request.key_agreement = Some(key_agreement_key.public_key());
    request.new_pin_enc = Some(pin_enc);
    request.pin_auth = Some(pin_auth);
    device.exec(request).map(|_| ())
}

#[test]
fn test_set_pin() {
    let key_agreement_key = KeyAgreementKey::generate();
    let options = Options {
        inspect_ifs: Some(Box::new(|ifs| {
            let mut files = list_fs(ifs);
            files.remove_standard();
            files.remove_state();
            files.assert_empty();
        })),
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        let reply = device.exec(GetInfo).unwrap();
        let options = reply.options.unwrap();
        assert_eq!(options.get("clientPin"), Some(&Value::from(false)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, b"123456").unwrap();

        let reply = device.exec(GetInfo).unwrap();
        let options = reply.options.unwrap();
        assert_eq!(options.get("clientPin"), Some(&Value::from(true)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = set_pin(&device, &key_agreement_key, &shared_secret, b"123456");
        // TODO: review error code
        assert_eq!(result, Err(Ctap2Error(0x30)));

        let reply = device.exec(GetInfo).unwrap();
        let options = reply.options.unwrap();
        assert_eq!(options.get("clientPin"), Some(&Value::from(true)));
    })
}

fn get_pin_hash_enc(shared_secret: &SharedSecret, pin: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(pin);
    let pin_hash = hasher.finalize();
    shared_secret.encrypt(&pin_hash[..16])
}

fn change_pin(
    device: &Ctap2,
    key_agreement_key: &KeyAgreementKey,
    shared_secret: &SharedSecret,
    old_pin: &[u8],
    new_pin: &[u8],
) -> Result<(), Ctap2Error> {
    let old_pin_hash_enc = get_pin_hash_enc(shared_secret, old_pin);
    let mut padded_new_pin = [0; 64];
    padded_new_pin[..new_pin.len()].copy_from_slice(new_pin);
    let new_pin_enc = shared_secret.encrypt(&padded_new_pin);
    let mut pin_auth_data = Vec::new();
    pin_auth_data.extend_from_slice(&new_pin_enc);
    pin_auth_data.extend_from_slice(&old_pin_hash_enc);
    let pin_auth = shared_secret.authenticate(&pin_auth_data);
    let mut request = ClientPin::new(2, 4);
    request.key_agreement = Some(key_agreement_key.public_key());
    request.pin_hash_enc = Some(old_pin_hash_enc);
    request.new_pin_enc = Some(new_pin_enc);
    request.pin_auth = Some(pin_auth);
    device.exec(request).map(|_| ())
}

#[test]
fn test_change_pin() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin1 = b"123456";
    let pin2 = b"654321";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = change_pin(&device, &key_agreement_key, &shared_secret, pin1, pin2);
        // TODO: review error code
        assert_eq!(result, Err(Ctap2Error(0x35)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin1).unwrap();

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        change_pin(&device, &key_agreement_key, &shared_secret, pin1, pin2).unwrap();

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = change_pin(&device, &key_agreement_key, &shared_secret, pin1, pin2);
        assert_eq!(result, Err(Ctap2Error(0x31)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin1,
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin2,
            0x01,
            None,
        )
        .unwrap();
    })
}

fn get_pin_token(
    device: &Ctap2,
    key_agreement_key: &KeyAgreementKey,
    shared_secret: &SharedSecret,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<String>,
) -> Result<PinToken, Ctap2Error> {
    let pin_hash_enc = get_pin_hash_enc(shared_secret, pin);
    let mut request = ClientPin::new(2, 9);
    request.key_agreement = Some(key_agreement_key.public_key());
    request.pin_hash_enc = Some(pin_hash_enc);
    request.permissions = Some(permissions);
    request.rp_id = rp_id;
    let reply = device.exec(request)?;
    let encrypted_pin_token = reply.pin_token.as_ref().unwrap().as_bytes().unwrap();
    Ok(shared_secret.decrypt_pin_token(encrypted_pin_token))
}

fn get_pin_retries(device: &Ctap2) -> u8 {
    let reply = device.exec(ClientPin::new(2, 1)).unwrap();
    reply.pin_retries.unwrap()
}

#[test]
fn test_get_pin_retries() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        assert_eq!(get_pin_retries(&device), 8);

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        assert_eq!(get_pin_retries(&device), 8);

        get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None).unwrap();
        assert_eq!(get_pin_retries(&device), 8);

        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));
        assert_eq!(get_pin_retries(&device), 7);

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));
        assert_eq!(get_pin_retries(&device), 6);

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x34)));
        assert_eq!(get_pin_retries(&device), 5);

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x34)));
        assert_eq!(get_pin_retries(&device), 5);

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None);
        assert_eq!(result, Err(Ctap2Error(0x34)));
        assert_eq!(get_pin_retries(&device), 5);
    })
}

#[test]
fn test_get_pin_retries_reset() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));
        assert_eq!(get_pin_retries(&device), 7);

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None).unwrap();
        assert_eq!(get_pin_retries(&device), 8);
    })
}

#[test]
fn test_get_pin_token() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None).unwrap();
    })
}

#[test]
fn test_get_pin_token_invalid_pin() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None).unwrap();
    })
}

#[test]
fn test_get_pin_token_invalid_shared_secret() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));

        // presenting an invalid PIN resets the shared secret so even the correct PIN is not accepted
        let result = get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None);
        assert_eq!(result, Err(Ctap2Error(0x31)));

        // requesting a new shared secret fixes the authentication
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None).unwrap();
    })
}

// TODO: simulate reboot and test that PIN_AUTH_BLOCKED is reset
// TODO: simulate reboot and test PIN_BLOCKED

#[test]
fn test_get_pin_token_pin_auth_blocked() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x31)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        assert_eq!(result, Err(Ctap2Error(0x34)));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None);
        assert_eq!(result, Err(Ctap2Error(0x34)));
    })
}

#[test]
fn test_get_pin_token_no_pin() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            b"654321",
            0x01,
            None,
        );
        // TODO: review if this is the correct error code
        assert_eq!(result, Err(Ctap2Error(0x35)));
    })
}

#[derive(Clone, Copy, Debug)]
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

impl Exhaustive for RequestPinToken {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        [
            Self::InvalidPermissions,
            Self::InvalidRpId,
            Self::NoRpId,
            Self::ValidRpId,
        ]
        .into_iter()
    }
}

#[derive(Clone, Copy, Debug)]
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

impl Exhaustive for AttestationFormatsPreference {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        [
            Self::Empty,
            Self::None,
            Self::Packed,
            Self::NonePacked,
            Self::PackedNone,
            Self::OtherNonePacked,
            Self::MultiOtherNonePacked,
        ]
        .into_iter()
    }
}

#[derive(Clone, Copy, Debug)]
enum PinAuth {
    NoPin,
    PinNoToken,
    PinToken(RequestPinToken),
}

impl Exhaustive for PinAuth {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        [Self::NoPin, Self::PinNoToken]
            .into_iter()
            .chain(RequestPinToken::iter_exhaustive().map(Self::PinToken))
    }
}

#[derive(Clone, Debug)]
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
            if !matches!(self.pin_auth, PinAuth::PinToken(_)) && options.uv == Some(true) {
                return Some(0x2c);
            }
            if matches!(self.pin_auth, PinAuth::PinNoToken) && options.rk == Some(true) {
                return Some(0x36);
            }
        }
        if let PinAuth::PinToken(
            RequestPinToken::InvalidPermissions | RequestPinToken::InvalidRpId,
        ) = &self.pin_auth
        {
            return Some(0x33);
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

        let is_rk = self
            .options
            .and_then(|options| options.rk)
            .unwrap_or_default();
        let is_successful = self.expected_error().is_none();
        let options = Options {
            inspect_ifs: Some(Box::new(move |ifs| {
                let mut files = list_fs(ifs);
                files.remove_standard();
                files.try_remove_state();
                let n = files.try_remove_keys();
                assert!(n <= 2, "n: {n}, files: {files:?}");
                if is_rk && is_successful {
                    assert_eq!(files.try_remove_rks(), 1, "{files:?}");
                }
                files.assert_empty();
            })),
            ..Default::default()
        };

        virt::run_ctap2_with_options(options, |device| {
            let mut pin_auth = None;
            match &self.pin_auth {
                PinAuth::NoPin => {}
                PinAuth::PinNoToken => {
                    let key_agreement_key = KeyAgreementKey::generate();
                    let shared_secret = get_shared_secret(&device, &key_agreement_key);
                    set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
                }
                PinAuth::PinToken(pin_token) => {
                    let key_agreement_key = KeyAgreementKey::generate();
                    let shared_secret = get_shared_secret(&device, &key_agreement_key);
                    set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
                    let pin_token = get_pin_token(
                        &device,
                        &key_agreement_key,
                        &shared_secret,
                        pin,
                        pin_token.permissions(0x01, 0x04),
                        pin_token.rp_id(rp_id, invalid_rp_id),
                    )
                    .unwrap();
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
                request.extensions = Some(MakeCredentialExtensionsInput {
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

impl Exhaustive for TestMakeCredential {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        exhaustive_struct! {
            pin_auth: PinAuth,
            options: Option<MakeCredentialOptions>,
            valid_pub_key_alg: bool,
            attestation_formats_preference: Option<AttestationFormatsPreference>,
            hmac_secret: bool,
        }
    }
}

#[test]
fn test_make_credential() {
    TestMakeCredential::run_all();
}

#[derive(Clone, Debug)]
struct TestGetAssertion {
    rk: bool,
    allow_list: bool,
    options: Option<GetAssertionOptions>,
    mc_extensions: Option<MakeCredentialExtensionsInput>,
    ga_hmac_secret: bool,
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
        if let Some(options) = self.options {
            if options.up == Some(false) && self.ga_hmac_secret {
                return Some(0x2b);
            }
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
            let key_agreement_key = KeyAgreementKey::generate();
            let shared_secret = get_shared_secret(&device, &key_agreement_key);

            let rp = Rp::new(rp_id);
            let user = User::new(b"id123")
                .name("john.doe")
                .display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            if self.rk {
                request.options = Some(MakeCredentialOptions::default().rk(true));
            }
            request.extensions = self.mc_extensions;
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
            if self.ga_hmac_secret || self.ga_third_party_payment.is_some() {
                let mut extensions = GetAssertionExtensionsInput {
                    third_party_payment: self.ga_third_party_payment,
                    ..Default::default()
                };
                if self.ga_hmac_secret {
                    // TODO: We always set the last byte to 0xff to work around the zero padding
                    // currently used by trussed.
                    let mut salt = [0xff; 32];
                    rand::thread_rng().fill_bytes(&mut salt[..31]);
                    let salt_enc = shared_secret.encrypt(&salt);
                    let salt_auth = shared_secret.authenticate(&salt_enc);
                    extensions.hmac_secret = Some(HmacSecretInput {
                        key_agreement: key_agreement_key.public_key(),
                        salt_enc,
                        salt_auth,
                        pin_protocol: Some(2),
                    });
                }
                request.extensions = Some(extensions);
            }
            request.options = self.options;
            let result = device.exec(request);
            if let Some(error) = self.expected_error() {
                assert_eq!(result, Err(Ctap2Error(error)));
                return;
            }
            let has_extensions =
                self.ga_hmac_secret || self.ga_third_party_payment.unwrap_or_default();
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
            assert_eq!(response.auth_data.ed_flag(), has_extensions,);
            assert_eq!(response.number_of_credentials, None);
            credential.verify_assertion(&response.auth_data, client_data_hash, &response.signature);
            if has_extensions {
                let extensions = response.auth_data.extensions.unwrap();

                if self.ga_hmac_secret {
                    let hmac_secret = extensions.get("hmac-secret").unwrap().as_bytes().unwrap();
                    let output = shared_secret.decrypt(hmac_secret);
                    assert_eq!(output.len(), 32);
                }

                if self.ga_third_party_payment.unwrap_or_default() {
                    let expected = self
                        .mc_extensions
                        .and_then(|e| e.third_party_payment)
                        .unwrap_or_default();
                    assert_eq!(
                        extensions.get("thirdPartyPayment"),
                        Some(&Value::from(expected))
                    );
                }
            } else {
                assert!(response.auth_data.extensions.is_none());
            }
        });
    }
}

impl Exhaustive for TestGetAssertion {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        exhaustive_struct! {
            rk: bool,
            allow_list: bool,
            options: Option<GetAssertionOptions>,
            mc_extensions: Option<MakeCredentialExtensionsInput>,
            ga_hmac_secret: bool,
            ga_third_party_payment: Option<bool>,
        }
    }
}

#[test]
fn test_get_assertion() {
    TestGetAssertion::run_all();
}

fn run_test_get_next_assertion(device: &Ctap2) {
    let rp_id = "example.com";
    // TODO: client data
    let client_data_hash = &[0; 32];

    let rp = Rp::new(rp_id);
    let users = vec![User::new(b"id1"), User::new(b"id2"), User::new(b"id3")];
    let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
    // TODO: test non-discoverable credentials and with allow list
    let mut credentials: Vec<_> = users
        .into_iter()
        .map(|user| {
            let mut request = MakeCredential::new(
                client_data_hash,
                rp.clone(),
                user.clone(),
                pub_key_cred_params.clone(),
            );
            request.options = Some(MakeCredentialOptions::default().rk(true));
            let response = device.exec(request).unwrap();
            response.auth_data.credential.unwrap()
        })
        .collect();

    let credential_ids: BTreeSet<_> = credentials
        .iter()
        .map(|credential| &credential.id)
        .collect();
    assert_eq!(credential_ids.len(), credentials.len());

    let request = GetAssertion::new(rp_id, client_data_hash);
    let response = device.exec(request).unwrap();
    assert_eq!(response.credential.ty, "public-key");
    assert_eq!(response.auth_data.credential, None);
    assert_eq!(response.number_of_credentials, Some(credentials.len()));
    let i = credentials
        .iter()
        .position(|credential| credential.id == response.credential.id)
        .unwrap();
    let credential = credentials.remove(i);
    credential.verify_assertion(&response.auth_data, client_data_hash, &response.signature);
    assert!(response.auth_data.extensions.is_none());

    let response = device.exec(GetNextAssertion).unwrap();
    assert_eq!(response.credential.ty, "public-key");
    assert_eq!(response.auth_data.credential, None);
    // TODO: fix number_of_credentials
    // assert_eq!(response.number_of_credentials, Some(credentials.len()));
    assert_eq!(response.number_of_credentials, None);
    let i = credentials
        .iter()
        .position(|credential| credential.id == response.credential.id)
        .unwrap();
    let credential = credentials.remove(i);
    credential.verify_assertion(&response.auth_data, client_data_hash, &response.signature);
    assert!(response.auth_data.extensions.is_none());

    let response = device.exec(GetNextAssertion).unwrap();
    assert_eq!(response.credential.ty, "public-key");
    assert_eq!(response.auth_data.credential, None);
    assert_eq!(response.number_of_credentials, None);
    let i = credentials
        .iter()
        .position(|credential| credential.id == response.credential.id)
        .unwrap();
    let credential = credentials.remove(i);
    credential.verify_assertion(&response.auth_data, client_data_hash, &response.signature);
    assert!(response.auth_data.extensions.is_none());

    assert_eq!(credentials, Vec::new());

    let error = device.exec(GetNextAssertion).unwrap_err();
    assert_eq!(error, Ctap2Error(0x30));
}

#[test]
fn test_get_next_assertion() {
    let options = Options {
        inspect_ifs: Some(Box::new(move |ifs| {
            let mut files = list_fs(ifs);
            files.remove_standard();
            files.remove_state();
            assert_eq!(files.try_remove_keys(), 4);
            assert_eq!(files.try_remove_rks(), 3);
            files.assert_empty();
        })),
        ..Default::default()
    };

    virt::run_ctap2_with_options(options, |device| {
        run_test_get_next_assertion(&device);
    });
}

#[test]
fn test_get_next_assertion_multi_rp() {
    let client_data_hash = b"";
    let options = Options {
        inspect_ifs: Some(Box::new(move |ifs| {
            let mut files = list_fs(ifs);
            files.remove_standard();
            files.remove_state();
            assert_eq!(files.try_remove_keys(), 10);
            assert_eq!(files.try_remove_rks(), 9);
            files.assert_empty();
        })),
        ..Default::default()
    };

    virt::run_ctap2_with_options(options, |device| {
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        for rp in ["test.com", "something.dev", "else.foobar"] {
            for user in [b"john.doe", b"jane.doe"] {
                let mut request = MakeCredential::new(
                    client_data_hash,
                    Rp::new(rp),
                    User::new(user),
                    pub_key_cred_params.clone(),
                );
                request.options = Some(MakeCredentialOptions::default().rk(true));
                device.exec(request).unwrap();
            }
        }
        run_test_get_next_assertion(&device);
    });
}

#[derive(Clone, Debug)]
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
            set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

            let pin_token =
                get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None)
                    .unwrap();
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
                request.extensions = Some(MakeCredentialExtensionsInput {
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
                get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x04, None)
                    .unwrap();
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
            )
            .unwrap();
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

impl Exhaustive for TestListCredentials {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        exhaustive_struct! {
            pin_token_rp_id: bool,
            third_party_payment: Option<bool>,
        }
    }
}

#[test]
fn test_list_credentials() {
    TestListCredentials::run_all();
}
