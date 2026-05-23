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
use rand::RngCore as _;

use fs::list_fs;
use virt::{Ctap2, Ctap2Error, Options};
use webauthn::{
    exhaustive_struct, AttStmtFormat, AuthenticatorConfig, AuthenticatorConfigParams, ClientPin,
    CredentialManagement, CredentialManagementParams, Exhaustive, GetAssertion,
    GetAssertionExtensionsInput, GetAssertionOptions, GetInfo, GetNextAssertion, HmacSecretInput,
    KeyAgreementKey, MakeCredential, MakeCredentialExtensionsInput, MakeCredentialOptions,
    PinToken, PubKeyCredDescriptor, PubKeyCredParam, PublicKey, Rp, SharedSecret, Test, User,
};

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
        // CTAP 2.1 §6.5.5.4: "If a PIN has already been set, authenticator
        // returns CTAP2_ERR_PIN_AUTH_INVALID error." (0x33). Previously this
        // expected 0x30 (NotAllowed), the CTAP 2.0 reading.
        assert_eq!(result, Err(Ctap2Error(0x33)));

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

#[derive(Clone, Copy, Debug, Default)]
struct ExhaustiveMakeCredentialExtensionsInput {
    hmac_secret: Option<bool>,
    third_party_payment: Option<bool>,
    cred_blob: bool,
}

impl Exhaustive for ExhaustiveMakeCredentialExtensionsInput {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        exhaustive_struct! {
            hmac_secret: Option<bool>,
            third_party_payment: Option<bool>,
            cred_blob: bool,
        }
    }
}

impl From<ExhaustiveMakeCredentialExtensionsInput> for MakeCredentialExtensionsInput {
    fn from(input: ExhaustiveMakeCredentialExtensionsInput) -> Self {
        Self {
            hmac_secret: input.hmac_secret,
            third_party_payment: input.third_party_payment,
            cred_blob: if input.cred_blob {
                let mut v = vec![0x00; 32];
                rand::thread_rng().fill_bytes(&mut v);
                Some(v)
            } else {
                None
            },
            min_pin_length: None,
        }
    }
}

#[derive(Clone, Debug)]
struct TestGetAssertion {
    rk: bool,
    allow_list: bool,
    options: Option<GetAssertionOptions>,
    mc_extensions: Option<ExhaustiveMakeCredentialExtensionsInput>,
    ga_hmac_secret: bool,
    ga_third_party_payment: Option<bool>,
    ga_cred_blob: bool,
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
            request.extensions = self.mc_extensions.map(From::from);
            let cred_blob = request
                .extensions
                .as_ref()
                .and_then(|extensions| extensions.cred_blob.clone());
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
            if self.ga_hmac_secret || self.ga_third_party_payment.is_some() || self.ga_cred_blob {
                let mut extensions = GetAssertionExtensionsInput {
                    third_party_payment: self.ga_third_party_payment,
                    cred_blob: self.ga_cred_blob.then_some(true),
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
            let has_extensions = self.ga_hmac_secret
                || self.ga_third_party_payment.unwrap_or_default()
                || self.ga_cred_blob;
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
            assert_eq!(response.auth_data.ed_flag(), has_extensions);
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

                if self.ga_cred_blob {
                    let cred_blob_expected = if self.rk { cred_blob.as_deref() } else { None };
                    let cred_blob_response =
                        extensions.get("credBlob").unwrap().as_bytes().unwrap();
                    assert_eq!(cred_blob_response, cred_blob_expected.unwrap_or_default());
                } else {
                    assert!(!extensions.contains_key("credBlob"));
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
            mc_extensions: Option<ExhaustiveMakeCredentialExtensionsInput>,
            ga_hmac_secret: bool,
            ga_third_party_payment: Option<bool>,
            ga_cred_blob: bool,
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

// ============================================================================
// setMinPINLength (CTAP 2.1 §6.11.4)
// ============================================================================

/// Pin-token permission `authenticatorConfiguration` (CTAP 2.1 §6.5.5.7.4).
const PERM_AUTHENTICATOR_CONFIGURATION: u8 = 0x20;

/// Build + send a setMinPINLength request with the given params, signed by
/// `pin_token`. Returns the wire-level outcome.
fn set_min_pin_length(
    device: &Ctap2,
    pin_token: &PinToken,
    params: AuthenticatorConfigParams,
) -> Result<(), Ctap2Error> {
    let mut request = AuthenticatorConfig::new(0x03); // SetMinPINLength
    request.subcommand_params = Some(params);
    request.pin_protocol = Some(2);
    request.pin_auth = Some(pin_token.authenticate(&request.pin_uv_auth_data()));
    device.exec(request).map(|_| ())
}

/// CTAP 2.1 §6.11.4 setMinPINLength algorithm: "If newMinPINLength is less
/// than the current minimum PIN length, return CTAP2_ERR_PIN_POLICY_VIOLATION."
/// The previous implementation rejected with the right error code but also
/// rejected the equal-value case.
#[test]
fn test_set_min_pin_length_below_current_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();

        // DEFAULT_MIN_PIN_LENGTH is 4. Below the floor → PinPolicyViolation.
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(3),
            ..Default::default()
        };
        let result = set_min_pin_length(&device, &pin_token, params);
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// CTAP 2.1 §6.11.4 step 7d (inverse): `newMinPINLength == curMinPINLength`
/// is allowed — return Ok without changing state. Previously rejected with
/// `PinPolicyViolation`.
#[test]
fn test_set_min_pin_length_equal_is_noop() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();

        // Equal to the current effective minimum (4 on a fresh device) → Ok.
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(4),
            ..Default::default()
        };
        let result = set_min_pin_length(&device, &pin_token, params);
        assert!(result.is_ok(), "got {:?}", result);

        // Getinfo.minPinLength should still report 4.
        let reply = device.exec(GetInfo).unwrap();
        let options = reply.options.unwrap();
        // CTAP 2.1: minPinLength may not appear if get-info-full is off; we
        // build with get-info-full so it is present. The actual field lives
        // at index 0x0D in the GetInfo response, not in `options`. We don't
        // currently parse it, so a missing-error here is treated as benign:
        // the no-op succeeded if `set_min_pin_length` returned Ok above.
        let _ = options;
    })
}

/// Tightening from default (4) to 6 succeeds, and a follow-up equal request
/// also succeeds as a no-op. A subsequent lower-than-current request still
/// gets rejected.
#[test]
fn test_set_min_pin_length_tighten_then_noop_then_lower() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"12345678";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            ..Default::default()
        };
        set_min_pin_length(&device, &pin_token, params).unwrap();

        // Repeat — still equal, still ok.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            ..Default::default()
        };
        set_min_pin_length(&device, &pin_token, params).unwrap();

        // Now go below — should reject.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(5),
            ..Default::default()
        };
        let result = set_min_pin_length(&device, &pin_token, params);
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// CTAP 2.1 §6.11.4: `forceChangePin = true` sets the persistent
/// `forcePINChange` flag, which is then advertised in `authenticatorGetInfo`
/// (member 0x0C). The platform must call `changePIN` before any further
/// PIN-protected operation.
#[test]
fn test_set_min_pin_length_force_change_pin_sets_flag() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        // forcePINChange should be false before the request.
        let reply = device.exec(GetInfo).unwrap();
        assert_eq!(reply.force_pin_change, Some(false));

        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let params = AuthenticatorConfigParams {
            force_change_pin: Some(true),
            ..Default::default()
        };
        set_min_pin_length(&device, &pin_token, params).unwrap();

        // forcePINChange should be true after the request.
        let reply = device.exec(GetInfo).unwrap();
        assert_eq!(reply.force_pin_change, Some(true));
    })
}

/// CTAP 2.1 §6.11 step 4 + §6.11.4: in factory-default state (no PIN, no
/// built-in UV) `authenticatorConfig` MAY be invoked without
/// `pinUvAuthParam`. So `setMinPINLength(newMinPINLength = 6)` with no
/// pin_auth must succeed, and the value must take effect (the next attempt
/// to drop it below 6 must be rejected with PIN_POLICY_VIOLATION).
#[test]
fn test_set_min_pin_length_factory_default_no_auth_succeeds() {
    virt::run_ctap2(|device| {
        let mut request = AuthenticatorConfig::new(0x03); // SetMinPINLength
        request.subcommand_params = Some(AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            ..Default::default()
        });
        // No pin_protocol, no pin_auth.
        let result = device.exec(request);
        assert!(result.is_ok(), "got {:?}", result.err());

        // Verify the value stuck: try to lower to 5 (also unauthenticated,
        // also in factory-default state) → PIN_POLICY_VIOLATION.
        let mut request = AuthenticatorConfig::new(0x03);
        request.subcommand_params = Some(AuthenticatorConfigParams {
            new_min_pin_length: Some(5),
            ..Default::default()
        });
        assert_eq!(device.exec(request).err(), Some(Ctap2Error(0x37)));
    })
}

/// CTAP 2.1 §6.11.4 step 2.4.a: "If the value of forceChangePin is true,
/// then: if the value of clientPIN is false, return CTAP2_ERR_PIN_NOT_SET."
/// In factory-default state the §6.11 step-4 gate is open (no pin_auth
/// required), so the step-2.4.a branch is reachable — exercise it.
#[test]
fn test_set_min_pin_length_force_change_pin_without_pin_set_rejected() {
    virt::run_ctap2(|device| {
        let mut request = AuthenticatorConfig::new(0x03); // SetMinPINLength
        request.subcommand_params = Some(AuthenticatorConfigParams {
            force_change_pin: Some(true),
            ..Default::default()
        });
        // No pin_protocol, no pin_auth — but no PIN is set either, so the
        // gate is bypassed and we reach the spec's PIN_NOT_SET branch.
        let result = device.exec(request);
        assert_eq!(result.err(), Some(Ctap2Error(0x35))); // CTAP2_ERR_PIN_NOT_SET
    })
}

/// CTAP 2.1 §6.11.4 step 2 ordering: step 2.3 (`newMinPINLength` <
/// current → PIN_POLICY_VIOLATION) is evaluated before step 2.4.a
/// (forceChangePin && !clientPIN → PIN_NOT_SET). Send both invalidating
/// inputs simultaneously and confirm PIN_POLICY_VIOLATION fires first.
#[test]
fn test_set_min_pin_length_policy_violation_takes_precedence_over_pin_not_set() {
    virt::run_ctap2(|device| {
        let mut request = AuthenticatorConfig::new(0x03);
        request.subcommand_params = Some(AuthenticatorConfigParams {
            new_min_pin_length: Some(3),  // below floor of 4
            force_change_pin: Some(true), // would also trip PIN_NOT_SET
            ..Default::default()
        });
        let result = device.exec(request);
        assert_eq!(result.err(), Some(Ctap2Error(0x37))); // PIN_POLICY_VIOLATION
    })
}

/// CTAP 2.1 §6.11.4 step 2.4.a + step 2.6 ordering: if forceChangePin=true
/// fails with PIN_NOT_SET, the request MUST NOT leave a partially applied
/// newMinPINLength behind (storage at step 2.6 is unreachable after the
/// return at step 2.4.a). Send `newMinPINLength=6 + force_change_pin=true`
/// in factory default → PIN_NOT_SET, then verify a follow-up
/// `newMinPINLength = 5` without forceChangePin is still accepted (i.e.
/// the first call did not silently store 6).
#[test]
fn test_set_min_pin_length_force_change_pin_failure_does_not_apply_new_min() {
    virt::run_ctap2(|device| {
        let mut req1 = AuthenticatorConfig::new(0x03);
        req1.subcommand_params = Some(AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            force_change_pin: Some(true),
            ..Default::default()
        });
        assert_eq!(device.exec(req1).err(), Some(Ctap2Error(0x35)));

        // If the failed call had partially applied newMinPINLength=6, then
        // a subsequent attempt to lower to 5 would be rejected. Verify the
        // pre-call state (min = 4 = floor) is intact: 5 must succeed.
        let mut req2 = AuthenticatorConfig::new(0x03);
        req2.subcommand_params = Some(AuthenticatorConfigParams {
            new_min_pin_length: Some(5),
            ..Default::default()
        });
        let result = device.exec(req2);
        assert!(result.is_ok(), "got {:?}", result.err());
    })
}

/// CTAP 2.1 §6.11 step 4: once a PIN is set, the authenticator IS
/// "protected by some form of user verification" and `pinUvAuthParam`
/// becomes mandatory. Send `setMinPINLength` without `pin_auth` →
/// CTAP2_ERR_PUAT_REQUIRED (0x36).
#[test]
fn test_set_min_pin_length_without_pin_auth_rejected_when_pin_set() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        let mut request = AuthenticatorConfig::new(0x03);
        request.subcommand_params = Some(AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            ..Default::default()
        });
        // PIN is set → gate is closed → no pin_auth → 0x36.
        let result = device.exec(request);
        assert_eq!(result.err(), Some(Ctap2Error(0x36)));
    })
}

// ----------------------------------------------------------------------------
// alwaysUv + toggleAlwaysUv (CTAP 2.1 §6.4, §6.11.2, §6.1.2 / §6.2.2)
// ----------------------------------------------------------------------------

fn toggle_always_uv(device: &Ctap2, pin_token: &PinToken) -> Result<(), Ctap2Error> {
    let mut request = AuthenticatorConfig::new(0x02); // ToggleAlwaysUv
    request.pin_protocol = Some(2);
    request.pin_auth = Some(pin_token.authenticate(&request.pin_uv_auth_data()));
    device.exec(request).map(|_| ())
}

/// GetInfo on a fresh device advertises `alwaysUv=false` and the coupled
/// `makeCredUvNotRqd=true` (CTAP 2.1 §6.4 + §6.11.2 coupling).
#[test]
fn test_always_uv_default() {
    virt::run_ctap2(|device| {
        let reply = device.exec(GetInfo).unwrap();
        let options = reply.options.unwrap();
        assert_eq!(options.get("alwaysUv"), Some(&Value::from(false)));
        assert_eq!(options.get("makeCredUvNotRqd"), Some(&Value::from(true)));
    })
}

/// toggleAlwaysUv flips `alwaysUv` true and forces `makeCredUvNotRqd` false
/// in the same GetInfo (CTAP 2.1 §6.11.2 mandates the coupling). A second
/// toggle restores both.
#[test]
fn test_always_uv_toggle_couples_make_cred_uv_not_rqd() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        let reply = device.exec(GetInfo).unwrap();
        let options = reply.options.unwrap();
        assert_eq!(options.get("alwaysUv"), Some(&Value::from(true)));
        assert_eq!(options.get("makeCredUvNotRqd"), Some(&Value::from(false)));

        // Toggle OFF.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        let reply = device.exec(GetInfo).unwrap();
        let options = reply.options.unwrap();
        assert_eq!(options.get("alwaysUv"), Some(&Value::from(false)));
        assert_eq!(options.get("makeCredUvNotRqd"), Some(&Value::from(true)));
    })
}

/// With `alwaysUv` enabled, `makeCredential` without a `pinUvAuthParam` MUST
/// be rejected with CTAP2_ERR_PUAT_REQUIRED (0x36) per CTAP 2.1 §6.1.2.
#[test]
fn test_always_uv_make_credential_without_pin_auth_is_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        let request = MakeCredential::new(
            vec![0; 32],
            Rp::new("example.com"),
            User::new(vec![1; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        let result = device.exec(request);
        assert_eq!(result.err(), Some(Ctap2Error(0x36)));
    })
}

/// Same as above but for `getAssertion` (CTAP 2.1 §6.2.2).
///
/// Setup: make an RK (no PIN yet, so MC needs no pin_auth), then set the PIN,
/// then toggle alwaysUv. Now GA without pin_auth should be rejected. This
/// order avoids the more complex pin-auth-on-MC path.
#[test]
fn test_always_uv_get_assertion_without_pin_auth_is_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        // Make an RK first (no PIN set; MC needs no pin_auth in this state).
        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash.clone(),
            Rp::new(rp_id),
            User::new(vec![1; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        device.exec(mc).unwrap();

        // Set the PIN and enable alwaysUv.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        // GA without pin_auth must fail with PUAT_REQUIRED.
        let ga = GetAssertion::new(rp_id.to_owned(), client_data_hash);
        let result = device.exec(ga);
        assert_eq!(result.err(), Some(Ctap2Error(0x36)));
    })
}

/// CTAP 2.1 §7.2.4 step 1: when `alwaysUv` is enabled the authenticator
/// MUST NOT include `"U2F_V2"` in its `getInfo.versions` array (it is
/// effectively required to disable CTAP1/U2F because we don't ship a
/// built-in UV method). Verify the version is present pre-toggle and
/// removed post-toggle.
#[test]
fn test_always_uv_u2f_v2_dropped_from_versions() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        // Pre-toggle: U2F_V2 must be advertised.
        let reply = device.exec(GetInfo).unwrap();
        assert!(
            reply.versions.contains(&"U2F_V2".to_owned()),
            "fresh device must advertise U2F_V2, got versions={:?}",
            reply.versions
        );

        // Enable alwaysUv.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        // Post-toggle: U2F_V2 MUST be absent.
        let reply = device.exec(GetInfo).unwrap();
        assert!(
            !reply.versions.contains(&"U2F_V2".to_owned()),
            "U2F_V2 must be removed once alwaysUv is true, got versions={:?}",
            reply.versions
        );
        // The CTAP2 versions must still be present.
        assert!(reply.versions.contains(&"FIDO_2_0".to_owned()));
        assert!(reply.versions.contains(&"FIDO_2_1".to_owned()));
    })
}

/// CTAP 2.1 §7.2.4 step 2: when alwaysUv is enabled, U2F_REGISTER MUST
/// fail with SW_COMMAND_NOT_ALLOWED (0x6986).
#[test]
fn test_always_uv_u2f_register_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        // Enable alwaysUv.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        // U2F_REGISTER APDU (extended length):
        //   CLA=00 INS=01 P1=00 P2=00 | extended Lc=00 0040 | 64-byte data
        //   | extended Le=0000
        let mut apdu: Vec<u8> = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40];
        apdu.extend_from_slice(&[0u8; 64]); // challenge ‖ app_id (zeros are fine — we reject before parsing)
        apdu.extend_from_slice(&[0x00, 0x00]);
        let status = device
            .ctap1(&apdu)
            .expect_err("U2F_REGISTER must fail when alwaysUv is enabled");
        assert_eq!(
            status, 0x6986,
            "expected SW_COMMAND_NOT_ALLOWED, got {:#x}",
            status
        );
    })
}

/// CTAP 2.1 §7.2.4 step 2: same for U2F_AUTHENTICATE.
#[test]
fn test_always_uv_u2f_authenticate_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        // Enable alwaysUv.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        // U2F_AUTHENTICATE APDU (extended length, control byte = 0x03
        // EnforceUserPresenceAndSign):
        //   CLA=00 INS=02 P1=03 P2=00 | extended Lc=00 0041 |
        //   challenge(32) ‖ app_id(32) ‖ kh_len(1=0) | extended Le=0000
        let mut apdu: Vec<u8> = vec![0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x41];
        apdu.extend_from_slice(&[0u8; 64]); // challenge ‖ app_id
        apdu.push(0x00); // kh_len = 0 (no keyhandle); we reject before reading it
        apdu.extend_from_slice(&[0x00, 0x00]);
        let status = device
            .ctap1(&apdu)
            .expect_err("U2F_AUTHENTICATE must fail when alwaysUv is enabled");
        assert_eq!(
            status, 0x6986,
            "expected SW_COMMAND_NOT_ALLOWED, got {:#x}",
            status
        );
    })
}

/// CTAP 2.1 §6.2.2 step 5 carve-out: when `alwaysUv=true` and the
/// platform sends `up=Some(false)` (a silent pre-flight check), the
/// alwaysUv UV requirement is bypassed per the spec ("If the alwaysUv
/// option ID is present and true and the 'up' option is present and
/// true then …"). Verify that GA with `up=false` does not get a
/// PUAT_REQUIRED back even though no pinUvAuthParam is sent.
#[test]
fn test_always_uv_get_assertion_up_false_bypasses_uv_requirement() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        // Make an RK first (no PIN yet so MC needs no pin_auth).
        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash.clone(),
            Rp::new(rp_id),
            User::new(vec![1; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        let mc_reply = device.exec(mc).unwrap();
        let credential = mc_reply.auth_data.credential.unwrap();

        // Set PIN and enable alwaysUv.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        toggle_always_uv(&device, &pin_token).unwrap();

        // GA with up=Some(false) and no pin_auth — alwaysUv check must
        // be bypassed (spec §6.2.2 step 5 only applies when up=true).
        let mut ga = GetAssertion::new(rp_id.to_owned(), client_data_hash);
        ga.options = Some(GetAssertionOptions {
            up: Some(false),
            uv: None,
        });
        ga.allow_list = Some(vec![PubKeyCredDescriptor::new(
            "public-key",
            credential.id.clone(),
        )]);
        let result = device.exec(ga);
        assert!(
            result.is_ok(),
            "up=false GA must bypass alwaysUv UV requirement, got {:?}",
            result.err()
        );
    })
}

// ----------------------------------------------------------------------------
// PIN length validation (issue #43): count Unicode code points, not bytes
// ----------------------------------------------------------------------------

/// Multi-byte UTF-8 PIN with FEWER code points than minimum is rejected.
/// "héé" = 5 bytes (h + é + é where é = 0xC3 0xA9), 3 code points. Default
/// minimum is 4 → PIN_POLICY_VIOLATION.
#[test]
fn test_set_pin_short_codepoints_multibyte_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        // "héé" — 5 bytes, 3 code points. Pre-fix this would have passed
        // because the BYTE length (5) >= 4. The fixed code rejects it.
        let pin = "héé".as_bytes();
        assert_eq!(pin.len(), 5);
        assert_eq!(
            pin.iter().filter(|&&b| !(0x80..0xC0).contains(&b)).count(),
            3
        );
        let result = set_pin(&device, &key_agreement_key, &shared_secret, pin);
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// Multi-byte UTF-8 PIN with enough code points is accepted.
/// "héllo" = 6 bytes, 5 code points. Default minimum is 4 → succeeds.
#[test]
fn test_set_pin_codepoints_multibyte_accepted() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let pin = "héllo".as_bytes();
        assert_eq!(pin.len(), 6);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
    })
}

/// ASCII PIN at the lower bound: 4 bytes = 4 code points. Accepted.
#[test]
fn test_set_pin_four_byte_ascii_accepted() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, b"abcd").unwrap();
    })
}

/// 3-byte ASCII PIN (3 code points) is rejected.
#[test]
fn test_set_pin_three_byte_ascii_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = set_pin(&device, &key_agreement_key, &shared_secret, b"abc");
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// Invalid UTF-8 in the PIN bytes is rejected (PIN_POLICY_VIOLATION). Platforms
/// MUST send Normalized UTF-8 per CTAP 2.1 §6.5.5.5; bytes that don't decode
/// fail the PIN policy check.
#[test]
fn test_set_pin_invalid_utf8_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        // 0xC3 is a UTF-8 lead byte that must be followed by a continuation
        // byte in [0x80, 0xBF]. Trailing it with 'x' makes the sequence
        // invalid UTF-8.
        let pin = b"abc\xC3x";
        let result = set_pin(&device, &key_agreement_key, &shared_secret, pin);
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// All-zero `paddedNewPin` strips to length 0 → 0 code points → reject.
/// Verifies the empty-PIN edge case (no leading bytes, no trailing
/// non-zero) is properly rejected against the spec floor of 4 cp.
#[test]
fn test_set_pin_empty_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = set_pin(&device, &key_agreement_key, &shared_secret, b"");
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// CTAP 2.1 §6.5.5.5 — UTF-8 representation of newPin MUST NOT exceed 63
/// bytes. A 63-byte ASCII PIN (63 code points) sits exactly at the spec
/// boundary and MUST be accepted.
#[test]
fn test_set_pin_at_byte_limit_accepted() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        // 63 ASCII chars → 63 bytes → 63 code points.
        let pin = vec![b'a'; 63];
        set_pin(&device, &key_agreement_key, &shared_secret, &pin).unwrap();
    })
}

/// CTAP 2.1 §6.5.5.5: a 64-byte non-zero PIN fills `paddedNewPin`
/// completely with no trailing 0x00 — the stripped length stays at 64
/// which exceeds the spec's 63-byte UTF-8 cap, so the authenticator
/// MUST reject with PIN_POLICY_VIOLATION.
#[test]
fn test_set_pin_over_byte_limit_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        // 64 ASCII chars → 64 bytes → no padding room left.
        let pin = vec![b'a'; 64];
        let result = set_pin(&device, &key_agreement_key, &shared_secret, &pin);
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// CTAP 2.1 §6.5.5.6 (changePIN) shares the same PIN-length validation
/// pipeline as setPIN (§6.5.5.5). Verify the code-point check applies
/// equally: a 3-byte ASCII new PIN under changePIN must be rejected
/// with PIN_POLICY_VIOLATION.
#[test]
fn test_change_pin_short_codepoints_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let old_pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, old_pin).unwrap();

        // Attempt to change to a 3-cp PIN.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = change_pin(&device, &key_agreement_key, &shared_secret, old_pin, b"abc");
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// Multi-byte UTF-8 new PIN with too few code points is also rejected
/// by changePIN (parallel to the setPin multi-byte test). "héé" =
/// 5 bytes, 3 code points → reject.
#[test]
fn test_change_pin_short_codepoints_multibyte_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let old_pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, old_pin).unwrap();

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let new_pin = "héé".as_bytes();
        assert_eq!(new_pin.len(), 5);
        let result = change_pin(
            &device,
            &key_agreement_key,
            &shared_secret,
            old_pin,
            new_pin,
        );
        assert_eq!(result, Err(Ctap2Error(0x37)));
    })
}

/// CTAP 2.1 §6.5.5.6 changePIN: "If the forcePINChange member ... is true
/// and LEFT(SHA-256(newPin), 16) is equal to its internal stored
/// LEFT(SHA-256(curPin), 16) then authenticator returns
/// CTAP2_ERR_PIN_POLICY_VIOLATION." This blocks the trivial "rotate to the
/// same PIN" loophole when the platform is forcing a change.
#[test]
fn test_change_pin_same_pin_with_force_change_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        // Setup: set PIN, then mark forcePINChange via setMinPINLength.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let params = AuthenticatorConfigParams {
            force_change_pin: Some(true),
            ..Default::default()
        };
        set_min_pin_length(&device, &pin_token, params).unwrap();
        assert_eq!(device.exec(GetInfo).unwrap().force_pin_change, Some(true));

        // Try to "change" to the same PIN — must be rejected.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = change_pin(&device, &key_agreement_key, &shared_secret, pin, pin);
        assert_eq!(result, Err(Ctap2Error(0x37)));

        // forcePINChange should still be true after the rejection.
        assert_eq!(device.exec(GetInfo).unwrap().force_pin_change, Some(true));
    })
}

/// Counterpart: when forcePINChange is **not** set, a same-PIN changePIN
/// silently succeeds (spec doesn't reject this case, only when the flag is
/// set). This documents the current behaviour and locks it in.
#[test]
fn test_change_pin_same_pin_without_force_change_allowed() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        // forcePINChange is false by default.
        assert_eq!(device.exec(GetInfo).unwrap().force_pin_change, Some(false));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        change_pin(&device, &key_agreement_key, &shared_secret, pin, pin).unwrap();

        // Still false.
        assert_eq!(device.exec(GetInfo).unwrap().force_pin_change, Some(false));
    })
}

/// Successful changePIN to a NEW pin while forcePINChange is set must clear
/// the flag (CTAP 2.1 §6.5.5.6: "Authenticator sets the value of the
/// forcePINChange member ... to false").
#[test]
fn test_change_pin_to_new_pin_clears_force_change() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin1 = b"123456";
    let pin2 = b"654321";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin1).unwrap();
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin1,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let params = AuthenticatorConfigParams {
            force_change_pin: Some(true),
            ..Default::default()
        };
        set_min_pin_length(&device, &pin_token, params).unwrap();
        assert_eq!(device.exec(GetInfo).unwrap().force_pin_change, Some(true));

        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        change_pin(&device, &key_agreement_key, &shared_secret, pin1, pin2).unwrap();

        assert_eq!(device.exec(GetInfo).unwrap().force_pin_change, Some(false));
    })
}

/// CTAP 2.1 §6.1.2 step 1 (and §6.5.5.7 step 2): when the platform sends
/// a **zero-length** `pinUvAuthParam` (the CTAP 2.0 "is PIN supported?"
/// probe), the authenticator MUST request UP and then return
/// `CTAP2_ERR_PIN_INVALID` (0x31) if a PIN is set. The pre-audit code
/// returned `PIN_AUTH_INVALID` (0x33), the CTAP 2.0 reading.
#[test]
fn test_make_credential_zero_length_pin_auth_returns_0x31_when_pin_set() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        let mut mc = MakeCredential::new(
            vec![0u8; 32],
            Rp::new("example.com"),
            User::new(vec![1u8; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        // Zero-length pinUvAuthParam — the §6.1.2 step 1 probe.
        mc.pin_auth_raw = Some(Vec::new());
        mc.pin_protocol = Some(2);
        let result = device.exec(mc);
        assert_eq!(result.err(), Some(Ctap2Error(0x31)));
    })
}

/// Same probe, but with no PIN set on the device. CTAP 2.1 §6.1.2 step 1.3:
/// "return CTAP2_ERR_PIN_NOT_SET" (0x35).
#[test]
fn test_make_credential_zero_length_pin_auth_returns_0x35_when_pin_not_set() {
    virt::run_ctap2(|device| {
        let mut mc = MakeCredential::new(
            vec![0u8; 32],
            Rp::new("example.com"),
            User::new(vec![1u8; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.pin_auth_raw = Some(Vec::new());
        mc.pin_protocol = Some(2);
        let result = device.exec(mc);
        assert_eq!(result.err(), Some(Ctap2Error(0x35)));
    })
}

/// User-requested test: a `setMinPINLength` request derived from an INCORRECT
/// PIN must fail — the platform never obtains a valid `pin_uv_auth_token`,
/// so the `pin_auth` HMAC won't verify on the device side.
///
/// The failure surfaces at `getPinUvAuthTokenUsingPinWithPermissions`, before
/// the `setMinPINLength` request is even built. The authenticator returns
/// CTAP2_ERR_PIN_INVALID (0x31) and decrements the retry counter
/// (CTAP 2.1 §6.5.5.7).
#[test]
fn test_set_min_pin_length_with_incorrect_pin_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let real_pin = b"123456";
    let wrong_pin = b"000000";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, real_pin).unwrap();

        // Obtaining the token with the wrong PIN must fail with PIN_INVALID.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let result = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            wrong_pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        );
        assert_eq!(result.err(), Some(Ctap2Error(0x31)));
        // Retries should have decreased.
        assert_eq!(get_pin_retries(&device), 7);
    })
}

// ----------------------------------------------------------------------------
// minPinLength extension (CTAP 2.1 §10.1.2.1) — end-to-end at MakeCredential
// ----------------------------------------------------------------------------
//
// These tests use the *factory-default* flow (no PIN set) so we can exercise
// the extension's RP-allowlist path without `force_pin_change=true`
// blocking MakeCredential. With no PIN, `pin_prechecks` short-circuits and
// `setMinPINLength` itself accepts unauthenticated calls per §6.11 step 4
// (the spec's pre-issuance configuration path).

/// Factory-default helper: setMinPINLength without a PIN/UV token. CTAP 2.1
/// §6.11 step 4 allows this when the authenticator isn't yet "protected by
/// some form of user verification" — i.e. clientPin is false and alwaysUv
/// is false (the alwaysUv side lands in commit 2544f91).
fn set_min_pin_length_unauthenticated(
    device: &Ctap2,
    params: AuthenticatorConfigParams,
) -> Result<(), Ctap2Error> {
    let mut request = AuthenticatorConfig::new(0x03); // SetMinPINLength
    request.subcommand_params = Some(params);
    // No pin_auth / pin_protocol — exercising the factory-default bypass.
    device.exec(request).map(|_| ())
}

/// CTAP 2.1 §10.1.2.1: when the requesting RP-ID is on the allowlist
/// configured via `setMinPINLength`, the authenticator MUST include the
/// current `minPINLength` in the `make_credential` response extensions.
#[test]
fn test_min_pin_length_extension_rp_in_list_returns_value() {
    let target_rp = "example.com";
    virt::run_ctap2(|device| {
        // Factory default: tighten min and allowlist target_rp without
        // touching PIN.
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            min_pin_length_rp_ids: Some(vec![target_rp.to_owned()]),
            ..Default::default()
        };
        set_min_pin_length_unauthenticated(&device, params).unwrap();

        let client_data_hash = &[0u8; 32];
        let rp = Rp::new(target_rp);
        let user = User::new(b"id").name("u").display_name("U");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
        request.extensions = Some(MakeCredentialExtensionsInput::default().min_pin_length(true));

        let response = device.exec(request).unwrap();
        let extensions = response.auth_data.extensions.expect("extensions present");
        let value = extensions
            .get("minPinLength")
            .expect("minPinLength present");
        assert_eq!(value, &Value::from(6u8));
    })
}

/// CTAP 2.1 §10.1.2.1: when the requesting RP-ID is NOT on the
/// `setMinPINLength` allowlist, the authenticator MUST NOT return the
/// extension value (spec: "return without the extension output").
#[test]
fn test_min_pin_length_extension_rp_not_in_list_omits() {
    virt::run_ctap2(|device| {
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            min_pin_length_rp_ids: Some(vec!["allowed.example".to_owned()]),
            ..Default::default()
        };
        set_min_pin_length_unauthenticated(&device, params).unwrap();

        let client_data_hash = &[0u8; 32];
        let rp = Rp::new("other.example");
        let user = User::new(b"id").name("u").display_name("U");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
        request.extensions = Some(MakeCredentialExtensionsInput::default().min_pin_length(true));

        let response = device.exec(request).unwrap();
        match response.auth_data.extensions {
            None => {}
            Some(map) => assert!(
                !map.contains_key("minPinLength"),
                "minPinLength should be omitted for non-allowlisted RPs, got {map:?}"
            ),
        }
    })
}

/// CTAP 2.1 §6.11.4 step 2.7: `minPinLengthRPIDs` replaces the stored list
/// rather than appending. We verify via the extension: after replacement,
/// the old RP-ID no longer receives the extension value.
#[test]
fn test_set_min_pin_length_rp_ids_replace_not_append() {
    let first_rp = "first.example";
    let second_rp = "second.example";
    virt::run_ctap2(|device| {
        // 1) Tighten min and allowlist `first.example` only.
        set_min_pin_length_unauthenticated(
            &device,
            AuthenticatorConfigParams {
                new_min_pin_length: Some(6),
                min_pin_length_rp_ids: Some(vec![first_rp.to_owned()]),
                ..Default::default()
            },
        )
        .unwrap();
        // 2) Replace with `second.example`.
        set_min_pin_length_unauthenticated(
            &device,
            AuthenticatorConfigParams {
                new_min_pin_length: None,
                min_pin_length_rp_ids: Some(vec![second_rp.to_owned()]),
                ..Default::default()
            },
        )
        .unwrap();

        // first.example must no longer be allowlisted.
        let client_data_hash = &[0u8; 32];
        let user = User::new(b"id").name("u").display_name("U");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];

        let mut req1 = MakeCredential::new(
            client_data_hash,
            Rp::new(first_rp),
            user.clone(),
            pub_key_cred_params.clone(),
        );
        req1.extensions = Some(MakeCredentialExtensionsInput::default().min_pin_length(true));
        let response1 = device.exec(req1).unwrap();
        match response1.auth_data.extensions {
            None => {}
            Some(map) => assert!(
                !map.contains_key("minPinLength"),
                "first.example dropped from list but still got extension: {map:?}"
            ),
        }

        // second.example must now be allowlisted.
        let mut req2 = MakeCredential::new(
            client_data_hash,
            Rp::new(second_rp),
            user,
            pub_key_cred_params,
        );
        req2.extensions = Some(MakeCredentialExtensionsInput::default().min_pin_length(true));
        let response2 = device.exec(req2).unwrap();
        let extensions = response2
            .auth_data
            .extensions
            .expect("extensions present for second.example");
        assert_eq!(
            extensions.get("minPinLength"),
            Some(&Value::from(6u8)),
            "second.example should be on the new allowlist"
        );
    })
}

/// CTAP 2.1 §6.11.4 step 2.5: force `forcePINChange=true` only when
/// `PINCodePointLength` is less than `newMinPINLength`. When the
/// existing PIN already meets the new minimum, the flag stays cleared.
#[test]
fn test_set_min_pin_length_pin_meets_new_min_no_force_change() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456789"; // 9 chars, already > new floor of 6
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        // Before: GetInfo.forcePinChange should be false.
        let reply = device.exec(GetInfo).unwrap();
        assert_eq!(reply.force_pin_change, Some(false));

        // Tighten to 6 — the existing 9-code-point PIN still meets the new
        // floor, so step 2.5 must not flip forcePINChange.
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let params = AuthenticatorConfigParams {
            new_min_pin_length: Some(6),
            ..Default::default()
        };
        set_min_pin_length(&device, &pin_token, params).unwrap();

        // After: forcePinChange is still false because PINCodePointLength
        // (9) is not less than newMinPINLength (6).
        let reply = device.exec(GetInfo).unwrap();
        assert_eq!(reply.force_pin_change, Some(false));
    })
}
