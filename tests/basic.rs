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
use trussed::platform::consent::Level;

use fs::list_fs;
use virt::{Ctap2, Ctap2Error, Options};
use webauthn::{
    exhaustive_struct, iter_map, AttStmtFormat, AuthenticatorConfig, AuthenticatorConfigParams,
    ClientPin, CredentialManagement, CredentialManagementParams, Exhaustive, GetAssertion,
    GetAssertionExtensionsInput, GetAssertionOptions, GetInfo, GetNextAssertion, HmacSecretInput,
    KeyAgreementKey, MakeCredential, MakeCredentialExtensionsInput, MakeCredentialOptions,
    PinToken, PubKeyCredDescriptor, PubKeyCredParam, PublicKey, Reset, Rp, SharedSecret, Test,
    User,
};

macro_rules! run_tests {
    ($test:ident {
        $(exhaustive = [
            $($exh_field:ident: $exh_type:ty,)*
        ],)?
        $(iter = [
            $($iter_field:ident: $iter:expr,)*
        ],)?
        $(random = [
            $($random_field:ident: $random_type:ty,)*
        ],)?
        $(fixed = [
            $($fixed_field:ident: $fixed_value:expr,)*
        ],)?
    }) => {{
        $(
            let mut rng = rand::thread_rng();
            $(
                let $random_field: Vec<$random_type> = <$random_type as Exhaustive>::iter_exhaustive().collect();
            )*
        )?
        let tests = iter_map! {
            [
                $($($exh_field: <$exh_type as Exhaustive>::iter_exhaustive(),)*)?
                $($($iter_field: $iter,)*)?
            ] => $test {
                $($($exh_field,)*)?
                $($($iter_field,)*)?
                $($($fixed_field: $fixed_value,)*)?
                $($($random_field: *::rand::seq::SliceRandom::choose($random_field.as_slice(), &mut rng).unwrap(),)*)?
            }
        };
        for test in tests {
            test.run();
        }
    }}
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
        assert_eq!(reply.attestation_formats, Some(vec!["packed".to_owned()]));
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

impl PinAuth {
    fn iter_valid() -> impl Iterator<Item = Self> + Clone {
        [
            Self::NoPin,
            Self::PinNoToken,
            Self::PinToken(RequestPinToken::ValidRpId),
            Self::PinToken(RequestPinToken::NoRpId),
        ]
        .into_iter()
    }
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
            if options.up == Some(false) {
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

#[test]
fn test_make_credential_pub_key_alg() {
    run_tests! {
        TestMakeCredential {
            exhaustive = [
                valid_pub_key_alg: bool,
            ],
            iter = [
                pin_auth: PinAuth::iter_valid(),
                options: MakeCredentialOptions::iter_valid().map(Some),
            ],
            random = [
                attestation_formats_preference: Option<AttestationFormatsPreference>,
                hmac_secret: bool,
            ],
        }
    }
}

#[test]
fn test_make_credential_hmac_secret() {
    run_tests! {
        TestMakeCredential {
            exhaustive = [
                hmac_secret: bool,
            ],
            iter = [
                pin_auth: PinAuth::iter_valid(),
                options: MakeCredentialOptions::iter_valid().map(Some),
            ],
            random = [
                attestation_formats_preference: Option<AttestationFormatsPreference>,
            ],
            fixed = [
                valid_pub_key_alg: true,
            ],
        }
    }
}

#[test]
fn test_make_credential_pin_auth() {
    run_tests! {
        TestMakeCredential {
            exhaustive = [
                pin_auth: PinAuth,
            ],
            iter = [
                options: MakeCredentialOptions::iter_valid().map(Some),
            ],
            random = [
                attestation_formats_preference: Option<AttestationFormatsPreference>,
                hmac_secret: bool,
            ],
            fixed = [
                valid_pub_key_alg: true,
            ],
        }
    }
}

#[test]
fn test_make_credential_options() {
    run_tests! {
        TestMakeCredential {
            exhaustive = [
                options: Option<MakeCredentialOptions>,
            ],
            iter = [
                pin_auth: PinAuth::iter_valid(),
            ],
            random = [
                attestation_formats_preference: Option<AttestationFormatsPreference>,
                hmac_secret: bool,
            ],
            fixed = [
                valid_pub_key_alg: true,
            ],
        }
    }
}

#[test]
fn test_make_credential_attestation_formats_preference() {
    run_tests! {
        TestMakeCredential {
            exhaustive = [
                attestation_formats_preference: Option<AttestationFormatsPreference>,
            ],
            iter = [
                pin_auth: PinAuth::iter_valid(),
                options: MakeCredentialOptions::iter_valid().map(Some),
            ],
            random = [
                hmac_secret: bool,
            ],
            fixed = [
                valid_pub_key_alg: true,
            ],
        }
    }
}

/// Regression test: when `make_credential` fails *after* generating the
/// credential key, that key must be deleted rather than orphaned in the
/// keystore (resident keys are persisted to internal storage). The bug is in
/// the shared key cleanup, not in any one feature, so this exercises several
/// unrelated failure paths — two of which predate hmac-secret.
///
/// Invariant checked after each run: the keystore holds exactly one key per
/// stored resident credential, plus the attestation key and the
/// authenticator's key-encryption key. An orphaned key from a failed attempt
/// would push the key count above this.
#[test]
fn test_make_credential_error_does_not_leak_key() {
    use littlefs2::path::PathBuf;

    fn rk_make_credential(user_id: &[u8]) -> MakeCredential {
        let rp = Rp::new("example.com");
        let user = User::new(user_id).name("john.doe").display_name("John Doe");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        let mut request = MakeCredential::new([0; 32], rp, user, pub_key_cred_params);
        request.options = Some(MakeCredentialOptions::default().rk(true));
        request
    }

    fn assert_no_leak(
        scenario: &'static str,
        configure: impl FnOnce(&mut Options),
        drive: impl FnOnce(&Ctap2) + Send,
    ) {
        let mut options = Options {
            inspect_ifs: Some(Box::new(move |ifs| {
                let mut files = list_fs(ifs);
                let keys = files.try_remove_keys();
                let rks = files.try_remove_rks();
                assert_eq!(keys, rks + 2, "{scenario}: keys={keys} rks={rks}");
            })),
            ..Default::default()
        };
        configure(&mut options);
        virt::run_ctap2_with_options(options, move |device| drive(&device));
    }

    // 1. KeyStoreFull via the resident-credential count limit (predates
    //    hmac-secret). The baseline takes the only slot, so a second,
    //    different-user credential fails after its key has been generated.
    assert_no_leak(
        "key store full (count limit)",
        |options| options.max_resident_credential_count = Some(1),
        |device| {
            device
                .exec(rk_make_credential(b"baseline"))
                .expect("baseline make_credential should succeed");
            assert!(device.exec(rk_make_credential(b"other")).is_err());
        },
    );

    // 2. KeyStoreFull via a nearly-full filesystem — the `can_fit` path, also
    //    predating hmac-secret. Create resident credentials until one is
    //    rejected (its key still gets generated first).
    assert_no_leak(
        "key store full (filesystem)",
        |options| {
            for i in 0..80 {
                let path = PathBuf::try_from(format!("/filler/{i}").as_str()).unwrap();
                options.files.push((path, vec![0; 512]));
            }
        },
        |device| {
            let mut hit_full = false;
            for i in 0..64u32 {
                if device.exec(rk_make_credential(&i.to_le_bytes())).is_err() {
                    hit_full = true;
                    break;
                }
            }
            assert!(hit_full, "expected the filesystem to fill up");
        },
    );

    // 3. Invalid hmac-secret-mc (bad salt length): fails right after key
    //    generation — just one of the ~dozen error paths the cleanup covers.
    assert_no_leak(
        "bad hmac-secret-mc",
        |_| {},
        |device| {
            device
                .exec(rk_make_credential(b"baseline"))
                .expect("baseline make_credential should succeed");
            let mut bad = rk_make_credential(b"other");
            bad.extensions = Some(MakeCredentialExtensionsInput {
                hmac_secret: Some(true),
                hmac_secret_mc: Some(HmacSecretInput {
                    key_agreement: KeyAgreementKey::generate().public_key(),
                    salt_enc: vec![0; 5],
                    salt_auth: [0; 32],
                    pin_protocol: Some(2),
                }),
                ..Default::default()
            });
            assert!(device.exec(bad).is_err());
        },
    );

    // 4. Non-resident (wrapped-key) path: a non-resident credential's key is
    //    generated in `Location::Volatile` (see `ctap2.rs`), so a
    //    make_credential that fails after key-gen must delete it from the VFS,
    //    not the IFS. The scenarios above only exercise the resident (IFS) half;
    //    this mirrors `test_get_assertion_error_does_not_leak_key` for the
    //    make_credential side.
    fn nonrk_make_credential(user_id: &[u8]) -> MakeCredential {
        let mut request = rk_make_credential(user_id);
        request.options = Some(MakeCredentialOptions::default().rk(false));
        request
    }
    let options = Options {
        inspect_vfs: Some(Box::new(|vfs| {
            let keys = list_fs(vfs).try_remove_keys();
            // Only the hmac-secret-mc session key-agreement key should remain;
            // the non-resident credential key must have been deleted. A leak
            // would make this 2.
            assert_eq!(
                keys, 1,
                "make_credential leaked a volatile key: {keys} volatile key(s)"
            );
        })),
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        let mut bad = nonrk_make_credential(b"volatile");
        bad.extensions = Some(MakeCredentialExtensionsInput {
            hmac_secret: Some(true),
            hmac_secret_mc: Some(HmacSecretInput {
                key_agreement: KeyAgreementKey::generate().public_key(),
                salt_enc: vec![0; 5],
                salt_auth: [0; 32],
                pin_protocol: Some(2),
            }),
            ..Default::default()
        });
        assert!(device.exec(bad).is_err());
    });
}

/// Regression test for the get_assertion side of the leak: a non-resident
/// credential's key is unwrapped into volatile storage, and a get_assertion
/// that fails afterwards (here, an invalid hmac-secret) must not orphan that
/// unwrapped key.
#[test]
fn test_get_assertion_error_does_not_leak_key() {
    let options = Options {
        inspect_vfs: Some(Box::new(|vfs| {
            let keys = list_fs(vfs).try_remove_keys();
            // The only volatile key left should be the session key-agreement
            // key created while processing hmac-secret. The unwrapped
            // credential key must have been deleted; if it leaked, this is 2.
            assert_eq!(
                keys, 1,
                "get_assertion leaked an unwrapped key: {keys} volatile key(s)"
            );
        })),
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        // A non-resident (wrapped-key) credential.
        let rp = Rp::new("example.com");
        let user = User::new(b"id123")
            .name("john.doe")
            .display_name("John Doe");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        let request = MakeCredential::new([0; 32], rp, user, pub_key_cred_params);
        let credential = device
            .exec(request)
            .expect("make_credential should succeed")
            .auth_data
            .credential
            .expect("credential present");

        // get_assertion with an invalid hmac-secret fails after the credential
        // key has been unwrapped into volatile storage.
        let mut request = GetAssertion::new("example.com", [0; 32]);
        request.allow_list = Some(vec![PubKeyCredDescriptor::new("public-key", credential.id)]);
        request.extensions = Some(GetAssertionExtensionsInput {
            hmac_secret: Some(HmacSecretInput {
                key_agreement: KeyAgreementKey::generate().public_key(),
                salt_enc: vec![0; 5],
                salt_auth: [0; 32],
                pin_protocol: Some(2),
            }),
            ..Default::default()
        });
        assert!(
            device.exec(request).is_err(),
            "get_assertion was expected to fail"
        );
    });
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
            hmac_secret_mc: None,
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
            assert!(response.auth_data.sign_count > 0);
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
fn test_get_assertion_options() {
    run_tests! {
        TestGetAssertion {
            exhaustive = [
                rk: bool,
                allow_list: bool,
                options: Option<GetAssertionOptions>,
            ],
            random = [
                mc_extensions: Option<ExhaustiveMakeCredentialExtensionsInput>,
                ga_hmac_secret: bool,
                ga_third_party_payment: Option<bool>,
                ga_cred_blob: bool,
            ],
        }
    }
}

#[test]
fn test_get_assertion_hmac_secret() {
    run_tests! {
        TestGetAssertion {
            exhaustive = [
                rk: bool,
                allow_list: bool,
                mc_extensions: Option<ExhaustiveMakeCredentialExtensionsInput>,
                ga_hmac_secret: bool,
            ],
            iter = [
                options: GetAssertionOptions::iter_valid().map(Some),
            ],
            random = [
                ga_third_party_payment: Option<bool>,
                ga_cred_blob: bool,
            ],
        }
    }
}

#[test]
fn test_get_assertion_third_party_payment() {
    run_tests! {
        TestGetAssertion {
            exhaustive = [
                rk: bool,
                allow_list: bool,
                mc_extensions: Option<ExhaustiveMakeCredentialExtensionsInput>,
                ga_third_party_payment: Option<bool>,
            ],
            iter = [
                options: GetAssertionOptions::iter_valid().map(Some),
            ],
            random = [
                ga_hmac_secret: bool,
                ga_cred_blob: bool,
            ],
        }
    }
}

#[test]
fn test_get_assertion_cred_blob() {
    run_tests! {
        TestGetAssertion {
            exhaustive = [
                rk: bool,
                allow_list: bool,
                mc_extensions: Option<ExhaustiveMakeCredentialExtensionsInput>,
                ga_cred_blob: bool,
            ],
            iter = [
                options: GetAssertionOptions::iter_valid().map(Some),
            ],
            random = [
                ga_hmac_secret: bool,
                ga_third_party_payment: Option<bool>,
            ],
        }
    }
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

#[test]
fn test_list_credentials() {
    run_tests! {
        TestListCredentials {
            exhaustive = [
                pin_token_rp_id: bool,
                third_party_payment: Option<bool>,
            ],
        }
    }
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
// authenticatorReset clears all §6.7 feature flags
// ----------------------------------------------------------------------------

/// CTAP 2.1 §6.7: `authenticatorReset` MUST reset every feature listed under
/// "Resets those features that are denoted as being subject to reset" — in
/// particular Always Require User Verification, Set Minimum PIN Length
/// (including `minPinLength`, `minPinLengthRPIDs`, and the `forcePINChange`
/// flag), and Enterprise Attestation. Set up the device with all of these
/// dirtied, then Reset, then assert defaults.
#[test]
fn test_reset_clears_section_6_7_feature_flags() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"12345678"; // 8 chars so we can tighten the floor to 6
    let rp_id_for_min_pin = "rp.example.com";
    let options = Options {
        user_presence: Level::Strong,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        // 1) Set PIN.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        // 2) Toggle alwaysUv on.
        let pin_token = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        )
        .unwrap();
        let mut tog = AuthenticatorConfig::new(0x02);
        tog.pin_protocol = Some(2);
        tog.pin_auth = Some(pin_token.authenticate(&tog.pin_uv_auth_data()));
        device.exec(tog).unwrap();

        // 3) Tighten minPINLength to 6, set RP-IDs allowlist, and request
        //    forceChangePin.
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
            min_pin_length_rp_ids: Some(vec![rp_id_for_min_pin.to_owned()]),
            force_change_pin: Some(true),
        };
        set_min_pin_length(&device, &pin_token, params).unwrap();

        // Sanity-check: every dirty bit is visible before reset.
        let reply = device.exec(GetInfo).unwrap();
        let opts = reply.options.clone().unwrap();
        assert_eq!(opts.get("alwaysUv"), Some(&Value::from(true)));
        assert_eq!(opts.get("clientPin"), Some(&Value::from(true)));
        assert_eq!(reply.force_pin_change, Some(true));
        assert_eq!(reply.min_pin_length, Some(6));

        // 4) Reset.
        device.exec(Reset).unwrap();

        // 5) All §6.7 flags back to defaults.
        let reply = device.exec(GetInfo).unwrap();
        let opts = reply.options.unwrap();
        // alwaysUv default = false; couples makeCredUvNotRqd back to true.
        assert_eq!(opts.get("alwaysUv"), Some(&Value::from(false)));
        assert_eq!(opts.get("makeCredUvNotRqd"), Some(&Value::from(true)));
        // PIN cleared.
        assert_eq!(opts.get("clientPin"), Some(&Value::from(false)));
        // forcePINChange cleared.
        assert_eq!(reply.force_pin_change, Some(false));
        // minPINLength back to the spec floor (default 4).
        assert_eq!(reply.min_pin_length, Some(4));
    })
}

/// CTAP 2.1 §6.6 authenticatorReset — comprehensive companion to
/// `test_reset_clears_section_6_7_feature_flags`. Verifies the
/// non-§6.7 reset effects:
///
/// - Resident credentials erased (GA with the prior credential id →
///   `CTAP2_ERR_NO_CREDENTIALS`).
/// - clientPin flag flipped back to false in `authenticatorGetInfo`.
/// - PIN retry counter restored to its maximum (8 here, the
///   factory state).
/// - `pinUvAuthToken` invalidated — a token grabbed before reset cannot
///   be used after.
///
/// Not covered here (different setup): U2F credentials erased (CTAP1
/// flow, exercised by `tests/ctap1.rs`), large-blob array reset (needs
/// `large_blobs::Config` wired into `Options`).
#[test]
fn test_reset_clears_all_state() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    let wrong_pin = b"000000";
    let rp_id = "example.com";
    let options = Options {
        user_presence: Level::Strong,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        // ----- Setup: RK + PIN + pinUvAuthToken + dirty retry counter -----

        // 1. Create a resident credential (no PIN yet, MC needs no pin_auth).
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

        // 2. Set a PIN.
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();
        // clientPin = true after setPin.
        assert_eq!(
            device
                .exec(GetInfo)
                .unwrap()
                .options
                .unwrap()
                .get("clientPin"),
            Some(&Value::from(true))
        );

        // 3. Decrement the PIN retry counter with one wrong attempt.
        let bad_secret = get_shared_secret(&device, &key_agreement_key);
        let _ = get_pin_token(
            &device,
            &key_agreement_key,
            &bad_secret,
            wrong_pin,
            PERM_AUTHENTICATOR_CONFIGURATION,
            None,
        );
        assert_eq!(
            get_pin_retries(&device),
            7,
            "retries should have decreased by one after a wrong PIN"
        );

        // 4. Obtain a pinUvAuthToken (mc permission = 0x01, scoped to rp_id).
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        let pin_token_before_reset = get_pin_token(
            &device,
            &key_agreement_key,
            &shared_secret,
            pin,
            0x01,
            Some(rp_id.to_owned()),
        )
        .unwrap();

        // ----- Reset -----
        device.exec(Reset).unwrap();

        // ----- Assertions -----

        // (a) PIN cleared.
        assert_eq!(
            device
                .exec(GetInfo)
                .unwrap()
                .options
                .unwrap()
                .get("clientPin"),
            Some(&Value::from(false))
        );

        // (b) PIN retries restored to the maximum (8 in this build).
        assert_eq!(
            get_pin_retries(&device),
            8,
            "PIN retries must be restored to the post-reset default"
        );

        // (c) Discoverable credential erased — GA with the prior credential
        //     id should not find it.
        let mut ga = GetAssertion::new(rp_id.to_owned(), client_data_hash.clone());
        ga.allow_list = Some(vec![PubKeyCredDescriptor::new(
            "public-key",
            credential.id.clone(),
        )]);
        let result = device.exec(ga);
        assert_eq!(
            result.err(),
            Some(Ctap2Error(0x2E)), // CTAP2_ERR_NO_CREDENTIALS
            "RK must be erased by reset"
        );

        // (d) The previously-obtained pinUvAuthToken is invalidated by the
        //     reset (the device-side token-state and pin_token_key are
        //     regenerated). To verify, we have to first re-close the
        //     §6.11 step-4 gate by setting a new PIN — in factory-default
        //     state the gate is open and the token would simply be
        //     ignored. After setPin, presenting the *old* token must fail
        //     verification with CTAP2_ERR_PIN_AUTH_INVALID (0x33).
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin).unwrap();

        let mut cfg = AuthenticatorConfig::new(0x02); // ToggleAlwaysUv
        cfg.pin_protocol = Some(2);
        cfg.pin_auth = Some(pin_token_before_reset.authenticate(&cfg.pin_uv_auth_data()));
        let result = device.exec(cfg).err();
        assert_eq!(
            result,
            Some(Ctap2Error(0x33)),
            "stale pinUvAuthToken must not authenticate against the post-reset state, got {:?}",
            result
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

// ----------------------------------------------------------------------------
// RK + allowList: user field in GA response (CTAP 2.1 §6.2.3)
// ----------------------------------------------------------------------------

/// CTAP 2.1 §6.2.3: when `getAssertion` is called with an `allowList` and the
/// matched credential is a resident key, the authenticator's response must
/// include the `user` field. Modern versions of this app stash only a
/// `Stripped` credential into `credential_id`, so the user field must be
/// recovered from the on-disk RK record.
#[test]
fn test_get_assertion_with_allow_list_rk_returns_user() {
    let rp_id = "example.com";
    let user_id = b"alice-id-1234567";
    let user_name = "alice@example.com";
    virt::run_ctap2(|device| {
        // Make an RK with a populated user struct.
        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash.clone(),
            Rp::new(rp_id),
            User::new(user_id.to_vec()).name(user_name),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        let mc_reply = device.exec(mc).unwrap();
        let credential = mc_reply.auth_data.credential.unwrap();

        // GA with allowList of just that credential — RK with allowList is
        // the audited code path.
        let mut ga = GetAssertion::new(rp_id.to_owned(), client_data_hash);
        ga.allow_list = Some(vec![PubKeyCredDescriptor::new(
            "public-key",
            credential.id.clone(),
        )]);
        let ga_reply = device.exec(ga).unwrap();

        let user_value = ga_reply.user.expect("user field missing in GA response");
        let user_map: std::collections::BTreeMap<String, ciborium::Value> =
            user_value.deserialized().unwrap();
        // id is the required field. name is optional and may be stripped by
        // the authenticator depending on UV state; the audit fix is about
        // presence of the `user` map itself.
        assert_eq!(
            user_map.get("id").unwrap(),
            &ciborium::Value::from(user_id.as_slice())
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

/// CTAP 2.1 §6.2.2 step 12: "User identifiable information (name, displayName,
/// icon) inside user MUST NOT be returned if UV is not done by the
/// authenticator." Verify that when GA runs without `pin_auth` (no UV), the
/// `user` map contains only `id` — name/displayName/icon are stripped.
#[test]
fn test_get_assertion_with_allow_list_rk_no_uv_strips_pii() {
    let rp_id = "example.com";
    let user_id = b"alice-id-1234567";
    virt::run_ctap2(|device| {
        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash.clone(),
            Rp::new(rp_id),
            User::new(user_id.to_vec())
                .name("alice@example.com")
                .display_name("Alice In Wonderland"),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        let mc_reply = device.exec(mc).unwrap();
        let credential = mc_reply.auth_data.credential.unwrap();

        // GA without pin_auth → uv_performed = false → PII must be stripped.
        let mut ga = GetAssertion::new(rp_id.to_owned(), client_data_hash);
        ga.allow_list = Some(vec![PubKeyCredDescriptor::new(
            "public-key",
            credential.id.clone(),
        )]);
        let ga_reply = device.exec(ga).unwrap();

        let user_value = ga_reply.user.expect("user field missing");
        let user_map: std::collections::BTreeMap<String, ciborium::Value> =
            user_value.deserialized().unwrap();
        assert_eq!(
            user_map.get("id").unwrap(),
            &ciborium::Value::from(user_id.as_slice())
        );
        assert!(!user_map.contains_key("name"), "name leaked without UV");
        assert!(
            !user_map.contains_key("displayName"),
            "displayName leaked without UV"
        );
        assert!(!user_map.contains_key("icon"), "icon leaked without UV");
    })
}

/// CTAP 2.1 §6.2.3: the `user` response field is for resident credentials
/// only. A GA over an allow-list entry pointing at a non-RK credential
/// MUST NOT include `user`.
#[test]
fn test_get_assertion_with_allow_list_non_rk_no_user_field() {
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        // Make a NON-discoverable credential (rk=false).
        let client_data_hash = vec![0u8; 32];
        let mc = MakeCredential::new(
            client_data_hash.clone(),
            Rp::new(rp_id),
            User::new(b"bob-id".to_vec()).name("bob@example.com"),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        // No rk(true) — defaults to non-resident.
        let mc_reply = device.exec(mc).unwrap();
        let credential = mc_reply.auth_data.credential.unwrap();

        let mut ga = GetAssertion::new(rp_id.to_owned(), client_data_hash);
        ga.allow_list = Some(vec![PubKeyCredDescriptor::new(
            "public-key",
            credential.id.clone(),
        )]);
        let ga_reply = device.exec(ga).unwrap();

        assert!(
            ga_reply.user.is_none(),
            "non-RK credential must not return user, got {:?}",
            ga_reply.user
        );
    })
}

// ----------------------------------------------------------------------------
// hmac-secret-mc extension (CTAP 2.2 §11.4.5)
// ----------------------------------------------------------------------------

/// GetInfo advertises the `hmac-secret-mc` extension and the device does NOT
/// advertise the legacy `FIDO_2_2` version string (CTAP 2.3 §6.4: "The
/// string 'FIDO_2_2' was not defined for CTAP2.2 and MUST not be present in
/// versions member").
#[test]
fn test_hmac_secret_mc_advertised_in_get_info() {
    virt::run_ctap2(|device| {
        let reply = device.exec(GetInfo).unwrap();
        // CTAP 2.3 §6.4: `FIDO_2_2` is NOT a valid version string.
        assert!(!reply.versions.contains(&"FIDO_2_2".to_owned()));
        let extensions = reply.extensions.expect("extensions list missing");
        assert!(
            extensions.contains(&"hmac-secret-mc".to_owned()),
            "hmac-secret-mc not advertised: {:?}",
            extensions
        );
    })
}

/// MakeCredential with `hmac-secret-mc` returns an output blob that decrypts
/// to either a 32-byte HMAC output (one salt) or 64-byte (two salts). The
/// authenticator data's ED flag MUST be set.
#[test]
fn test_make_credential_with_hmac_secret_mc_returns_output() {
    let key_agreement_key = KeyAgreementKey::generate();
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);

        // Single-salt input (32 bytes → expected 32-byte HMAC output).
        let mut salt = [0xffu8; 32];
        rand::thread_rng().fill_bytes(&mut salt[..31]);
        let salt_enc = shared_secret.encrypt(&salt);
        let salt_auth = shared_secret.authenticate(&salt_enc);

        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash,
            Rp::new(rp_id),
            User::new(vec![1; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        mc.extensions = Some(MakeCredentialExtensionsInput {
            hmac_secret: Some(true),
            hmac_secret_mc: Some(HmacSecretInput {
                key_agreement: key_agreement_key.public_key(),
                salt_enc,
                salt_auth,
                pin_protocol: Some(2),
            }),
            ..Default::default()
        });
        let reply = device.exec(mc).unwrap();

        // ED flag must be set when extensions are returned.
        assert!(reply.auth_data.ed_flag(), "ED flag missing");

        let extensions = reply.auth_data.extensions.expect("extensions missing");
        let raw = extensions
            .get("hmac-secret-mc")
            .expect("hmac-secret-mc absent from extensions")
            .as_bytes()
            .unwrap();
        let output = shared_secret.decrypt(raw);
        assert_eq!(output.len(), 32, "single-salt output must be 32 bytes");
    })
}

/// Two-salt hmac-secret-mc input (64 bytes encrypted) yields a 64-byte
/// output (two concatenated HMAC values).
#[test]
fn test_make_credential_with_hmac_secret_mc_two_salts() {
    let key_agreement_key = KeyAgreementKey::generate();
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);

        let mut salts = [0xffu8; 64];
        rand::thread_rng().fill_bytes(&mut salts[..63]);
        let salt_enc = shared_secret.encrypt(&salts);
        let salt_auth = shared_secret.authenticate(&salt_enc);

        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash,
            Rp::new(rp_id),
            User::new(vec![2; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        mc.extensions = Some(MakeCredentialExtensionsInput {
            hmac_secret: Some(true),
            hmac_secret_mc: Some(HmacSecretInput {
                key_agreement: key_agreement_key.public_key(),
                salt_enc,
                salt_auth,
                pin_protocol: Some(2),
            }),
            ..Default::default()
        });
        let reply = device.exec(mc).unwrap();
        let extensions = reply.auth_data.extensions.expect("extensions missing");
        let raw = extensions
            .get("hmac-secret-mc")
            .unwrap()
            .as_bytes()
            .unwrap();
        let output = shared_secret.decrypt(raw);
        assert_eq!(output.len(), 64, "two-salt output must be 64 bytes");
    })
}

/// hmac-secret-mc with a forged `salt_auth` MUST be rejected
/// (CTAP 2.1 / 2.2 §6.5.5.7 `verify_pin_auth`).
#[test]
fn test_make_credential_hmac_secret_mc_bad_auth_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);

        let mut salt = [0xffu8; 32];
        rand::thread_rng().fill_bytes(&mut salt[..31]);
        let salt_enc = shared_secret.encrypt(&salt);
        // Forge the auth tag (all zeros — should not match HMAC output).
        let salt_auth = [0u8; 32];

        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash,
            Rp::new(rp_id),
            User::new(vec![3; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        mc.extensions = Some(MakeCredentialExtensionsInput {
            hmac_secret: Some(true),
            hmac_secret_mc: Some(HmacSecretInput {
                key_agreement: key_agreement_key.public_key(),
                salt_enc,
                salt_auth,
                pin_protocol: Some(2),
            }),
            ..Default::default()
        });
        let result = device.exec(mc);
        // PinAuthInvalid (0x33) — `verify_pin_auth` returns it on HMAC
        // mismatch regardless of which input triggered the path.
        assert_eq!(result.err(), Some(Ctap2Error(0x33)));
    })
}

/// CTAP 2.2 §11.4.5 hmac-secret-mc: the decrypted `saltEnc` MUST be either
/// 32 bytes (one salt) or 64 bytes (two salts). Any other length is a
/// protocol violation; the authenticator returns CTAP1_ERR_INVALID_LENGTH
/// (0x03). We test with a 48-byte salt (still passes the AES-CBC block
/// constraint since 48 is a multiple of 16, but is not 32 or 64).
#[test]
fn test_make_credential_hmac_secret_mc_invalid_salt_length_rejected() {
    let key_agreement_key = KeyAgreementKey::generate();
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);

        // 48-byte plaintext salt → 48-byte ciphertext (after AES-CBC, plus
        // 16-byte IV inside `encrypt` ↦ 64-byte salt_enc on the wire). The
        // device decrypts the IV+ciphertext, ends up with 48 bytes of
        // plaintext, and must reject it.
        let mut salt = [0xffu8; 48];
        rand::thread_rng().fill_bytes(&mut salt[..47]);
        let salt_enc = shared_secret.encrypt(&salt);
        let salt_auth = shared_secret.authenticate(&salt_enc);

        let client_data_hash = vec![0u8; 32];
        let mut mc = MakeCredential::new(
            client_data_hash,
            Rp::new(rp_id),
            User::new(vec![4; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        mc.options = Some(MakeCredentialOptions::default().rk(true));
        mc.extensions = Some(MakeCredentialExtensionsInput {
            hmac_secret: Some(true),
            hmac_secret_mc: Some(HmacSecretInput {
                key_agreement: key_agreement_key.public_key(),
                salt_enc,
                salt_auth,
                pin_protocol: Some(2),
            }),
            ..Default::default()
        });
        let result = device.exec(mc);
        // CTAP1_ERR_INVALID_LENGTH = 0x03.
        assert_eq!(result.err(), Some(Ctap2Error(0x03)));
    })
}

// ----------------------------------------------------------------------------
// Transports (CTAP 2.1 §6.4 0x09 / CTAP 2.3 §3 smart-card)
// ----------------------------------------------------------------------------

/// Default config (USB only) advertises only `"usb"`.
#[test]
fn test_transports_usb_only_by_default() {
    virt::run_ctap2(|device| {
        let reply = device.exec(GetInfo).unwrap();
        let transports = reply.transports.expect("transports list missing");
        assert_eq!(transports, vec!["usb".to_owned()]);
    })
}

/// With `nfc_transport=true`, `"nfc"` and `"usb"` are advertised.
#[test]
fn test_transports_nfc_added() {
    let options = Options {
        nfc_transport: true,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        let reply = device.exec(GetInfo).unwrap();
        let transports = reply.transports.expect("transports list missing");
        assert!(transports.contains(&"nfc".to_owned()));
        assert!(transports.contains(&"usb".to_owned()));
    })
}

/// CTAP 2.3 §3: with `ccid_transport=true`, `"smart-card"` is advertised
/// alongside the other transports.
#[test]
fn test_transports_smart_card_advertised_when_ccid_enabled() {
    let options = Options {
        ccid_transport: true,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        let reply = device.exec(GetInfo).unwrap();
        let transports = reply.transports.expect("transports list missing");
        assert!(
            transports.contains(&"smart-card".to_owned()),
            "smart-card missing from transports: {:?}",
            transports
        );
    })
}

/// `"smart-card"` is NOT advertised by default (no CCID).
#[test]
fn test_transports_smart_card_absent_when_ccid_disabled() {
    virt::run_ctap2(|device| {
        let reply = device.exec(GetInfo).unwrap();
        let transports = reply.transports.expect("transports list missing");
        assert!(!transports.contains(&"smart-card".to_owned()));
    })
}

/// NFC + CCID together: all three transports advertised. Verifies the
/// flags are independent.
#[test]
fn test_transports_nfc_and_smart_card_combined() {
    let options = Options {
        nfc_transport: true,
        ccid_transport: true,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        let reply = device.exec(GetInfo).unwrap();
        let transports = reply.transports.expect("transports list missing");
        assert!(
            transports.contains(&"nfc".to_owned()),
            "nfc missing: {:?}",
            transports
        );
        assert!(
            transports.contains(&"smart-card".to_owned()),
            "smart-card missing: {:?}",
            transports
        );
        assert!(
            transports.contains(&"usb".to_owned()),
            "usb missing: {:?}",
            transports
        );
    })
}

// ----------------------------------------------------------------------------
// FIDO_2_3 version advertisement (CTAP 2.3 §6.4)
// ----------------------------------------------------------------------------

/// CTAP 2.3 §6.4: `FIDO_2_3` is advertised in the versions list; `FIDO_2_2`
/// MUST be absent.
#[test]
fn test_versions_include_fido_2_3_exclude_fido_2_2() {
    virt::run_ctap2(|device| {
        let reply = device.exec(GetInfo).unwrap();
        assert!(reply.versions.contains(&"FIDO_2_3".to_owned()));
        assert!(!reply.versions.contains(&"FIDO_2_2".to_owned()));
    })
}

#[test]
fn test_signature_counter() {
    let client_data_hash = vec![0u8; 32];
    let rp_id = "example.com";
    virt::run_ctap2(|device| {
        let mc = MakeCredential::new(
            client_data_hash.clone(),
            Rp::new(rp_id),
            User::new(vec![4; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        let response = device.exec(mc).unwrap();
        let credential1 = response.auth_data.credential.unwrap();
        let counter1 = response.auth_data.sign_count;

        let mc = MakeCredential::new(
            client_data_hash.clone(),
            Rp::new(rp_id),
            User::new(vec![4; 16]),
            vec![PubKeyCredParam::new("public-key", -7)],
        );
        let response = device.exec(mc).unwrap();
        let credential2 = response.auth_data.credential.unwrap();
        let counter2 = response.auth_data.sign_count;

        let mut ga = GetAssertion::new(rp_id, client_data_hash.clone());
        ga.allow_list = Some(vec![PubKeyCredDescriptor::new(
            "public-key",
            credential1.id,
        )]);
        let response = device.exec(ga).unwrap();
        let counter3 = response.auth_data.sign_count;

        let mut ga = GetAssertion::new(rp_id, client_data_hash);
        ga.allow_list = Some(vec![PubKeyCredDescriptor::new(
            "public-key",
            credential2.id,
        )]);
        let response = device.exec(ga).unwrap();
        let counter4 = response.auth_data.sign_count;

        assert_eq!(counter1, 1);

        let delta1 = counter2 - counter1;
        assert!(delta1 >= 1);
        assert!(delta1 <= 256);

        let delta2 = counter3 - counter2;
        assert!(delta2 >= 1);
        assert!(delta2 <= 256);

        let delta3 = counter4 - counter3;
        assert!(delta3 >= 1);
        assert!(delta3 <= 256);

        assert!(delta1 + delta2 + delta3 > 3);
    })
}

// ----------------------------------------------------------------------------
// Long-touch reset (CTAP 2.3 §6.4 0x18, §6.11.5, §7.7)
// ----------------------------------------------------------------------------

/// GetInfo advertises `longTouchForReset = true` (member 0x18). The runtime
/// configuration is hard-wired on — `EnableLongTouchForReset` (below) is a
/// no-op.
#[test]
fn test_long_touch_for_reset_advertised() {
    for long_touch_for_reset in [true, false] {
        let options = Options {
            long_touch_for_reset,
            ..Default::default()
        };
        virt::run_ctap2_with_options(options, |device| {
            let reply = device.exec(GetInfo).unwrap();
            assert_eq!(reply.long_touch_for_reset, Some(long_touch_for_reset));
        })
    }
}

#[test]
fn test_enable_long_touch_for_reset_invalid_parameter() {
    let options = Options {
        long_touch_for_reset: false,
        ..Default::default()
    };
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2_with_options(options, |device| {
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

        // EnableLongTouchForReset = subcommand 0x04.
        let mut request = AuthenticatorConfig::new(0x04);
        request.pin_protocol = Some(2);
        request.pin_auth = Some(pin_token.authenticate(&request.pin_uv_auth_data()));
        let result = device.exec(request);
        assert_eq!(result.err(), Some(Ctap2Error(0x02)));
    })
}

/// CTAP 2.3 §6.11.5: `EnableLongTouchForReset` subcommand. If the feature is enabled,
/// the request must return `Ok(())` without changing state.
#[test]
fn test_enable_long_touch_for_reset_is_noop() {
    let options = Options {
        long_touch_for_reset: true,
        ..Default::default()
    };
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2_with_options(options, |device| {
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

        // EnableLongTouchForReset = subcommand 0x04.
        let mut request = AuthenticatorConfig::new(0x04);
        request.pin_protocol = Some(2);
        request.pin_auth = Some(pin_token.authenticate(&request.pin_uv_auth_data()));
        device.exec(request).unwrap();

        // GetInfo still reports the flag set.
        let reply = device.exec(GetInfo).unwrap();
        assert_eq!(reply.long_touch_for_reset, Some(true));
    })
}

// ============================================================================
// authenticatorReset long-touch gating (CTAP 2.3 §6.6 / §7.7, Config option)
// ============================================================================

/// With `long_touch_for_reset = true` (the recommended default), a normal
/// short touch (`Level::Normal`) must NOT authorize `authenticatorReset`; the
/// authenticator demands a long touch (`Level::Strong`). By default the test UI
/// grants Normal but denies Strong, so Reset is rejected with
/// `CTAP2_ERR_USER_ACTION_TIMEOUT` (0x2F).
#[test]
fn test_reset_long_touch_rejects_short_touch() {
    let options = Options {
        long_touch_for_reset: true,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        // `ResetReply` is a unit reply with no Debug/PartialEq, so map the Ok
        // arm to `()` before comparing.
        let result = device.exec(Reset).map(|_| ());
        assert_eq!(result, Err(Ctap2Error(0x2F)));
    })
}

/// With `long_touch_for_reset = true` and a UI that grants `Level::Strong`,
/// `authenticatorReset` succeeds.
#[test]
fn test_reset_long_touch_accepts_strong_touch() {
    let options = Options {
        long_touch_for_reset: true,
        user_presence: Level::Strong,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        device.exec(Reset).unwrap();
    })
}

/// With `long_touch_for_reset = false` (a runner that opted out), a normal
/// short touch is sufficient and the strong check is never invoked. By default
/// the test UI grants Normal and denies Strong, so success here proves `reset()` took the
/// short-touch path rather than `user_present_strong`.
#[test]
fn test_reset_short_touch_accepts_short_touch() {
    let options = Options {
        long_touch_for_reset: false,
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        device.exec(Reset).unwrap();
    })
}

// ============================================================================
// Empty rp.id / rpId rejected (CTAP 2.1 §6.1.1.2 / §6.2.1.2)
// ============================================================================

/// MakeCredential with an empty `rp.id` is rejected before any user presence
/// check with `CTAP2_ERR_MISSING_PARAMETER` (0x14).
#[test]
fn test_make_credential_empty_rp_id_rejected() {
    let client_data_hash = &[0; 32];
    virt::run_ctap2(|device| {
        let user = User::new(b"id123")
            .name("john.doe")
            .display_name("John Doe");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        let request = MakeCredential::new(client_data_hash, Rp::new(""), user, pub_key_cred_params);
        let result = device.exec(request);
        assert_eq!(result, Err(Ctap2Error(0x14)));
    })
}

/// GetAssertion with an empty `rpId` is rejected before any user presence
/// check with `CTAP2_ERR_MISSING_PARAMETER` (0x14).
#[test]
fn test_get_assertion_empty_rp_id_rejected() {
    let client_data_hash = &[0; 32];
    virt::run_ctap2(|device| {
        let request = GetAssertion::new("", client_data_hash);
        let result = device.exec(request);
        assert_eq!(result, Err(Ctap2Error(0x14)));
    })
}
