#![cfg(feature = "dispatch")]

mod virt;
mod webauthn;

use std::collections::BTreeMap;

use ciborium::Value;
use hex_literal::hex;

use virt::{Ctap2, Ctap2Error};
use webauthn::{
    ClientPin, CredentialManagement, CredentialManagementParams, GetInfo, KeyAgreementKey,
    MakeCredential, MakeCredentialOptions, PinToken, PubKeyCredParam, PublicKey, Rp, SharedSecret,
    User,
};

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

#[derive(Clone, Debug)]
struct RequestPinToken {
    permissions: u8,
    rp_id: Option<String>,
}

#[derive(Debug)]
struct TestMakeCredential {
    pin_token: Option<RequestPinToken>,
    pub_key_alg: i32,
}

impl TestMakeCredential {
    fn run(&self) {
        let key_agreement_key = KeyAgreementKey::generate();
        let pin = b"123456";
        let rp_id = "example.com";
        // TODO: client data
        let client_data_hash = b"";

        virt::run_ctap2(|device| {
            let pin_auth = self.pin_token.as_ref().map(|pin_token| {
                let shared_secret = get_shared_secret(&device, &key_agreement_key);
                set_pin(&device, &key_agreement_key, &shared_secret, pin);
                let pin_token = get_pin_token(
                    &device,
                    &key_agreement_key,
                    &shared_secret,
                    pin,
                    pin_token.permissions,
                    pin_token.rp_id.clone(),
                );
                pin_token.authenticate(client_data_hash)
            });

            let rp = Rp::new(rp_id);
            let user = User::new(b"id123")
                .name("john.doe")
                .display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", self.pub_key_alg)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            if let Some(pin_auth) = pin_auth {
                request.pin_auth = Some(pin_auth);
                request.pin_protocol = Some(2);
            }

            let result = device.exec(request);
            if let Some(error) = self.expected_error() {
                assert_eq!(result, Err(Ctap2Error(error)));
            } else {
                let reply = result.unwrap();
                assert_eq!(reply.fmt, "packed");
                assert!(reply.auth_data.is_bytes());
                assert!(reply.att_stmt.is_map());
            }
        });
    }

    fn expected_error(&self) -> Option<u8> {
        if let Some(pin_token) = &self.pin_token {
            if pin_token.permissions != 0x01 {
                return Some(0x33);
            }
            if let Some(rp_id) = &pin_token.rp_id {
                if rp_id != "example.com" {
                    return Some(0x33);
                }
            }
        }
        if self.pub_key_alg != -7 {
            return Some(0x26);
        }
        None
    }
}

#[test]
fn test_make_credential() {
    let pin_tokens = [
        None,
        Some(RequestPinToken {
            permissions: 0x01,
            rp_id: None,
        }),
        Some(RequestPinToken {
            permissions: 0x01,
            rp_id: Some("example.com".to_owned()),
        }),
        Some(RequestPinToken {
            permissions: 0x01,
            rp_id: Some("test.com".to_owned()),
        }),
        Some(RequestPinToken {
            permissions: 0x04,
            rp_id: None,
        }),
    ];
    for pin_token in pin_tokens {
        for pub_key_alg in [-7, -11] {
            let test = TestMakeCredential {
                pin_token: pin_token.clone(),
                pub_key_alg,
            };
            println!("{}", "=".repeat(80));
            println!("Running test:");
            println!("{test:#?}");
            println!();
            test.run();
        }
    }
}

#[derive(Debug)]
struct TestListCredentials {
    pin_token_rp_id: bool,
}

impl TestListCredentials {
    fn run(&self) {
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
            let reply = device.exec(request).unwrap();
            let auth_data = reply.auth_data.as_bytes().unwrap();
            assert!(auth_data.len() >= 37, "{}", auth_data.len());
            assert_eq!(
                auth_data[32] & 0b1,
                0b1,
                "up flag not set in auth_data: 0b{:b}",
                auth_data[32]
            );
            assert_eq!(
                auth_data[32] & 0b100,
                0b100,
                "uv flag not set in auth_data: 0b{:b}",
                auth_data[32]
            );

            let pin_token =
                get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x04, None);
            let pin_auth = pin_token.authenticate(&[0x02]);
            let request = CredentialManagement {
                subcommand: 0x02,
                subcommand_params: None,
                pin_protocol: 2,
                pin_auth,
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
                rp_id_hash: reply.rp_id_hash.unwrap().as_bytes().unwrap().to_owned(),
            };
            let mut pin_auth_param = vec![0x04];
            pin_auth_param.extend_from_slice(&params.serialized());
            let pin_auth = pin_token.authenticate(&pin_auth_param);
            let request = CredentialManagement {
                subcommand: 0x04,
                subcommand_params: Some(params),
                pin_protocol: 2,
                pin_auth,
            };
            let reply = device.exec(request).unwrap();
            let user: BTreeMap<String, Value> = reply.user.unwrap().deserialized().unwrap();
            assert_eq!(reply.total_credentials, Some(1));
            assert_eq!(user.get("id").unwrap(), &Value::from(user_id.as_slice()));
        });
    }
}

#[test]
fn test_list_credentials() {
    for pin_token_rp_id in [false, true] {
        let test = TestListCredentials { pin_token_rp_id };
        println!("{}", "=".repeat(80));
        println!("Running test:");
        println!("{test:#?}");
        println!();
        test.run();
    }
}
