#![cfg(feature = "dispatch")]

mod virt;
mod webauthn;

use std::collections::BTreeMap;

use ciborium::Value;
use ctap_types::ctap2::Operation;

use virt::Ctap2Error;
use webauthn::{MakeCredentialRequest, PubKeyCredParam, Rp, User};

#[test]
fn test_ping() {
    virt::run_ctaphid(|device| {
        device.ping(&[0xf1, 0xd0]).unwrap();
    });
}

#[test]
fn test_get_info() {
    virt::run_ctap2(|device| {
        let reply: BTreeMap<u8, Value> = device.call(Operation::GetInfo, &Value::Null).unwrap();
        let versions: Vec<String> = reply.get(&1).unwrap().deserialized().unwrap();
        assert!(versions.contains(&"FIDO_2_0".to_owned()));
        assert!(versions.contains(&"FIDO_2_1".to_owned()));
    });
}

#[test]
fn test_make_credential() {
    virt::run_ctap2(|device| {
        let rp = Rp::new("example.com");
        let user = User::new(b"id123")
            .name("john.doe")
            .display_name("John Doe");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
        let request = MakeCredentialRequest::new(b"", rp, user, pub_key_cred_params);
        let reply: BTreeMap<u8, Value> = device
            .call(Operation::MakeCredential, &request.into())
            .unwrap();
        assert_eq!(reply.get(&1).unwrap(), &Value::from("packed"));
        assert!(reply.contains_key(&2));
        assert!(reply.contains_key(&3));
    });
}

#[test]
fn test_make_credential_invalid_params() {
    virt::run_ctap2(|device| {
        let rp = Rp::new("example.com");
        let user = User::new(b"id123")
            .name("john.doe")
            .display_name("John Doe");
        let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -11)];
        let request = MakeCredentialRequest::new(b"", rp, user, pub_key_cred_params);
        let result = device.call::<Value>(Operation::MakeCredential, &request.into());
        assert_eq!(result, Err(Ctap2Error(0x26)));
    });
}
