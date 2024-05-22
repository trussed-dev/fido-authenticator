#![cfg(feature = "dispatch")]

mod virt;
mod webauthn;

use virt::Ctap2Error;
use webauthn::{GetInfo, MakeCredential, PubKeyCredParam, Rp, User};

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
        let request = MakeCredential::new(b"", rp, user, pub_key_cred_params);
        let reply = device.exec(request).unwrap();
        assert_eq!(reply.fmt, "packed");
        assert!(reply.auth_data.is_bytes());
        assert!(reply.att_stmt.is_map());
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
        let request = MakeCredential::new(b"", rp, user, pub_key_cred_params);
        let result = device.exec(request);
        assert_eq!(result, Err(Ctap2Error(0x26)));
    });
}
