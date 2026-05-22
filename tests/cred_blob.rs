#![cfg(feature = "dispatch")]

pub mod virt;
pub mod webauthn;

use ciborium::Value;
use rand::RngCore as _;

use virt::Ctap2Error;
use webauthn::{
    exhaustive_struct, Exhaustive, GetAssertion, GetAssertionExtensionsInput, MakeCredential,
    MakeCredentialExtensionsInput, MakeCredentialOptions, PubKeyCredDescriptor, PubKeyCredParam,
    Rp, Test, User,
};

#[derive(Clone, Copy, Debug)]
struct CredBlobLen(usize);

impl Exhaustive for CredBlobLen {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        [0, 1, 5, 22, 31, 32, 33, 255, 1024].into_iter().map(Self)
    }
}

#[derive(Clone, Debug)]
struct TestCredBlob {
    rk: bool,
    allow_list: bool,
    mc_cred_blob: Option<CredBlobLen>,
    ga_cred_blob: Option<bool>,
}

impl Test for TestCredBlob {
    fn test(&self) {
        let rp_id = "example.com";
        // TODO: client data
        let client_data_hash = &[0; 32];

        virt::run_ctap2(|device| {
            let cred_blob_ok = self.rk && self.mc_cred_blob.map(|cb| cb.0 <= 32).unwrap_or(false);

            let rp = Rp::new(rp_id);
            let user = User::new(b"id123")
                .name("john.doe")
                .display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            if self.rk {
                request.options = Some(MakeCredentialOptions::default().rk(true));
            }
            let cred_blob = self.mc_cred_blob.map(|cred_blob_len| {
                let mut v = vec![0x00; cred_blob_len.0];
                rand::thread_rng().fill_bytes(&mut v);
                v
            });
            if let Some(cred_blob) = &cred_blob {
                request.extensions =
                    Some(MakeCredentialExtensionsInput::default().cred_blob(cred_blob.clone()));
            }
            let response = device.exec(request).unwrap();
            if cred_blob.is_some() {
                let extensions = response.auth_data.extensions.unwrap();
                assert_eq!(extensions.get("credBlob"), Some(&Value::Bool(cred_blob_ok)));
            }
            let credential = response.auth_data.credential.unwrap();

            let mut request = GetAssertion::new(rp_id, client_data_hash);
            if self.allow_list {
                request.allow_list = Some(vec![PubKeyCredDescriptor::new(
                    "public-key",
                    credential.id.clone(),
                )]);
            }
            if let Some(cred_blob) = self.ga_cred_blob {
                request.extensions =
                    Some(GetAssertionExtensionsInput::default().cred_blob(cred_blob));
            }
            let result = device.exec(request);

            if !self.rk && !self.allow_list {
                assert_eq!(result, Err(Ctap2Error(0x2e)));
                return;
            }

            let response = result.unwrap();
            assert_eq!(response.credential.id, credential.id);
            if self.ga_cred_blob == Some(true) {
                let extensions = response.auth_data.extensions.unwrap();
                let cred_blob_response = extensions.get("credBlob").unwrap().as_bytes().unwrap();
                if cred_blob_ok {
                    assert_eq!(Some(cred_blob_response), cred_blob.as_ref());
                } else {
                    assert!(cred_blob_response.is_empty());
                }
            } else {
                assert!(response.auth_data.extensions.is_none());
            }
        });
    }
}

impl Exhaustive for TestCredBlob {
    fn iter_exhaustive() -> impl Iterator<Item = Self> + Clone {
        exhaustive_struct! {
            rk: bool,
            allow_list: bool,
            mc_cred_blob: Option<CredBlobLen>,
            ga_cred_blob: Option<bool>,
        }
    }
}

#[test]
fn test_cred_blob() {
    TestCredBlob::run_all();
}
