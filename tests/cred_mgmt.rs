#![cfg(feature = "dispatch")]

pub mod authenticator;
pub mod virt;
pub mod webauthn;

use std::collections::BTreeMap;

use littlefs2::path::PathBuf;

use authenticator::Authenticator;
use virt::{Ctap2Error, Options};
use webauthn::{Rp, User};

#[test]
fn test_list_credentials() {
    virt::run_ctap2(|device| {
        let mut authenticator = Authenticator::new(device).set_pin(b"123456");
        let mut credentials: BTreeMap<_, _> = (0..10)
            .map(|i| {
                // TODO: set other fields than id
                let rp_id = format!("rp{i}");
                let user = b"john.doe";
                authenticator
                    .make_credential(Rp::new(rp_id.clone()), User::new(user))
                    .unwrap();
                (rp_id, user)
            })
            .collect();

        let rps = authenticator.list_rps();
        assert_eq!(rps.len(), 10);
        for rp in &rps {
            assert_eq!(rp.name, None);
            let expected = credentials.remove(&rp.id).unwrap();

            let mut credentials = authenticator.list_credentials(&rp.id);
            assert_eq!(credentials.len(), 1);
            let actual = credentials.pop().unwrap();

            assert_eq!(actual.id, expected);
            assert_eq!(actual.name, None);
            assert_eq!(actual.display_name, None);
        }
        assert!(credentials.is_empty());
    })
}

#[test]
fn test_max_credential_count() {
    let options = Options {
        max_resident_credential_count: Some(10),
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        let mut authenticator = Authenticator::new(device).set_pin(b"123456");
        let metadata = authenticator.credentials_metadata();
        assert_eq!(metadata.existing, 0);
        assert_eq!(metadata.remaining, 10);

        for i in 0..10 {
            let rp = Rp::new(format!("rp{i}"));
            let user = User::new(b"john.doe");
            authenticator.make_credential(rp, user).unwrap();

            let metadata = authenticator.credentials_metadata();
            assert_eq!(metadata.existing, i + 1);
            assert_eq!(metadata.remaining, 9 - i);
        }

        let rps = authenticator.list_rps();
        assert_eq!(rps.len(), 10);
        for rp in &rps {
            let credentials = authenticator.list_credentials(&rp.id);
            assert_eq!(credentials.len(), 1);
        }

        let rp = Rp::new("rp11");
        let user = User::new(b"john.doe");
        let result = authenticator.make_credential(rp, user);
        assert_eq!(result, Err(Ctap2Error(0x28)));

        let rps = authenticator.list_rps();
        assert_eq!(rps.len(), 10);
        for rp in &rps {
            let credentials = authenticator.list_credentials(&rp.id);
            assert_eq!(credentials.len(), 1);
        }
    })
}

#[test]
fn test_filesystem_full() {
    let mut options = Options {
        max_resident_credential_count: Some(10),
        ..Default::default()
    };
    for i in 0..80 {
        let path = PathBuf::try_from(format!("/test/{i}").as_str()).unwrap();
        options.files.push((path, vec![0; 512]));
    }
    // TODO: inspect filesystem after run and check remaining blocks
    virt::run_ctap2_with_options(options, |device| {
        let mut authenticator = Authenticator::new(device).set_pin(b"123456");
        let metadata = authenticator.credentials_metadata();
        assert_eq!(metadata.existing, 0);
        // This number depends on filesystem layout details and may change if the filesystem
        // layout or implementation are changed.
        assert_eq!(metadata.remaining, 5);
        let n = metadata.remaining;

        let mut i = 0;
        loop {
            let rp = Rp::new(format!("rp{i}"));
            let user = User::new(b"john.doe");
            let result = authenticator.make_credential(rp, user);

            if result == Err(Ctap2Error(0x28)) {
                break;
            }
            result.unwrap();

            let metadata = authenticator.credentials_metadata();
            assert_eq!(metadata.existing, i + 1);

            i += 1;
        }

        // We should be able to create at least 1 but not more than n credentials.
        assert!(i > 0);
        assert!(i < n);
        // Our estimate should not be more than one credential off.
        assert!(n - i <= 1);

        let metadata = authenticator.credentials_metadata();
        assert_eq!(metadata.existing, i);
        assert_eq!(metadata.remaining, 0);
    })
}
