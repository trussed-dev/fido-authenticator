#![cfg(feature = "dispatch")]

pub mod authenticator;
pub mod virt;
pub mod webauthn;

use std::collections::BTreeSet;

use littlefs2::path::PathBuf;

use authenticator::{Authenticator, Pin};
use virt::{Ctap2Error, Options};
use webauthn::{CredentialData, PubKeyCredDescriptor, Rp, User};

struct CredMgmt<'a> {
    authenticator: Authenticator<'a, Pin>,
    credentials: Vec<(Rp, User, CredentialData)>,
}

impl<'a> CredMgmt<'a> {
    fn new(authenticator: Authenticator<'a, Pin>) -> Self {
        Self {
            authenticator,
            credentials: Default::default(),
        }
    }

    fn make_credential(&mut self, rp: Rp, user: User) -> Result<CredentialData, Ctap2Error> {
        self.authenticator
            .make_credential(rp.clone(), user.clone())
            .inspect(|credential_data| {
                self.credentials.push((rp, user, credential_data.clone()));
            })
    }

    fn delete_credential(&mut self, id: Vec<u8>) -> Result<(), Ctap2Error> {
        self.authenticator.delete_credential(&id);
        self.credentials.retain(|(_, _, data)| data.id != id);
        Ok(())
    }

    fn delete_credential_at(&mut self, i: usize) -> Result<(), Ctap2Error> {
        assert!(i < self.credentials.len());
        let id = self.credentials[i].2.id.clone();
        self.delete_credential(id)
    }

    fn update_user(&mut self, id: Vec<u8>, user: User) -> Result<(), Ctap2Error> {
        self.authenticator.update_user(&id, user.clone())?;
        self.credentials
            .iter_mut()
            .filter(|(_, _, data)| data.id == id)
            .for_each(|cred| cred.1 = user.clone());
        Ok(())
    }

    fn update_user_at(&mut self, i: usize, user: User) -> Result<(), Ctap2Error> {
        assert!(i < self.credentials.len());
        let id = self.credentials[i].2.id.clone();
        self.update_user(id, user)
    }

    fn list(&mut self) {
        let expected_rp_ids = self.rp_ids();
        let actual_rps = self.authenticator.list_rps();
        let actual_rp_ids: BTreeSet<_> = actual_rps.iter().map(|rp| rp.id.clone()).collect();
        assert_eq!(expected_rp_ids, actual_rp_ids);
        // TODO: check other RP fields than ID

        for rp_id in expected_rp_ids {
            assert!(actual_rps.iter().any(|rp| rp.id == rp_id));
            let expected_credentials = self.credentials(&rp_id);
            let actual_credentials = self.authenticator.list_credentials(&rp_id);
            let actual_credentials: BTreeSet<_> = actual_credentials.into_iter().collect();
            assert_eq!(expected_credentials, actual_credentials);
        }
    }

    fn rp_ids(&self) -> BTreeSet<String> {
        self.credentials
            .iter()
            .map(|(rp, _, _)| rp.id.clone())
            .collect()
    }

    fn credentials(&self, rp_id: &str) -> BTreeSet<(User, PubKeyCredDescriptor)> {
        self.credentials
            .iter()
            .filter(|(rp, _, _)| rp.id == rp_id)
            .map(|(_, user, data)| {
                (
                    user.clone(),
                    PubKeyCredDescriptor::new("public-key", data.id.clone()),
                )
            })
            .collect()
    }
}

fn generate_rp(i: usize) -> Rp {
    // TODO: set other fields than id
    let rp_id = format!("rp{i}");
    Rp::new(rp_id)
}

fn generate_user(i: u8) -> User {
    // TODO: set other fields than id
    let mut user = Vec::from(b"john.doe");
    user.push(i);
    User::new(user)
}

#[test]
fn test_list_credentials() {
    virt::run_ctap2(|device| {
        let authenticator = Authenticator::new(device).set_pin(b"123456");
        let mut cred_mgmt = CredMgmt::new(authenticator);
        for i in 0..10 {
            let rp = generate_rp(i);
            let user = generate_user(0);
            cred_mgmt.make_credential(rp, user).unwrap();
        }

        cred_mgmt.list();
    })
}

#[test]
fn test_list_credentials_multi() {
    virt::run_ctap2(|device| {
        let authenticator = Authenticator::new(device).set_pin(b"123456");
        let mut cred_mgmt = CredMgmt::new(authenticator);
        for (i, n) in [1, 3, 1, 3, 2].into_iter().enumerate() {
            let rp = generate_rp(i);
            for j in 0..n {
                let user = generate_user(j);
                cred_mgmt.make_credential(rp.clone(), user).unwrap();
            }
        }

        cred_mgmt.list();
    })
}

#[test]
fn test_list_credentials_delete() {
    virt::run_ctap2(|device| {
        let authenticator = Authenticator::new(device).set_pin(b"123456");
        let mut cred_mgmt = CredMgmt::new(authenticator);
        for (i, n) in [1, 3, 1, 3, 2].into_iter().enumerate() {
            let rp = generate_rp(i);
            for j in 0..n {
                let user = generate_user(j);
                cred_mgmt.make_credential(rp.clone(), user).unwrap();
            }
        }

        // deletes the only credential for rp2
        cred_mgmt.delete_credential_at(4).unwrap();
        // deletes one of three credentials for rp1
        cred_mgmt.delete_credential_at(2).unwrap();

        cred_mgmt.list();
    })
}

#[test]
fn test_list_credentials_update_user() {
    virt::run_ctap2(|device| {
        let authenticator = Authenticator::new(device).set_pin(b"123456");
        let mut cred_mgmt = CredMgmt::new(authenticator);
        for (i, n) in [1, 3, 1, 3, 2].into_iter().enumerate() {
            let rp = generate_rp(i);
            for j in 0..n {
                let user = generate_user(j);
                cred_mgmt.make_credential(rp.clone(), user).unwrap();
            }
        }

        // case 1: updates the only credential for rp2

        // changing the user ID fails
        let user = generate_user(98);
        assert_eq!(cred_mgmt.update_user_at(4, user), Err(Ctap2Error(0x02)));

        cred_mgmt.list();

        // setting the display name works
        let mut user = generate_user(0);
        user.display_name = Some("John Doe".into());
        cred_mgmt.update_user_at(4, user).unwrap();

        cred_mgmt.list();

        // case 2: updates one of three credentials for rp1

        // changing the user ID fails
        let user = generate_user(99);
        assert_eq!(cred_mgmt.update_user_at(2, user), Err(Ctap2Error(0x02)));

        cred_mgmt.list();

        // setting the display name works
        let mut user = generate_user(1);
        user.display_name = Some("John Doe".into());
        cred_mgmt.update_user_at(2, user).unwrap();

        cred_mgmt.list();
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

#[test]
fn test_filesystem_full_update_user() {
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
        let authenticator = Authenticator::new(device).set_pin(b"123456");
        let mut cred_mgmt = CredMgmt::new(authenticator);

        let mut i = 0;
        loop {
            let rp = generate_rp(i);
            let user = generate_user(0);
            let result = cred_mgmt.make_credential(rp, user);

            if result == Err(Ctap2Error(0x28)) {
                break;
            }
            result.unwrap();

            i += 1;
        }

        cred_mgmt.list();

        // filesystem is now full, we cannot create new credentials
        // but: we still want to be able to update existing credentials
        let mut user = generate_user(0);
        user.display_name = Some("John Doe".into());
        cred_mgmt.update_user_at(1, user).unwrap();

        cred_mgmt.list();
    })
}
