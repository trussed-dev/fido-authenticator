//! TODO: T

use core::{cmp, convert::TryFrom, num::NonZeroU32};

use littlefs2_core::{Path, PathBuf};
use trussed_core::{
    syscall, try_syscall,
    types::{DirEntry, Location},
};

use cosey::PublicKey;
use ctap_types::{
    ctap2::credential_management::{CredentialProtectionPolicy, Response},
    webauthn::{PublicKeyCredentialDescriptorRef, PublicKeyCredentialUserEntity},
    ByteArray, Error,
};

use super::RK_DIR;
use crate::{
    constants::MAX_RESIDENT_CREDENTIALS_GUESSTIMATE,
    credential::FullCredential,
    state::{CredentialManagementEnumerateCredentials, CredentialManagementEnumerateRps},
    Authenticator, Result, TrussedRequirements, UserPresence,
};

pub(crate) struct CredentialManagement<'a, UP, T>
where
    UP: UserPresence,
{
    authnr: &'a mut Authenticator<UP, T>,
}

impl<UP, T> core::ops::Deref for CredentialManagement<'_, UP, T>
where
    UP: UserPresence,
{
    type Target = Authenticator<UP, T>;
    fn deref(&self) -> &Self::Target {
        self.authnr
    }
}

impl<UP, T> core::ops::DerefMut for CredentialManagement<'_, UP, T>
where
    UP: UserPresence,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.authnr
    }
}

impl<'a, UP, T> CredentialManagement<'a, UP, T>
where
    UP: UserPresence,
{
    pub fn new(authnr: &'a mut Authenticator<UP, T>) -> Self {
        Self { authnr }
    }
}

/// Get the hex hashed ID of the RP from the filename of a RP directory OR a "new" RK path
fn get_rp_id_hex(entry: &DirEntry) -> &str {
    get_rp_id_hex_from_file_name(entry.file_name().as_str())
}

fn get_rp_id_hex_from_file_name(file_name: &str) -> &str {
    file_name
        .split('.')
        .next()
        .expect("Split always returns at least one empty string")
}

impl<UP, T> CredentialManagement<'_, UP, T>
where
    UP: UserPresence,
    T: TrussedRequirements,
{
    pub fn get_creds_metadata(&mut self) -> Result<Response> {
        info!("get metadata");
        let mut response: Response = Default::default();

        let credential_count = self.count_credentials()?;
        // We have a fixed limit determined by the configuration and an estimated limit determined
        // by the available space on the filesystem.  The effective limit is the lower of the two.
        let max_remaining = self
            .config
            .max_resident_credential_count
            .unwrap_or(MAX_RESIDENT_CREDENTIALS_GUESSTIMATE)
            .saturating_sub(credential_count);
        let estimate_remaining = self.estimate_remaining().unwrap_or(u32::MAX);

        response.existing_resident_credentials_count = Some(credential_count);
        response.max_possible_remaining_residential_credentials_count =
            Some(cmp::min(max_remaining, estimate_remaining));

        Ok(response)
    }

    pub fn count_credentials(&mut self) -> Result<u32> {
        let dir = PathBuf::from(RK_DIR);
        let mut num_rks = 0;

        let mut maybe_next =
            syscall!(self
                .trussed
                .read_dir_first(Location::Internal, dir.clone(), None))
            .entry;

        while let Some(rp) = maybe_next {
            if rp.metadata().is_dir() {
                error!("Migration not complete");
                return Err(Error::Other);
            }

            num_rks += 1;
            maybe_next = syscall!(self.trussed.read_dir_next()).entry;
        }

        Ok(num_rks)
    }

    pub fn first_relying_party(&mut self) -> Result<Response> {
        info!("first rp");

        let mut response = Response::default();
        let dir = PathBuf::from(RK_DIR);

        let maybe_first_rp =
            syscall!(self
                .trussed
                .read_dir_first(Location::Internal, dir.clone(), None))
            .entry;

        let Some(first_rp) = maybe_first_rp else {
            response.total_rps = Some(0);
            return Ok(response);
        };

        // The first one counts
        let mut total_rps = 1;

        if first_rp.metadata().is_dir() {
            warn!("Migration did not finish");
            return Err(Error::Other);
        }

        let first_credential_data = syscall!(self
            .trussed
            .read_file(Location::Internal, first_rp.path().into()))
        .data;

        let credential = FullCredential::deserialize(&first_credential_data)?;
        let rp_id_hash: [u8; 32] = syscall!(self.trussed.hash_sha256(credential.rp.id().as_ref()))
            .hash
            .as_slice()
            .try_into()
            .map_err(|_| Error::Other)?;

        let mut current_rp = first_rp;

        let mut current_id_hex = get_rp_id_hex(&current_rp);

        while let Some(entry) = syscall!(self.trussed.read_dir_next()).entry {
            let id_hex = get_rp_id_hex(&entry);
            if id_hex != current_id_hex {
                total_rps += 1;
                current_rp = entry;
                current_id_hex = get_rp_id_hex(&current_rp)
            }
        }

        if let Some(remaining) = NonZeroU32::new(total_rps - 1) {
            self.state.runtime.cached_rp = Some(CredentialManagementEnumerateRps {
                remaining,
                rp_id_hash,
            });
        }

        response.total_rps = Some(total_rps);
        response.rp_id_hash = Some(ByteArray::new(rp_id_hash));
        response.rp = Some(credential.data.rp.into());
        Ok(response)
    }

    pub fn next_relying_party(&mut self) -> Result<Response> {
        let CredentialManagementEnumerateRps {
            remaining,
            rp_id_hash: last_rp_id_hash,
        } = self
            .state
            .runtime
            .cached_rp
            .clone()
            .ok_or(Error::NotAllowed)?;

        let filename = super::rp_file_name_prefix(&last_rp_id_hash);

        let dir = PathBuf::from(RK_DIR);

        let maybe_next_rp = syscall!(self.trussed.read_dir_first_alphabetical(
            Location::Internal,
            dir,
            Some(filename.clone())
        ))
        .entry;

        let mut response = Response::default();

        let Some(current_rp) = maybe_next_rp else {
            return Err(Error::NotAllowed);
        };

        let current_id_hex = get_rp_id_hex(&current_rp);

        debug_assert!(current_rp
            .file_name()
            .as_str()
            .starts_with(filename.as_str()));

        while let Some(entry) = syscall!(self.trussed.read_dir_next()).entry {
            let id_hex = get_rp_id_hex(&entry);
            if id_hex == current_id_hex {
                continue;
            }

            if entry.metadata().is_dir() {
                warn!("While iterating: migration is not finished");
                return Err(Error::Other);
            }

            let data = syscall!(self
                .trussed
                .read_file(Location::Internal, entry.path().into()))
            .data;

            let credential = FullCredential::deserialize(&data)?;
            let rp_id_hash: [u8; 32] =
                syscall!(self.trussed.hash_sha256(credential.rp.id().as_ref()))
                    .hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Other)?;
            response.rp_id_hash = Some(ByteArray::new(rp_id_hash));
            response.rp = Some(credential.data.rp.into());

            if let Some(new_remaining) = NonZeroU32::new(remaining.get() - 1) {
                self.state.runtime.cached_rp = Some(CredentialManagementEnumerateRps {
                    remaining: new_remaining,
                    rp_id_hash,
                });
            }

            return Ok(response);
        }

        Err(Error::NotAllowed)
    }

    pub fn first_credential(&mut self, rp_id_hash: &[u8; 32]) -> Result<Response> {
        info!("first credential");

        self.state.runtime.cached_rk = None;

        let rp_dir_start = super::rp_file_name_prefix(rp_id_hash);

        let mut num_rks = 0;

        let mut maybe_entry = syscall!(self.trussed.read_dir_first_alphabetical(
            Location::Internal,
            PathBuf::from(RK_DIR),
            Some(rp_dir_start.clone())
        ))
        .entry;

        let mut first_rk = None;

        while let Some(entry) = maybe_entry {
            if !entry
                .file_name()
                .as_str()
                .starts_with(rp_dir_start.as_str())
            {
                // We got past all credentials for the relevant RP
                break;
            }

            if entry.file_name() == &*rp_dir_start {
                // This is the case where we
                debug_assert!(entry.metadata().is_dir());
                error!("Migration did not run");
                return Err(Error::Other);
            }

            first_rk = first_rk.or(Some(entry));
            num_rks += 1;

            maybe_entry = syscall!(self.trussed.read_dir_next()).entry;
        }

        let first_rk = first_rk.ok_or(Error::NoCredentials)?;

        // extract data required into response
        let mut response = self.extract_response_from_credential_file(first_rk.path())?;
        response.total_credentials = Some(num_rks);

        // cache state for next call
        if num_rks > 1 {
            // let rp_id_hash = response.rp_id_hash.as_ref().unwrap().clone();
            self.state.runtime.cached_rk = Some(CredentialManagementEnumerateCredentials {
                remaining: num_rks - 1,
                prev_filename: first_rk.file_name().into(),
            });
        }

        Ok(response)
    }

    pub fn next_credential(&mut self) -> Result<Response> {
        info!("next credential");

        let cache = self
            .state
            .runtime
            .cached_rk
            .take()
            .ok_or(Error::NotAllowed)?;

        let CredentialManagementEnumerateCredentials {
            remaining,
            prev_filename,
        } = cache;

        let rp_id_hex = get_rp_id_hex_from_file_name(prev_filename.as_str());
        syscall!(self.trussed.read_dir_first_alphabetical(
            Location::Internal,
            PathBuf::from(RK_DIR),
            Some(prev_filename.clone()),
        ))
        .entry;

        // The previous entry was already read. Skip to the next
        let Some(entry) = syscall!(self.trussed.read_dir_next()).entry else {
            return Err(Error::NoCredentials);
        };

        if get_rp_id_hex(&entry) != rp_id_hex {
            // We reached the end of the credentials for the rp
            return Err(Error::NoCredentials);
        }

        if entry.metadata().is_dir() {
            warn!("Migration did not finish");
            return Err(Error::Other);
        }

        let response = self.extract_response_from_credential_file(entry.path())?;

        // cache state for next call
        if remaining > 1 {
            self.state.runtime.cached_rk = Some(CredentialManagementEnumerateCredentials {
                remaining: remaining - 1,
                prev_filename: entry.file_name().into(),
            });
        }

        Ok(response)
    }

    fn extract_response_from_credential_file(&mut self, rk_path: &Path) -> Result<Response> {
        // user (0x06)
        // credentialID (0x07): PublicKeyCredentialDescriptor
        // publicKey (0x08): public key of the credential in COSE_Key format
        // totalCredentials (0x09): total number of credentials for this RP
        // credProtect (0x0A): credential protection policy

        let serialized = syscall!(self.trussed.read_file(Location::Internal, rk_path.into(),)).data;

        let credential = FullCredential::deserialize(&serialized)
            // this may be a confusing error message
            .map_err(|_| Error::InvalidCredential)?;

        // now fill response

        // why these contortions to get kek. sheesh
        let authnr = &mut self.authnr;
        let kek = authnr
            .state
            .persistent
            .key_encryption_key(&mut authnr.trussed)?;

        let credential_id = credential.id(&mut self.trussed, kek, None)?;

        use crate::credential::Key;
        let private_key = match credential.key {
            Key::ResidentKey(key) => key,
            _ => return Err(Error::InvalidCredential),
        };

        use crate::SigningAlgorithm;

        let algorithm = SigningAlgorithm::try_from(credential.algorithm)?;
        let cose_public_key = algorithm.derive_public_key(&mut self.trussed, private_key);
        let cose_public_key = match algorithm {
            SigningAlgorithm::P256 => {
                PublicKey::P256Key(ctap_types::serde::cbor_deserialize(&cose_public_key).unwrap())
            }
            SigningAlgorithm::Ed25519 => PublicKey::Ed25519Key(
                ctap_types::serde::cbor_deserialize(&cose_public_key).unwrap(),
            ),
        };
        let cred_protect = match credential.cred_protect {
            Some(x) => Some(x),
            None => Some(CredentialProtectionPolicy::Optional),
        };

        let mut response = Response::default();
        response.user = Some(credential.data.user.into());
        response.credential_id = Some(credential_id.into());
        response.public_key = Some(cose_public_key);
        response.cred_protect = cred_protect;
        response.large_blob_key = credential.data.large_blob_key;
        response.third_party_payment =
            Some(credential.data.third_party_payment.unwrap_or_default());
        Ok(response)
    }

    fn find_credential(
        &mut self,
        credential: &PublicKeyCredentialDescriptorRef<'_>,
    ) -> Option<PathBuf> {
        let credential_id_hash = self.hash(credential.id);
        let mut hex = [b'0'; 16];
        let hex_str = super::format_hex(&credential_id_hash[..8], &mut hex);
        let dir = PathBuf::from(RK_DIR);

        let mut maybe_entry =
            try_syscall!(self.trussed.read_dir_first(Location::Internal, dir, None))
                .ok()?
                .entry;
        while let Some(entry) = maybe_entry {
            if entry.file_name().as_str().ends_with(&hex_str) {
                return Some(entry.path().into());
            }
            maybe_entry = syscall!(self.trussed.read_dir_next()).entry;
        }
        None
    }

    pub fn delete_credential(
        &mut self,
        credential_descriptor: &PublicKeyCredentialDescriptorRef<'_>,
    ) -> Result<Response> {
        info!("delete credential");
        let rk_path = self
            .find_credential(credential_descriptor)
            .ok_or(Error::InvalidCredential)?;

        // DELETE
        self.delete_resident_key_by_path(&rk_path)?;

        // just return OK
        let response = Default::default();
        Ok(response)
    }

    pub fn update_user_information(
        &mut self,
        credential_descriptor: &PublicKeyCredentialDescriptorRef<'_>,
        user: &PublicKeyCredentialUserEntity,
    ) -> Result<Response> {
        info!("update user information");

        // locate and parse existing credential
        let rk_path = self
            .find_credential(credential_descriptor)
            .ok_or(Error::NoCredentials)?;
        let serialized = syscall!(self.trussed.read_file(Location::Internal, rk_path.clone())).data;
        let mut credential =
            FullCredential::deserialize(&serialized).map_err(|_| Error::InvalidCredential)?;

        // TODO: check remaining space, return KeyStoreFull

        // the updated user ID must match the stored user ID
        if credential.user.id() != &user.id {
            error!("updated user ID does not match original user ID");
            return Err(Error::InvalidParameter);
        }

        // update user name and display name unless the values are not set or empty
        let credential_user = credential.data.user.as_mut();
        credential_user.name = user.name.as_ref().filter(|s| !s.is_empty()).cloned();
        credential_user.display_name = user
            .display_name
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned();

        // write updated credential
        let serialized = credential.serialize()?;
        try_syscall!(self
            .trussed
            .write_file(Location::Internal, rk_path, serialized, None))
        .map_err(|_| Error::KeyStoreFull)?;

        Ok(Default::default())
    }
}
