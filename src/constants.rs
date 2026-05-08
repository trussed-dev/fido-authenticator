//! Constants.

use trussed_core::types::{CertId, KeyId};

pub const FIDO2_UP_TIMEOUT: u32 = 30_000;
pub const U2F_UP_TIMEOUT: u32 = 250;

pub const ATTESTATION_CERT_ID: CertId = CertId::from_special(0);
pub const ATTESTATION_KEY_ID: KeyId = KeyId::from_special(0);

pub const MAX_RESIDENT_CREDENTIALS_GUESSTIMATE: u32 = 100;

/// Maximum number of bytes of `credBlob` data we accept per credential
/// (CTAP 2.1 §11.1; spec floor is 32). Reported in `authenticatorGetInfo`
/// as `maxCredBlobLength`.
pub const MAX_CRED_BLOB_LENGTH: usize = 32;
