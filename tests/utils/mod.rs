use super::{
    virt::{Ctap2, Ctap2Error},
    webauthn::{ClientPin, KeyAgreementKey, PinToken, PublicKey, SharedSecret},
};

pub fn get_shared_secret(device: &Ctap2, platform_key_agreement: &KeyAgreementKey) -> SharedSecret {
    let reply = device.exec(ClientPin::new(2, 2)).unwrap();
    let authenticator_key_agreement: PublicKey = reply.key_agreement.unwrap().into();
    platform_key_agreement.shared_secret(&authenticator_key_agreement)
}

pub fn set_pin(
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

pub fn get_pin_hash_enc(shared_secret: &SharedSecret, pin: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(pin);
    let pin_hash = hasher.finalize();
    shared_secret.encrypt(&pin_hash[..16])
}

pub fn get_pin_token(
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
