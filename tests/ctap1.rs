#![cfg(feature = "dispatch")]

#[allow(unused)]
mod virt;
#[allow(unused)]
mod webauthn;

use ctaphid::{Device, HidDevice};
use hex_literal::hex;
use iso7816::{
    command::{class::Class, instruction::Instruction, CommandBuilder, ExpectedLen},
    response::Status,
};
use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
use x509_parser::public_key::PublicKey;

#[test]
fn test_version() {
    virt::run_ctaphid(|device| {
        let response = version(&device);
        assert_eq!(response, b"U2F_V2".as_slice());
    })
}

#[test]
fn test_authenticate() {
    virt::run_ctaphid(|device| {
        let challenge = &hex!("4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb");
        let application = &hex!("f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4");
        let register = register(&device, challenge, application);

        let challenge = &hex!("ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57");

        // check-only
        let err = authenticate(&device, 7, challenge, application, &register)
            .err()
            .unwrap();
        assert_eq!(err, Status::ConditionsOfUseNotSatisfied);

        // enforce user presence
        let response = authenticate(&device, 3, challenge, application, &register).unwrap();
        assert_eq!(response.user_presence & 1, 1);
        assert_eq!(response.counter, 1);

        // don’t enforce user presence
        let response = authenticate(&device, 8, challenge, application, &register).unwrap();
        assert_eq!(response.user_presence & 1, 0);
        assert_eq!(response.counter, 2);
    });
}

#[test]
fn test_authenticate_wrong_application() {
    virt::run_ctaphid(|device| {
        let challenge = &hex!("4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb");
        let mut application =
            hex!("f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4");
        let register = register(&device, challenge, &application);
        application.reverse();

        let challenge = &hex!("ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57");
        for mode in [3, 7, 8] {
            let err = authenticate(&device, mode, challenge, &application, &register)
                .err()
                .unwrap();
            assert_eq!(err, Status::IncorrectDataParameter);
        }
    });
}

#[test]
fn test_authenticate_wrong_keyhandle() {
    virt::run_ctaphid(|device| {
        let challenge = &hex!("4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb");
        let application = &hex!("f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4");
        let mut register = register(&device, challenge, application);
        register.keyhandle.reverse();

        let challenge = &hex!("ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57");
        for mode in [3, 7, 8] {
            let err = authenticate(&device, mode, challenge, application, &register)
                .err()
                .unwrap();
            assert_eq!(err, Status::IncorrectDataParameter);
        }
    });
}

fn version<D: HidDevice>(device: &Device<D>) -> Vec<u8> {
    let command = build_command(3, 0, &[]);
    exec(device, &command).unwrap()
}

struct Register {
    user_key: VerifyingKey,
    keyhandle: Vec<u8>,
}

fn register<D: HidDevice>(
    device: &Device<D>,
    challenge: &[u8; 32],
    application: &[u8; 32],
) -> Register {
    let mut request = [0; 64];
    request[..32].copy_from_slice(challenge);
    request[32..].copy_from_slice(application);
    let command = build_command(1, 0, &request);
    let response = exec(device, &command).unwrap();

    let (first, response) = response.split_first().unwrap();
    let (user_key, response) = response.split_at(65);
    let (keyhandle_len, response) = response.split_first().unwrap();
    let (keyhandle, response) = response.split_at(usize::from(*keyhandle_len));
    let (signature, cert) = x509_parser::parse_x509_certificate(response).unwrap();

    assert_eq!(*first, 0x05);

    let mut message = Vec::new();
    message.push(0x00);
    message.extend_from_slice(application);
    message.extend_from_slice(challenge);
    message.extend_from_slice(keyhandle);
    message.extend_from_slice(user_key);

    let signature = DerSignature::from_bytes(signature).unwrap();
    let public_key = cert.tbs_certificate.subject_pki.parsed().unwrap();
    let PublicKey::EC(ec_point) = public_key else {
        panic!("unexpected public key in attestation certificate");
    };
    let public_key = VerifyingKey::from_sec1_bytes(ec_point.data()).unwrap();
    public_key.verify(&message, &signature).unwrap();

    Register {
        user_key: VerifyingKey::from_sec1_bytes(user_key).unwrap(),
        keyhandle: keyhandle.into(),
    }
}

struct Authenticate {
    user_presence: u8,
    counter: u32,
}

fn authenticate<D: HidDevice>(
    device: &Device<D>,
    mode: u8,
    challenge: &[u8; 32],
    application: &[u8; 32],
    register: &Register,
) -> Result<Authenticate, Status> {
    let mut request = Vec::new();
    request.extend_from_slice(challenge);
    request.extend_from_slice(application);
    request.push(register.keyhandle.len().try_into().unwrap());
    request.extend_from_slice(&register.keyhandle);
    let command = build_command(2, mode, &request);
    let response = exec(device, &command)?;

    let (user_presence, response) = response.split_first().unwrap();
    let (counter, signature) = response.split_at(4);

    let mut message = Vec::new();
    message.extend_from_slice(application);
    message.push(*user_presence);
    message.extend_from_slice(counter);
    message.extend_from_slice(challenge);

    let signature = DerSignature::from_bytes(signature).unwrap();
    register.user_key.verify(&message, &signature).unwrap();

    Ok(Authenticate {
        user_presence: *user_presence,
        counter: u32::from_be_bytes(counter.try_into().unwrap()),
    })
}

fn exec<D: HidDevice>(device: &Device<D>, command: &[u8]) -> Result<Vec<u8>, Status> {
    let mut response = device.ctap1(command).unwrap();
    let low = response.pop().unwrap();
    let high = response.pop().unwrap();
    let status = u16::from_be_bytes([high, low]);
    let status = Status::from_u16(status);
    if status == Status::Success {
        Ok(response)
    } else {
        Err(status)
    }
}

fn build_command(ins: u8, p1: u8, data: &[u8]) -> heapless::Vec<u8, 1024> {
    let builder = CommandBuilder::new(
        Class::from_byte(0).unwrap(),
        Instruction::from(ins),
        p1,
        0,
        data,
        ExpectedLen::Max,
    );
    let mut buffer = heapless::Vec::new();
    builder.serialize_into(&mut buffer).unwrap();
    buffer
}
