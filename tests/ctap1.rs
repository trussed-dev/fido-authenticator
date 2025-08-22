#![cfg(feature = "dispatch")]

pub mod virt;
pub mod webauthn;

use ctaphid::{Device, HidDevice};
use hex_literal::hex;
use iso7816::{
    command::{class::Class, instruction::Instruction, CommandBuilder, ExpectedLen},
    response::Status,
};
use littlefs2_core::path;
use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
use x509_parser::public_key::PublicKey;

use virt::Options;

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

#[test]
fn test_authenticate_upgrade() {
    // manually extracted after running register on commit 79b05b576863236fe54750b18e862ce0801f2040
    let state: &[u8] = &hex!("A5726B65795F656E6372797074696F6E5F6B65795010926EC1ACF475A6ED273BD951BC4A6E706B65795F7772617070696E675F6B65795061743976EDACA263BD30DE70ADFBAF0B781A636F6E73656375746976655F70696E5F6D69736D617463686573006870696E5F68617368F66974696D657374616D7001");
    let key_encryption_key: &[u8] = &hex!("00020003A0BAA6066B22616147F242DEC9C4B450F6189A10EE036C36E697E647B2C1D3E1000000000000000000000000");
    let key_wrapping_key: &[u8] = &hex!("000200037719CE721FB206F9788BB7E550777C03795ECFE0B211AB7D50C5C2CE21B43E8E010000000000000000000000");
    let options = Options {
        files: vec![
            (path!("fido/dat/persistent-state.cbor").into(), state.into()),
            (
                path!("fido/sec/10926ec1acf475a6ed273bd951bc4a6e").into(),
                key_encryption_key.into(),
            ),
            (
                path!("fido/sec/61743976edaca263bd30de70adfbaf0b").into(),
                key_wrapping_key.into(),
            ),
        ],
        ..Default::default()
    };

    virt::run_ctaphid_with_options(options, |device| {
        let application = &hex!("f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4");
        let keyhandle = hex!("A3005878B3F2499ACECB2C08F437DEF0F41929BD4DCFBCA7D43E893B18799BA61F6D84A36EAFCB87D9E833AEA1FE68BABD27A4B89C83C32EC25B092D915D9EA207ECA4BDE5A06E3CDCCFE0E93600AC28A6A8A61E4A1C6881C67E252F00425672427CFC59463B097364F45FD050F8E6BE1C6CD45C1F7D9B5732E334A8014C533D8BF37EEF0D8D7D16B6DF025055B1A6492F5607139EF420D47051A5F3");
        let user_key = &hex!("04AE6B38AE33494A3A58A9FED8A1C5DA2683F510A69B9DE4D8849648485ECDCC21918E6124F6E0B71E7B3C5D92F08EC38D3161E236FF72743923141E97089AA2C4");
        let register = Register {
            user_key: VerifyingKey::from_sec1_bytes(user_key).unwrap(),
            keyhandle: keyhandle.into(),
        };

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
