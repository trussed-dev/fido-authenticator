//! Dispatch of incoming requests over CTAPHID or NFC APDUs into CTAP1 and CTAP2.

mod apdu;
mod ctaphid;

#[allow(unused_imports)]
use crate::msp;
use crate::{Authenticator, TrussedRequirements, UserPresence};

use ctap_types::{ctap1, ctap2};
use iso7816::Status;

impl<UP, T> iso7816::App for Authenticator<UP, T>
where
    UP: UserPresence,
{
    fn aid(&self) -> iso7816::Aid {
        iso7816::Aid::new(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
    }
}

#[inline(never)]
/// Deserialize U2F, call authenticator, serialize response *Result*.
fn handle_ctap1_from_hid<T, UP>(
    authenticator: &mut Authenticator<UP, T>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) where
    T: TrussedRequirements,
    UP: UserPresence,
{
    debug!(
        "handle CTAP1: remaining stack: {} bytes",
        msp() - 0x2000_0000
    );
    {
        let command = apdu_dispatch::Command::try_from(data);
        if let Err(status) = command {
            let code: [u8; 2] = (Status::IncorrectDataParameter).into();
            debug!("CTAP1 parse error: {:?} ({})", status, hex_str!(&code));
            response.extend_from_slice(&code).ok();
            return;
        }

        // debug!("1A SP: {:X}", msp());
        match try_handle_ctap1(authenticator, &command.unwrap(), response) {
            Ok(()) => {
                debug!("U2F response {} bytes", response.len());
                // Need to add x9000 success code (normally the apdu-dispatch does this, but
                // since u2f uses apdus over ctaphid, we must do it here.)
                response.extend_from_slice(&[0x90, 0x00]).ok();
            }
            Err(status) => {
                let code: [u8; 2] = status.into();
                debug!("CTAP1 error: {:?} ({})", status, hex_str!(&code));
                response.extend_from_slice(&code).ok();
            }
        }
    }
    // debug!("1B SP: {:X}", msp());
    debug!("end handle CTAP1");
}

#[inline(never)]
/// Deserialize CBOR, call authenticator, serialize response *Result*.
fn handle_ctap2<T, UP>(
    authenticator: &mut Authenticator<UP, T>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) where
    T: TrussedRequirements,
    UP: UserPresence,
{
    debug!(
        "handle CTAP2: remaining stack: {} bytes",
        msp() - 0x2000_0000
    );

    debug!("1a SP: {:X}", msp());
    // debug!("2A SP: {:X}", msp());
    if let Err(error) = try_handle_ctap2(authenticator, data, response) {
        debug!("CTAP2 error: {:02X}", error);
        response.push(error).ok();
    }
    // debug!("2B SP: {:X}", msp());
    debug!("end handle CTAP2");
}

#[inline(never)]
fn try_handle_ctap1<T, UP>(
    authenticator: &mut Authenticator<UP, T>,
    command: &apdu_dispatch::Command,
    response: &mut apdu_dispatch::response::Data,
) -> Result<(), Status>
where
    T: TrussedRequirements,
    UP: UserPresence,
{
    // Annoyance: We can't load in fido-authenticator constructor.
    authenticator
        .state
        .persistent
        .load_if_not_initialised(&mut authenticator.trussed);

    // let command = apdu_dispatch::Command::try_from(data)
    //     .map_err(|_| Status::IncorrectDataParameter)?;
    // let ctap_request = ctap1::Request::try_from(&command)
    //     .map_err(|_| Status::IncorrectDataParameter)?;
    // drop(command);
    // let ctap_response = ctap1::Authenticator::call_ctap1(authenticator, &ctap_request)?;
    // drop(ctap_request);

    // Goal of these nested scopes is to keep stack small.
    let ctap_response = {
        let ctap_request = ctap1::Request::try_from(command)?;
        ctap1::Authenticator::call_ctap1(authenticator, &ctap_request)?
    };
    // debug!("1b SP: {:X}", msp());

    ctap_response.serialize(response).ok();
    Ok(())
}

#[inline(never)]
fn try_handle_ctap2<T, UP>(
    authenticator: &mut Authenticator<UP, T>,
    data: &[u8],
    response: &mut apdu_dispatch::response::Data,
) -> Result<(), u8>
where
    T: TrussedRequirements,
    UP: UserPresence,
{
    // Annoyance: We can't load in fido-authenticator constructor.
    authenticator
        .state
        .persistent
        .load_if_not_initialised(&mut authenticator.trussed);

    debug!(
        "try_handle CTAP2: remaining stack: {} bytes",
        msp() - 0x2000_0000
    );

    // let ctap_request = ctap2::Request::deserialize(data)
    //     .map_err(|error| error as u8)?;
    // let ctap_response = ctap2::Authenticator::call_ctap2(authenticator, &ctap_request)
    //         .map_err(|error| error as u8)?;

    // Goal of these nested scopes is to keep stack small.
    let ctap_response = try_get_ctap2_response(authenticator, data)?;
    ctap_response.serialize(response);
    Ok(())
}

#[inline(never)]
fn try_get_ctap2_response<T, UP>(
    authenticator: &mut Authenticator<UP, T>,
    data: &[u8],
) -> Result<ctap2::Response, u8>
where
    T: TrussedRequirements,
    UP: UserPresence,
{
    // Annoyance: We can't load in fido-authenticator constructor.
    authenticator
        .state
        .persistent
        .load_if_not_initialised(&mut authenticator.trussed);

    debug!(
        "try_get CTAP2: remaining stack: {} bytes",
        msp() - 0x2000_0000
    );

    // Goal of these nested scopes is to keep stack small.
    let ctap_request = ctap2::Request::deserialize(data)
        .map(|request| {
            info!("Received CTAP2 request {:?}", request_operation(&request));
            trace!("CTAP2 request: {:?}", request);
            request
        })
        .map_err(|error| {
            error!("Failed to deserialize CTAP2 request: {:?}", error);
            trace!("The problematic input data was: {}", hex_str!(data));
            error as u8
        })?;
    debug!("2a SP: {:X}", msp());
    use ctap2::Authenticator;
    authenticator
        .call_ctap2(&ctap_request)
        .map(|response| {
            info!("Sending CTAP2 response {:?}", response_operation(&response));
            trace!("CTAP2 response: {:?}", response);
            response
        })
        .map_err(|error| {
            info!("CTAP2 error: {:?}", error);
            error as u8
        })
}

#[allow(unused)]
fn request_operation(request: &ctap2::Request) -> ctap2::Operation {
    match request {
        ctap2::Request::MakeCredential(_) => ctap2::Operation::MakeCredential,
        ctap2::Request::GetAssertion(_) => ctap2::Operation::GetAssertion,
        ctap2::Request::GetNextAssertion => ctap2::Operation::GetNextAssertion,
        ctap2::Request::GetInfo => ctap2::Operation::GetInfo,
        ctap2::Request::ClientPin(_) => ctap2::Operation::ClientPin,
        ctap2::Request::Reset => ctap2::Operation::Reset,
        ctap2::Request::CredentialManagement(_) => ctap2::Operation::CredentialManagement,
        ctap2::Request::Selection => ctap2::Operation::Selection,
        ctap2::Request::LargeBlobs(_) => ctap2::Operation::LargeBlobs,
        ctap2::Request::Vendor(operation) => ctap2::Operation::Vendor(*operation),
    }
}

#[allow(unused)]
fn response_operation(request: &ctap2::Response) -> Option<ctap2::Operation> {
    match request {
        ctap2::Response::MakeCredential(_) => Some(ctap2::Operation::MakeCredential),
        ctap2::Response::GetAssertion(_) => Some(ctap2::Operation::GetAssertion),
        ctap2::Response::GetNextAssertion(_) => Some(ctap2::Operation::GetNextAssertion),
        ctap2::Response::GetInfo(_) => Some(ctap2::Operation::GetInfo),
        ctap2::Response::ClientPin(_) => Some(ctap2::Operation::ClientPin),
        ctap2::Response::Reset => Some(ctap2::Operation::Reset),
        ctap2::Response::CredentialManagement(_) => Some(ctap2::Operation::CredentialManagement),
        ctap2::Response::Selection => Some(ctap2::Operation::Selection),
        ctap2::Response::LargeBlobs(_) => Some(ctap2::Operation::LargeBlobs),
        ctap2::Response::Vendor => None,
    }
}
