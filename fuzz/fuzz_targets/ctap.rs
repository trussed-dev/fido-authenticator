#![no_main]

use ctap_types::{authenticator::Request, ctap1::Authenticator as _, ctap2::Authenticator as _};
use fido_authenticator::{Authenticator, Config, Conforming};
use trussed_staging::virt;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|requests: Vec<Request<'_>>| {
    virt::with_ram_client("fido", |client| {
        let mut authenticator = Authenticator::new(
            client,
            Conforming {},
            Config {
                max_msg_size: 0,
                skip_up_timeout: None,
                max_resident_credential_count: None,
                large_blobs: None,
                nfc_transport: false,
            },
        );

        for request in requests {
            match request {
                Request::Ctap1(request) => {
                    authenticator.call_ctap1(&request).ok();
                }
                Request::Ctap2(request) => {
                    authenticator.call_ctap2(&request).ok();
                }
            }
        }
    });
});
