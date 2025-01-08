// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for opcard.
//! Run with cargo run --example usbip --features dispatch

use littlefs2_core::path;
use trussed::{
    backend::BackendId,
    client::ClientBuilder,
    service::Service,
    types::Location,
    virt::{Platform, Ram, StoreProvider},
};
use trussed_staging::virt::{BackendIds, Dispatcher};
use trussed_usbip::{Client, Syscall};

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

type VirtClient = Client<Dispatcher>;

struct FidoApp {
    fido: fido_authenticator::Authenticator<fido_authenticator::Conforming, VirtClient>,
}

impl<S: StoreProvider> trussed_usbip::Apps<'static, S, Dispatcher> for FidoApp {
    type Data = ();
    fn new(service: &mut Service<Platform<S>, Dispatcher>, syscall: Syscall, _data: ()) -> Self {
        let large_blogs = Some(fido_authenticator::LargeBlobsConfig {
            location: Location::External,
            #[cfg(feature = "chunked")]
            max_size: 4096,
        });

        let client = ClientBuilder::new(path!("fido"))
            .backends(&[
                BackendId::Core,
                BackendId::Custom(BackendIds::StagingBackend),
            ])
            .prepare(service)
            .expect("failed to create client")
            .build(syscall);
        FidoApp {
            fido: fido_authenticator::Authenticator::new(
                client,
                fido_authenticator::Conforming {},
                fido_authenticator::Config {
                    max_msg_size: usbd_ctaphid::constants::MESSAGE_SIZE,
                    skip_up_timeout: None,
                    max_resident_credential_count: Some(10),
                    large_blobs: large_blogs,
                    nfc_transport: false,
                },
            ),
        }
    }

    fn with_ctaphid_apps<T>(
        &mut self,
        f: impl FnOnce(
            &mut [&mut dyn ctaphid_dispatch::app::App<
                'static,
                { ctaphid_dispatch::MESSAGE_SIZE },
            >],
        ) -> T,
    ) -> T {
        f(&mut [&mut self.fido])
    }
}

fn main() {
    env_logger::init();

    let options = trussed_usbip::Options {
        manufacturer: Some(MANUFACTURER.to_owned()),
        product: Some(PRODUCT.to_owned()),
        serial_number: Some("TEST".into()),
        vid: VID,
        pid: PID,
    };
    trussed_usbip::Builder::new(Ram::default(), options)
        .dispatch(Dispatcher::default())
        .build::<FidoApp>()
        .exec(|_platform| {});
}
