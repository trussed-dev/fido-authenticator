// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for opcard.
//! Run with cargo run --example usbip --features trussed/virt,dispatch

use trussed::backend::{BackendId, CoreOnly};
use trussed::types::Location;
use trussed::virt::{self, Client, Ram, UserInterface};
use trussed::{ClientImplementation, Platform};
use trussed_usbip::ClientBuilder;

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

pub use trussed_hkdf::virt::Dispatcher;

type VirtClient = ClientImplementation<trussed_usbip::Service<Ram, Dispatcher>, Dispatcher>;

struct FidoApp {
    fido: fido_authenticator::Authenticator<fido_authenticator::Conforming, VirtClient>,
}

impl trussed_usbip::Apps<'static, VirtClient, Dispatcher> for FidoApp {
    type Data = ();
    fn new<B: ClientBuilder<VirtClient, Dispatcher>>(builder: &B, _data: ()) -> Self {
        let large_blogs = Some(fido_authenticator::LargeBlobsConfig {
            location: Location::External,
            #[cfg(feature = "chunked")]
            max_size: 4096,
        });

        FidoApp {
            fido: fido_authenticator::Authenticator::new(
                builder.build("fido", &[BackendId::Core]),
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
        f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'static>]) -> T,
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
    trussed_usbip::Builder::new(virt::Ram::default(), options)
        .dispatch(Dispatcher)
        .build::<FidoApp>()
        .exec(|_platform| {});
}
