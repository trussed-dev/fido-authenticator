// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for opcard.
//! Run with cargo run --example usbip --features trussed/virt,dispatch

use trussed::api::{reply, request};
use trussed::backend::BackendId;
use trussed::serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl};
use trussed::service::ServiceResources;
use trussed::types::{Location, NoData};
use trussed::virt::{self, Ram};
use trussed::{ClientImplementation, Error, Platform};
use trussed_hkdf::{HkdfBackend, HkdfExtension};
use trussed_usbip::ClientBuilder;

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

#[derive(Default)]
struct Context {
    #[cfg(feature = "chunked")]
    staging: trussed_staging::StagingContext,
}

#[derive(Default)]
struct Dispatch {
    #[cfg(feature = "chunked")]
    staging: trussed_staging::StagingBackend,
}

impl ExtensionDispatch for Dispatch {
    type BackendId = Backend;
    type Context = Context;
    type ExtensionId = Extension;

    fn extension_request<P: Platform>(
        &mut self,
        backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut trussed::types::Context<Self::Context>,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        match backend {
            #[cfg(feature = "chunked")]
            Backend::Staging => match extension {
                Extension::Chunked => self.staging.extension_request_serialized(
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                _ => Err(Error::RequestNotAvailable),
            },
            Backend::Hkdf => match extension {
                Extension::Hkdf => HkdfBackend.extension_request_serialized(
                    &mut ctx.core,
                    &mut NoData,
                    request,
                    resources,
                ),
                #[cfg(feature = "chunked")]
                _ => Err(Error::RequestNotAvailable),
            },
        }
    }
}

#[cfg(feature = "chunked")]
impl ExtensionId<trussed_chunked::ChunkedExtension> for Dispatch {
    type Id = Extension;

    const ID: Extension = Extension::Chunked;
}

impl ExtensionId<HkdfExtension> for Dispatch {
    type Id = Extension;

    const ID: Extension = Extension::Hkdf;
}

enum Backend {
    #[cfg(feature = "chunked")]
    Staging,
    Hkdf,
}

enum Extension {
    #[cfg(feature = "chunked")]
    Chunked,
    Hkdf,
}

impl From<Extension> for u8 {
    fn from(extension: Extension) -> u8 {
        match extension {
            #[cfg(feature = "chunked")]
            Extension::Chunked => 0,
            Extension::Hkdf => 1,
        }
    }
}

impl TryFrom<u8> for Extension {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self, Error> {
        match id {
            #[cfg(feature = "chunked")]
            0 => Ok(Self::Chunked),
            1 => Ok(Self::Hkdf),
            _ => Err(Error::InternalError),
        }
    }
}

type VirtClient = ClientImplementation<trussed_usbip::Service<Ram, Dispatch>, Dispatch>;

struct FidoApp {
    fido: fido_authenticator::Authenticator<fido_authenticator::Conforming, VirtClient>,
}

impl trussed_usbip::Apps<'static, VirtClient, Dispatch> for FidoApp {
    type Data = ();
    fn new<B: ClientBuilder<VirtClient, Dispatch>>(builder: &B, _data: ()) -> Self {
        let large_blogs = Some(fido_authenticator::LargeBlobsConfig {
            location: Location::External,
            #[cfg(feature = "chunked")]
            max_size: 4096,
        });

        FidoApp {
            fido: fido_authenticator::Authenticator::new(
                builder.build(
                    "fido",
                    &[
                        BackendId::Core,
                        BackendId::Custom(Backend::Hkdf),
                        #[cfg(feature = "chunked")]
                        BackendId::Custom(Backend::Staging),
                    ],
                ),
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
        .dispatch(Dispatch::default())
        .build::<FidoApp>()
        .exec(|_platform| {});
}
