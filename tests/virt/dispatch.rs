use trussed::{
    api::{reply, request},
    serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
    service::ServiceResources,
    types::NoData,
    Error, Platform,
};
use trussed_hkdf::{HkdfBackend, HkdfExtension};

#[derive(Default)]
pub struct Context {
    #[cfg(feature = "chunked")]
    staging: trussed_staging::StagingContext,
}

#[derive(Default)]
pub struct Dispatch {
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

pub enum Backend {
    #[cfg(feature = "chunked")]
    Staging,
    Hkdf,
}

pub enum Extension {
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
