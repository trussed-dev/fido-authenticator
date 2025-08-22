mod pipe;

use std::{
    borrow::Cow,
    cell::RefCell,
    fmt::{self, Debug, Formatter},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Once,
    },
    thread,
    time::{Duration, SystemTime},
};

use ciborium::Value;
use ctap_types::ctap2::Operation;
use ctaphid::{
    error::{RequestError, ResponseError},
    HidDevice, HidDeviceInfo,
};
use ctaphid_dispatch::{Channel, Dispatch, Requester, DEFAULT_MESSAGE_SIZE};
use fido_authenticator::{Authenticator, Config, Conforming};
use littlefs2::{object_safe::DynFilesystem, path, path::PathBuf};
use rand::{
    distributions::{Distribution, Uniform},
    RngCore as _,
};
use trussed::{
    backend::BackendId,
    platform::Platform as _,
    store::Store as _,
    virt::{self, StoreConfig},
};
use trussed_staging::virt::{BackendIds, Client, Dispatcher};

use crate::webauthn::Request;

use pipe::Pipe;

// see: https://github.com/Nitrokey/nitrokey-3-firmware/tree/main/utils/test-certificates/fido
const ATTESTATION_CERT: &[u8] = include_bytes!("../data/fido-cert.der");
const ATTESTATION_KEY: &[u8] = include_bytes!("../data/fido-key.trussed");

static INIT_LOGGER: Once = Once::new();

pub fn run_ctaphid<F, T>(f: F) -> T
where
    F: FnOnce(ctaphid::Device<Device>) -> T + Send,
    T: Send,
{
    run_ctaphid_with_options(Default::default(), f)
}

pub fn run_ctaphid_with_options<F, T>(options: Options, f: F) -> T
where
    F: FnOnce(ctaphid::Device<Device>) -> T + Send,
    T: Send,
{
    INIT_LOGGER.call_once(|| {
        env_logger::init();
    });
    let mut files = options.files;
    files.push((path!("fido/x5c/00").into(), ATTESTATION_CERT.into()));
    files.push((path!("fido/sec/00").into(), ATTESTATION_KEY.into()));
    with_client(
        &files,
        |client| {
            let mut authenticator = Authenticator::new(
                client,
                Conforming {},
                Config {
                    max_msg_size: 0,
                    skip_up_timeout: None,
                    max_resident_credential_count: options.max_resident_credential_count,
                    large_blobs: None,
                    nfc_transport: false,
                },
            );

            let channel = Channel::new();
            let (rq, rp) = channel.split().unwrap();

            thread::scope(|s| {
                let stop = Arc::new(AtomicBool::new(false));
                let poller_stop = stop.clone();
                let poller = s.spawn(move || {
                    let mut dispatch = Dispatch::new(rp);
                    while !poller_stop.load(Ordering::Relaxed) {
                        dispatch.poll(&mut [&mut authenticator]);
                        thread::sleep(Duration::from_millis(1));
                    }
                });

                let runner = s.spawn(move || {
                    let device = Device::new(rq);
                    let device = ctaphid::Device::new(device, DeviceInfo).unwrap();
                    f(device)
                });

                let result = runner.join();
                stop.store(true, Ordering::Relaxed);
                poller.join().unwrap();
                result.unwrap()
            })
        },
        |ifs| {
            if let Some(inspect_ifs) = options.inspect_ifs {
                inspect_ifs(ifs);
            }
        },
    )
}

pub fn run_ctap2<F, T>(f: F) -> T
where
    F: FnOnce(Ctap2) -> T + Send,
    T: Send,
{
    run_ctaphid(|device| f(Ctap2(device)))
}

pub fn run_ctap2_with_options<F, T>(options: Options, f: F) -> T
where
    F: FnOnce(Ctap2) -> T + Send,
    T: Send,
{
    run_ctaphid_with_options(options, |device| f(Ctap2(device)))
}

pub type InspectFsFn = Box<dyn Fn(&dyn DynFilesystem)>;

#[derive(Default)]
pub struct Options {
    pub files: Vec<(PathBuf, Vec<u8>)>,
    pub max_resident_credential_count: Option<u32>,
    pub inspect_ifs: Option<InspectFsFn>,
}

pub struct Ctap2<'a>(ctaphid::Device<Device<'a>>);

impl Ctap2<'_> {
    pub fn exec<R: Request>(&self, request: R) -> Result<R::Reply, Ctap2Error> {
        let operation = Operation::try_from(R::COMMAND)
            .map(|op| format!("{op:?}"))
            .unwrap_or_else(|_| "?".to_owned());
        log::info!("Executing command {:#x} ({})", R::COMMAND, operation);
        let request = request.into();
        log::debug!("Sending request {request:?}");
        let mut serialized = Vec::new();
        ciborium::into_writer(&request, &mut serialized).unwrap();
        let reply = self
            .0
            .ctap2(R::COMMAND, &serialized)
            .map_err(|err| match err {
                ctaphid::error::Error::CommandError(ctaphid::error::CommandError::CborError(
                    value,
                )) => {
                    log::warn!("Received CTAP2 error {value:#x}");
                    Ctap2Error(value)
                }
                err => panic!("failed to execute CTAP2 command: {err:?}"),
            })?;
        let value: Value = if reply.is_empty() {
            Value::Map(Vec::new())
        } else {
            ciborium::from_reader(reply.as_slice()).unwrap()
        };
        log::debug!("Received reply {value:?}");
        Ok(value.into())
    }
}

#[derive(PartialEq)]
pub struct Ctap2Error(pub u8);

impl Debug for Ctap2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ctap2Error")
            .field(&format_args!("{:#x}", self.0))
            .finish()
    }
}

#[derive(Debug)]
pub struct DeviceInfo;

impl HidDeviceInfo for DeviceInfo {
    fn vendor_id(&self) -> u16 {
        0x20a0
    }

    fn product_id(&self) -> u16 {
        0x42b2
    }

    fn path(&self) -> Cow<'_, str> {
        "test".into()
    }
}

pub struct Device<'a>(RefCell<Pipe<'a, DEFAULT_MESSAGE_SIZE>>);

impl<'a> Device<'a> {
    fn new(requester: Requester<'a, DEFAULT_MESSAGE_SIZE>) -> Self {
        Self(RefCell::new(Pipe::new(requester)))
    }
}

impl HidDevice for Device<'_> {
    type Info = DeviceInfo;

    fn send(&self, data: &[u8]) -> Result<(), RequestError> {
        self.0.borrow_mut().push(data);
        Ok(())
    }

    fn receive<'a>(
        &self,
        buffer: &'a mut [u8],
        timeout: Option<Duration>,
    ) -> Result<&'a [u8], ResponseError> {
        let start = SystemTime::now();

        loop {
            if let Some(timeout) = timeout {
                let elapsed = start.elapsed().unwrap();
                if elapsed >= timeout {
                    return Err(ResponseError::Timeout);
                }
            }

            if let Some(response) = self.0.borrow_mut().pop() {
                return if buffer.len() >= response.len() {
                    log::info!("received response: {} bytes", response.len());
                    buffer[..response.len()].copy_from_slice(&response);
                    Ok(&buffer[..response.len()])
                } else {
                    Err(ResponseError::PacketReceivingFailed(
                        "invalid buffer size".into(),
                    ))
                };
            }

            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn with_client<F, F2, T>(files: &[(PathBuf, Vec<u8>)], f: F, inspect_ifs: F2) -> T
where
    F: FnOnce(Client) -> T,
    F2: FnOnce(&dyn DynFilesystem),
{
    virt::with_platform(StoreConfig::ram(), |mut platform| {
        // virt always uses the same seed -- request some random bytes to reach a somewhat random
        // state
        let uniform = Uniform::from(0..64);
        let n = uniform.sample(&mut rand::thread_rng());
        for _ in 0..n {
            platform.rng().next_u32();
        }

        let store = platform.store();
        let ifs = store.ifs();

        for (path, content) in files {
            if let Some(dir) = path.parent() {
                ifs.create_dir_all(&dir).unwrap();
            }
            ifs.write(path, content).unwrap();
        }

        let result = platform.run_client_with_backends(
            "fido",
            Dispatcher::default(),
            &[
                BackendId::Custom(BackendIds::StagingBackend),
                BackendId::Core,
            ],
            f,
        );

        inspect_ifs(ifs);

        result
    })
}
