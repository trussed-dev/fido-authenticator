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
use fido_authenticator::{
    Authenticator, Config, Conforming, Silent, TrussedRequirements, UserPresence,
};
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
            let config = Config {
                max_msg_size: 0,
                skip_up_timeout: None,
                max_resident_credential_count: options.max_resident_credential_count,
                large_blobs: None,
                nfc_transport: options.nfc_transport,
                ccid_transport: options.ccid_transport,
                firmware_version: Some(0),
                long_touch_for_reset: options.long_touch_for_reset.unwrap_or(true),
            };
            let mut authenticator = Authenticator::new(
                client,
                TestUp::new(options.silent_up, options.reject_strong_up),
                config,
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
    pub nfc_transport: bool,
    pub ccid_transport: bool,
    /// When true, the authenticator is constructed with `Silent` user
    /// presence — every UP check (including `user_present_strong` for
    /// authenticatorReset, CTAP 2.3 §7.7) auto-grants. Needed by tests
    /// that exercise paths that would otherwise stall on the virt UI's
    /// default `Level::Normal` (which doesn't satisfy `Level::Strong`).
    pub silent_up: bool,
    /// When true, the authenticator is constructed with the test-only
    /// `TestUp::ShortOnly` user presence: a short touch (`Level::Normal`) is
    /// granted but a long touch (`Level::Strong`) is denied with
    /// `OperationDenied`. Lets a test assert that `long_touch_for_reset`
    /// actually gates `authenticatorReset` on a long touch.
    pub reject_strong_up: bool,
    /// Overrides `Config::long_touch_for_reset`. `None` keeps the recommended
    /// default (`true`).
    pub long_touch_for_reset: Option<bool>,
    pub inspect_ifs: Option<InspectFsFn>,
}

/// Either `Conforming` (default — goes through trussed's user_present
/// syscall) or `Silent` (auto-grants every UP request). The wrapper lets the
/// test runner pick between them at runtime without leaking the choice into
/// the surrounding generics.
#[derive(Copy, Clone)]
pub enum TestUp {
    Conforming,
    Silent,
    /// Grants a short touch (`Level::Normal`) but denies a long touch
    /// (`Level::Strong`) with `OperationDenied`. Used to test that
    /// `long_touch_for_reset` actually requires a long touch for reset.
    ShortOnly,
}

impl TestUp {
    fn new(silent: bool, reject_strong: bool) -> Self {
        if reject_strong {
            Self::ShortOnly
        } else if silent {
            Self::Silent
        } else {
            Self::Conforming
        }
    }
}

impl UserPresence for TestUp {
    fn user_present<T: TrussedRequirements>(
        self,
        trussed: &mut T,
        timeout_milliseconds: u32,
    ) -> Result<(), ctap_types::Error> {
        match self {
            Self::Conforming => Conforming {}.user_present(trussed, timeout_milliseconds),
            Self::Silent => Silent {}.user_present(trussed, timeout_milliseconds),
            // Short touch is granted.
            Self::ShortOnly => Silent {}.user_present(trussed, timeout_milliseconds),
        }
    }

    fn user_present_strong<T: TrussedRequirements>(
        self,
        trussed: &mut T,
        timeout_milliseconds: u32,
    ) -> Result<(), ctap_types::Error> {
        match self {
            Self::Conforming => Conforming {}.user_present_strong(trussed, timeout_milliseconds),
            Self::Silent => Silent {}.user_present_strong(trussed, timeout_milliseconds),
            // Long touch is denied — the user only managed a short touch.
            Self::ShortOnly => Err(ctap_types::Error::OperationDenied),
        }
    }
}

pub struct Ctap2<'a>(ctaphid::Device<Device<'a>>);

impl Ctap2<'_> {
    /// Send a raw CTAP1 (U2F) APDU and return the response body / SW
    /// status. Used by tests that need to verify CTAP1-level behaviour
    /// from within a CTAP2 test setup (e.g. the `alwaysUv` § 7.2.4
    /// "disable U2F" path, where toggling `alwaysUv` requires CTAP2 but
    /// the side effect is observable on the U2F dispatch).
    pub fn ctap1(&self, apdu: &[u8]) -> Result<Vec<u8>, u16> {
        let mut response = self.0.ctap1(apdu).unwrap();
        let low = response.pop().unwrap();
        let high = response.pop().unwrap();
        let status = u16::from_be_bytes([high, low]);
        if status == 0x9000 {
            Ok(response)
        } else {
            Err(status)
        }
    }

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
