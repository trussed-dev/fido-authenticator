mod pipe;

use std::{
    borrow::Cow,
    cell::RefCell,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Once, OnceLock,
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
use ctaphid_dispatch::{
    dispatch::Dispatch,
    types::{Channel, Requester},
};
use fido_authenticator::{Authenticator, Config, Conforming};
use serde::de::DeserializeOwned;
use trussed_staging::virt;

use pipe::Pipe;

static INIT_LOGGER: Once = Once::new();
static CHANNEL: OnceLock<Channel> = OnceLock::new();

pub fn run_ctaphid<F, T>(f: F) -> T
where
    F: FnOnce(ctaphid::Device<Device>) -> T,
{
    INIT_LOGGER.call_once(|| {
        env_logger::init();
    });
    virt::with_ram_client("fido", |client| {
        // TODO: setup attestation cert

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

        let channel = CHANNEL.get_or_init(Channel::new);
        let (rq, rp) = channel.split().unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let poller_stop = stop.clone();
        let poller = thread::spawn(move || {
            let mut dispatch = Dispatch::new(rp);
            while !poller_stop.load(Ordering::Relaxed) {
                dispatch.poll(&mut [&mut authenticator]);
                thread::sleep(Duration::from_millis(10));
            }
        });

        let device = Device::new(rq);
        let device = ctaphid::Device::new(device, DeviceInfo).unwrap();
        let result = f(device);
        stop.store(true, Ordering::Relaxed);
        poller.join().unwrap();
        result
    })
}

pub fn run_ctap2<F, T>(f: F) -> T
where
    F: FnOnce(Ctap2) -> T,
{
    run_ctaphid(|device| f(Ctap2(device)))
}

pub struct Ctap2(ctaphid::Device<Device>);

impl Ctap2 {
    pub fn call<T: DeserializeOwned>(&self, operation: Operation, data: &Value) -> T {
        let mut serialized = Vec::new();
        ciborium::into_writer(data, &mut serialized).unwrap();
        let reply = self.0.ctap2(operation.into(), &serialized).unwrap();
        ciborium::from_reader(reply.as_slice()).unwrap()
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

pub struct Device(RefCell<Pipe>);

impl Device {
    fn new(requester: Requester<'static>) -> Self {
        Self(RefCell::new(Pipe::new(requester)))
    }
}

impl HidDevice for Device {
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

            thread::sleep(Duration::from_millis(10));
        }
    }
}
