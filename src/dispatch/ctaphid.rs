use ctaphid_app::{App, Command, Error};
use heapless_bytes::Bytes;
use trussed_core::InterruptFlag;

#[allow(unused_imports)]
use crate::msp;
use crate::{Authenticator, TrussedRequirements, UserPresence};

impl<UP, T, const N: usize> App<'static, N> for Authenticator<UP, T>
where
    UP: UserPresence,
    T: TrussedRequirements,
{
    fn commands(&self) -> &'static [Command] {
        &[Command::Cbor, Command::Msg]
    }

    #[inline(never)]
    fn call(
        &mut self,
        command: Command,
        request: &[u8],
        response: &mut Bytes<N>,
    ) -> Result<(), Error> {
        debug_now!(
            "ctaphid-dispatch: remaining stack: {} bytes",
            msp() - 0x2000_0000
        );

        if request.is_empty() {
            debug_now!("invalid request length in ctaphid.call");
            return Err(Error::InvalidLength);
        }

        // info_now!("request: ");
        // blocking::dump_hex(request, request.len());
        match command {
            Command::Cbor => super::handle_ctap2(self, request, response),
            Command::Msg => super::handle_ctap1_from_hid(self, request, response),
            _ => {
                debug_now!("ctaphid trying to dispatch {:?}", command);
            }
        };
        Ok(())
    }

    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        self.trussed.interrupt()
    }
}
