use ctaphid_dispatch::app as ctaphid;

#[allow(unused_imports)]
use crate::msp;
use crate::{Authenticator, TrussedRequirements, UserPresence};
use trussed::interrupt::InterruptFlag;

impl<UP, T> ctaphid::App<'static> for Authenticator<UP, T>
where
    UP: UserPresence,
    T: TrussedRequirements,
{
    fn commands(&self) -> &'static [ctaphid::Command] {
        &[ctaphid::Command::Cbor, ctaphid::Command::Msg]
    }

    #[inline(never)]
    fn call(
        &mut self,
        command: ctaphid::Command,
        request: &ctaphid::Message,
        response: &mut ctaphid::Message,
    ) -> ctaphid::AppResult {
        debug_now!(
            "ctaphid-dispatch: remaining stack: {} bytes",
            msp() - 0x2000_0000
        );

        if request.is_empty() {
            debug_now!("invalid request length in ctaphid.call");
            return Err(ctaphid::Error::InvalidLength);
        }

        // info_now!("request: ");
        // blocking::dump_hex(request, request.len());
        match command {
            ctaphid::Command::Cbor => super::handle_ctap2(self, request, response),
            ctaphid::Command::Msg => super::handle_ctap1_from_hid(self, request, response),
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
