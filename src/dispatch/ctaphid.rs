use ctaphid_dispatch::app as ctaphid;

use crate::{Authenticator, TrussedRequirements, UserPresence};
#[allow(unused_imports)]
use crate::msp;

impl<UP, T> ctaphid::App for Authenticator<UP, T>
where UP: UserPresence,
      T: TrussedRequirements,
{

    fn commands(&self,) -> &'static [ctaphid::Command] {
        &[ ctaphid::Command::Cbor, ctaphid::Command::Msg ]
    }

    #[inline(never)]
    fn call(&mut self, command: ctaphid::Command, request: &ctaphid::Message, response: &mut ctaphid::Message) -> ctaphid::AppResult {

        debug_now!("ctaphid-dispatch: remaining stack: {} bytes", msp() - 0x2000_0000);

        if request.len() < 1 {
            return Err(ctaphid::Error::InvalidLength);
        }

        // info_now!("request: ");
        // blocking::dump_hex(request, request.len());
        Ok(match command {

            ctaphid::Command::Cbor => super::handle_ctap2(self, request, response),
            ctaphid::Command::Msg => super::handle_ctap1(self, request, response),
            _ => {
                debug_now!("ctaphid trying to dispatch {:?}", command);
            }
        })
    }
}
