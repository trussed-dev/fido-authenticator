// TODO: extract this, like credential_management.rs

pub(crate) struct ClientPin<'a, UP, T>
where UP: UserPresence,
{
    authnr: &'a mut Authenticator<UP, T>,
}

