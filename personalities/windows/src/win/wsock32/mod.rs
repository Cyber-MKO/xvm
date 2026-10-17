//! `wsock32.dll`, one submodule per API area.

pub(crate) mod convert;
mod hostname;
mod select;
mod sockets;
mod startup;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        startup::exports(),
        hostname::exports(),
        sockets::exports(),
        select::exports(),
        convert::exports(),
    ]
    .concat()
}
