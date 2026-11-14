//! `advapi32.dll`, one submodule per API area.

mod crypt;
mod registry;
mod scm;
mod service;
mod sid;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        service::exports(),
        crypt::exports(),
        registry::exports(),
        scm::exports(),
        sid::exports(),
    ]
    .concat()
}
