//! `advapi32.dll`, one submodule per API area.

mod service;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    service::exports()
}
