//! `psapi.dll`, one submodule per API area.

mod modules;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    modules::exports()
}
