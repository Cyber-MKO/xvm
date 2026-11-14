//! `psapi.dll`, one submodule per API area.

mod modules;
mod process;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    let mut all = modules::exports();
    all.extend(process::exports());
    all
}
