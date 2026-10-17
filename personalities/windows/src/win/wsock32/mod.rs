//! `wsock32.dll`, one submodule per API area.

mod hostname;
mod startup;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    let mut all = startup::exports();
    all.extend(hostname::exports());
    all
}
