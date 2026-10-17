//! `wsock32.dll`, one submodule per API area.

mod startup;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    startup::exports()
}
