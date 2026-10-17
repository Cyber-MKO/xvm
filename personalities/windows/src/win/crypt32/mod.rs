//! `crypt32.dll`, one submodule per API area.

mod store;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    store::exports()
}
