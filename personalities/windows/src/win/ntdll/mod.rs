//! `ntdll.dll`, one submodule per API area.

mod loader;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    loader::exports()
}
