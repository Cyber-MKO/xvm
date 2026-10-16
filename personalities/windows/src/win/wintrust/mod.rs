//! `wintrust.dll`, one submodule per API area.

mod trust;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    trust::exports()
}
