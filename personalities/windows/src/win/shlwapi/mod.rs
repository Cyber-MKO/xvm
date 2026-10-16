//! `shlwapi.dll`, one submodule per API area.

mod path;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    path::exports()
}
