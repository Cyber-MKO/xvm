//! `kernel32.dll`, one submodule per API area.

mod critsec;
mod error;
mod exception;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [error::exports(), critsec::exports(), exception::exports()].concat()
}
