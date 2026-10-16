//! `kernel32.dll`, one submodule per API area.

mod critsec;
pub(crate) mod error;
mod exception;
mod module;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        error::exports(),
        critsec::exports(),
        exception::exports(),
        module::exports(),
    ]
    .concat()
}
