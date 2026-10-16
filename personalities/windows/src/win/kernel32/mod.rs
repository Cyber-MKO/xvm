//! `kernel32.dll`, one submodule per API area.

mod codepage;
mod critsec;
pub(crate) mod error;
mod exception;
mod module;
mod path;
pub(crate) mod process;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        error::exports(),
        critsec::exports(),
        codepage::exports(),
        exception::exports(),
        module::exports(),
        path::exports(),
        process::exports(),
    ]
    .concat()
}
