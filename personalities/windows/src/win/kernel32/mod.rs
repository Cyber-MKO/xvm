//! `kernel32.dll`, one submodule per API area.

mod codepage;
pub(crate) mod critsec;
pub(crate) mod error;
mod exception;
pub(crate) mod file;
mod handle;
mod library;
mod module;
mod path;
pub(crate) mod process;
pub(crate) mod sync;
mod tls;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        error::exports(),
        critsec::exports(),
        codepage::exports(),
        exception::exports(),
        file::exports(),
        handle::exports(),
        library::exports(),
        module::exports(),
        path::exports(),
        tls::exports(),
        sync::exports(),
        process::exports(),
    ]
    .concat()
}
