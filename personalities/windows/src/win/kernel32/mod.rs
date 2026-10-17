//! `kernel32.dll`, one submodule per API area.

mod attributes;
mod codepage;
pub(crate) mod critsec;
pub(crate) mod env;
pub(crate) mod error;
mod exception;
pub(crate) mod file;
mod fileio;
mod handle;
mod heap;
mod library;
mod lockfile;
mod memory;
mod module;
mod path;
pub(crate) mod process;
pub(crate) mod sync;
mod sysinfo;
pub(crate) mod thread;
pub(crate) mod time;
mod timezone;
mod tls;
mod version;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        error::exports(),
        attributes::exports(),
        critsec::exports(),
        codepage::exports(),
        env::exports(),
        exception::exports(),
        file::exports(),
        fileio::exports(),
        handle::exports(),
        heap::exports(),
        library::exports(),
        lockfile::exports(),
        memory::exports(),
        module::exports(),
        path::exports(),
        tls::exports(),
        time::exports(),
        timezone::exports(),
        thread::exports(),
        sync::exports(),
        process::exports(),
        version::exports(),
        sysinfo::exports(),
    ]
    .concat()
}
