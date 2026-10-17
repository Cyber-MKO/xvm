//! `msvcrt.dll`: our C runtime on top of host libc (docs/phase1-sizing.md,
//! decision 2). All functions are cdecl.

mod convert;
mod ctype;
mod dir;
mod errno;
mod heap;
mod locale;
mod locks;
mod lowio;
mod msstring;
mod startup;
mod stat;
pub(crate) mod stdio;
mod string;
mod time;
mod wide;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        startup::exports(),
        heap::exports(),
        string::exports(),
        dir::exports(),
        errno::exports(),
        wide::exports(),
        locale::exports(),
        lowio::exports(),
        stdio::exports(),
        ctype::exports(),
        convert::exports(),
        msstring::exports(),
        locks::exports(),
        stat::exports(),
        time::exports(),
    ]
    .concat()
}

/// Exported variables, as (name, size in bytes).
pub(super) fn data() -> Vec<(&'static str, u32)> {
    startup::data()
}
