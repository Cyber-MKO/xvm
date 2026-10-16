//! `msvcrt.dll`: our C runtime on top of host libc (docs/phase1-sizing.md,
//! decision 2). All functions are cdecl.

mod dir;
mod errno;
mod heap;
mod startup;
mod string;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    [
        startup::exports(),
        heap::exports(),
        string::exports(),
        dir::exports(),
        errno::exports(),
    ]
    .concat()
}

/// Exported variables, as (name, size in bytes).
pub(super) fn data() -> Vec<(&'static str, u32)> {
    startup::data()
}
