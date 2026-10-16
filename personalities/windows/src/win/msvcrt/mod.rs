//! `msvcrt.dll`: our C runtime on top of host libc (docs/phase1-sizing.md,
//! decision 2). All functions are cdecl.

mod startup;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    startup::exports()
}
