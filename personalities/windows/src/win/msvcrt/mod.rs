//! `msvcrt.dll`: our C runtime on top of host libc (docs/phase1-sizing.md,
//! decision 2). All functions are cdecl.

mod convert;
mod ctype;
mod dir;
mod errno;
pub(crate) mod find;
mod fullpath;
mod heap;
mod jump;
mod locale;
mod locks;
mod lowio;
mod msstring;
mod random;
mod remove;
mod startup;
mod stat;
pub(crate) mod stdio;
mod strerror;
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
        random::exports(),
        strerror::exports(),
        fullpath::exports(),
        find::exports(),
        remove::exports(),
    ]
    .concat()
}

/// Functions that run on the caller's own stack, without the trampoline.
pub(super) fn raw_exports() -> Vec<(&'static str, u32)> {
    jump::exports()
}

/// Exported variables, as (name, size in bytes).
pub(super) fn data() -> Vec<(&'static str, u32)> {
    let mut data = startup::data();
    // FILE _iob[_IOB_ENTRIES]: stdin, stdout and stderr, then free slots.
    data.push(("_iob", stdio::IOB_ENTRIES * 32));
    data
}

/// Sets up the variables of the image just loaded at `module`.
pub(super) fn on_load(p: &mut crate::process::Process, module: usize) {
    if let Some(iob) = p.modules()[module].export_address("_iob") {
        stdio::init_standard_streams(p, iob);
    }
}
