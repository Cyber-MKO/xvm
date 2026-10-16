//! Emulated system DLL functions, one module per DLL.
//!
//! Every function here needs a census entry naming its caller, a test and a
//! row in docs/api/windows.md (CLAUDE.md rule 3).

mod kernel32;

/// The functions we implement for `dll`, as (export name, address) pairs.
/// System DLLs with nothing implemented yet return an empty list; their
/// imports become gaps.
pub fn exports(dll: &str) -> Vec<(&'static str, u32)> {
    match dll.to_ascii_lowercase().as_str() {
        "kernel32.dll" => kernel32::exports(),
        _ => Vec::new(),
    }
}
