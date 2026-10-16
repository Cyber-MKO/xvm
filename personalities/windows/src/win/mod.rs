//! Emulated system DLL functions and variables, one module per DLL.
//!
//! Every export here needs a census entry naming its caller, a test and a
//! row in docs/api/windows.md (CLAUDE.md rule 3).

use crate::emu::EmuExport;

mod advapi32;
mod crypt32;
pub(crate) mod kernel32;
mod msvcrt;
mod psapi;
mod text;

/// What we implement for `dll`. System DLLs with nothing implemented yet
/// return an empty list; their imports become gaps.
pub fn exports(dll: &str) -> Vec<(&'static str, EmuExport)> {
    let (functions, data) = match dll.to_ascii_lowercase().as_str() {
        "advapi32.dll" => (advapi32::exports(), Vec::new()),
        "crypt32.dll" => (crypt32::exports(), Vec::new()),
        "kernel32.dll" => (kernel32::exports(), Vec::new()),
        "msvcrt.dll" => (msvcrt::exports(), msvcrt::data()),
        "psapi.dll" => (psapi::exports(), Vec::new()),
        _ => (Vec::new(), Vec::new()),
    };
    let functions = functions.into_iter().map(|(n, a)| (n, EmuExport::Code(a)));
    let data = data.into_iter().map(|(n, size)| (n, EmuExport::Data(size)));
    functions.chain(data).collect()
}
