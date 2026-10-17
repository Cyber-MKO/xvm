//! Emulated system DLL functions and variables, one module per DLL.
//!
//! Every export here needs a census entry naming its caller, a test and a
//! row in docs/api/windows.md (CLAUDE.md rule 3).

use crate::emu::EmuExport;

mod advapi32;
mod crypt32;
pub(crate) mod facts;
mod iphlpapi;
pub(crate) mod kernel32;
mod mpr;
pub(crate) mod msvcrt;
mod ntdll;
mod psapi;
mod shlwapi;
mod text;
pub(crate) mod wevtapi;
mod wintrust;
mod ws2_32;
mod wsock32;

/// Sets up the variables of the emulated `dll` just loaded at `module`.
pub fn on_load(p: &mut crate::process::Process, dll: &str, module: usize) {
    if dll.eq_ignore_ascii_case("msvcrt.dll") {
        msvcrt::on_load(p, module);
    }
}

/// What we implement for `dll`. System DLLs with nothing implemented yet
/// return an empty list; their imports become gaps.
pub fn exports(dll: &str) -> Vec<(&'static str, EmuExport)> {
    let (functions, data) = match dll.to_ascii_lowercase().as_str() {
        "advapi32.dll" => (advapi32::exports(), Vec::new()),
        "crypt32.dll" => (crypt32::exports(), Vec::new()),
        "iphlpapi.dll" => (iphlpapi::exports(), Vec::new()),
        "kernel32.dll" => (kernel32::exports(), Vec::new()),
        "mpr.dll" => (mpr::exports(), Vec::new()),
        "msvcrt.dll" => (msvcrt::exports(), msvcrt::data()),
        "ntdll.dll" => (ntdll::exports(), Vec::new()),
        "psapi.dll" => (psapi::exports(), Vec::new()),
        "shlwapi.dll" => (shlwapi::exports(), Vec::new()),
        "wevtapi.dll" => (wevtapi::exports(), Vec::new()),
        "wintrust.dll" => (wintrust::exports(), Vec::new()),
        "ws2_32.dll" => (ws2_32::exports(), Vec::new()),
        "wsock32.dll" => (wsock32::exports(), Vec::new()),
        _ => (Vec::new(), Vec::new()),
    };
    let raw = if dll.eq_ignore_ascii_case("msvcrt.dll") {
        msvcrt::raw_exports()
    } else {
        Vec::new()
    };
    let functions = functions.into_iter().map(|(n, a)| (n, EmuExport::Code(a)));
    let raw = raw.into_iter().map(|(n, a)| (n, EmuExport::Raw(a)));
    let data = data.into_iter().map(|(n, size)| (n, EmuExport::Data(size)));
    functions.chain(raw).chain(data).collect()
}
