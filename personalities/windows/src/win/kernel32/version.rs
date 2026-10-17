//! The OS version: `GetVersionExA`.
//!
//! The version and build come from the engine's `os_info` section. As
//! the GetVersionEx page on Microsoft Learn says, a program whose manifest
//! does not declare Windows 8.1 or Windows 10 sees Windows 8 (6.2) on
//! later systems, and one that declares only Windows 8.1 sees at most 6.3.
//! The builds reported then are those versions' own (9200, 9600).
//!
//! | Field | Source |
//! | --- | --- |
//! | Major, minor, build | `os_info.version`, `os_info.build`, capped by the manifest |
//! | `szCSDVersion`, service pack | `CSDVersion` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`; empty when absent |
//! | `wProductType` | `ProductType` under `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions`, else `InstallationType` under `CurrentVersion` |
//! | `wSuiteMask` | Not modelled yet: 0, a logged gap |
//!
//! `OSVERSIONINFOA` is 148 bytes; `OSVERSIONINFOEXA` adds service pack
//! major and minor (u16), suite mask (u16), product type and a reserved
//! byte, for 156.

use serde_json::Value;

use super::error::{ERROR_INSUFFICIENT_BUFFER, set_last_error};
use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};

const CALLER: Caller = ("kernel32.dll", "GetVersionExA");
const VER_PLATFORM_WIN32_NT: u32 = 2;
const VER_NT_WORKSTATION: u8 = 1;
const VER_NT_DOMAIN_CONTROLLER: u8 = 2;
const VER_NT_SERVER: u8 = 3;
const ERROR_NOT_SUPPORTED: u32 = 50;

// supportedOS IDs from "Application manifests" on Microsoft Learn.
const WINDOWS_10: &str = "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}";
const WINDOWS_8_1: &str = "{1f676c76-80e1-4239-95bb-83d0f6d0da78}";

const CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const PRODUCT_OPTIONS: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions";

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("GetVersionExA", GetVersionExA as *const () as u32)]
}

/// The highest version a program with `manifest` is shown.
fn cap(manifest: Option<&str>) -> Option<(u32, u32, u32)> {
    let declares = |id: &str| manifest.is_some_and(|m| m.to_ascii_lowercase().contains(id));
    if declares(WINDOWS_10) {
        None
    } else if declares(WINDOWS_8_1) {
        Some((6, 3, 9600))
    } else {
        Some((6, 2, 9200))
    }
}

/// (major, minor, build) the program sees.
fn shown(real: (u32, u32, u32), manifest: Option<&str>) -> (u32, u32, u32) {
    match cap(manifest) {
        Some(cap) if (real.0, real.1) > (cap.0, cap.1) => cap,
        _ => real,
    }
}

fn real_version(os_info: &Value) -> Option<(u32, u32, u32)> {
    let version = os_info.get("version")?.as_str()?;
    let (major, minor) = version.split_once('.')?;
    let build = match os_info.get("build")? {
        Value::String(s) => s.parse().ok()?,
        Value::Number(n) => u32::try_from(n.as_u64()?).ok()?,
        _ => return None,
    };
    Some((major.parse().ok()?, minor.parse().ok()?, build))
}

fn reg_string(key: &str, name: &str) -> Result<Option<String>, ()> {
    Ok(facts::reg_value(CALLER, key, name)?
        .and_then(|v| v.get("data").and_then(Value::as_str).map(str::to_string)))
}

fn product_type() -> Result<Option<u8>, ()> {
    if let Some(t) = reg_string(PRODUCT_OPTIONS, "ProductType")? {
        return Ok(match t.to_ascii_lowercase().as_str() {
            "winnt" => Some(VER_NT_WORKSTATION),
            "lanmannt" => Some(VER_NT_DOMAIN_CONTROLLER),
            "servernt" => Some(VER_NT_SERVER),
            _ => None,
        });
    }
    Ok(
        reg_string(CURRENT_VERSION, "InstallationType")?.and_then(|t| {
            match t.to_ascii_lowercase().as_str() {
                "client" => Some(VER_NT_WORKSTATION),
                "server" | "server core" => Some(VER_NT_SERVER),
                _ => None,
            }
        }),
    )
}

/// Fills `OSVERSIONINFOA` or `OSVERSIONINFOEXA`, chosen by its first
/// field. Returns FALSE with ERROR_INSUFFICIENT_BUFFER for another size,
/// or with ERROR_NOT_SUPPORTED (a logged gap) when a fact is missing.
#[allow(non_snake_case)]
extern "stdcall" fn GetVersionExA(info: *mut u8) -> i32 {
    // SAFETY: info starts with dwOSVersionInfoSize (the API's contract).
    let size = unsafe { info.cast::<u32>().read_unaligned() };
    if size != 148 && size != 156 {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let fail = |what: &str| {
        with_current(|p| {
            p.record_runtime_gap(GapKind::Feature, CALLER.0, &format!("{}: {what}", CALLER.1))
        });
        set_last_error(ERROR_NOT_SUPPORTED);
        0
    };
    let Some(os_info) = facts::section(CALLER, "os_info") else {
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    };
    let Some(real) = real_version(&os_info) else {
        return fail("os_info has no usable version and build");
    };
    let manifest = with_current(|p| p.main_module().and_then(|m| m.manifest.clone()));
    let (major, minor, build) = shown(real, manifest.as_deref());
    let Ok(csd) = reg_string(CURRENT_VERSION, "CSDVersion") else {
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    };
    let csd = csd.unwrap_or_default();
    let mut buf = vec![0u8; size as usize];
    buf[0..4].copy_from_slice(&size.to_le_bytes());
    buf[4..8].copy_from_slice(&major.to_le_bytes());
    buf[8..12].copy_from_slice(&minor.to_le_bytes());
    buf[12..16].copy_from_slice(&build.to_le_bytes());
    buf[16..20].copy_from_slice(&VER_PLATFORM_WIN32_NT.to_le_bytes());
    let text = csd.as_bytes();
    buf[20..20 + text.len().min(127)].copy_from_slice(&text[..text.len().min(127)]);
    if size == 156 {
        let product = match product_type() {
            Ok(Some(t)) => t,
            Ok(None) => return fail("no ProductType or InstallationType in the registry"),
            Err(()) => {
                set_last_error(ERROR_NOT_SUPPORTED);
                return 0;
            }
        };
        let service_pack = csd
            .strip_prefix("Service Pack ")
            .and_then(|n| n.parse::<u16>().ok())
            .unwrap_or(0);
        buf[148..150].copy_from_slice(&service_pack.to_le_bytes());
        with_current(|p| {
            p.record_runtime_gap(GapKind::Feature, CALLER.0, "GetVersionExA: wSuiteMask")
        });
        buf[154] = product;
    }
    // SAFETY: info holds `size` bytes (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), info, buf.len()) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use serde_json::json;

    fn base(registry: Value) -> Value {
        json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "os_info": {"product_name": "Windows Server 2022", "version": "10.0", "build": "20348"},
            "registry": {"keys": registry},
        })
    }

    fn host() -> Value {
        json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b", "os": "windows",
               "identity": {"hostname": "H"}})
    }

    fn call(size: u32) -> (i32, Vec<u8>) {
        let mut buf = vec![0xaau8; size.max(4) as usize];
        buf[0..4].copy_from_slice(&size.to_le_bytes());
        let rc = GetVersionExA(buf.as_mut_ptr());
        (rc, buf)
    }

    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }

    #[test]
    fn the_manifest_caps_what_the_program_sees() {
        assert_eq!(shown((10, 0, 20348), None), (6, 2, 9200));
        let only_8_1 = format!("<supportedOS Id=\"{}\"/>", WINDOWS_8_1.to_uppercase());
        assert_eq!(shown((10, 0, 20348), Some(&only_8_1)), (6, 3, 9600));
        let ten = format!("<supportedOS Id=\"{WINDOWS_10}\"/>");
        assert_eq!(shown((10, 0, 20348), Some(&ten)), (10, 0, 20348));
        assert_eq!(shown((6, 1, 7601), None), (6, 1, 7601));
    }

    #[test]
    fn reports_the_engine_version_for_both_structures() {
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(
            base(json!({
                CURRENT_VERSION: {"InstallationType": {"type": "REG_SZ", "data": "Server"}},
            })),
            host(),
        ));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        // No main module, so no manifest: Windows 8 is what it sees.
        let (rc, b) = call(148);
        assert_eq!(rc, 1);
        assert_eq!(
            [u32_at(&b, 4), u32_at(&b, 8), u32_at(&b, 12), u32_at(&b, 16)],
            [6, 2, 9200, 2]
        );
        assert_eq!(b[20], 0, "no CSD version");
        let (rc, b) = call(156);
        assert_eq!((rc, b[154]), (1, VER_NT_SERVER));
        assert_eq!(&b[148..150], [0, 0]);
        assert_eq!(call(100).0, 0);
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(gaps, ["GetVersionExA: wSuiteMask"]);
    }

    #[test]
    fn product_options_and_service_packs() {
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(
            base(json!({
                CURRENT_VERSION: {"CSDVersion": {"type": "REG_SZ", "data": "Service Pack 1"}},
                PRODUCT_OPTIONS: {"ProductType": {"type": "REG_SZ", "data": "WinNT"}},
            })),
            host(),
        ));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let (rc, b) = call(156);
        assert_eq!((rc, b[154], b[148]), (1, VER_NT_WORKSTATION, 1));
        assert_eq!(&b[20..34], b"Service Pack 1");
    }

    #[test]
    fn without_an_engine_it_fails_and_logs() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        assert_eq!(call(148).0, 0);
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(
            gaps,
            ["GetVersionExA: section os_info needs the host-state engine"]
        );
    }
}
