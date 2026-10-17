//! The OS version: `GetVersionExA`, `VerifyVersionInfoW`,
//! `VerSetConditionMask`.
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
//!
//! `VerifyVersionInfoW` compares the same facts, capped the same way, as
//! the VerifyVersionInfo page on Microsoft Learn says. Major, minor and
//! service pack major and minor compare in that order as one version,
//! with the condition of the first one requested; the build, platform
//! and product type compare on their own. The suite mask is not modelled
//! yet: asking for it fails with ERROR_NOT_SUPPORTED, a logged gap.
//!
//! `VerSetConditionMask` keeps three bits per type, the type's bit
//! position times three from the low end (`VER_SET_CONDITION`, winnt.h).

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
    vec![
        ("GetVersionExA", GetVersionExA as *const () as u32),
        ("VerifyVersionInfoW", VerifyVersionInfoW as *const () as u32),
        (
            "VerSetConditionMask",
            VerSetConditionMask as *const () as u32,
        ),
    ]
}

// Type mask bits and conditions from the VerifyVersionInfo page.
const VER_MINORVERSION: u32 = 0x1;
const VER_MAJORVERSION: u32 = 0x2;
const VER_BUILDNUMBER: u32 = 0x4;
const VER_PLATFORMID: u32 = 0x8;
const VER_SERVICEPACKMINOR: u32 = 0x10;
const VER_SERVICEPACKMAJOR: u32 = 0x20;
const VER_SUITENAME: u32 = 0x40;
const VER_PRODUCT_TYPE: u32 = 0x80;
const VER_EQUAL: u8 = 1;
const VER_LESS_EQUAL: u8 = 5;
const ERROR_BAD_ARGUMENTS: u32 = 160;
const ERROR_OLD_WIN_VERSION: u32 = 1150;

/// Sets `condition` for every type in `types`. A zero type mask or
/// condition leaves the mask as it was.
#[allow(non_snake_case)]
extern "stdcall" fn VerSetConditionMask(mask: u64, types: u32, condition: u8) -> u64 {
    if types == 0 || condition == 0 {
        return mask;
    }
    let mut mask = mask;
    for bit in 0..8 {
        if types & (1 << bit) != 0 {
            mask = (mask & !(7 << (bit * 3))) | (u64::from(condition & 7) << (bit * 3));
        }
    }
    mask
}

fn condition_of(mask: u64, ty: u32) -> u8 {
    ((mask >> (ty.trailing_zeros() * 3)) & 7) as u8
}

/// Whether `have` meets `want` under `condition`, or None for a condition
/// that does not apply to numbers.
fn holds<T: Ord>(have: T, want: T, condition: u8) -> Option<bool> {
    use std::cmp::Ordering::*;
    let order = have.cmp(&want);
    Some(match condition {
        VER_EQUAL => order == Equal,
        2 => order == Greater,
        3 => order != Less,
        4 => order == Less,
        VER_LESS_EQUAL => order != Greater,
        _ => return None,
    })
}

/// Compares the system with `OSVERSIONINFOEXW` `info` for the types in
/// `types`, under the conditions in `mask`. TRUE when it meets them;
/// FALSE with ERROR_OLD_WIN_VERSION when not, ERROR_BAD_ARGUMENTS for a
/// bad mask, or ERROR_NOT_SUPPORTED when a fact is missing.
#[allow(non_snake_case)]
extern "stdcall" fn VerifyVersionInfoW(info: *const u8, types: u32, mask: u64) -> i32 {
    const CALLER: Caller = ("kernel32.dll", "VerifyVersionInfoW");
    // SAFETY: an OSVERSIONINFOEXW, 284 bytes (the API's contract).
    let info = unsafe { std::slice::from_raw_parts(info, 284) };
    let u32_at = |o: usize| u32::from_le_bytes(info[o..o + 4].try_into().unwrap());
    let u16_at = |o: usize| u32::from(u16::from_le_bytes([info[o], info[o + 1]]));
    let bad = || {
        set_last_error(ERROR_BAD_ARGUMENTS);
        0
    };
    if types == 0 || types & !0xff != 0 {
        return bad();
    }
    let fail = |what: &str| {
        with_current(|p| {
            p.record_runtime_gap(GapKind::Feature, CALLER.0, &format!("{}: {what}", CALLER.1))
        });
        set_last_error(ERROR_NOT_SUPPORTED);
        0
    };
    if types & VER_SUITENAME != 0 {
        return fail("the suite mask");
    }
    let Some(os_info) = facts::section(CALLER, "os_info") else {
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    };
    let Some(real) = real_version(&os_info) else {
        return fail("os_info has no usable version and build");
    };
    let manifest = with_current(|p| p.main_module().and_then(|m| m.manifest.clone()));
    let (major, minor, build) = shown(real, manifest.as_deref());
    let service_pack = if types & (VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR) != 0 {
        let Ok(csd) = facts::reg_value(CALLER, CURRENT_VERSION, "CSDVersion") else {
            set_last_error(ERROR_NOT_SUPPORTED);
            return 0;
        };
        csd.and_then(|v| v.get("data").and_then(Value::as_str).map(str::to_string))
            .and_then(|c| c.strip_prefix("Service Pack ").and_then(|n| n.parse().ok()))
            .unwrap_or(0u32)
    } else {
        0
    };
    // The version, as far as it is asked for, under its first condition.
    let parts = [
        (VER_MAJORVERSION, major, u32_at(4)),
        (VER_MINORVERSION, minor, u32_at(8)),
        (VER_SERVICEPACKMAJOR, service_pack, u16_at(276)),
        (VER_SERVICEPACKMINOR, 0, u16_at(278)),
    ];
    let asked: Vec<_> = parts.iter().filter(|(t, ..)| types & t != 0).collect();
    let mut ok = true;
    if let Some((first, ..)) = asked.first() {
        let have: Vec<u32> = asked.iter().map(|p| p.1).collect();
        let want: Vec<u32> = asked.iter().map(|p| p.2).collect();
        match holds(have, want, condition_of(mask, *first)) {
            Some(r) => ok &= r,
            None => return bad(),
        }
    }
    for (ty, have, want) in [
        (VER_BUILDNUMBER, build, u32_at(12)),
        (VER_PLATFORMID, VER_PLATFORM_WIN32_NT, u32_at(16)),
    ] {
        if types & ty != 0 {
            match holds(have, want, condition_of(mask, ty)) {
                Some(r) => ok &= r,
                None => return bad(),
            }
        }
    }
    if types & VER_PRODUCT_TYPE != 0 {
        let product = match product_type() {
            Ok(Some(t)) => t,
            Ok(None) => return fail("no ProductType or InstallationType in the registry"),
            Err(()) => {
                set_last_error(ERROR_NOT_SUPPORTED);
                return 0;
            }
        };
        match holds(product, info[282], condition_of(mask, VER_PRODUCT_TYPE)) {
            Some(r) => ok &= r,
            None => return bad(),
        }
    }
    if ok {
        1
    } else {
        set_last_error(ERROR_OLD_WIN_VERSION);
        0
    }
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

    /// An `OSVERSIONINFOEXW` asking for major.minor, SP major and a
    /// product type.
    fn wanted(major: u32, minor: u32, sp: u16, product: u8) -> Vec<u8> {
        let mut b = vec![0u8; 284];
        b[0..4].copy_from_slice(&284u32.to_le_bytes());
        b[4..8].copy_from_slice(&major.to_le_bytes());
        b[8..12].copy_from_slice(&minor.to_le_bytes());
        b[276..278].copy_from_slice(&sp.to_le_bytes());
        b[282] = product;
        b
    }

    #[test]
    fn verify_version_info_compares_capped_versions() {
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(
            base(json!({
                CURRENT_VERSION: {"InstallationType": {"type": "REG_SZ", "data": "Server"}},
            })),
            host(),
        ));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        // IsWindowsVersionOrGreater: major, minor and SP major, >=.
        let at_least = |major, minor| {
            let mut m = VerSetConditionMask(0, VER_MAJORVERSION, 3);
            m = VerSetConditionMask(m, VER_MINORVERSION, 3);
            m = VerSetConditionMask(m, VER_SERVICEPACKMAJOR, 3);
            let types = VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR;
            VerifyVersionInfoW(wanted(major, minor, 0, 0).as_ptr(), types, m)
        };
        // Without a manifest the program sees 6.2.
        assert_eq!(at_least(6, 1), 1);
        assert_eq!(at_least(6, 2), 1);
        assert_eq!(at_least(6, 3), 0);
        assert_eq!(
            crate::win::kernel32::error::GetLastError(),
            ERROR_OLD_WIN_VERSION
        );
        assert_eq!(at_least(5, 9), 1, "major decides first");
        // IsWindowsServer: product type not equal to workstation.
        let m = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);
        let w = wanted(0, 0, 0, VER_NT_WORKSTATION);
        assert_eq!(VerifyVersionInfoW(w.as_ptr(), VER_PRODUCT_TYPE, m), 0);
        let w = wanted(0, 0, 0, VER_NT_SERVER);
        assert_eq!(VerifyVersionInfoW(w.as_ptr(), VER_PRODUCT_TYPE, m), 1);
        // Bad masks and the suite mask.
        assert_eq!(VerifyVersionInfoW(w.as_ptr(), 0, m), 0);
        assert_eq!(
            crate::win::kernel32::error::GetLastError(),
            ERROR_BAD_ARGUMENTS
        );
        assert_eq!(VerifyVersionInfoW(w.as_ptr(), VER_BUILDNUMBER, 0), 0);
        assert_eq!(VerifyVersionInfoW(w.as_ptr(), VER_SUITENAME, m), 0);
        assert_eq!(runtime.lock().gaps().len(), 1);
    }

    #[test]
    fn condition_masks_keep_three_bits_per_type() {
        let m = VerSetConditionMask(0, VER_MAJORVERSION, 3);
        assert_eq!(m, 3 << 3);
        let m = VerSetConditionMask(m, VER_PRODUCT_TYPE, VER_LESS_EQUAL);
        assert_eq!(m, (3 << 3) | (5 << 21));
        assert_eq!(VerSetConditionMask(m, 0, 1), m);
        assert_eq!(VerSetConditionMask(m, VER_MAJORVERSION, 0), m);
        assert_eq!(condition_of(m, VER_PRODUCT_TYPE), VER_LESS_EQUAL);
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
