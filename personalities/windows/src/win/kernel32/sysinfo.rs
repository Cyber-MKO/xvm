//! The system: `GetSystemInfo`, `GetProcessAffinityMask`,
//! `GlobalMemoryStatusEx`.
//!
//! `SYSTEM_INFO` as a 32-bit process sees it, from the GetSystemInfo page
//! and "WOW64 Implementation Details" on Microsoft Learn:
//!
//! | Field | Value |
//! | --- | --- |
//! | Architecture, processor type | Intel (0), Pentium (586): a 32-bit process sees x86 |
//! | Page size, allocation granularity | 4096, 65536 |
//! | Application addresses | 0x10000 to 0x7ffeffff, or to 0xfffeffff for a large-address-aware image on 64-bit Windows |
//! | Processors, active mask | `hardware.cpu.logical_processors`, at most 32 |
//! | Level, revision | Family, and model and stepping, from `Identifier` under `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` |
//!
//! A missing fact is a logged gap: 1 processor, or level and revision 0.
//!
//! `GetProcessAffinityMask` gives every processor to the process and the
//! system: one bit per processor of `GetSystemInfo`'s count.
//!
//! `GlobalMemoryStatusEx` fills MEMORYSTATUSEX (64 bytes):
//!
//! | Field | Value |
//! | --- | --- |
//! | Total physical memory | `hardware.memory_mb` |
//! | Total virtual memory | The application address range above |
//! | Memory load, available memory, page file | Not modelled: a logged gap. Load 0, everything available, a page file the size of memory |
//!
//! Without `hardware.memory_mb` it fails with ERROR_NOT_SUPPORTED, a
//! logged gap.
use serde_json::Value;

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};

const CALLER: Caller = ("kernel32.dll", "GetSystemInfo");
const CPU_KEY: &str = r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0";
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x20;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("GetSystemInfo", GetSystemInfo as *const () as u32),
        (
            "GetProcessAffinityMask",
            GetProcessAffinityMask as *const () as u32,
        ),
        (
            "GlobalMemoryStatusEx",
            GlobalMemoryStatusEx as *const () as u32,
        ),
    ]
}

fn gap(what: &str) {
    with_current(|p| {
        p.record_runtime_gap(GapKind::Feature, CALLER.0, &format!("{}: {what}", CALLER.1))
    });
}

/// (level, revision) from an identifier such as
/// "Intel64 Family 6 Model 85 Stepping 7".
fn level_revision(identifier: &str) -> Option<(u16, u16)> {
    let words: Vec<&str> = identifier.split_whitespace().collect();
    let after = |key: &str| -> Option<u16> {
        let i = words.iter().position(|w| w.eq_ignore_ascii_case(key))?;
        words.get(i + 1)?.parse().ok()
    };
    let (family, model, stepping) = (after("Family")?, after("Model")?, after("Stepping")?);
    Some((family, (model << 8) | stepping))
}

/// The host's processor count as a 32-bit process sees it (1 to 32).
fn processors() -> u32 {
    let processors = facts::section(CALLER, "hardware")
        .and_then(|h| h.pointer("/cpu/logical_processors").and_then(Value::as_u64))
        .map(|n| n.clamp(1, 32) as u32);
    processors.unwrap_or_else(|| {
        gap("no hardware.cpu.logical_processors");
        1
    })
}

fn mask(processors: u32) -> u32 {
    if processors >= 32 {
        u32::MAX
    } else {
        (1u32 << processors) - 1
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn GetProcessAffinityMask(process: u32, own: *mut u32, system: *mut u32) -> i32 {
    if process != super::process::CURRENT_PROCESS || own.is_null() || system.is_null() {
        gap("another process, or NULL masks");
        super::error::set_last_error(super::error::ERROR_INVALID_PARAMETER);
        return 0;
    }
    let m = mask(processors());
    // SAFETY: writable (the API's contract).
    unsafe {
        *own = m;
        *system = m;
    }
    1
}

#[allow(non_snake_case)]
extern "stdcall" fn GetSystemInfo(out: *mut u8) {
    let processors = processors();
    let identifier = facts::reg_value(CALLER, CPU_KEY, "Identifier")
        .ok()
        .flatten()
        .and_then(|v| v.get("data").and_then(Value::as_str).map(str::to_string));
    let (level, revision) = identifier
        .as_deref()
        .and_then(level_revision)
        .unwrap_or_else(|| {
            gap("no processor Identifier in the registry");
            (0, 0)
        });
    let maximum = maximum_address();
    let mask = mask(processors);
    let mut buf = [0u8; 36];
    buf[4..8].copy_from_slice(&4096u32.to_le_bytes());
    buf[8..12].copy_from_slice(&0x1_0000u32.to_le_bytes());
    buf[12..16].copy_from_slice(&maximum.to_le_bytes());
    buf[16..20].copy_from_slice(&mask.to_le_bytes());
    buf[20..24].copy_from_slice(&processors.to_le_bytes());
    buf[24..28].copy_from_slice(&586u32.to_le_bytes());
    buf[28..32].copy_from_slice(&0x1_0000u32.to_le_bytes());
    buf[32..34].copy_from_slice(&level.to_le_bytes());
    buf[34..36].copy_from_slice(&revision.to_le_bytes());
    // SAFETY: out holds a SYSTEM_INFO (the API's contract).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
}

/// The highest application address: more for a large-address-aware
/// image on 64-bit Windows.
fn maximum_address() -> u32 {
    let large = with_current(|p| {
        p.main_module()
            .is_some_and(|m| m.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0)
    });
    if large && facts::is_64bit(CALLER) == Some(true) {
        0xfffe_ffff
    } else {
        0x7ffe_ffff
    }
}

/// The lowest application address.
const MINIMUM_ADDRESS: u32 = 0x1_0000;

/// Fills MEMORYSTATUSEX. FALSE with ERROR_INVALID_PARAMETER when its
/// `dwLength` is not 64.
#[allow(non_snake_case)]
extern "stdcall" fn GlobalMemoryStatusEx(out: *mut u8) -> i32 {
    use super::error::{ERROR_INVALID_PARAMETER, set_last_error};
    const ERROR_NOT_SUPPORTED: u32 = 50;
    // SAFETY: out starts with dwLength (the API's contract).
    if out.is_null() || unsafe { out.cast::<u32>().read_unaligned() } != 64 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let caller: Caller = ("kernel32.dll", "GlobalMemoryStatusEx");
    let gap = |what: &str| {
        with_current(|p| {
            p.record_runtime_gap(GapKind::Feature, caller.0, &format!("{}: {what}", caller.1))
        })
    };
    let total = facts::section(caller, "hardware")
        .and_then(|h| h.get("memory_mb").and_then(Value::as_u64))
        .and_then(|mb| mb.checked_mul(1 << 20));
    let Some(total) = total else {
        gap("no hardware.memory_mb in the host profile");
        set_last_error(ERROR_NOT_SUPPORTED);
        return 0;
    };
    gap("memory in use is not modelled");
    let virtual_total = u64::from(maximum_address() + 1 - MINIMUM_ADDRESS);
    let mut buf = [0u8; 64];
    buf[0..4].copy_from_slice(&64u32.to_le_bytes());
    for (i, v) in [total, total, total, total, virtual_total, virtual_total, 0]
        .into_iter()
        .enumerate()
    {
        buf[8 + 8 * i..16 + 8 * i].copy_from_slice(&v.to_le_bytes());
    }
    // SAFETY: out holds a MEMORYSTATUSEX (checked above).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use serde_json::json;

    fn run(registry: Value) -> ([u8; 36], Vec<String>) {
        let base = json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "os_info": {"architecture": "x86_64"},
            "hardware": {"cpu": {"logical_processors": 4}, "memory_mb": 8192},
            "registry": {"keys": registry},
        });
        let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                          "os": "windows", "identity": {"hostname": "H"}});
        let mut process = Process::new(Vec::new());
        process.engine = Some(facts::test_engine(base, host));
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();
        let mut buf = [0xaau8; 36];
        GetSystemInfo(buf.as_mut_ptr());
        let mut memory = [0u8; 64];
        assert_eq!(GlobalMemoryStatusEx(memory.as_mut_ptr()), 0, "no dwLength");
        memory[0] = 64;
        assert_eq!(GlobalMemoryStatusEx(memory.as_mut_ptr()), 1);
        let q = |i: usize| u64::from_le_bytes(memory[8 + 8 * i..16 + 8 * i].try_into().unwrap());
        assert_eq!((q(0), q(1)), (8 << 30, 8 << 30), "8 GB, all available");
        assert_eq!((q(4), q(5)), (0x7ffe_0000, 0x7ffe_0000), "2 GB less 128 KB");
        let (mut own, mut system) = (0, 0);
        let me = super::super::process::CURRENT_PROCESS;
        assert_eq!(GetProcessAffinityMask(me, &mut own, &mut system), 1);
        assert_eq!((own, system), (0xf, 0xf), "four processors");
        let gaps = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        (buf, gaps)
    }

    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }

    #[test]
    fn a_32_bit_view_of_the_profile_hardware() {
        let (b, gaps) = run(json!({CPU_KEY: {"Identifier":
            {"type": "REG_SZ", "data": "Intel64 Family 6 Model 85 Stepping 7"}}}));
        assert_eq!(&b[0..2], [0, 0], "x86");
        assert_eq!(
            (u32_at(&b, 4), u32_at(&b, 8), u32_at(&b, 12)),
            (4096, 0x10000, 0x7ffe_ffff)
        );
        assert_eq!(
            (u32_at(&b, 16), u32_at(&b, 20), u32_at(&b, 24)),
            (0xf, 4, 586)
        );
        assert_eq!(u32_at(&b, 28), 0x10000);
        assert_eq!(u16::from_le_bytes([b[32], b[33]]), 6);
        assert_eq!(u16::from_le_bytes([b[34], b[35]]), (85 << 8) | 7);
        assert_eq!(
            gaps,
            ["GlobalMemoryStatusEx: memory in use is not modelled"]
        );
        let (b, gaps) = run(json!({}));
        assert_eq!(&b[32..36], [0, 0, 0, 0]);
        assert_eq!(
            gaps[0],
            "GetSystemInfo: no processor Identifier in the registry"
        );
    }
}
