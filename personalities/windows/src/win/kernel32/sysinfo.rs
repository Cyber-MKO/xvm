//! The system: `GetSystemInfo`.
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

use serde_json::Value;

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};

const CALLER: Caller = ("kernel32.dll", "GetSystemInfo");
const CPU_KEY: &str = r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0";
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x20;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("GetSystemInfo", GetSystemInfo as *const () as u32)]
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

#[allow(non_snake_case)]
extern "stdcall" fn GetSystemInfo(out: *mut u8) {
    let processors = facts::section(CALLER, "hardware")
        .and_then(|h| h.pointer("/cpu/logical_processors").and_then(Value::as_u64))
        .map(|n| n.clamp(1, 32) as u32);
    let processors = processors.unwrap_or_else(|| {
        gap("no hardware.cpu.logical_processors");
        1
    });
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
    let large = with_current(|p| {
        p.main_module()
            .is_some_and(|m| m.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0)
    });
    let maximum: u32 = if large && facts::is_64bit(CALLER) == Some(true) {
        0xfffe_ffff
    } else {
        0x7ffe_ffff
    };
    let mask = if processors == 32 {
        u32::MAX
    } else {
        (1u32 << processors) - 1
    };
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
            "hardware": {"cpu": {"logical_processors": 4}},
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
        assert!(gaps.is_empty());
        let (b, gaps) = run(json!({}));
        assert_eq!(&b[32..36], [0, 0, 0, 0]);
        assert_eq!(
            gaps,
            ["GetSystemInfo: no processor Identifier in the registry"]
        );
    }
}
