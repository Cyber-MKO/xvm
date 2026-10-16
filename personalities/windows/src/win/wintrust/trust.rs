//! Signature verdicts: `WinVerifyTrust`.
//!
//! Verdicts come from the host profile, not from parsing signatures
//! (brief, Decisions):
//! - An emulated system DLL is signed and valid.
//! - A file listed in `windows.trusted_files` is valid while its SHA-256
//!   matches, and has a bad digest otherwise.
//! - Any other file is not signed.
//!
//! Real system DLLs are catalog-signed, so on Windows a file-based check
//! of one fails and callers fall back to the catalog functions. Ours
//! succeeds at once, so that fallback does not run for them.
//!
//! Supported: `WINTRUST_ACTION_GENERIC_VERIFY_V2` with a file path
//! (`WTD_CHOICE_FILE`). Anything else is a logged gap.

use crate::gap::GapKind;
use crate::paths::DriveMap;
use crate::process::Process;
use crate::runtime::with_current;
use crate::sha256;
use crate::win::text::wide;

// From the WinVerifyTrust and WINTRUST_DATA pages on Microsoft Learn.
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800b_0001;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800b_0003;
const TRUST_E_NOSIGNATURE: u32 = 0x800b_0100;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
/// HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), for a listed file that is
/// missing on the drive.
const FILE_NOT_FOUND: u32 = 0x8007_0002;

const WTD_CHOICE_FILE: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;

/// {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}, in GUID memory layout.
const GENERIC_VERIFY_V2: [u8; 16] = [
    0x6b, 0xc5, 0xaa, 0x00, 0x44, 0xcd, 0xd0, 0x11, 0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee,
];

/// A state handle for callers that ask for one and close it later.
const STATE_HANDLE: u32 = 1;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("WinVerifyTrust", WinVerifyTrust as *const () as u32)]
}

/// The verdict for one file, by Windows path.
fn verdict(p: &Process, path: &str) -> u32 {
    let params = &p.params;
    let Ok(full) = DriveMap::full_path(path, &params.current_directory) else {
        return FILE_NOT_FOUND;
    };
    let emulated = p
        .modules()
        .iter()
        .filter(|m| m.emulated)
        .filter_map(|m| m.windows_path(params))
        .any(|w| w.eq_ignore_ascii_case(&full));
    if emulated {
        return 0;
    }
    let Some(expected) = params.trusted_files.get(&full.to_ascii_uppercase()) else {
        return TRUST_E_NOSIGNATURE;
    };
    let Ok(host) = params.drives.to_host(&full, &params.current_directory) else {
        return FILE_NOT_FOUND;
    };
    match std::fs::read(host) {
        Ok(data) if sha256::digest(&data) == *expected => 0,
        Ok(_) => TRUST_E_BAD_DIGEST,
        Err(_) => FILE_NOT_FOUND,
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn WinVerifyTrust(_window: u32, action: *const [u8; 16], data: *mut u32) -> u32 {
    // SAFETY: a GUID and a WINTRUST_DATA (the API's contract); the fields
    // read are inside the documented structure.
    let (action, choice, file_info, state_action) = unsafe {
        (
            *action,
            *data.add(5),
            *data.add(6) as *const u32,
            *data.add(7),
        )
    };
    with_current(|p| {
        if action != GENERIC_VERIFY_V2 {
            p.record_runtime_gap(
                GapKind::Feature,
                "wintrust.dll",
                "WinVerifyTrust action other than GENERIC_VERIFY_V2",
            );
            return TRUST_E_PROVIDER_UNKNOWN;
        }
        if state_action == WTD_STATEACTION_CLOSE {
            // SAFETY: hWVTStateData is the ninth field.
            unsafe { *data.add(8) = 0 };
            return 0;
        }
        if choice != WTD_CHOICE_FILE || file_info.is_null() {
            p.record_runtime_gap(
                GapKind::Feature,
                "wintrust.dll",
                &format!("WinVerifyTrust union choice {choice}"),
            );
            return TRUST_E_SUBJECT_FORM_UNKNOWN;
        }
        // SAFETY: WINTRUST_FILE_INFO { cbStruct, pcwszFilePath, hFile, .. }.
        let path = unsafe { *file_info.add(1) as *const u16 };
        // SAFETY: NULL or a NUL-terminated UTF-16 path.
        let Some(path) = (unsafe { wide(path) }) else {
            p.record_runtime_gap(
                GapKind::Feature,
                "wintrust.dll",
                "WinVerifyTrust by file handle only",
            );
            return TRUST_E_SUBJECT_FORM_UNKNOWN;
        };
        if state_action != 0 {
            // SAFETY: as above.
            unsafe { *data.add(8) = STATE_HANDLE };
        }
        verdict(p, &path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    fn verify(path: &str) -> u32 {
        let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
        let file_info = [16, wide.as_ptr() as u32, 0, 0];
        let mut data = [0u32; 13];
        data[0] = 52;
        data[5] = WTD_CHOICE_FILE;
        data[6] = file_info.as_ptr() as u32;
        data[7] = 1;
        let result = WinVerifyTrust(0, &GENERIC_VERIFY_V2, data.as_mut_ptr());
        assert_eq!(data[8], STATE_HANDLE);
        data[7] = WTD_STATEACTION_CLOSE;
        assert_eq!(WinVerifyTrust(0, &GENERIC_VERIFY_V2, data.as_mut_ptr()), 0);
        assert_eq!(data[8], 0);
        result
    }

    #[test]
    fn verdicts_follow_the_trusted_file_list() {
        let root = std::env::temp_dir().join(format!("xvm-trust-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("agent")).unwrap();
        std::fs::write(c.join("agent/good.exe"), b"shipped").unwrap();
        std::fs::write(c.join("agent/changed.dll"), b"tampered").unwrap();
        std::fs::write(c.join("agent/other.dll"), b"x").unwrap();

        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), c)]));
        process.params.current_directory = r"C:\".into();
        process.params.trusted_files = BTreeMap::from([
            (r"C:\AGENT\GOOD.EXE".to_string(), sha256::digest(b"shipped")),
            (
                r"C:\AGENT\CHANGED.DLL".to_string(),
                sha256::digest(b"shipped"),
            ),
            (r"C:\AGENT\GONE.DLL".to_string(), sha256::digest(b"shipped")),
        ]);
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();

        assert_eq!(verify(r"c:\agent\Good.exe"), 0);
        assert_eq!(verify(r"C:\agent\changed.dll"), TRUST_E_BAD_DIGEST);
        assert_eq!(verify(r"C:\agent\other.dll"), TRUST_E_NOSIGNATURE);
        assert_eq!(verify(r"C:\agent\gone.dll"), FILE_NOT_FOUND);
        assert!(runtime.lock().gaps().is_empty());

        let mut data = [0u32; 13];
        data[5] = 2;
        data[6] = 0x1000;
        assert_eq!(
            WinVerifyTrust(0, &GENERIC_VERIFY_V2, data.as_mut_ptr()),
            TRUST_E_SUBJECT_FORM_UNKNOWN
        );
        assert_eq!(
            WinVerifyTrust(0, &[0; 16], data.as_mut_ptr()),
            TRUST_E_PROVIDER_UNKNOWN
        );
        assert_eq!(runtime.lock().gaps().len(), 2);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
