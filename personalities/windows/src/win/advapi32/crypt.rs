//! CryptoAPI random numbers: `CryptAcquireContextA`, `CryptAcquireContextW`,
//! `CryptGenRandom`, `CryptReleaseContext`.
//!
//! Following the two functions' pages on Microsoft Learn. Random bytes
//! are all the census shows the agent asking for, so a context holds no
//! keys. `CRYPT_VERIFYCONTEXT` contexts need no key container. The
//! default container (no name) opens, or is created with
//! `CRYPT_NEWKEYSET`, without being stored on the host's disk: that is a
//! logged gap. Named containers, deleting containers and named providers
//! are logged gaps that fail. The bytes come from the real kernel's
//! random source: randomness is not a host fact.

use std::ffi::c_char;

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::kernel32::error::{ERROR_INVALID_PARAMETER, set_last_error};

const CRYPT_VERIFYCONTEXT: u32 = 0xf000_0000;
const CRYPT_SILENT: u32 = 0x40;
const CRYPT_MACHINE_KEYSET: u32 = 0x20;
const CRYPT_NEWKEYSET: u32 = 0x8;
// From the CryptAcquireContext page.
const NTE_BAD_KEYSET: u32 = 0x8009_0016;
const NTE_BAD_FLAGS: u32 = 0x8009_0009;
const NTE_KEYSET_NOT_DEF: u32 = 0x8009_0019;
/// Provider handles are opaque values, not kernel handles.
const FIRST_PROVIDER: u32 = 0x0010_0000;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "CryptAcquireContextA",
            CryptAcquireContextA as *const () as u32,
        ),
        (
            "CryptAcquireContextW",
            CryptAcquireContextW as *const () as u32,
        ),
        ("CryptGenRandom", CryptGenRandom as *const () as u32),
        (
            "CryptReleaseContext",
            CryptReleaseContext as *const () as u32,
        ),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "advapi32.dll", what));
}

#[allow(non_snake_case)]
extern "stdcall" fn CryptAcquireContextA(
    provider: *mut u32,
    container: *const c_char,
    provider_name: *const c_char,
    _provider_type: u32,
    flags: u32,
) -> i32 {
    acquire(
        "CryptAcquireContextA",
        provider,
        !container.is_null(),
        !provider_name.is_null(),
        flags,
    )
}

/// As `CryptAcquireContextA`, with UTF-16 names.
#[allow(non_snake_case)]
extern "stdcall" fn CryptAcquireContextW(
    provider: *mut u32,
    container: *const u16,
    provider_name: *const u16,
    _provider_type: u32,
    flags: u32,
) -> i32 {
    acquire(
        "CryptAcquireContextW",
        provider,
        !container.is_null(),
        !provider_name.is_null(),
        flags,
    )
}

fn acquire(
    function: &str,
    provider: *mut u32,
    container: bool,
    provider_name: bool,
    flags: u32,
) -> i32 {
    if provider.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let known = CRYPT_VERIFYCONTEXT | CRYPT_SILENT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET;
    if flags & !known != 0 {
        gap(&format!("{function} flags beyond opening and creating"));
        set_last_error(NTE_BAD_FLAGS);
        return 0;
    }
    if container {
        gap(&format!("{function} named key containers"));
        set_last_error(NTE_BAD_KEYSET);
        return 0;
    }
    if flags & CRYPT_VERIFYCONTEXT == 0 {
        gap(&format!(
            "{function} default key container (not stored on disk)"
        ));
    }
    if provider_name {
        gap(&format!("{function} named providers"));
        set_last_error(NTE_KEYSET_NOT_DEF);
        return 0;
    }
    let handle = with_current(|p| {
        let next = p.crypt_providers.last().map_or(FIRST_PROVIDER, |h| h + 8);
        p.crypt_providers.push(next);
        next
    });
    // SAFETY: writable (the API's contract).
    unsafe { *provider = handle };
    1
}

/// Ends a context. NTE_BAD_UID for a handle that is not one, and
/// NTE_BAD_FLAGS for non-zero flags, as the CryptReleaseContext page says.
#[allow(non_snake_case)]
extern "stdcall" fn CryptReleaseContext(provider: u32, flags: u32) -> i32 {
    const NTE_BAD_UID: u32 = 0x8009_0001;
    if flags != 0 {
        set_last_error(NTE_BAD_FLAGS);
        return 0;
    }
    let known = with_current(|p| {
        let at = p.crypt_providers.iter().position(|&h| h == provider);
        at.map(|i| p.crypt_providers.remove(i)).is_some()
    });
    if !known {
        set_last_error(NTE_BAD_UID);
        return 0;
    }
    1
}

/// Fills `buffer` with `len` random bytes.
#[allow(non_snake_case)]
extern "stdcall" fn CryptGenRandom(provider: u32, len: u32, buffer: *mut u8) -> i32 {
    let known = with_current(|p| p.crypt_providers.contains(&provider));
    if !known || (buffer.is_null() && len != 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let mut done = 0usize;
    while done < len as usize {
        // SAFETY: buffer holds len bytes (the API's contract).
        let n = unsafe { libc::getrandom(buffer.add(done).cast(), len as usize - done, 0) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        done += n as usize;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn verify_contexts_give_random_bytes() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut h = 0;
        let null = std::ptr::null();
        assert_eq!(
            CryptAcquireContextA(&mut h, null, null, 1, CRYPT_VERIFYCONTEXT | CRYPT_SILENT),
            1
        );
        assert_ne!(h, 0);
        let mut w = 0;
        let wnull: *const u16 = std::ptr::null();
        assert_eq!(
            CryptAcquireContextW(&mut w, wnull, wnull, 1, CRYPT_VERIFYCONTEXT | CRYPT_SILENT),
            1
        );
        assert!(w != h && w != 0, "a second context");
        let name: Vec<u16> = "keys\0".encode_utf16().collect();
        assert_eq!(
            CryptAcquireContextW(&mut w, name.as_ptr(), wnull, 1, CRYPT_VERIFYCONTEXT),
            0
        );
        assert_eq!(CryptReleaseContext(w, 1), 0, "flags must be 0");
        assert_eq!(CryptReleaseContext(w, 0), 1);
        assert_eq!(CryptReleaseContext(w, 0), 0, "released");
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        assert_eq!(CryptGenRandom(h, 64, a.as_mut_ptr()), 1);
        assert_eq!(CryptGenRandom(h, 64, b.as_mut_ptr()), 1);
        assert_ne!(a, b);
        assert_ne!(a, [0; 64]);
        assert_eq!(CryptGenRandom(h + 4, 1, a.as_mut_ptr()), 0);
        assert_eq!(CryptAcquireContextA(&mut h, c"box".as_ptr(), null, 1, 0), 0);
        // Wazuh's order: the default container, then creating it.
        assert_eq!(CryptAcquireContextA(&mut h, null, null, 1, 0), 1);
        assert_eq!(
            CryptAcquireContextA(&mut h, null, null, 1, CRYPT_NEWKEYSET),
            1
        );
        assert_eq!(CryptGenRandom(h, 8, a.as_mut_ptr()), 1);
        assert_eq!(
            CryptAcquireContextA(&mut h, null, null, 1, 0x10),
            0,
            "delete"
        );
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(
            gaps,
            [
                "CryptAcquireContextW named key containers",
                "CryptAcquireContextA named key containers",
                "CryptAcquireContextA default key container (not stored on disk)",
                "CryptAcquireContextA flags beyond opening and creating",
            ]
        );
    }
}
