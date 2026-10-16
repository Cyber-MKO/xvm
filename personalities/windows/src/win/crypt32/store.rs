//! System certificate stores: open, enumerate, name and close.
//!
//! Store contents come from the host profile (`windows.cert_stores`). A
//! store the profile does not list opens empty, and that is logged as a
//! gap. Certificates are handed out as `CERT_CONTEXT` structures (layout
//! from wincrypt.h on Microsoft Learn) that live as long as the process,
//! so freeing them, which `CertEnumCertificatesInStore` does on Windows,
//! is not needed.
//!
//! `CERT_INFO` is filled with the version, serial number (little-endian,
//! as CryptoAPI keeps it), issuer, validity and subject. The signature
//! algorithm, public key, unique IDs and extensions are left empty.

use std::ffi::c_char;

use crate::gap::GapKind;
use crate::process::{CertEntry, CertStore, Process};
use crate::runtime::with_current;
use crate::win::kernel32::error::{ERROR_INVALID_HANDLE, set_last_error};
use crate::win::text::ansi;
use crate::x509::{
    Certificate, Name, OID_COMMON_NAME, OID_EMAIL, OID_ORGANIZATION, OID_ORGANIZATIONAL_UNIT,
};

const X509_ASN_ENCODING: u32 = 1;
/// `CRYPT_E_NOT_FOUND`, from "COM Error Codes (Security and Setup)".
const CRYPT_E_NOT_FOUND: u32 = 0x8009_2004;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const CERT_NAME_ISSUER_FLAG: u32 = 1;
/// Seconds from 1601-01-01 (the FILETIME epoch) to 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 11_644_473_600;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        (
            "CertOpenSystemStoreA",
            CertOpenSystemStoreA as *const () as u32,
        ),
        (
            "CertEnumCertificatesInStore",
            CertEnumCertificatesInStore as *const () as u32,
        ),
        ("CertGetNameStringA", CertGetNameStringA as *const () as u32),
        ("CertCloseStore", CertCloseStore as *const () as u32),
    ]
}

/// Build the CryptoAPI view of a certificate.
fn entry(cert: &Certificate, store: u32) -> CertEntry {
    let mut buffers: Vec<Box<[u8]>> = vec![
        cert.der.clone().into(),
        cert.serial.iter().rev().copied().collect(),
        cert.issuer.der.clone().into(),
        cert.subject.der.clone().into(),
    ];
    let addr = |b: &mut Box<[u8]>| b.as_mut_ptr() as u32;
    let (der, serial, issuer, subject) = {
        let [a, b, c, d] = &mut buffers[..] else {
            unreachable!()
        };
        (addr(a), addr(b), addr(c), addr(d))
    };
    let filetime = |unix: i64| {
        let ticks = ((unix + FILETIME_UNIX_OFFSET) * 10_000_000) as u64;
        [ticks as u32, (ticks >> 32) as u32]
    };
    let mut info = Box::new([0u32; 28]);
    info[0] = cert.version;
    info[1..3].copy_from_slice(&[cert.serial.len() as u32, serial]);
    // [3..6] SignatureAlgorithm: not filled.
    info[6..8].copy_from_slice(&[cert.issuer.der.len() as u32, issuer]);
    info[8..10].copy_from_slice(&filetime(cert.not_before));
    info[10..12].copy_from_slice(&filetime(cert.not_after));
    info[12..14].copy_from_slice(&[cert.subject.der.len() as u32, subject]);
    // [14..28] public key, unique IDs and extensions: not filled.
    let context = Box::new([
        X509_ASN_ENCODING,
        der,
        cert.der.len() as u32,
        info.as_ptr() as u32,
        store,
    ]);
    CertEntry {
        cert: cert.clone(),
        context,
        info,
        buffers,
    }
}

fn store_mut(p: &mut Process, handle: u32) -> Option<&mut CertStore> {
    p.crypt
        .stores
        .iter_mut()
        .find(|(h, s)| *h == handle && s.open)
        .map(|(_, s)| s)
}

/// Opens a system store by name, such as `ROOT`. `provider` is unused,
/// as documented.
#[allow(non_snake_case)]
extern "stdcall" fn CertOpenSystemStoreA(_provider: u32, name: *const c_char) -> u32 {
    // SAFETY: a NUL-terminated string (the API's contract).
    let name = unsafe { ansi(name) }.unwrap_or_default();
    with_current(|p| {
        p.crypt.next_handle += 1;
        let handle = 0x00c0_0000 + p.crypt.next_handle * 8;
        let certs = p
            .params
            .cert_stores
            .get(&name.to_ascii_uppercase())
            .cloned();
        if certs.is_none() {
            p.record_runtime_gap(
                GapKind::Feature,
                "crypt32.dll",
                &format!("certificate store {name} not in the host profile"),
            );
        }
        let entries = certs
            .unwrap_or_default()
            .iter()
            .map(|c| entry(c, handle))
            .collect();
        p.crypt.stores.push((
            handle,
            CertStore {
                name,
                entries,
                open: true,
            },
        ));
        handle
    })
}

/// The certificate after `previous` (or the first), or NULL with
/// CRYPT_E_NOT_FOUND at the end.
#[allow(non_snake_case)]
extern "stdcall" fn CertEnumCertificatesInStore(store: u32, previous: u32) -> u32 {
    with_current(|p| {
        let Some(s) = store_mut(p, store) else {
            set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        };
        let next = if previous == 0 {
            0
        } else {
            match s
                .entries
                .iter()
                .position(|e| e.context.as_ptr() as u32 == previous)
            {
                Some(i) => i + 1,
                None => s.entries.len(),
            }
        };
        match s.entries.get(next) {
            Some(e) => e.context.as_ptr() as u32,
            None => {
                set_last_error(CRYPT_E_NOT_FOUND);
                0
            }
        }
    })
}

/// Closes the store. Its certificates stay valid, as they do on Windows
/// while their contexts are held.
#[allow(non_snake_case)]
extern "stdcall" fn CertCloseStore(store: u32, _flags: u32) -> i32 {
    with_current(|p| match store_mut(p, store) {
        Some(s) => {
            s.open = false;
            1
        }
        None if store == 0 => 1,
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    })
}

/// `CERT_NAME_SIMPLE_DISPLAY_TYPE`: the first of commonName,
/// organizationalUnitName, organizationName and emailAddress, from the
/// subject, or the issuer with `CERT_NAME_ISSUER_FLAG`.
fn simple_display(name: &Name) -> Option<&str> {
    [
        OID_COMMON_NAME,
        OID_ORGANIZATIONAL_UNIT,
        OID_ORGANIZATION,
        OID_EMAIL,
    ]
    .iter()
    .find_map(|oid| name.first(oid))
}

/// Returns the length of the name in characters with its NUL. With a NULL
/// buffer or zero size, only the length. A name that cannot be found is
/// an empty string (returns 1).
#[allow(non_snake_case)]
extern "stdcall" fn CertGetNameStringA(
    context: u32,
    kind: u32,
    flags: u32,
    _type_para: u32,
    out: *mut c_char,
    out_chars: u32,
) -> u32 {
    let text = with_current(|p| {
        let cert = p
            .crypt
            .stores
            .iter()
            .flat_map(|(_, s)| &s.entries)
            .find(|e| e.context.as_ptr() as u32 == context)
            .map(|e| e.cert.clone());
        let Some(cert) = cert else {
            return String::new();
        };
        if kind != CERT_NAME_SIMPLE_DISPLAY_TYPE || flags & !CERT_NAME_ISSUER_FLAG != 0 {
            p.record_runtime_gap(
                GapKind::Feature,
                "crypt32.dll",
                &format!("CertGetNameStringA type {kind} flags 0x{flags:x}"),
            );
            return String::new();
        }
        let name = if flags & CERT_NAME_ISSUER_FLAG != 0 {
            &cert.issuer
        } else {
            &cert.subject
        };
        match simple_display(name) {
            Some(text) => text.to_string(),
            None => {
                // Windows would look in the subject alternative name next.
                p.record_runtime_gap(
                    GapKind::Feature,
                    "crypt32.dll",
                    "CertGetNameStringA subject alternative name",
                );
                String::new()
            }
        }
    });
    // ANSI output; characters outside ASCII become '?' until code pages.
    let bytes: Vec<u8> = text
        .chars()
        .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
        .collect();
    let needed = bytes.len() as u32 + 1;
    if out.is_null() || out_chars == 0 {
        return needed;
    }
    let n = (bytes.len()).min(out_chars as usize - 1);
    // SAFETY: out holds out_chars bytes (the API's contract).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast(), out, n);
        *out.add(n) = 0;
    }
    n as u32 + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;

    const DIGICERT: &[u8] = include_bytes!(
        "../../../../../control/profiles/example-windows/certs/digicert-assured-id-root-ca.der"
    );

    fn runtime_with_root() -> Runtime {
        let mut process = Process::new(Vec::new());
        let cert = Certificate::parse(DIGICERT).unwrap();
        process.params.cert_stores.insert("ROOT".into(), vec![cert]);
        Runtime::new(process)
    }

    fn name_of(context: u32, flags: u32) -> String {
        let len = CertGetNameStringA(context, 4, flags, 0, std::ptr::null_mut(), 0);
        let mut buf = vec![0 as c_char; len as usize];
        assert_eq!(
            CertGetNameStringA(context, 4, flags, 0, buf.as_mut_ptr(), len),
            len
        );
        // SAFETY: NUL-terminated by CertGetNameStringA.
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn enumerates_the_profile_root_store() {
        let runtime = runtime_with_root();
        let _thread = runtime.attach().unwrap();
        let store = CertOpenSystemStoreA(0, c"root".as_ptr());
        assert_ne!(store, 0);
        let first = CertEnumCertificatesInStore(store, 0);
        assert_ne!(first, 0);
        assert_eq!(name_of(first, 0), "DigiCert Assured ID Root CA");
        assert_eq!(
            name_of(first, CERT_NAME_ISSUER_FLAG),
            "DigiCert Assured ID Root CA"
        );
        assert_eq!(CertEnumCertificatesInStore(store, first), 0);
        assert_eq!(CertCloseStore(store, 0), 1);
        assert_eq!(CertEnumCertificatesInStore(store, 0), 0);
        assert!(runtime.lock().gaps().is_empty());

        // SAFETY: CERT_CONTEXT and CERT_INFO stay valid for the process.
        unsafe {
            let ctx = first as *const u32;
            assert_eq!(*ctx, X509_ASN_ENCODING);
            let der = std::slice::from_raw_parts(*ctx.add(1) as *const u8, *ctx.add(2) as usize);
            assert_eq!(der, DIGICERT);
            assert_eq!(*ctx.add(4), store);
            let info = *ctx.add(3) as *const u32;
            assert_eq!(*info, 2);
            let serial =
                std::slice::from_raw_parts(*info.add(2) as *const u8, *info.add(1) as usize);
            assert_eq!(serial[0], 0x39, "serial is little-endian");
            // NotBefore: 2006-11-10 00:00:00 UTC as FILETIME.
            let not_before = (*info.add(9) as u64) << 32 | *info.add(8) as u64;
            assert_eq!(not_before, 128_075_904_000_000_000);
        }
    }

    #[test]
    fn copies_truncate_and_unknown_stores_are_gaps() {
        let runtime = runtime_with_root();
        let _thread = runtime.attach().unwrap();
        let store = CertOpenSystemStoreA(0, c"ROOT".as_ptr());
        let cert = CertEnumCertificatesInStore(store, 0);
        let mut small = [0x55 as c_char; 9];
        assert_eq!(CertGetNameStringA(cert, 4, 0, 0, small.as_mut_ptr(), 9), 9);
        // SAFETY: NUL-terminated by CertGetNameStringA.
        let text = unsafe { std::ffi::CStr::from_ptr(small.as_ptr()) };
        assert_eq!(text.to_str().unwrap(), "DigiCert");

        let my = CertOpenSystemStoreA(0, c"MY".as_ptr());
        assert_ne!(my, 0);
        assert_eq!(CertEnumCertificatesInStore(my, 0), 0);
        assert_eq!(
            CertGetNameStringA(cert, 1, 0, 0, std::ptr::null_mut(), 0),
            1
        );
        let gaps = runtime.lock().gaps().to_vec();
        assert_eq!(gaps.len(), 2, "{gaps:?}");
        assert!(gaps.iter().all(|g| g.kind == GapKind::Feature));
    }
}
