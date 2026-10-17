//! `oleaut32.dll`: BSTR strings and `VariantClear`.
//!
//! A BSTR, as the BSTR page on Microsoft Learn describes it, points at
//! UTF-16 text that is preceded by its length in bytes (4 bytes) and
//! followed by a NUL. NULL is a valid empty BSTR. They live on host
//! libc's heap.
//!
//! `VariantClear` frees what a VARIANT owns and leaves it `VT_EMPTY`:
//! a BSTR is freed and an interface is released. Arrays and by-reference
//! variants are a logged gap.

use crate::gap::GapKind;
use crate::runtime::with_current;

pub(crate) const VT_EMPTY: u16 = 0;
pub(crate) const VT_NULL: u16 = 1;
pub(crate) const VT_BSTR: u16 = 8;
const VT_DISPATCH: u16 = 9;
const VT_UNKNOWN: u16 = 13;
const VT_ARRAY: u16 = 0x2000;
const VT_BYREF: u16 = 0x4000;
const S_OK: u32 = 0;
const DISP_E_BADVARTYPE: u32 = 0x8002_0008;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("SysAllocString", SysAllocString as *const () as u32),
        ("SysAllocStringLen", SysAllocStringLen as *const () as u32),
        ("SysFreeString", SysFreeString as *const () as u32),
        ("SysStringLen", SysStringLen as *const () as u32),
        ("VariantClear", VariantClear as *const () as u32),
    ]
}

/// A BSTR holding `len` UTF-16 units copied from `text`, or zeroed when
/// `text` is NULL. NULL when out of memory.
pub(crate) fn alloc(text: *const u16, len: usize) -> *mut u16 {
    let Some(bytes) = len.checked_mul(2).filter(|&b| b <= u32::MAX as usize - 6) else {
        return std::ptr::null_mut();
    };
    // SAFETY: plain allocation of the prefix, the text and the NUL.
    let block = unsafe { libc::calloc(1, 4 + bytes + 2) }.cast::<u8>();
    if block.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the block holds 4 + bytes + 2 bytes; text, when given,
    // holds `len` units (the caller's contract).
    unsafe {
        block.cast::<u32>().write_unaligned(bytes as u32);
        let out = block.add(4).cast::<u16>();
        if !text.is_null() {
            std::ptr::copy_nonoverlapping(text, out, len);
        }
        out
    }
}

/// A BSTR copy of `s`.
pub(crate) fn from_str(s: &str) -> *mut u16 {
    let units: Vec<u16> = s.encode_utf16().collect();
    alloc(units.as_ptr(), units.len())
}

/// A copy of a NUL-terminated string, or NULL for NULL.
#[allow(non_snake_case)]
extern "stdcall" fn SysAllocString(text: *const u16) -> *mut u16 {
    if text.is_null() {
        return std::ptr::null_mut();
    }
    let mut len = 0;
    // SAFETY: a NUL-terminated string (the API's contract).
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    alloc(text, len)
}

/// A BSTR of `len` units, copied from `text` unless it is NULL.
#[allow(non_snake_case)]
extern "stdcall" fn SysAllocStringLen(text: *const u16, len: u32) -> *mut u16 {
    alloc(text, len as usize)
}

#[allow(non_snake_case)]
pub(crate) extern "stdcall" fn SysFreeString(bstr: *mut u16) {
    if !bstr.is_null() {
        // SAFETY: a BSTR from `alloc`, whose block starts 4 bytes before.
        unsafe { libc::free(bstr.cast::<u8>().sub(4).cast()) };
    }
}

/// The length in UTF-16 units; 0 for NULL.
#[allow(non_snake_case)]
pub(crate) extern "stdcall" fn SysStringLen(bstr: *const u16) -> u32 {
    if bstr.is_null() {
        return 0;
    }
    // SAFETY: a BSTR: its byte length is in the 4 bytes before it.
    unsafe { bstr.cast::<u8>().sub(4).cast::<u32>().read_unaligned() / 2 }
}

/// Frees what the VARIANT at `v` owns and sets it to VT_EMPTY.
#[allow(non_snake_case)]
extern "stdcall" fn VariantClear(v: *mut u8) -> u32 {
    if v.is_null() {
        return S_OK;
    }
    // SAFETY: a 16-byte VARIANT (the API's contract): vt at 0, the value
    // at 8.
    unsafe {
        let vt = v.cast::<u16>().read_unaligned();
        let value = v.add(8).cast::<u32>().read_unaligned();
        if vt & (VT_ARRAY | VT_BYREF) != 0 {
            with_current(|p| {
                p.record_runtime_gap(
                    GapKind::Feature,
                    "oleaut32.dll",
                    &format!("VariantClear of type 0x{vt:04x}"),
                )
            });
            return DISP_E_BADVARTYPE;
        }
        match vt {
            VT_BSTR => SysFreeString(value as *mut u16),
            VT_UNKNOWN | VT_DISPATCH if value != 0 => {
                // IUnknown::Release is the third vtable slot.
                let vtable = *(value as *const u32);
                let release: extern "stdcall" fn(u32) -> u32 =
                    std::mem::transmute(*(vtable as *const u32).add(2) as usize);
                release(value);
            }
            _ => {}
        }
        v.cast::<u16>().write_unaligned(VT_EMPTY);
    }
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    #[test]
    fn bstrs_carry_their_length() {
        let text: Vec<u16> = "KB5000001\0".encode_utf16().collect();
        let b = SysAllocString(text.as_ptr());
        assert_eq!(SysStringLen(b), 9);
        // SAFETY: 9 units and a NUL.
        assert_eq!(unsafe { std::slice::from_raw_parts(b, 10) }, &text[..]);
        // SAFETY: the prefix before the text.
        let bytes = unsafe { b.cast::<u8>().sub(4).cast::<u32>().read_unaligned() };
        assert_eq!(bytes, 18);
        SysFreeString(b);
        let part = SysAllocStringLen(text.as_ptr(), 2);
        assert_eq!(SysStringLen(part), 2);
        // SAFETY: NUL-terminated after 2 units.
        assert_eq!(unsafe { *part.add(2) }, 0);
        SysFreeString(part);
        assert!(SysAllocString(std::ptr::null()).is_null());
        assert_eq!(SysStringLen(std::ptr::null()), 0);
        SysFreeString(std::ptr::null_mut());
    }

    #[test]
    fn variant_clear_frees_strings() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let mut v = [0u8; 16];
        v[0..2].copy_from_slice(&VT_BSTR.to_le_bytes());
        v[8..12].copy_from_slice(&(from_str("x") as u32).to_le_bytes());
        assert_eq!(VariantClear(v.as_mut_ptr()), S_OK);
        assert_eq!(u16::from_le_bytes([v[0], v[1]]), VT_EMPTY);
        v[0..2].copy_from_slice(&(VT_ARRAY | VT_BSTR).to_le_bytes());
        assert_eq!(VariantClear(v.as_mut_ptr()), DISP_E_BADVARTYPE);
        assert_eq!(runtime.lock().gaps().len(), 1);
    }
}
