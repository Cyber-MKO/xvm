//! COM objects for emulated interfaces.
//!
//! A COM object is a pointer to a pointer to its vtable, an array of
//! stdcall functions that take the object as their first argument. Agent
//! code calls them directly, not through an import, so each method we
//! implement gets a thunk that, like an emulated export's, goes through
//! the realigning trampoline (`emu::TRAMPOLINE`). Each method we do not
//! implement gets a gap trap that names the interface and method, and
//! stops the process (CLAUDE.md rule 4).
//!
//! Objects are `Object<T>`: the vtable pointer, a reference count, then
//! the object's own data. `release` frees the object at a count of zero.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::emu::TRAMPOLINE;
use crate::gap::{Gap, GapKind};
use crate::map::{MapError, Mapped};
use crate::pe::Protection;
use crate::runtime::with_current;

const PAGE: usize = 0x1000;
const THUNK_SIZE: usize = 16;
/// Thunks start after the trampoline, 16-byte aligned.
const FIRST_THUNK: usize = TRAMPOLINE.len().div_ceil(16) * 16;

const READ_WRITE: Protection = Protection {
    read: true,
    write: true,
    execute: false,
};
const READ_EXECUTE: Protection = Protection {
    read: true,
    write: false,
    execute: true,
};

/// Pages of thunks, each starting with its own copy of the trampoline.
/// They live as long as the process.
struct Thunks {
    pages: Vec<Mapped>,
    used: usize,
}

static THUNKS: Mutex<Thunks> = Mutex::new(Thunks {
    pages: Vec::new(),
    used: 0,
});

/// A thunk that runs `target`, a stdcall or cdecl function, on a 16-byte
/// aligned stack.
fn thunk(target: u32) -> Result<u32, MapError> {
    let mut t = THUNKS.lock().unwrap();
    if t.pages.is_empty() || t.used + THUNK_SIZE > PAGE {
        let page = Mapped::anonymous(0, PAGE)?;
        // SAFETY: a new page, writable, with nothing running from it.
        unsafe { page.write(0, &TRAMPOLINE) };
        t.pages.push(page);
        t.used = FIRST_THUNK;
    }
    let used = t.used;
    let page = t.pages.last().unwrap();
    let at = page.base() + used as u32;
    let mut code = [0xccu8; THUNK_SIZE];
    code[0] = 0xb8; // mov eax, target
    code[1..5].copy_from_slice(&target.to_le_bytes());
    code[5] = 0xe9; // jmp trampoline
    let rel = page.base().wrapping_sub(at + 10);
    code[6..10].copy_from_slice(&rel.to_le_bytes());
    page.set_protection(0, PAGE, READ_WRITE)?;
    // SAFETY: writable now; thunks already handed out are not overwritten,
    // and none run while the page is briefly not executable because
    // vtables are built before any object using this page exists.
    unsafe { page.write(used, &code) };
    page.set_protection(0, PAGE, READ_EXECUTE)?;
    t.used += THUNK_SIZE;
    Ok(at)
}

/// A vtable slot: a method name and its implementation, or `None` for a
/// method we do not implement.
pub type Slot = (&'static str, Option<u32>);

/// Builds the vtable of `interface` (from `dll`) and returns its address.
/// Vtables are never freed; build each once.
pub fn vtable(dll: &str, interface: &str, slots: &[Slot]) -> Result<u32, MapError> {
    let mut table = Vec::with_capacity(slots.len());
    for &(method, code) in slots {
        let entry = match code {
            Some(target) => thunk(target)?,
            None => with_current(|p| {
                let gap = Gap {
                    module: p.main_module().map(|m| m.name.clone()).unwrap_or_default(),
                    kind: GapKind::Feature,
                    dll: dll.to_string(),
                    symbol: format!("{interface}::{method}"),
                };
                p.trap(&gap)
            })?,
        };
        table.push(entry);
    }
    Ok(Box::leak(table.into_boxed_slice()).as_ptr() as u32)
}

/// A COM object: what agent code points at.
#[repr(C)]
pub struct Object<T> {
    vtable: u32,
    refs: AtomicU32,
    pub data: T,
}

/// A new object with one reference. Returns the interface pointer.
pub fn new_object<T>(vtable: u32, data: T) -> u32 {
    let object = Box::new(Object {
        vtable,
        refs: AtomicU32::new(1),
        data,
    });
    Box::into_raw(object) as u32
}

/// The object behind an interface pointer from `new_object::<T>`.
///
/// # Safety
///
/// `this` must come from `new_object::<T>` and still be alive.
pub unsafe fn object<'a, T>(this: u32) -> &'a Object<T> {
    // SAFETY: the caller's contract.
    unsafe { &*(this as *const Object<T>) }
}

/// The vtable address of an object, to tell interfaces apart.
///
/// # Safety
///
/// `this` must point at a live COM object.
pub unsafe fn vtable_of(this: u32) -> u32 {
    // SAFETY: the caller's contract; the vtable pointer comes first.
    unsafe { *(this as *const u32) }
}

/// `IUnknown::AddRef`.
pub extern "stdcall" fn add_ref<T>(this: u32) -> u32 {
    // SAFETY: COM calls methods on live objects only.
    unsafe { object::<T>(this) }
        .refs
        .fetch_add(1, Ordering::SeqCst)
        + 1
}

/// `IUnknown::Release`: frees the object when the count reaches zero.
pub extern "stdcall" fn release<T>(this: u32) -> u32 {
    // SAFETY: COM calls methods on live objects only.
    let left = unsafe { object::<T>(this) }
        .refs
        .fetch_sub(1, Ordering::SeqCst)
        - 1;
    if left == 0 {
        // SAFETY: the last reference; the object came from Box::into_raw.
        drop(unsafe { Box::from_raw(this as *mut Object<T>) });
    }
    left
}

/// A GUID in its in-memory layout.
pub type Guid = [u8; 16];

/// A GUID from its text form, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub const fn guid(text: &str) -> Guid {
    const fn hex(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    let t = text.as_bytes();
    let mut digits = [0u8; 32];
    let (mut i, mut n) = (0, 0);
    while i < t.len() {
        if t[i] != b'-' {
            digits[n] = hex(t[i]);
            n += 1;
        }
        i += 1;
    }
    assert!(n == 32, "a GUID has 32 hex digits");
    // Data1 (4 bytes), Data2 and Data3 (2 each) are little-endian; Data4
    // is 8 bytes in order.
    let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut out = [0u8; 16];
    let mut k = 0;
    while k < 16 {
        out[k] = (digits[2 * order[k]] << 4) | digits[2 * order[k] + 1];
        k += 1;
    }
    out
}

/// Reads the GUID at `p`, or None for NULL.
///
/// # Safety
///
/// `p` must be NULL or point at 16 readable bytes.
pub unsafe fn read_guid(p: *const u8) -> Option<Guid> {
    // SAFETY: the caller's contract.
    (!p.is_null()).then(|| unsafe { p.cast::<Guid>().read_unaligned() })
}

/// The text form of a GUID, for gap records.
pub fn guid_text(g: &Guid) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    let tail: String = g[8..].iter().map(|b| format!("{b:02x}")).collect();
    format!("{d1:08x}-{d2:04x}-{d3:04x}-{}-{}", &tail[..4], &tail[4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;

    struct Counter(u32);

    extern "stdcall" fn get(this: u32, out: *mut u32) -> u32 {
        // SAFETY: a live Counter object; out is writable.
        unsafe { *out = object::<Counter>(this).data.0 };
        0
    }

    #[test]
    fn objects_count_references_through_realigning_thunks() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let table = vtable(
            "test.dll",
            "ITest",
            &[
                ("QueryInterface", None),
                ("AddRef", Some(add_ref::<Counter> as *const () as u32)),
                ("Release", Some(release::<Counter> as *const () as u32)),
                ("Get", Some(get as *const () as u32)),
            ],
        )
        .unwrap();
        let this = new_object(table, Counter(42));
        // SAFETY: the vtable just built: four entries.
        let slots = unsafe { std::slice::from_raw_parts(table as *const u32, 4) };
        // SAFETY: the thunks run these stdcall functions.
        let (add, rel, get_value) = unsafe {
            (
                std::mem::transmute::<u32, extern "stdcall" fn(u32) -> u32>(slots[1]),
                std::mem::transmute::<u32, extern "stdcall" fn(u32) -> u32>(slots[2]),
                std::mem::transmute::<u32, extern "stdcall" fn(u32, *mut u32) -> u32>(slots[3]),
            )
        };
        assert_eq!(unsafe { vtable_of(this) }, table);
        assert_eq!(add(this), 2);
        let mut value = 0;
        assert_eq!(get_value(this, &mut value), 0);
        assert_eq!(value, 42);
        assert_eq!(rel(this), 1);
        assert_eq!(rel(this), 0);
        assert_ne!(slots[0], 0, "a trap for the missing method");
    }

    #[test]
    fn guids_in_memory_order() {
        let g = guid("4590f811-1d3a-11d0-891f-00aa004b2e24");
        assert_eq!(
            g,
            [
                0x11, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b,
                0x2e, 0x24
            ]
        );
        assert_eq!(guid_text(&g), "4590f811-1d3a-11d0-891f-00aa004b2e24");
    }
}
