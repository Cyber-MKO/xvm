use serde_json::json;

use super::wbem::{
    IID_IENUM_WBEM_CLASS_OBJECT, IID_IWBEM_LOCATOR, IID_IWBEM_SERVICES, WBEM_E_INVALID_NAMESPACE,
    WBEM_E_LOCAL_CREDENTIALS, WBEM_E_NOT_FOUND, WBEM_E_NOT_SUPPORTED, select_all, us_date,
};
use super::*;
use crate::process::Process;
use crate::runtime::Runtime;
use crate::win::facts;
use crate::win::oleaut32;

const CLSID_WBEM_LOCATOR: Guid = com::guid("4590f811-1d3a-11d0-891f-00aa004b2e24");

fn host() -> (Runtime, crate::runtime::Attached) {
    let base = json!({
        "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
        "source": {"golden_capture": "synthetic"},
        "hotfixes": [
            {"name": "KB5000001", "description": "Update", "installed_on": "2026-01-05",
             "installed_by": "NT AUTHORITY\\SYSTEM"},
            {"name": "KB5000002", "description": "Security Update", "installed_on": "2026-11-20"},
        ],
    });
    let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                      "os": "windows", "identity": {"hostname": "WIN-WEB-01"}});
    let mut process = Process::new(Vec::new());
    process.engine = Some(facts::test_engine(base, host));
    let runtime = Runtime::new(process);
    let thread = runtime.attach().unwrap();
    (runtime, thread)
}

/// The function in vtable slot `i` of the object at `this`.
fn slot(this: u32, i: usize) -> usize {
    // SAFETY: a live COM object whose vtable has more than `i` entries.
    unsafe { *((*(this as *const u32)) as *const u32).add(i) as usize }
}

fn bstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// The string or NULL in a VARIANT.
fn variant_text(v: &[u8; 16]) -> Option<String> {
    let vt = u16::from_le_bytes([v[0], v[1]]);
    let p = u32::from_le_bytes(v[8..12].try_into().unwrap());
    match vt {
        oleaut32::VT_NULL => None,
        oleaut32::VT_BSTR => {
            // SAFETY: a BSTR from Get.
            let len = oleaut32::SysStringLen(p as *const u16) as usize;
            // SAFETY: as above.
            let units = unsafe { std::slice::from_raw_parts(p as *const u16, len) };
            Some(String::from_utf16(units).unwrap())
        }
        other => panic!("type {other}"),
    }
}

type Release = extern "stdcall" fn(u32) -> u32;
type Connect = extern "stdcall" fn(
    u32,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    i32,
    *const u16,
    u32,
    *mut u32,
) -> u32;
type Query = extern "stdcall" fn(u32, *const u16, *const u16, u32, u32, *mut u32) -> u32;
type Next = extern "stdcall" fn(u32, i32, u32, *mut u32, *mut u32) -> u32;
type Get = extern "stdcall" fn(u32, *const u16, i32, *mut u8, *mut i32, *mut i32) -> u32;
type QueryInterface = extern "stdcall" fn(u32, *const u8, *mut u32) -> u32;

#[test]
fn hotfixes_through_wmi() {
    let (runtime, _thread) = host();
    let mut locator = 0;
    let create = |out: &mut u32| {
        CoCreateInstance(
            CLSID_WBEM_LOCATOR.as_ptr(),
            0,
            1,
            IID_IWBEM_LOCATOR.as_ptr(),
            out,
        )
    };
    assert_eq!(create(&mut locator), CO_E_NOTINITIALIZED);
    assert_eq!(CoInitializeEx(0, 0), S_OK);
    assert_eq!(CoInitializeEx(0, 0), S_FALSE);
    assert_eq!(CoInitializeEx(0, 2), RPC_E_CHANGED_MODE);
    assert_eq!(create(&mut locator), S_OK);
    assert_ne!(locator, 0);

    // SAFETY: the vtable slots hold these methods.
    let (connect, release): (Connect, Release) = unsafe {
        (
            std::mem::transmute::<usize, Connect>(slot(locator, 3)),
            std::mem::transmute::<usize, Release>(slot(locator, 2)),
        )
    };
    let mut services = 0;
    let none = std::ptr::null();
    let ns = bstr("ROOT\\CIMV2");
    assert_eq!(
        connect(
            locator,
            ns.as_ptr(),
            none,
            none,
            none,
            0,
            none,
            0,
            &mut services
        ),
        S_OK
    );
    let other = bstr(r"\\.\root\default");
    let mut dummy = 0;
    assert_eq!(
        connect(
            locator,
            other.as_ptr(),
            none,
            none,
            none,
            0,
            none,
            0,
            &mut dummy
        ),
        WBEM_E_INVALID_NAMESPACE
    );
    let user = bstr("admin");
    assert_eq!(
        connect(
            locator,
            ns.as_ptr(),
            user.as_ptr(),
            none,
            none,
            0,
            none,
            0,
            &mut dummy
        ),
        WBEM_E_LOCAL_CREDENTIALS
    );
    assert_eq!(CoSetProxyBlanket(services, 10, 0, 0, 3, 3, 0, 0), S_OK);

    // QueryInterface: its own interface, and a logged miss.
    // SAFETY: slot 0 is QueryInterface.
    let qi: QueryInterface =
        unsafe { std::mem::transmute::<usize, QueryInterface>(slot(services, 0)) };
    let mut same = 0;
    assert_eq!(qi(services, IID_IWBEM_SERVICES.as_ptr(), &mut same), S_OK);
    assert_eq!(same, services);
    release(same);
    assert_eq!(
        qi(services, IID_IENUM_WBEM_CLASS_OBJECT.as_ptr(), &mut same),
        E_NOINTERFACE
    );

    // SAFETY: slot 20 is ExecQuery.
    let exec: Query = unsafe { std::mem::transmute::<usize, Query>(slot(services, 20)) };
    let (wql, q) = (bstr("WQL"), bstr("SELECT * FROM Win32_QuickFixEngineering"));
    let mut rows = 0;
    assert_eq!(
        exec(services, wql.as_ptr(), q.as_ptr(), 0x30, 0, &mut rows),
        S_OK
    );
    let other = bstr("SELECT HotFixID FROM Win32_QuickFixEngineering");
    assert_eq!(
        exec(services, wql.as_ptr(), other.as_ptr(), 0x30, 0, &mut dummy),
        WBEM_E_NOT_SUPPORTED
    );

    // SAFETY: slot 4 of IEnumWbemClassObject is Next.
    let next: Next = unsafe { std::mem::transmute::<usize, Next>(slot(rows, 4)) };
    let (mut objects, mut returned) = ([0u32; 4], 0);
    assert_eq!(next(rows, -1, 1, objects.as_mut_ptr(), &mut returned), S_OK);
    assert_eq!(returned, 1);
    let first = objects[0];
    assert_eq!(
        next(rows, -1, 4, objects.as_mut_ptr(), &mut returned),
        S_FALSE
    );
    assert_eq!(returned, 1, "one row left");
    let second = objects[0];
    assert_eq!(
        next(rows, -1, 4, objects.as_mut_ptr(), &mut returned),
        S_FALSE
    );
    assert_eq!(returned, 0);

    // SAFETY: slot 4 of IWbemClassObject is Get.
    let get: Get = unsafe { std::mem::transmute::<usize, Get>(slot(first, 4)) };
    let read = |row: u32, name: &str| {
        let mut v = [0u8; 16];
        let (mut t, mut f) = (0, 0);
        let n = bstr(name);
        let hr = get(row, n.as_ptr(), 0, v.as_mut_ptr(), &mut t, &mut f);
        assert_eq!((hr, t), (S_OK, 8), "{name}");
        let text = variant_text(&v);
        oleaut32::SysFreeString(u32::from_le_bytes(v[8..12].try_into().unwrap()) as *mut u16);
        text
    };
    assert_eq!(read(first, "HotFixID").as_deref(), Some("KB5000001"));
    assert_eq!(read(first, "InstalledOn").as_deref(), Some("1/5/2026"));
    assert_eq!(
        read(first, "InstalledBy").as_deref(),
        Some("NT AUTHORITY\\SYSTEM")
    );
    assert_eq!(read(first, "csname").as_deref(), Some("WIN-WEB-01"));
    assert_eq!(
        read(first, "__CLASS").as_deref(),
        Some("Win32_QuickFixEngineering")
    );
    assert_eq!(
        read(second, "Description").as_deref(),
        Some("Security Update")
    );
    assert_eq!(read(second, "InstalledBy"), None, "not in this entry");
    assert_eq!(read(second, "Caption"), None);
    let missing = bstr("NoSuchProperty");
    assert_eq!(
        get(
            first,
            missing.as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut()
        ),
        WBEM_E_NOT_FOUND
    );

    for object in [first, second, rows, services, locator] {
        release(object);
    }
    CoUninitialize();
    CoUninitialize();
    let gaps: Vec<String> = runtime
        .lock()
        .gaps()
        .iter()
        .map(|g| g.symbol.clone())
        .collect();
    assert!(
        gaps.iter()
            .any(|g| g.contains("Win32_QuickFixEngineering.Caption")),
        "{gaps:?}"
    );
    assert!(gaps.iter().any(|g| g.contains("root\\default")), "{gaps:?}");
    assert!(gaps.iter().any(|g| g.starts_with("WQL query")), "{gaps:?}");
    assert!(
        gaps.iter().any(|g| g.starts_with("QueryInterface")),
        "{gaps:?}"
    );
}

#[test]
fn other_classes_are_gaps() {
    let (runtime, _thread) = host();
    assert_eq!(CoInitializeEx(0, 0), S_OK);
    let mut out = 1;
    let clsid = com::guid("00000000-0000-0000-0000-000000000001");
    let iid = IID_IUNKNOWN;
    assert_eq!(
        CoCreateInstance(clsid.as_ptr(), 0, 1, iid.as_ptr(), &mut out),
        REGDB_E_CLASSNOTREG
    );
    assert_eq!(out, 0);
    assert_eq!(CoSetProxyBlanket(0, 0, 0, 0, 0, 0, 0, 0), E_INVALIDARG);
    CoUninitialize();
    assert_eq!(runtime.lock().gaps().len(), 1);
}

#[test]
fn wql_and_dates() {
    assert_eq!(select_all("select  *  from Win32_Foo"), Some("Win32_Foo"));
    assert_eq!(select_all("SELECT * FROM A WHERE B = 1"), None);
    assert_eq!(us_date("2026-01-05").as_deref(), Some("1/5/2026"));
    assert_eq!(us_date("bad"), None);
}
