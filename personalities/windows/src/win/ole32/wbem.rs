//! WMI: the locator, `ROOT\CIMV2`, and the one query the census shows,
//! `SELECT * FROM Win32_QuickFixEngineering`.
//!
//! Interfaces and their method order follow the WMI COM API reference on
//! Microsoft Learn (IWbemLocator, IWbemServices, IEnumWbemClassObject,
//! IWbemClassObject) and the published `wbemcli` interface definitions.
//!
//! | Method | Behaviour |
//! | --- | --- |
//! | `IWbemLocator::ConnectServer` | The local `ROOT\CIMV2` namespace only. Credentials on a local connection fail with WBEM_E_LOCAL_CREDENTIALS, as documented. Other namespaces and remote servers are logged gaps |
//! | `IWbemServices::ExecQuery` | WQL `SELECT * FROM Win32_QuickFixEngineering`, one row per entry in the profile's `hotfixes` list. Other queries are logged gaps |
//! | `IEnumWbemClassObject::Next`, `Skip`, `Reset` | Over the rows taken when the query ran |
//! | `IWbemClassObject::Get` | String properties as VT_BSTR. A property the profile has no source for is VT_NULL and a logged gap |
//!
//! Every other method is a gap trap. Each object answers `QueryInterface`
//! for `IUnknown` and its own interface; any other is a logged gap.
//!
//! `InstalledOn` is month/day/year without leading zeros, the form
//! `Win32_QuickFixEngineering` reports on en-US hosts; the profile keeps
//! an ISO date.

use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

use super::{E_NOINTERFACE, E_OUTOFMEMORY, IID_IUNKNOWN, S_FALSE, S_OK, gap};
use crate::com::{self, Guid, Slot, add_ref, new_object, object, release};
use crate::win::facts::{self, Caller};
use crate::win::oleaut32::{self, VT_BSTR, VT_NULL};
use crate::win::text::wide;

pub(super) const CLSID_WBEM_LOCATOR: Guid = com::guid("4590f811-1d3a-11d0-891f-00aa004b2e24");
pub(super) const IID_IWBEM_LOCATOR: Guid = com::guid("dc12a687-737f-11cf-884d-00aa004b2e24");
pub(super) const IID_IWBEM_SERVICES: Guid = com::guid("9556dc99-828c-11cf-a37e-00aa003240c7");
pub(super) const IID_IENUM_WBEM_CLASS_OBJECT: Guid =
    com::guid("027947e1-d731-11ce-a357-000000000001");
const IID_IWBEM_CLASS_OBJECT: Guid = com::guid("dc12a681-737f-11cf-884d-00aa004b2e24");

/// The DLL gap records name: WMI's client side.
const DLL: &str = "wbemprox.dll";
const CALLER: Caller = (DLL, "IWbemServices::ExecQuery");

// WBEMSTATUS values from the WMI error constants page.
const WBEM_E_FAILED: u32 = 0x8004_1001;
pub(super) const WBEM_E_NOT_FOUND: u32 = 0x8004_1002;
const WBEM_E_INVALID_PARAMETER: u32 = 0x8004_1008;
pub(super) const WBEM_E_NOT_SUPPORTED: u32 = 0x8004_100c;
pub(super) const WBEM_E_INVALID_NAMESPACE: u32 = 0x8004_100e;
const WBEM_E_INVALID_QUERY_TYPE: u32 = 0x8004_1011;
pub(super) const WBEM_E_LOCAL_CREDENTIALS: u32 = 0x8004_1064;

const CIM_STRING: i32 = 8;
const WBEM_FLAVOR_ORIGIN_PROPAGATED: i32 = 0x20;
const WBEM_FLAVOR_ORIGIN_SYSTEM: i32 = 0x40;
const WBEM_FLAG_RETURN_IMMEDIATELY: u32 = 0x10;
const WBEM_FLAG_FORWARD_ONLY: u32 = 0x20;

const HOTFIX_CLASS: &str = "Win32_QuickFixEngineering";

/// The interface an object type implements.
trait Interface {
    const IID: Guid;
}

struct Locator;
struct Services;
struct Enumerator {
    rows: Vec<Row>,
    next: Mutex<usize>,
}
/// One instance: its class and property values; None is NULL, with the
/// reason it is a gap when it is one.
#[derive(Clone, Debug)]
struct Row {
    class: &'static str,
    properties: Vec<(&'static str, Result<Option<String>, &'static str>)>,
}

impl Interface for Locator {
    const IID: Guid = IID_IWBEM_LOCATOR;
}
impl Interface for Services {
    const IID: Guid = IID_IWBEM_SERVICES;
}
impl Interface for Enumerator {
    const IID: Guid = IID_IENUM_WBEM_CLASS_OBJECT;
}
impl Interface for Row {
    const IID: Guid = IID_IWBEM_CLASS_OBJECT;
}

/// Answers for `IUnknown` and the object's own interface.
extern "stdcall" fn query_interface<T: Interface>(this: u32, iid: *const u8, out: *mut u32) -> u32 {
    if out.is_null() {
        return super::E_POINTER;
    }
    // SAFETY: NULL or a GUID (the method's contract).
    let iid = unsafe { com::read_guid(iid) };
    if iid == Some(IID_IUNKNOWN) || iid == Some(T::IID) {
        add_ref::<T>(this);
        // SAFETY: writable (checked above).
        unsafe { *out = this };
        return S_OK;
    }
    if let Some(iid) = iid {
        gap(&format!(
            "QueryInterface of a WMI object for {{{}}}",
            com::guid_text(&iid)
        ));
    }
    // SAFETY: writable (checked above).
    unsafe { *out = 0 };
    E_NOINTERFACE
}

fn unknown<T: Interface>() -> [Slot; 3] {
    [
        (
            "QueryInterface",
            Some(query_interface::<T> as *const () as u32),
        ),
        ("AddRef", Some(add_ref::<T> as *const () as u32)),
        ("Release", Some(release::<T> as *const () as u32)),
    ]
}

/// The four vtables, built on first use.
struct Vtables {
    locator: u32,
    services: u32,
    enumerator: u32,
    row: u32,
}

static VTABLES: OnceLock<Option<Vtables>> = OnceLock::new();

fn build() -> Option<Vtables> {
    let with = |interface: &str, base: [Slot; 3], rest: &[Slot]| {
        let slots: Vec<Slot> = base.into_iter().chain(rest.iter().copied()).collect();
        com::vtable(DLL, interface, &slots).ok()
    };
    let none = |names: &[&'static str]| -> Vec<Slot> { names.iter().map(|&n| (n, None)).collect() };
    let locator = with(
        "IWbemLocator",
        unknown::<Locator>(),
        &[("ConnectServer", Some(connect_server as *const () as u32))],
    )?;
    let mut services = none(&[
        "OpenNamespace",
        "CancelAsyncCall",
        "QueryObjectSink",
        "GetObject",
        "GetObjectAsync",
        "PutClass",
        "PutClassAsync",
        "DeleteClass",
        "DeleteClassAsync",
        "CreateClassEnum",
        "CreateClassEnumAsync",
        "PutInstance",
        "PutInstanceAsync",
        "DeleteInstance",
        "DeleteInstanceAsync",
        "CreateInstanceEnum",
        "CreateInstanceEnumAsync",
        "ExecQuery",
        "ExecQueryAsync",
        "ExecNotificationQuery",
        "ExecNotificationQueryAsync",
        "ExecMethod",
        "ExecMethodAsync",
    ]);
    services[17].1 = Some(exec_query as *const () as u32);
    let services = with("IWbemServices", unknown::<Services>(), &services)?;
    let enumerator = with(
        "IEnumWbemClassObject",
        unknown::<Enumerator>(),
        &[
            ("Reset", Some(reset as *const () as u32)),
            ("Next", Some(next as *const () as u32)),
            ("NextAsync", None),
            ("Clone", None),
            ("Skip", Some(skip as *const () as u32)),
        ],
    )?;
    let mut row = none(&[
        "GetQualifierSet",
        "Get",
        "Put",
        "Delete",
        "GetNames",
        "BeginEnumeration",
        "Next",
        "EndEnumeration",
        "GetPropertyQualifierSet",
        "Clone",
        "GetObjectText",
        "SpawnDerivedClass",
        "SpawnInstance",
        "CompareTo",
        "GetPropertyOrigin",
        "InheritsFrom",
        "GetMethod",
        "PutMethod",
        "DeleteMethod",
        "BeginMethodEnumeration",
        "NextMethod",
        "EndMethodEnumeration",
        "GetMethodQualifierSet",
        "GetMethodOrigin",
    ]);
    row[1].1 = Some(get as *const () as u32);
    let row = with("IWbemClassObject", unknown::<Row>(), &row)?;
    Some(Vtables {
        locator,
        services,
        enumerator,
        row,
    })
}

fn vtables() -> Result<&'static Vtables, u32> {
    VTABLES.get_or_init(build).as_ref().ok_or(E_OUTOFMEMORY)
}

/// A new locator, for `CoCreateInstance`, as `iid`.
pub(super) fn locator(iid: &Guid) -> Result<u32, u32> {
    if *iid != IID_IUNKNOWN && *iid != IID_IWBEM_LOCATOR {
        gap(&format!("the WMI locator as {{{}}}", com::guid_text(iid)));
        return Err(E_NOINTERFACE);
    }
    Ok(new_object(vtables()?.locator, Locator))
}

/// A BSTR or wide string argument as text; None for NULL.
fn text(p: *const u16) -> Option<String> {
    // SAFETY: NULL or a NUL-terminated string (the methods' contract).
    unsafe { wide(p) }
}

/// Connects to a namespace on this host.
#[allow(clippy::too_many_arguments)]
extern "stdcall" fn connect_server(
    _this: u32,
    resource: *const u16,
    user: *const u16,
    password: *const u16,
    _locale: *const u16,
    _flags: i32,
    _authority: *const u16,
    _context: u32,
    out: *mut u32,
) -> u32 {
    if out.is_null() {
        return WBEM_E_INVALID_PARAMETER;
    }
    // SAFETY: writable (checked above).
    unsafe { *out = 0 };
    let Some(resource) = text(resource) else {
        return WBEM_E_INVALID_PARAMETER;
    };
    let namespace = match resource.strip_prefix(r"\\") {
        Some(rest) => {
            let (server, namespace) = rest.split_once('\\').unwrap_or((rest, ""));
            if server != "." && !server.eq_ignore_ascii_case("localhost") {
                gap(&format!("WMI on another server ({resource})"));
                return WBEM_E_NOT_SUPPORTED;
            }
            namespace.to_string()
        }
        None => resource,
    };
    if !namespace.eq_ignore_ascii_case(r"ROOT\CIMV2") {
        gap(&format!("WMI namespace {namespace}"));
        return WBEM_E_INVALID_NAMESPACE;
    }
    if !user.is_null() || !password.is_null() {
        return WBEM_E_LOCAL_CREDENTIALS;
    }
    match vtables() {
        Ok(v) => {
            // SAFETY: writable (checked above).
            unsafe { *out = new_object(v.services, Services) };
            S_OK
        }
        Err(hr) => hr,
    }
}

/// `SELECT * FROM CLASS`, the only form we answer: the class name, or
/// None for any other query.
pub(super) fn select_all(query: &str) -> Option<&str> {
    let words: Vec<&str> = query.split_whitespace().collect();
    match words[..] {
        [select, "*", from, class]
            if select.eq_ignore_ascii_case("SELECT") && from.eq_ignore_ascii_case("FROM") =>
        {
            Some(class)
        }
        _ => None,
    }
}

/// `YYYY-MM-DD` as `M/D/YYYY`.
pub(super) fn us_date(iso: &str) -> Option<String> {
    let mut parts = iso.splitn(3, '-').map(str::parse::<u32>);
    let (y, m, d) = (
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    Some(format!("{m}/{d}/{y}"))
}

fn hotfix_rows() -> Result<Vec<Row>, u32> {
    let list =
        facts::call(CALLER, "list", json!({"name": "hotfixes"})).map_err(|_| WBEM_E_FAILED)?;
    let host = facts::section(CALLER, "identity").and_then(|i| {
        i.get("hostname")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let text = |h: &Value, k: &str| h.get(k).and_then(Value::as_str).map(str::to_string);
    const NOT_IN_PROFILE: &str = "not in the host profile";
    Ok(list
        .as_array()
        .into_iter()
        .flatten()
        .map(|h| Row {
            class: HOTFIX_CLASS,
            properties: vec![
                ("HotFixID", Ok(text(h, "name"))),
                ("Description", Ok(text(h, "description"))),
                ("InstalledBy", Ok(text(h, "installed_by"))),
                (
                    "InstalledOn",
                    Ok(text(h, "installed_on").as_deref().and_then(us_date)),
                ),
                ("CSName", Ok(host.clone())),
                ("Caption", Err(NOT_IN_PROFILE)),
                ("FixComments", Err(NOT_IN_PROFILE)),
                ("InstallDate", Err(NOT_IN_PROFILE)),
                ("Name", Err(NOT_IN_PROFILE)),
                ("ServicePackInEffect", Err(NOT_IN_PROFILE)),
                ("Status", Err(NOT_IN_PROFILE)),
            ],
        })
        .collect())
}

/// Runs a WQL query and returns an enumerator over its rows.
extern "stdcall" fn exec_query(
    _this: u32,
    language: *const u16,
    query: *const u16,
    flags: u32,
    _context: u32,
    out: *mut u32,
) -> u32 {
    if out.is_null() {
        return WBEM_E_INVALID_PARAMETER;
    }
    // SAFETY: writable (checked above).
    unsafe { *out = 0 };
    let (Some(language), Some(query)) = (text(language), text(query)) else {
        return WBEM_E_INVALID_PARAMETER;
    };
    if !language.eq_ignore_ascii_case("WQL") {
        return WBEM_E_INVALID_QUERY_TYPE;
    }
    if flags & !(WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY) != 0 {
        gap(&format!("ExecQuery flags 0x{flags:x}"));
    }
    let rows = match select_all(&query) {
        Some(class) if class.eq_ignore_ascii_case(HOTFIX_CLASS) => hotfix_rows(),
        _ => {
            gap(&format!("WQL query {query:?}"));
            return WBEM_E_NOT_SUPPORTED;
        }
    };
    let rows = match rows {
        Ok(rows) => rows,
        Err(hr) => return hr,
    };
    match vtables() {
        Ok(v) => {
            let e = Enumerator {
                rows,
                next: Mutex::new(0),
            };
            // SAFETY: writable (checked above).
            unsafe { *out = new_object(v.enumerator, e) };
            S_OK
        }
        Err(hr) => hr,
    }
}

extern "stdcall" fn reset(this: u32) -> u32 {
    // SAFETY: a live enumerator.
    *unsafe { object::<Enumerator>(this) }
        .data
        .next
        .lock()
        .unwrap() = 0;
    S_OK
}

/// Moves past up to `count` rows. Returns the rows passed.
fn advance(this: u32, count: usize) -> std::ops::Range<usize> {
    // SAFETY: a live enumerator.
    let e = &unsafe { object::<Enumerator>(this) }.data;
    let mut next = e.next.lock().unwrap();
    let start = *next;
    *next = (start + count).min(e.rows.len());
    start..*next
}

/// Returns up to `count` rows as new objects. S_OK when all were there,
/// WBEM_S_FALSE (1) when fewer.
extern "stdcall" fn next(
    this: u32,
    _timeout: i32,
    count: u32,
    objects: *mut u32,
    returned: *mut u32,
) -> u32 {
    if objects.is_null() || returned.is_null() {
        return WBEM_E_INVALID_PARAMETER;
    }
    let table = match vtables() {
        Ok(v) => v.row,
        Err(hr) => return hr,
    };
    let range = advance(this, count as usize);
    // SAFETY: a live enumerator.
    let rows = &unsafe { object::<Enumerator>(this) }.data.rows;
    let n = range.len();
    for (i, row) in rows[range].iter().enumerate() {
        // SAFETY: `count` writable slots (the method's contract).
        unsafe { *objects.add(i) = new_object(table, row.clone()) };
    }
    // SAFETY: writable (checked above).
    unsafe { *returned = n as u32 };
    if n == count as usize { S_OK } else { S_FALSE }
}

extern "stdcall" fn skip(this: u32, _timeout: i32, count: u32) -> u32 {
    if advance(this, count as usize).len() == count as usize {
        S_OK
    } else {
        S_FALSE
    }
}

/// Reads a property: its value as a VARIANT, its CIM type and flavor.
extern "stdcall" fn get(
    this: u32,
    name: *const u16,
    _flags: i32,
    value: *mut u8,
    cim_type: *mut i32,
    flavor: *mut i32,
) -> u32 {
    let Some(name) = text(name) else {
        return WBEM_E_INVALID_PARAMETER;
    };
    // SAFETY: a live class object.
    let row = &unsafe { object::<Row>(this) }.data;
    let (found, origin) = if name.eq_ignore_ascii_case("__CLASS") {
        (Ok(Some(row.class.to_string())), WBEM_FLAVOR_ORIGIN_SYSTEM)
    } else {
        match row
            .properties
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(&name))
        {
            Some((_, v)) => (v.clone(), WBEM_FLAVOR_ORIGIN_PROPAGATED),
            None => {
                if name.starts_with("__") {
                    gap(&format!("WMI system property {name}"));
                }
                return WBEM_E_NOT_FOUND;
            }
        }
    };
    let found = found.unwrap_or_else(|why| {
        gap(&format!("{}.{name} is {why}", row.class));
        None
    });
    if !value.is_null() {
        let (vt, data) = match found {
            Some(s) => (VT_BSTR, oleaut32::from_str(&s) as u32),
            None => (VT_NULL, 0),
        };
        // SAFETY: a 16-byte VARIANT (the method's contract).
        unsafe {
            std::ptr::write_bytes(value, 0, 16);
            value.cast::<u16>().write_unaligned(vt);
            value.add(8).cast::<u32>().write_unaligned(data);
        }
    }
    // SAFETY: NULL or writable (the method's contract).
    unsafe {
        if let Some(t) = cim_type.as_mut() {
            *t = CIM_STRING;
        }
        if let Some(f) = flavor.as_mut() {
            *f = origin;
        }
    }
    S_OK
}
