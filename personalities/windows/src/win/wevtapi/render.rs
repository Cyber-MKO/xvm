//! Rendering: `EvtCreateRenderContext`, `EvtRender`.
//!
//! From "Rendering Events", EVT_SYSTEM_PROPERTY_ID and EVT_VARIANT on
//! Microsoft Learn. An EVT_VARIANT is 16 bytes: the value (8), Count (4),
//! Type (4); strings, SIDs and GUIDs point into the same buffer after
//! the array. Elements the event lacks render as EvtVarTypeNull.
//!
//! | Context | Values |
//! | --- | --- |
//! | System | The 18 system properties, in EVT_SYSTEM_PROPERTY_ID order |
//! | User | Each `EventData/Data` value, as a string |
//! | Values | The paths given: `Event/System/...` as for System, `Event/EventData/Data[@Name='X']` as a string |
//!
//! XML renders the event's XML; a bookmark renders its bookmark XML.
//! Both are UTF-16 with a NUL, and `BufferUsed` counts bytes.

use serde_json::Value;

use super::{ContextKind, EventData, EvtObject, bookmark_xml, gap, insert, object};
use crate::win::kernel32::error::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error,
};
use crate::win::text::wide;

const EVT_RENDER_CONTEXT_VALUES: u32 = 0;
const EVT_RENDER_CONTEXT_SYSTEM: u32 = 1;
const EVT_RENDER_CONTEXT_USER: u32 = 2;
pub(super) const EVT_RENDER_EVENT_VALUES: u32 = 0;
pub(super) const EVT_RENDER_EVENT_XML: u32 = 1;
pub(super) const EVT_RENDER_BOOKMARK: u32 = 2;

/// The system property paths, in EVT_SYSTEM_PROPERTY_ID order.
const SYSTEM_PATHS: [&str; 18] = [
    "Event/System/Provider/@Name",
    "Event/System/Provider/@Guid",
    "Event/System/EventID",
    "Event/System/EventID/@Qualifiers",
    "Event/System/Level",
    "Event/System/Task",
    "Event/System/Opcode",
    "Event/System/Keywords",
    "Event/System/TimeCreated/@SystemTime",
    "Event/System/EventRecordID",
    "Event/System/Correlation/@ActivityID",
    "Event/System/Correlation/@RelatedActivityID",
    "Event/System/Execution/@ProcessID",
    "Event/System/Execution/@ThreadID",
    "Event/System/Channel",
    "Event/System/Computer",
    "Event/System/Security/@UserID",
    "Event/System/Version",
];

#[derive(Debug, Clone, PartialEq)]
enum Variant {
    Null,
    Str(String),
    Byte(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    HexInt64(u64),
    FileTime(u64),
    Sid(Vec<u8>),
    Guid([u8; 16]),
}

/// A SID such as `S-1-5-18` in binary form.
fn sid_bytes(text: &str) -> Option<Vec<u8>> {
    let mut parts = text.strip_prefix("S-")?.split('-');
    let revision: u8 = parts.next()?.parse().ok()?;
    let authority: u64 = parts.next()?.parse().ok()?;
    let subs: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let mut out = vec![revision, subs.len() as u8];
    out.extend_from_slice(&authority.to_be_bytes()[2..]);
    for s in subs {
        out.extend_from_slice(&s.to_le_bytes());
    }
    Some(out)
}

/// A GUID such as `{0CCE9223-69AE-11D9-BED3-505054503030}` in binary form.
fn guid_bytes(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok();
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = byte(i)?;
    }
    out[0..4].reverse();
    out[4..6].reverse();
    out[6..8].reverse();
    Some(out)
}

/// The FILETIME of an ISO 8601 UTC time, to 100 nanoseconds.
fn filetime(text: &str) -> Option<u64> {
    let (whole, fraction) = text
        .trim_end_matches('Z')
        .split_once('.')
        .unwrap_or((text, "0"));
    let seconds =
        crate::win::kernel32::time::parse_utc(&format!("{}Z", whole.trim_end_matches('Z')))? / 1000;
    let digits: String = fraction.chars().take_while(char::is_ascii_digit).collect();
    let ticks: u64 = format!("{digits:0<7}")[..7].parse().ok()?;
    Some(((seconds + 11_644_473_600) as u64) * 10_000_000 + ticks)
}

/// The `SystemTime` attribute in the event XML, which keeps 7 digits.
fn xml_time(xml: &str) -> Option<&str> {
    let start = xml.find("SystemTime='")? + "SystemTime='".len();
    Some(&xml[start..start + xml[start..].find('\'')?])
}

fn system_value(data: &EventData, index: usize) -> Variant {
    let j = &data.json;
    let num = |key: &str| j.get(key).and_then(Value::as_u64);
    let text = |key: &str| j.get(key).and_then(Value::as_str).map(str::to_string);
    match index {
        0 => text("provider").map_or(Variant::Null, Variant::Str),
        1 => text("provider_guid")
            .and_then(|g| guid_bytes(&g))
            .map_or(Variant::Null, Variant::Guid),
        2 => Variant::UInt16(num("event_id").unwrap_or(0) as u16),
        3 => num("qualifiers").map_or(Variant::Null, |q| Variant::UInt16(q as u16)),
        4 => Variant::Byte(num("level").unwrap_or(0) as u8),
        5 => Variant::UInt16(num("task").unwrap_or(0) as u16),
        6 => Variant::Byte(num("opcode").unwrap_or(0) as u8),
        7 => Variant::HexInt64(
            text("keywords")
                .and_then(|k| u64::from_str_radix(k.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0),
        ),
        8 => xml_time(&data.xml)
            .or(j.get("time").and_then(Value::as_str))
            .and_then(filetime)
            .map_or(Variant::Null, Variant::FileTime),
        9 => Variant::UInt64(data.record_id),
        10 | 11 => Variant::Null,
        12 => num("process_id").map_or(Variant::Null, |n| Variant::UInt32(n as u32)),
        13 => num("thread_id").map_or(Variant::Null, |n| Variant::UInt32(n as u32)),
        14 => Variant::Str(text("channel").unwrap_or_else(|| data.channel.clone())),
        15 => text("computer").map_or(Variant::Null, Variant::Str),
        16 => text("user_id")
            .and_then(|s| sid_bytes(&s))
            .map_or(Variant::Null, Variant::Sid),
        _ => Variant::Byte(num("version").unwrap_or(0) as u8),
    }
}

/// The `EventData/Data` items as (name, value).
fn data_items(data: &EventData) -> Vec<(String, String)> {
    match data.json.get("data") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| {
                let field = |k: &str| i.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                (field("name"), field("value"))
            })
            .collect(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str().map_or_else(|| v.to_string(), str::to_string),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn path_value(data: &EventData, path: &str) -> Variant {
    let path = path.trim_start_matches('/');
    if let Some(i) = SYSTEM_PATHS
        .iter()
        .position(|p| p.eq_ignore_ascii_case(path))
    {
        return system_value(data, i);
    }
    let named = path
        .strip_prefix("Event/EventData/Data[@Name='")
        .and_then(|rest| rest.strip_suffix("']"));
    if let Some(name) = named {
        return data_items(data)
            .into_iter()
            .find(|(n, _)| n == name)
            .map_or(Variant::Null, |(_, v)| Variant::Str(v));
    }
    gap(&format!("EvtRender value path {path}"));
    Variant::Null
}

/// EVT_VARIANTs for `values`, laid out for a buffer at `base`.
fn layout(values: &[Variant], base: u32) -> Vec<u8> {
    let mut head = vec![0u8; values.len() * 16];
    let mut tail: Vec<u8> = Vec::new();
    let place = |bytes: &[u8], tail: &mut Vec<u8>| {
        while !tail.len().is_multiple_of(8) {
            tail.push(0);
        }
        let at = base + (values.len() * 16 + tail.len()) as u32;
        tail.extend_from_slice(bytes);
        at
    };
    for (i, v) in values.iter().enumerate() {
        let (value, kind): (u64, u32) = match v {
            Variant::Null => (0, 0),
            Variant::Str(s) => {
                let units: Vec<u8> = s
                    .encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect();
                (place(&units, &mut tail) as u64, 1)
            }
            Variant::Byte(b) => (*b as u64, 4),
            Variant::UInt16(n) => (*n as u64, 6),
            Variant::UInt32(n) => (*n as u64, 8),
            Variant::UInt64(n) => (*n, 10),
            Variant::Guid(g) => (place(g, &mut tail) as u64, 15),
            Variant::FileTime(t) => (*t, 17),
            Variant::Sid(s) => (place(s, &mut tail) as u64, 19),
            Variant::HexInt64(n) => (*n, 21),
        };
        head[16 * i..16 * i + 8].copy_from_slice(&value.to_le_bytes());
        head[16 * i + 12..16 * i + 16].copy_from_slice(&kind.to_le_bytes());
    }
    head.extend(tail);
    head
}

#[allow(non_snake_case)]
pub(super) extern "stdcall" fn EvtCreateRenderContext(
    count: u32,
    paths: *const u32,
    flags: u32,
) -> u32 {
    let kind = match flags {
        EVT_RENDER_CONTEXT_SYSTEM => ContextKind::System,
        EVT_RENDER_CONTEXT_USER => ContextKind::User,
        EVT_RENDER_CONTEXT_VALUES if !paths.is_null() || count == 0 => {
            let list = (0..count as usize)
                // SAFETY: an array of `count` LPCWSTRs (the API's contract).
                .map(|i| unsafe { wide(*paths.add(i) as *const u16) }.unwrap_or_default())
                .collect();
            ContextKind::Values(list)
        }
        _ => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    };
    insert(EvtObject::RenderContext(kind))
}

fn copy_out(bytes: &[u8], size: u32, out: *mut u8, used: *mut u32) -> i32 {
    if !used.is_null() {
        // SAFETY: writable (the API's contract).
        unsafe { *used = bytes.len() as u32 };
    }
    if out.is_null() || (size as usize) < bytes.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: out holds `size` bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    1
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[allow(non_snake_case, clippy::too_many_arguments)]
pub(super) extern "stdcall" fn EvtRender(
    context: u32,
    fragment: u32,
    flags: u32,
    size: u32,
    out: *mut u8,
    used: *mut u32,
    count: *mut u32,
) -> i32 {
    let set_count = |n: usize| {
        if !count.is_null() {
            // SAFETY: writable (the API's contract).
            unsafe { *count = n as u32 };
        }
    };
    match (flags, object(fragment)) {
        (EVT_RENDER_EVENT_XML, Some(EvtObject::Event(data))) => {
            set_count(0);
            copy_out(&utf16(&data.xml), size, out, used)
        }
        (EVT_RENDER_BOOKMARK, Some(EvtObject::Bookmark(marks))) => {
            set_count(0);
            copy_out(&utf16(&bookmark_xml(&marks)), size, out, used)
        }
        (EVT_RENDER_EVENT_VALUES, Some(EvtObject::Event(data))) => {
            let values: Vec<Variant> = match object(context) {
                Some(EvtObject::RenderContext(ContextKind::System)) => (0..SYSTEM_PATHS.len())
                    .map(|i| system_value(&data, i))
                    .collect(),
                Some(EvtObject::RenderContext(ContextKind::User)) => data_items(&data)
                    .into_iter()
                    .map(|(_, v)| Variant::Str(v))
                    .collect(),
                Some(EvtObject::RenderContext(ContextKind::Values(paths))) => {
                    paths.iter().map(|p| path_value(&data, p)).collect()
                }
                _ => {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return 0;
                }
            };
            set_count(values.len());
            copy_out(&layout(&values, out as u32), size, out, used)
        }
        (_, None) => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
        _ => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    }
}
