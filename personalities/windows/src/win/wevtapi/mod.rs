//! `wevtapi.dll`: the Windows Event Log API, on the host-state engine's
//! event logs.
//!
//! Following the functions' pages and "Subscribing to Events",
//! "Rendering Events" and "Bookmarking Events" on Microsoft Learn:
//!
//! | Function | Behaviour |
//! | --- | --- |
//! | `EvtSubscribe` | Push subscriptions (a callback). A Windows thread per subscription, with its own engine connection, waits with `evt.wait` and delivers each new event with `evt.query`, in record order. Starts at future events, the oldest, or after a bookmark |
//! | `EvtCreateRenderContext`, `EvtRender` | In `render.rs` |
//! | `EvtFormatMessage` | The event's message (`evt.format_message`) |
//! | `EvtOpenPublisherMetadata` | A handle naming the provider |
//! | `EvtCreateBookmark`, `EvtUpdateBookmark` | A channel and record ID; XML as documented |
//! | `EvtClose` | Any handle; a subscription stops delivering |
//!
//! Remote sessions, pull subscriptions (a signal event), and message
//! kinds other than the event's own are logged gaps. EVT_HANDLEs are
//! values of their own, not kernel handles.

mod render;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use xvm_engine::client::{Client, ClientError};
use xvm_engine::protocol::code;

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::kernel32::error::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, set_last_error,
};
use crate::win::text::wide;

const EVT_SUBSCRIBE_TO_FUTURE_EVENTS: u32 = 1;
const EVT_SUBSCRIBE_START_AT_OLDEST_RECORD: u32 = 2;
const EVT_SUBSCRIBE_START_AFTER_BOOKMARK: u32 = 3;
const EVT_SUBSCRIBE_ORIGIN_MASK: u32 = 3;
const EVT_SUBSCRIBE_TOLERATE_QUERY_ERRORS: u32 = 0x1000;
const EVT_SUBSCRIBE_STRICT: u32 = 0x1_0000;
const EVT_SUBSCRIBE_ACTION_ERROR: u32 = 0;
const EVT_SUBSCRIBE_ACTION_DELIVER: u32 = 1;
const EVT_FORMAT_MESSAGE_EVENT: u32 = 1;

// From "System Error Codes (15000-15999)" on Microsoft Learn.
const ERROR_EVT_INVALID_QUERY: u32 = 15001;
const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;
const ERROR_EVT_MESSAGE_NOT_FOUND: u32 = 15027;
const ERROR_NOT_FOUND: u32 = 1168;
/// The subscription's engine connection failed.
const RPC_S_CALL_FAILED: u32 = 1726;

/// How long one engine wait lasts, so a closed subscription ends soon.
const WAIT_MS: u64 = 1000;
const BATCH: u64 = 100;
const FIRST_HANDLE: u32 = 0x0100_0000;

/// One event, as the engine gave it.
#[derive(Debug, Clone)]
pub struct EventData {
    pub channel: String,
    pub record_id: u64,
    pub json: Value,
    pub xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextKind {
    System,
    User,
    Values(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum EvtObject {
    Subscription(Arc<AtomicBool>),
    Event(Arc<EventData>),
    RenderContext(ContextKind),
    /// Channel name to the last record ID read there.
    Bookmark(BTreeMap<String, u64>),
    /// The provider's name, for the message kinds that will need it.
    Publisher(#[allow(dead_code)] String),
}

/// The process's EVT_HANDLEs.
#[derive(Debug, Default)]
pub struct EvtState {
    objects: BTreeMap<u32, EvtObject>,
    next: u32,
}

impl EvtState {
    fn insert(&mut self, object: EvtObject) -> u32 {
        self.next = self.next.max(FIRST_HANDLE) + 4;
        self.objects.insert(self.next, object);
        self.next
    }
}

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("EvtSubscribe", EvtSubscribe as *const () as u32),
        ("EvtClose", EvtClose as *const () as u32),
        (
            "EvtCreateRenderContext",
            render::EvtCreateRenderContext as *const () as u32,
        ),
        ("EvtRender", render::EvtRender as *const () as u32),
        ("EvtFormatMessage", EvtFormatMessage as *const () as u32),
        (
            "EvtOpenPublisherMetadata",
            EvtOpenPublisherMetadata as *const () as u32,
        ),
        ("EvtCreateBookmark", EvtCreateBookmark as *const () as u32),
        ("EvtUpdateBookmark", EvtUpdateBookmark as *const () as u32),
    ]
}

fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "wevtapi.dll", what));
}

pub(crate) fn object(handle: u32) -> Option<EvtObject> {
    with_current(|p| p.evt.objects.get(&handle).cloned())
}

fn insert(object: EvtObject) -> u32 {
    with_current(|p| p.evt.insert(object))
}

fn connect() -> Option<Client> {
    let (socket, host) = with_current(|p| p.engine_addr.clone())?;
    Client::connect(&socket, &host).ok()
}

/// The bookmark XML "Bookmarking Events" shows.
pub(crate) fn bookmark_xml(marks: &BTreeMap<String, u64>) -> String {
    let mut xml = String::from("<BookmarkList>\r\n");
    for (i, (channel, record)) in marks.iter().enumerate() {
        let current = if i == 0 { " IsCurrent='true'" } else { "" };
        xml.push_str(&format!(
            "  <Bookmark Channel='{channel}' RecordId='{record}'{current}/>\r\n"
        ));
    }
    xml.push_str("</BookmarkList>");
    xml
}

/// The channels and record IDs a bookmark XML names.
fn parse_bookmark(xml: &str) -> Option<BTreeMap<String, u64>> {
    let attribute = |tag: &str, name: &str| -> Option<String> {
        let start = tag.find(&format!("{name}="))? + name.len() + 1;
        let quote = tag[start..].chars().next()?;
        let rest = &tag[start + 1..];
        Some(rest[..rest.find(quote)?].to_string())
    };
    let mut marks = BTreeMap::new();
    for piece in xml.split("<Bookmark ").skip(1) {
        let tag = &piece[..piece.find('>')?];
        let channel = attribute(tag, "Channel")?;
        let record = attribute(tag, "RecordId")?.parse().ok()?;
        marks.insert(channel, record);
    }
    xml.contains("<BookmarkList").then_some(marks)
}

/// One subscription's delivery loop, on its own Windows thread.
fn deliver(
    mut client: Client,
    channel: String,
    query: String,
    mut after: u64,
    callback: u32,
    context: u32,
    stop: Arc<AtomicBool>,
) -> u32 {
    // SAFETY: DWORD WINAPI EVT_SUBSCRIBE_CALLBACK(EVT_SUBSCRIBE_NOTIFY_ACTION,
    // PVOID, EVT_HANDLE), given to EvtSubscribe.
    let callback: extern "stdcall" fn(u32, u32, u32) -> u32 =
        unsafe { std::mem::transmute(callback as usize) };
    while !stop.load(Ordering::SeqCst) {
        let waited = client.call(
            "evt.wait",
            json!({"channel": channel, "after": after, "timeout_ms": WAIT_MS}),
        );
        let Ok(waited) = waited else {
            gap("EvtSubscribe: the engine connection ended");
            callback(EVT_SUBSCRIBE_ACTION_ERROR, context, RPC_S_CALL_FAILED);
            return 1;
        };
        if waited.get("reset").and_then(Value::as_bool) == Some(true) {
            after = 0;
        }
        let newest = waited
            .get("newest_record_id")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        while newest > after && !stop.load(Ordering::SeqCst) {
            let params =
                json!({"channel": channel, "query": query, "after": after, "limit": BATCH});
            let (Ok(json), Ok(xml)) = (
                client.call("evt.query", merge(&params, "json")),
                client.call("evt.query", merge(&params, "xml")),
            ) else {
                gap("EvtSubscribe: the engine connection ended");
                callback(EVT_SUBSCRIBE_ACTION_ERROR, context, RPC_S_CALL_FAILED);
                return 1;
            };
            let events = json
                .get("events")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let xmls = xml
                .get("events")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for (event, rendered) in events.into_iter().zip(xmls) {
                if stop.load(Ordering::SeqCst) {
                    return 0;
                }
                let data = EventData {
                    channel: channel.clone(),
                    record_id: event.get("record_id").and_then(Value::as_u64).unwrap_or(0),
                    xml: rendered
                        .get("xml")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    json: event,
                };
                // The handle is valid only while the callback runs.
                let handle = insert(EvtObject::Event(Arc::new(data)));
                callback(EVT_SUBSCRIBE_ACTION_DELIVER, context, handle);
                with_current(|p| p.evt.objects.remove(&handle));
            }
            let last = json
                .get("last_record_id")
                .and_then(Value::as_u64)
                .unwrap_or(after);
            let more = json.get("more").and_then(Value::as_bool) == Some(true);
            // Events the query does not match still move the subscription on.
            after = if more { last } else { last.max(newest) };
        }
    }
    0
}

fn merge(params: &Value, format: &str) -> Value {
    let mut p = params.clone();
    p["format"] = json!(format);
    p
}

#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn EvtSubscribe(
    session: u32,
    signal_event: u32,
    channel: *const u16,
    query: *const u16,
    bookmark: u32,
    context: u32,
    callback: u32,
    flags: u32,
) -> u32 {
    let fail = |code: u32| {
        set_last_error(code);
        0
    };
    if session != 0 {
        gap("EvtSubscribe with a remote session");
        return fail(ERROR_INVALID_PARAMETER);
    }
    if signal_event != 0 || callback == 0 {
        gap("EvtSubscribe pull subscriptions (a signal event)");
        return fail(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let (channel, query) = unsafe { (wide(channel), wide(query)) };
    let Some(channel) = channel else {
        gap("EvtSubscribe without a channel (a structured query)");
        return fail(ERROR_INVALID_PARAMETER);
    };
    let query = query.unwrap_or_else(|| "*".into());
    if flags
        & !(EVT_SUBSCRIBE_ORIGIN_MASK | EVT_SUBSCRIBE_TOLERATE_QUERY_ERRORS | EVT_SUBSCRIBE_STRICT)
        != 0
    {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let Some(mut client) = connect() else {
        gap("EvtSubscribe needs the host-state engine");
        return fail(ERROR_EVT_CHANNEL_NOT_FOUND);
    };
    // The newest record now, which also checks that the channel exists.
    let newest = match client.call("evt.wait", json!({"channel": channel, "timeout_ms": 0})) {
        Ok(v) => v
            .get("newest_record_id")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        Err(ClientError::Engine(e)) if e.code == code::NOT_FOUND => {
            return fail(ERROR_EVT_CHANNEL_NOT_FOUND);
        }
        Err(_) => return fail(ERROR_EVT_CHANNEL_NOT_FOUND),
    };
    // Check the query once, as Windows does when it subscribes.
    let probe =
        json!({"channel": channel, "query": query, "after": newest, "limit": 1, "format": "json"});
    if let Err(ClientError::Engine(e)) = client.call("evt.query", probe)
        && e.code == code::BAD_QUERY
        && flags & EVT_SUBSCRIBE_TOLERATE_QUERY_ERRORS == 0
    {
        return fail(ERROR_EVT_INVALID_QUERY);
    }
    let after = match flags & EVT_SUBSCRIBE_ORIGIN_MASK {
        EVT_SUBSCRIBE_TO_FUTURE_EVENTS => newest,
        EVT_SUBSCRIBE_START_AT_OLDEST_RECORD => 0,
        EVT_SUBSCRIBE_START_AFTER_BOOKMARK => {
            let marked = match object(bookmark) {
                Some(EvtObject::Bookmark(marks)) => marks
                    .iter()
                    .find(|(c, _)| c.eq_ignore_ascii_case(&channel))
                    .map(|(_, r)| *r),
                _ => return fail(ERROR_INVALID_HANDLE),
            };
            match marked {
                Some(record) => record,
                // Not in the bookmark: strict fails, otherwise the oldest.
                None if flags & EVT_SUBSCRIBE_STRICT != 0 => return fail(ERROR_NOT_FOUND),
                None => 0,
            }
        }
        _ => return fail(ERROR_INVALID_PARAMETER),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let Some(runtime) = crate::runtime::current() else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    let run = {
        let stop = stop.clone();
        move || deliver(client, channel, query, after, callback, context, stop)
    };
    if runtime.spawn_thread(0, run).is_err() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    insert(EvtObject::Subscription(stop))
}

#[allow(non_snake_case)]
extern "stdcall" fn EvtClose(handle: u32) -> i32 {
    match with_current(|p| p.evt.objects.remove(&handle)) {
        Some(EvtObject::Subscription(stop)) => {
            stop.store(true, Ordering::SeqCst);
            1
        }
        Some(_) => 1,
        None => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    }
}

/// Copy `text` and its NUL into a buffer of `size` characters; `used` gets
/// the characters needed. ERROR_INSUFFICIENT_BUFFER when it does not fit.
pub(crate) fn put_wide(text: &str, out: *mut u16, size: u32, used: *mut u32) -> i32 {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    units.push(0);
    if !used.is_null() {
        // SAFETY: writable (the APIs' contract).
        unsafe { *used = units.len() as u32 };
    }
    if out.is_null() || (size as usize) < units.len() {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: out holds `size` characters.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), out, units.len()) };
    1
}

/// The event's message. Other message kinds are logged gaps.
#[allow(non_snake_case, clippy::too_many_arguments)]
extern "stdcall" fn EvtFormatMessage(
    _publisher: u32,
    event: u32,
    _message_id: u32,
    _value_count: u32,
    _values: u32,
    flags: u32,
    size: u32,
    out: *mut u16,
    used: *mut u32,
) -> i32 {
    if flags != EVT_FORMAT_MESSAGE_EVENT {
        gap(&format!("EvtFormatMessage kind {flags}"));
        set_last_error(ERROR_EVT_MESSAGE_NOT_FOUND);
        return 0;
    }
    let Some(EvtObject::Event(data)) = object(event) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    const CALLER: crate::win::facts::Caller = ("wevtapi.dll", "EvtFormatMessage");
    let params = json!({"channel": data.channel, "record_id": data.record_id});
    let message = crate::win::facts::call(CALLER, "evt.format_message", params)
        .ok()
        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string));
    match message {
        Some(text) => put_wide(&text, out, size, used),
        None => {
            set_last_error(ERROR_EVT_MESSAGE_NOT_FOUND);
            0
        }
    }
}

#[allow(non_snake_case)]
extern "stdcall" fn EvtOpenPublisherMetadata(
    session: u32,
    publisher: *const u16,
    log_file: *const u16,
    _locale: u32,
    _flags: u32,
) -> u32 {
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let Some(name) = (unsafe { wide(publisher) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if session != 0 || !log_file.is_null() {
        gap("EvtOpenPublisherMetadata with a session or log file");
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    insert(EvtObject::Publisher(name))
}

/// An empty bookmark, or one from bookmark XML.
#[allow(non_snake_case)]
extern "stdcall" fn EvtCreateBookmark(xml: *const u16) -> u32 {
    // SAFETY: NUL-terminated or NULL (the API's contract).
    let marks = match unsafe { wide(xml) } {
        None => BTreeMap::new(),
        Some(text) => match parse_bookmark(&text) {
            Some(marks) => marks,
            None => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
        },
    };
    insert(EvtObject::Bookmark(marks))
}

/// Points the bookmark at `event`.
#[allow(non_snake_case)]
extern "stdcall" fn EvtUpdateBookmark(bookmark: u32, event: u32) -> i32 {
    let Some(EvtObject::Event(data)) = object(event) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    with_current(|p| match p.evt.objects.get_mut(&bookmark) {
        Some(EvtObject::Bookmark(marks)) => {
            marks.clear();
            marks.insert(data.channel.clone(), data.record_id);
            1
        }
        _ => {
            set_last_error(ERROR_INVALID_HANDLE);
            0
        }
    })
}

#[cfg(test)]
mod tests;
