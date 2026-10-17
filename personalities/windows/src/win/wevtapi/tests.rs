use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::json;

use super::render::{
    EVT_RENDER_BOOKMARK, EVT_RENDER_EVENT_VALUES, EVT_RENDER_EVENT_XML, EvtRender,
};
use super::*;
use crate::process::Process;
use crate::runtime::Runtime;

const CHANNELS: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog";

/// What the callback saw, per delivered event.
#[derive(Debug, Clone, Default)]
struct Seen {
    record: u64,
    xml: String,
    provider: String,
    event_id: u16,
    level: u8,
    keywords: u64,
    time_type: u32,
    sid: Vec<u8>,
    named: String,
    message: String,
}

static SEEN: Mutex<Vec<(u32, Seen)>> = Mutex::new(Vec::new());
static CONTEXTS: Mutex<(u32, u32)> = Mutex::new((0, 0));

fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn render(context: u32, event: u32, flags: u32) -> (Vec<u8>, u32) {
    let (mut used, mut count) = (0, 0);
    assert_eq!(
        EvtRender(
            context,
            event,
            flags,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut count
        ),
        0
    );
    let mut buf = vec![0u8; used as usize];
    assert_eq!(
        EvtRender(
            context,
            event,
            flags,
            used,
            buf.as_mut_ptr(),
            &mut used,
            &mut count
        ),
        1
    );
    (buf, count)
}

fn string_at(ptr: u64) -> String {
    // SAFETY: a NUL-terminated UTF-16 string inside the render buffer.
    unsafe { crate::win::text::wide(ptr as usize as *const u16) }.unwrap()
}

extern "stdcall" fn on_event(action: u32, context: u32, event: u32) -> u32 {
    if action != EVT_SUBSCRIBE_ACTION_DELIVER {
        return 0;
    }
    let (system, values) = *CONTEXTS.lock().unwrap();
    let (xml, _) = render(0, event, EVT_RENDER_EVENT_XML);
    let units: Vec<u16> = xml
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut seen = Seen {
        xml: String::from_utf16(&units[..units.len() - 1]).unwrap(),
        ..Seen::default()
    };
    let (buf, count) = render(system, event, EVT_RENDER_EVENT_VALUES);
    assert_eq!(count, 18);
    let field = |i: usize| -> (u64, u32) {
        let v = u64::from_le_bytes(buf[16 * i..16 * i + 8].try_into().unwrap());
        let t = u32::from_le_bytes(buf[16 * i + 12..16 * i + 16].try_into().unwrap());
        (v, t)
    };
    seen.provider = string_at(field(0).0);
    seen.event_id = field(2).0 as u16;
    seen.level = field(4).0 as u8;
    seen.keywords = field(7).0;
    seen.time_type = field(8).1;
    seen.record = field(9).0;
    let (sid, sid_type) = field(16);
    assert_eq!(sid_type, 19);
    // SAFETY: the SID inside the buffer: 8 bytes, then one sub-authority.
    seen.sid = unsafe { std::slice::from_raw_parts(sid as usize as *const u8, 12) }.to_vec();
    let (named, _) = render(values, event, EVT_RENDER_EVENT_VALUES);
    seen.named = string_at(u64::from_le_bytes(named[0..8].try_into().unwrap()));
    let mut text = vec![0u16; 64];
    let mut used = 0;
    assert_eq!(
        EvtFormatMessage(0, event, 0, 0, 0, 1, 64, text.as_mut_ptr(), &mut used),
        1
    );
    seen.message = String::from_utf16(&text[..used as usize - 1]).unwrap();
    SEEN.lock().unwrap().push((context, seen));
    0
}

fn host() -> (Runtime, crate::runtime::Attached, Client) {
    let base = json!({
        "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
        "source": {"golden_capture": "synthetic"},
        "registry": {"keys": {format!("{CHANNELS}\\Application"): {}}},
    });
    let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                      "os": "windows", "identity": {"hostname": "WIN-01"}});
    let (socket, name) = crate::testing::serve(base, host);
    let mut process = Process::new(Vec::new());
    process.engine_addr = Some((socket.clone(), name.clone()));
    process.engine = Some(Arc::new(std::sync::Mutex::new(
        Client::connect(&socket, &name).unwrap(),
    )));
    let runtime = Runtime::new(process);
    let thread = runtime.attach().unwrap();
    (runtime, thread, Client::connect(&socket, &name).unwrap())
}

fn write(writer: &mut Client, id: u32) {
    writer
        .call(
            "evt.write",
            json!({"channel": "Application", "event": {
                "provider": "XvmTest", "event_id": id, "level": 2, "keywords": "0x80000000000000",
                "user_id": "S-1-5-18", "message": format!("Event {id}."),
                "data": [{"name": "Path", "value": format!("C:\\{id}")}],
            }}),
        )
        .unwrap();
}

fn wait_for(context: u32, n: usize) -> Vec<Seen> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let seen: Vec<Seen> = SEEN
            .lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| *c == context)
            .map(|(_, s)| s.clone())
            .collect();
        if seen.len() >= n || Instant::now() > deadline {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn subscriptions_deliver_and_render_events() {
    let (runtime, _thread, mut writer) = host();
    let system = render::EvtCreateRenderContext(0, std::ptr::null(), 1);
    let path = wide_z("Event/EventData/Data[@Name='Path']");
    let paths = [path.as_ptr() as u32];
    let values = render::EvtCreateRenderContext(1, paths.as_ptr(), 0);
    *CONTEXTS.lock().unwrap() = (system, values);
    write(&mut writer, 1000);
    let channel = wide_z("Application");
    let callback = on_event as *const () as u32;

    // Future events only: event 1000 is already there.
    let future = EvtSubscribe(0, 0, channel.as_ptr(), std::ptr::null(), 0, 11, callback, 1);
    assert_ne!(future, 0);
    write(&mut writer, 1001);
    let seen = wait_for(11, 1);
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!((s.record, s.event_id, s.level), (2, 1001, 2));
    assert_eq!(s.provider, "XvmTest");
    assert_eq!(s.keywords, 0x80_0000_0000_0000);
    assert_eq!(s.time_type, 17, "a FILETIME");
    assert_eq!(s.sid, [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], "S-1-5-18");
    assert_eq!(s.named, "C:\\1001");
    assert_eq!(s.message, "Event 1001.");
    assert!(s.xml.starts_with("<Event xmlns="), "{}", s.xml);
    assert!(s.xml.contains("<EventRecordID>2</EventRecordID>"));
    assert_eq!(EvtClose(future), 1);

    // From the oldest record, and after a bookmark at record 1.
    let oldest = EvtSubscribe(0, 0, channel.as_ptr(), std::ptr::null(), 0, 12, callback, 2);
    let records: Vec<u64> = wait_for(12, 2).iter().map(|s| s.record).collect();
    assert_eq!(records, [1, 2]);
    EvtClose(oldest);
    let xml = wide_z(
        "<BookmarkList>\r\n  <Bookmark Channel='Application' RecordId='1' IsCurrent='true'/>\r\n</BookmarkList>",
    );
    let bookmark = EvtCreateBookmark(xml.as_ptr());
    let after = EvtSubscribe(
        0,
        0,
        channel.as_ptr(),
        std::ptr::null(),
        bookmark,
        13,
        callback,
        3,
    );
    let records: Vec<u64> = wait_for(13, 1).iter().map(|s| s.record).collect();
    assert_eq!(records, [2]);
    EvtClose(after);

    // A query, an unknown channel and pull subscriptions.
    let q = wide_z("*[System[EventID=1000]]");
    let filtered = EvtSubscribe(0, 0, channel.as_ptr(), q.as_ptr(), 0, 14, callback, 2);
    let ids: Vec<u16> = wait_for(14, 1).iter().map(|s| s.event_id).collect();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(ids, [1000]);
    EvtClose(filtered);
    let nowhere = wide_z("Nowhere");
    assert_eq!(
        EvtSubscribe(0, 0, nowhere.as_ptr(), std::ptr::null(), 0, 0, callback, 1),
        0
    );
    assert_eq!(
        crate::win::kernel32::error::GetLastError(),
        ERROR_EVT_CHANNEL_NOT_FOUND
    );
    assert_eq!(
        EvtSubscribe(0, 0x40, channel.as_ptr(), std::ptr::null(), 0, 0, 0, 1),
        0
    );
    assert!(
        runtime
            .lock()
            .gaps()
            .iter()
            .any(|g| g.symbol.contains("pull subscriptions"))
    );
}

#[test]
fn bookmarks_render_as_documented() {
    let (_runtime, _thread, _writer) = host();
    let empty = EvtCreateBookmark(std::ptr::null());
    let (xml, _) = render(0, empty, EVT_RENDER_BOOKMARK);
    let units: Vec<u16> = xml
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(
        String::from_utf16(&units).unwrap(),
        "<BookmarkList>\r\n</BookmarkList>\0"
    );
    let marks = BTreeMap::from([("System".to_string(), 4)]);
    let text = bookmark_xml(&marks);
    assert_eq!(
        text,
        "<BookmarkList>\r\n  <Bookmark Channel='System' RecordId='4' IsCurrent='true'/>\r\n</BookmarkList>"
    );
    assert_eq!(parse_bookmark(&text), Some(marks));
    let bad = wide_z("<NotABookmark/>");
    assert_eq!(EvtCreateBookmark(bad.as_ptr()), 0);
    assert_eq!(EvtClose(empty), 1);
    assert_eq!(EvtClose(empty), 0);
}
