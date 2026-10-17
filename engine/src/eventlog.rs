//! Windows event logs: one store per host, one ring of events per channel.
//!
//! Channels are the ones the host's registry declares, as on Windows:
//! classic logs under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\NAME`
//! and modern channels under
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NAME`. Each
//! channel's size limit is that key's `MaxSize`. When a channel is full the
//! oldest events are dropped and record IDs keep counting, which is the
//! Windows default ("overwrite events as needed").
//!
//! Events are rendered to the Windows event schema XML on read. Message text
//! comes from the event itself (golden corpus replay) or from the host's
//! message templates (profile `event_messages`, built from a golden capture).
//! A missing template is reported as such, never invented.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::evtquery::{Expr, Subject};
use crate::merge::norm;
use crate::protocol::code;
use crate::runtime::{Live, Rejected, check_time};

const CLASSIC: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog";
const MODERN: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels";
/// Used when a channel's key has no MaxSize: the documented Windows default (20480 KB).
pub const DEFAULT_MAX_SIZE: u64 = 20 * 1024 * 1024;
/// Events counted toward a channel's size by their stored JSON length, a
/// stand-in for Windows' binary record size.
const EVENT_FIELDS: [&str; 15] = [
    "provider",
    "provider_guid",
    "event_source",
    "event_id",
    "qualifiers",
    "version",
    "level",
    "task",
    "opcode",
    "keywords",
    "time",
    "process_id",
    "thread_id",
    "user_id",
    "data",
];

fn bad(msg: impl Into<String>) -> Rejected {
    Rejected(code::BAD_REQUEST, msg.into())
}

/// One stored event. `doc` holds the caller's fields, checked and normalised.
#[derive(Debug, Clone)]
pub struct Event {
    pub record_id: u64,
    pub channel: String,
    pub computer: String,
    pub doc: Map<String, Value>,
    pub size: usize,
}

impl Event {
    fn u(&self, k: &str) -> u64 {
        self.doc.get(k).and_then(Value::as_u64).unwrap_or(0)
    }

    fn s(&self, k: &str) -> Option<&str> {
        self.doc.get(k).and_then(Value::as_str)
    }

    pub fn time(&self) -> &str {
        self.s("time").unwrap_or_default()
    }

    pub fn data(&self) -> Vec<(Option<&str>, &str)> {
        self.doc
            .get("data")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|d| {
                        (
                            d.get("name").and_then(Value::as_str),
                            d["value"].as_str().unwrap_or(""),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The event as JSON, with the engine's fields.
    pub fn to_value(&self) -> Value {
        let mut out = self.doc.clone();
        out.insert("record_id".into(), self.record_id.into());
        out.insert("channel".into(), self.channel.clone().into());
        out.insert("computer".into(), self.computer.clone().into());
        Value::Object(out)
    }

    /// The event in the Windows event schema, as EvtRender with EvtRenderEventXml returns it.
    pub fn xml(&self) -> String {
        let mut x = String::with_capacity(512);
        x.push_str("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>");
        x.push_str("<Provider Name='");
        x.push_str(&esc(self.s("provider").unwrap_or_default()));
        x.push('\'');
        if let Some(g) = self.s("provider_guid") {
            x.push_str(&format!(" Guid='{}'", esc(g)));
        }
        if let Some(src) = self.s("event_source") {
            x.push_str(&format!(" EventSourceName='{}'", esc(src)));
        }
        x.push_str("/>");
        match self.doc.get("qualifiers").and_then(Value::as_u64) {
            Some(q) => x.push_str(&format!(
                "<EventID Qualifiers='{q}'>{}</EventID>",
                self.u("event_id")
            )),
            None => x.push_str(&format!("<EventID>{}</EventID>", self.u("event_id"))),
        }
        x.push_str(&format!(
            "<Version>{}</Version><Level>{}</Level><Task>{}</Task><Opcode>{}</Opcode><Keywords>{}</Keywords>",
            self.u("version"),
            self.u("level"),
            self.u("task"),
            self.u("opcode"),
            esc(self.s("keywords").unwrap_or("0x0"))
        ));
        x.push_str(&format!(
            "<TimeCreated SystemTime='{}'/>",
            seven_digit_time(self.time())
        ));
        x.push_str(&format!(
            "<EventRecordID>{}</EventRecordID><Correlation/>",
            self.record_id
        ));
        match (self.doc.get("process_id"), self.doc.get("thread_id")) {
            (None, None) => x.push_str("<Execution/>"),
            (p, t) => x.push_str(&format!(
                "<Execution ProcessID='{}' ThreadID='{}'/>",
                p.and_then(Value::as_u64).unwrap_or(0),
                t.and_then(Value::as_u64).unwrap_or(0)
            )),
        }
        x.push_str(&format!(
            "<Channel>{}</Channel><Computer>{}</Computer>",
            esc(&self.channel),
            esc(&self.computer)
        ));
        match self.s("user_id") {
            Some(u) => x.push_str(&format!("<Security UserID='{}'/>", esc(u))),
            None => x.push_str("<Security/>"),
        }
        x.push_str("</System>");
        let data = self.data();
        if data.is_empty() {
            x.push_str("<EventData/>");
        } else {
            x.push_str("<EventData>");
            for (name, value) in data {
                match name {
                    Some(n) => {
                        x.push_str(&format!("<Data Name='{}'>{}</Data>", esc(n), esc(value)))
                    }
                    None => x.push_str(&format!("<Data>{}</Data>", esc(value))),
                }
            }
            x.push_str("</EventData>");
        }
        x.push_str("</Event>");
        x
    }
}

/// `2026-10-16T10:00:00.25Z` to `2026-10-16T10:00:00.2500000Z`, the precision Windows renders.
fn seven_digit_time(t: &str) -> String {
    let Some(base) = t.strip_suffix('Z') else {
        return t.to_string();
    };
    let (secs, frac) = base.split_once('.').unwrap_or((base, ""));
    let mut f: String = frac.chars().take(7).collect();
    while f.len() < 7 {
        f.push('0');
    }
    format!("{secs}.{f}Z")
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

struct Subj<'a> {
    e: &'a Event,
    now_ms: Option<i64>,
}

fn time_ms(t: &str) -> Option<i64> {
    crate::runtime::parse_ms(t)
}

impl Subject for Subj<'_> {
    fn field(&self, name: &str) -> Option<Value> {
        let e = self.e;
        Some(match name {
            "EventID" => e.u("event_id").into(),
            "Level" => e.u("level").into(),
            "Task" => e.u("task").into(),
            "Opcode" => e.u("opcode").into(),
            "Version" => e.u("version").into(),
            "EventRecordID" => e.record_id.into(),
            "Computer" => e.computer.clone().into(),
            "Channel" => e.channel.clone().into(),
            "Keywords" => e.s("keywords").unwrap_or("0x0").into(),
            "Provider@Name" => e.s("provider")?.into(),
            "Provider@Guid" => e.s("provider_guid")?.into(),
            "Provider@EventSourceName" => e.s("event_source")?.into(),
            "Security@UserID" => e.s("user_id")?.into(),
            "TimeCreated@SystemTime" => seven_digit_time(e.time()).into(),
            _ => return None,
        })
    }

    fn data(&self) -> Vec<(Option<&str>, &str)> {
        self.e.data()
    }

    fn age_ms(&self) -> Option<u64> {
        let t = time_ms(self.e.time())?;
        Some(self.now_ms?.saturating_sub(t).max(0) as u64)
    }
}

/// Check an event from a caller and normalise it. `time` fills in a missing `time`.
pub fn check_event(v: &Value, time: &str) -> Result<Map<String, Value>, Rejected> {
    let obj = v
        .as_object()
        .ok_or_else(|| bad("event must be an object"))?;
    if let Some(k) = obj
        .keys()
        .find(|k| !EVENT_FIELDS.contains(&k.as_str()) && *k != "message")
    {
        return Err(bad(format!("unknown event field {k}")));
    }
    let mut out = Map::new();
    let provider = obj
        .get("provider")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("event needs a provider"))?;
    out.insert("provider".into(), provider.into());
    for k in ["provider_guid", "event_source", "user_id", "message"] {
        match obj.get(k) {
            None => {}
            Some(Value::String(s)) => {
                out.insert(k.into(), s.clone().into());
            }
            Some(_) => return Err(bad(format!("{k} must be text"))),
        }
    }
    for (k, max, required) in [
        ("event_id", 65_535, true),
        ("qualifiers", 65_535, false),
        ("version", 255, false),
        ("level", 255, false),
        ("task", 65_535, false),
        ("opcode", 255, false),
        ("process_id", u64::from(u32::MAX), false),
        ("thread_id", u64::from(u32::MAX), false),
    ] {
        match obj.get(k) {
            None if required => return Err(bad(format!("event needs {k}"))),
            None => {}
            Some(v) => {
                let n = v
                    .as_u64()
                    .filter(|n| *n <= max)
                    .ok_or_else(|| bad(format!("{k} must be a whole number up to {max}")))?;
                out.insert(k.into(), n.into());
            }
        }
    }
    match obj.get("keywords") {
        None => {}
        Some(Value::String(s))
            if s.starts_with("0x") && u64::from_str_radix(&s[2..], 16).is_ok() =>
        {
            out.insert("keywords".into(), s.clone().into());
        }
        Some(_) => return Err(bad("keywords must be hex text such as 0x8020000000000000")),
    }
    let t = match obj.get("time") {
        None => time.to_string(),
        Some(Value::String(s)) => {
            check_time(s)?;
            s.clone()
        }
        Some(_) => return Err(bad("time must be text")),
    };
    out.insert("time".into(), t.into());
    let data = match obj.get("data") {
        None => Vec::new(),
        Some(Value::Array(a)) => {
            let mut items = Vec::with_capacity(a.len());
            for d in a {
                let value = d
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("each data item needs a text value"))?;
                let mut item = Map::new();
                if let Some(n) = d.get("name") {
                    let n = n.as_str().ok_or_else(|| bad("a data name must be text"))?;
                    item.insert("name".into(), n.into());
                }
                item.insert("value".into(), value.into());
                items.push(Value::Object(item));
            }
            items
        }
        // An object keeps its order: name to value.
        Some(Value::Object(m)) => m
            .iter()
            .map(|(n, v)| {
                v.as_str()
                    .map(|s| json!({"name": n, "value": s}))
                    .ok_or_else(|| bad(format!("data value {n} must be text")))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(bad("data must be a list or an object")),
    };
    if !data.is_empty() {
        out.insert("data".into(), Value::Array(data));
    }
    Ok(out)
}

/// One channel's events.
#[derive(Debug, Default, Clone)]
pub struct Channel {
    pub name: String,
    pub events: VecDeque<Arc<Event>>,
    pub bytes: u64,
    pub max_bytes: u64,
    pub max_from_registry: bool,
    pub next_record_id: u64,
}

impl Channel {
    pub fn new(name: String, max_bytes: u64, from_registry: bool) -> Self {
        Channel {
            name,
            max_bytes,
            max_from_registry: from_registry,
            next_record_id: 1,
            ..Default::default()
        }
    }

    /// Add an event, dropping the oldest while the channel is over its size.
    /// Returns the record ID of the oldest event still kept.
    pub fn push(&mut self, e: Arc<Event>) -> u64 {
        self.bytes += e.size as u64;
        self.next_record_id = self.next_record_id.max(e.record_id + 1);
        self.events.push_back(e);
        while self.bytes > self.max_bytes && self.events.len() > 1 {
            if let Some(old) = self.events.pop_front() {
                self.bytes -= old.size as u64;
            }
        }
        self.events
            .front()
            .map_or(self.next_record_id, |e| e.record_id)
    }

    pub fn info(&self) -> Value {
        json!({
            "name": self.name,
            "events": self.events.len(),
            "oldest_record_id": self.events.front().map(|e| e.record_id),
            "newest_record_id": self.events.back().map(|e| e.record_id),
            "bytes": self.bytes,
            "max_size": self.max_bytes,
            "max_size_from_registry": self.max_from_registry,
        })
    }
}

/// A host's event logs.
#[derive(Debug, Default, Clone)]
pub struct EventLogs {
    pub channels: BTreeMap<String, Channel>,
}

/// The channels the registry declares, with their spelling and size limit.
pub fn declared_channels(reg: &Live<'_>) -> BTreeMap<String, (String, u64, bool)> {
    let mut out = BTreeMap::new();
    for root in [CLASSIC, MODERN] {
        for name in reg.subkeys(root).unwrap_or_default() {
            let key = format!(r"{root}\{name}");
            let max = reg
                .value(&key, "MaxSize")
                .and_then(|(_, v)| v["data"].as_u64())
                .filter(|n| *n > 0);
            out.entry(norm(&name)).or_insert((
                name,
                max.unwrap_or(DEFAULT_MAX_SIZE),
                max.is_some(),
            ));
        }
    }
    out
}

impl EventLogs {
    /// Find or open a channel the registry declares.
    pub fn channel_mut(&mut self, name: &str, reg: &Live<'_>) -> Result<&mut Channel, Rejected> {
        let key = norm(name);
        if !self.channels.contains_key(&key) {
            let declared = declared_channels(reg);
            let (spelled, max, from_reg) = declared
                .get(&key)
                .cloned()
                .ok_or_else(|| Rejected(code::NOT_FOUND, format!("no event channel {name}")))?;
            self.channels
                .insert(key.clone(), Channel::new(spelled, max, from_reg));
        }
        Ok(self.channels.get_mut(&key).expect("just inserted"))
    }

    pub fn channel(&self, name: &str) -> Option<&Channel> {
        self.channels.get(&norm(name))
    }

    /// Events after `after`, matching `query`, at most `limit`.
    pub fn read(
        &self,
        name: &str,
        after: u64,
        query: &Expr,
        limit: usize,
        now: &str,
    ) -> (Vec<Arc<Event>>, bool) {
        let Some(ch) = self.channel(name) else {
            return (Vec::new(), false);
        };
        let now_ms = time_ms(now);
        // Record IDs only grow, so skip straight to the first one after `after`.
        let start = ch.events.partition_point(|e| e.record_id <= after);
        let mut out = Vec::new();
        let mut more = false;
        for e in ch.events.iter().skip(start) {
            if query.matches(&Subj { e, now_ms }) {
                if out.len() == limit {
                    more = true;
                    break;
                }
                out.push(e.clone());
            }
        }
        (out, more)
    }
}

/// Fill a message template: `%1`..`%99` take the event's data values in order, `%%` is `%`.
pub fn format_message(template: &str, data: &[(Option<&str>, &str)]) -> Result<String, String> {
    let mut out = String::with_capacity(template.len() + 64);
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('%') => {
                chars.next();
                out.push('%');
            }
            Some(d) if d.is_ascii_digit() => {
                let mut n = 0usize;
                while let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                    n = n * 10 + d as usize;
                    chars.next();
                }
                let (_, value) = data.get(n.wrapping_sub(1)).ok_or_else(|| {
                    format!("template uses %{n}, the event has {} values", data.len())
                })?;
                out.push_str(value);
            }
            _ => out.push('%'),
        }
    }
    Ok(out)
}

/// The template for an event: `templates[provider]["ID/VERSION"]`, then `["ID"]`.
pub fn find_template<'a>(templates: &'a Value, e: &Event) -> Option<&'a str> {
    let by_provider = templates.get(e.s("provider")?)?;
    let id = e.u("event_id");
    by_provider
        .get(format!("{id}/{}", e.u("version")))
        .or_else(|| by_provider.get(id.to_string()))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(doc: Value) -> Event {
        let doc = check_event(&doc, "2026-10-16T10:00:00Z").unwrap();
        Event {
            record_id: 9,
            channel: "Security".into(),
            computer: "WIN-01".into(),
            size: 10,
            doc,
        }
    }

    #[test]
    fn renders_the_event_schema() {
        let e = event(
            json!({"provider": "Microsoft-Windows-Security-Auditing", "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
            "event_id": 4624, "version": 2, "task": 12544, "keywords": "0x8020000000000000",
            "process_id": 640, "thread_id": 700, "time": "2026-10-16T10:00:00.25Z",
            "data": [{"name": "TargetUserName", "value": "bob & <eve>"}, {"name": "LogonType", "value": "3"}]}),
        );
        assert_eq!(
            e.xml(),
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>\
<EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>\
<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-10-16T10:00:00.2500000Z'/>\
<EventRecordID>9</EventRecordID><Correlation/><Execution ProcessID='640' ThreadID='700'/>\
<Channel>Security</Channel><Computer>WIN-01</Computer><Security/></System>\
<EventData><Data Name='TargetUserName'>bob &amp; &lt;eve&gt;</Data><Data Name='LogonType'>3</Data></EventData></Event>"
        );
    }

    #[test]
    fn classic_events() {
        let e = event(
            json!({"provider": "Service Control Manager", "event_source": "Service Control Manager",
            "event_id": 7036, "qualifiers": 16384, "level": 4, "user_id": "S-1-5-18",
            "data": {"param1": "Windows Time", "param2": "stopped"}}),
        );
        let x = e.xml();
        assert!(x.contains(
            "<Provider Name='Service Control Manager' EventSourceName='Service Control Manager'/>"
        ));
        assert!(x.contains("<EventID Qualifiers='16384'>7036</EventID>"));
        assert!(x.contains("<Execution/>"));
        assert!(x.contains("<Security UserID='S-1-5-18'/>"));
        assert!(x.contains("<Keywords>0x0</Keywords>"));
        assert!(
            x.contains("<Data Name='param1'>Windows Time</Data><Data Name='param2'>stopped</Data>")
        );
    }

    #[test]
    fn bad_events() {
        for (doc, why) in [
            (json!({"event_id": 1}), "provider"),
            (json!({"provider": "p"}), "event_id"),
            (json!({"provider": "p", "event_id": 70000}), "event_id"),
            (
                json!({"provider": "p", "event_id": 1, "keywords": "8020"}),
                "keywords",
            ),
            (
                json!({"provider": "p", "event_id": 1, "data": [{"name": "x"}]}),
                "text value",
            ),
            (
                json!({"provider": "p", "event_id": 1, "colour": 1}),
                "unknown event field",
            ),
            (
                json!({"provider": "p", "event_id": 1, "time": "noon"}),
                "time",
            ),
        ] {
            let err = check_event(&doc, "2026-10-16T10:00:00Z").unwrap_err();
            assert!(err.1.contains(why), "{doc}: {}", err.1);
        }
    }

    #[test]
    fn messages() {
        let data = [(Some("a"), "alice"), (Some("b"), "3")];
        assert_eq!(
            format_message("User %1 logged on (type %2), 100%% sure.\r\n\t%1", &data).unwrap(),
            "User alice logged on (type 3), 100% sure.\r\n\talice"
        );
        assert!(format_message("%3", &data).unwrap_err().contains("%3"));
        assert_eq!(format_message("50% off", &data).unwrap(), "50% off");
    }

    #[test]
    fn retention_drops_oldest() {
        let mut ch = Channel::new("App".into(), 25, true);
        for id in 1..=5 {
            let mut e = event(json!({"provider": "p", "event_id": 1}));
            e.record_id = id;
            ch.push(Arc::new(e));
        }
        assert_eq!(
            ch.events.iter().map(|e| e.record_id).collect::<Vec<_>>(),
            [4, 5]
        );
        assert_eq!(ch.next_record_id, 6);
        assert_eq!(ch.bytes, 20);
    }
}
