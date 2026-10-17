//! Event queries: the XPath subset that event log subscribers use.
//!
//! Written from Microsoft's public description of event queries ("Consuming
//! Events", "XPath 1.0 limitations", Microsoft Learn). A query is either a
//! bare XPath expression or a `<QueryList>` document with `<Select Path=...>`
//! elements. Supported:
//!
//! | Form | Example |
//! | --- | --- |
//! | Everything | `*`, `Event`, `Event/System` |
//! | System predicate | `Event/System[EventID=4624]`, `*[System[(EventID=4624 or EventID=4625) and Level<=3]]` |
//! | Path inside a predicate | `*[System/EventID=4624]` |
//! | System fields | `EventID`, `Level`, `Task`, `Opcode`, `Version`, `EventRecordID`, `Computer`, `Channel`, `Keywords` |
//! | Attributes | `Provider[@Name='x']`, `Provider[@EventSourceName='x']`, `Security[@UserID='S-1-5-18']`, `TimeCreated[@SystemTime>='2026-10-16T00:00:00Z']` |
//! | Functions | `timediff(@SystemTime) <= 86400000`, `band(Keywords, 0x8010000000000000)` |
//! | Event data | `EventData[Data[@Name='TargetUserName']='bob']`, `EventData[Data='bob']` |
//! | Operators | `=`, `!=`, `<`, `<=`, `>`, `>=`, `and`, `or`, parentheses |
//!
//! Anything else (`Suppress`, `not()`, `UserData`, other functions) is
//! rejected with a message naming it, never silently ignored.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Op {
    fn holds(self, ord: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::*;
        match self {
            Op::Eq => ord == Equal,
            Op::Ne => ord != Equal,
            Op::Lt => ord == Less,
            Op::Le => ord != Greater,
            Op::Gt => ord == Greater,
            Op::Ge => ord != Less,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Num(u64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    All,
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    /// A System element or attribute compared with a literal.
    Field(String, Op, Lit),
    TimeDiff(Op, u64),
    Band(u64),
    /// `Data[@Name='x'] op lit`, or any data value when the name is `None`.
    Data(Option<String>, Op, Lit),
}

/// What a query needs to know about one event.
pub trait Subject {
    /// A System field or attribute: `EventID`, `Provider@Name`, `TimeCreated@SystemTime`...
    fn field(&self, name: &str) -> Option<Value>;
    /// Event data values, in order, with their names.
    fn data(&self) -> Vec<(Option<&str>, &str)>;
    /// Milliseconds between the event and now.
    fn age_ms(&self) -> Option<u64>;
}

const NUMERIC: [&str; 6] = [
    "EventID",
    "Level",
    "Task",
    "Opcode",
    "Version",
    "EventRecordID",
];
const TEXT: [&str; 2] = ["Computer", "Channel"];

fn parse_keywords(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

impl Expr {
    pub fn matches(&self, e: &dyn Subject) -> bool {
        match self {
            Expr::All => true,
            Expr::And(a, b) => a.matches(e) && b.matches(e),
            Expr::Or(a, b) => a.matches(e) || b.matches(e),
            Expr::Field(name, op, lit) => {
                let Some(v) = e.field(name) else { return false };
                compare(&v, *op, lit)
            }
            Expr::TimeDiff(op, ms) => e.age_ms().is_some_and(|age| op.holds(age.cmp(ms))),
            Expr::Band(mask) => e
                .field("Keywords")
                .and_then(|k| k.as_str().and_then(parse_keywords))
                .is_some_and(|k| k & mask != 0),
            Expr::Data(name, op, lit) => e.data().iter().any(|(n, v)| {
                let named = match name {
                    Some(want) => n.is_some_and(|n| n == want),
                    None => true,
                };
                named && compare(&Value::String((*v).to_string()), *op, lit)
            }),
        }
    }
}

fn compare(v: &Value, op: Op, lit: &Lit) -> bool {
    match lit {
        Lit::Num(n) => {
            let have = v.as_u64().or_else(|| v.as_str().and_then(parse_keywords));
            have.is_some_and(|h| op.holds(h.cmp(n)))
        }
        Lit::Str(s) => {
            let have = match v {
                Value::String(x) => x.clone(),
                other => other.to_string(),
            };
            op.holds(have.as_str().cmp(s.as_str()))
        }
    }
}

// ---------------------------------------------------------------- tokens

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Attr(String),
    Str(String),
    Num(u64),
    Op(Op),
    LBrack,
    RBrack,
    LParen,
    RParen,
    Slash,
    Star,
    Comma,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'[' => {
                out.push(Tok::LBrack);
                i += 1
            }
            b']' => {
                out.push(Tok::RBrack);
                i += 1
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1
            }
            b'/' => {
                out.push(Tok::Slash);
                i += 1
            }
            b'*' => {
                out.push(Tok::Star);
                i += 1
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1
            }
            b'=' => {
                out.push(Tok::Op(Op::Eq));
                i += 1
            }
            b'!' if b.get(i + 1) == Some(&b'=') => {
                out.push(Tok::Op(Op::Ne));
                i += 2
            }
            b'<' | b'>' => {
                let eq = b.get(i + 1) == Some(&b'=');
                out.push(Tok::Op(match (c, eq) {
                    (b'<', false) => Op::Lt,
                    (b'<', true) => Op::Le,
                    (_, false) => Op::Gt,
                    (_, true) => Op::Ge,
                }));
                i += 1 + usize::from(eq);
            }
            b'\'' | b'"' => {
                let end = src[i + 1..]
                    .find(c as char)
                    .ok_or("unterminated string in query")?;
                out.push(Tok::Str(src[i + 1..i + 1 + end].to_string()));
                i += end + 2;
            }
            b'@' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j == start {
                    return Err("@ without an attribute name".into());
                }
                out.push(Tok::Attr(src[start..j].to_string()));
                i = j;
            }
            b'0'..=b'9' => {
                let mut j = i;
                let hex = b[i] == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X'));
                if hex {
                    j += 2;
                    while j < b.len() && b[j].is_ascii_hexdigit() {
                        j += 1;
                    }
                } else {
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                let text = &src[i..j];
                let n = if hex {
                    u64::from_str_radix(&text[2..], 16)
                } else {
                    text.parse()
                }
                .map_err(|_| format!("bad number {text}"))?;
                out.push(Tok::Num(n));
                i = j;
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let mut j = i;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'-')
                {
                    j += 1;
                }
                out.push(Tok::Name(src[i..j].to_string()));
                i = j;
            }
            _ => return Err(format!("unexpected character {:?} in query", c as char)),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- parser

struct P {
    toks: Vec<Tok>,
    pos: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Level {
    /// Inside `*[...]` or `Event[...]`.
    Event,
    /// Inside `System[...]`.
    System,
    /// Inside `EventData[...]`.
    Data,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn expect(&mut self, want: Tok) -> Result<(), String> {
        match self.next() {
            Some(t) if t == want => Ok(()),
            other => Err(format!("expected {want:?}, found {other:?}")),
        }
    }

    fn eat_name(&mut self, name: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Name(n)) if n == name) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn lit(&mut self) -> Result<Lit, String> {
        match self.next() {
            Some(Tok::Num(n)) => Ok(Lit::Num(n)),
            Some(Tok::Str(s)) => Ok(Lit::Str(s)),
            other => Err(format!("expected a number or a string, found {other:?}")),
        }
    }

    fn op(&mut self) -> Result<Op, String> {
        match self.next() {
            Some(Tok::Op(o)) => Ok(o),
            other => Err(format!("expected a comparison, found {other:?}")),
        }
    }

    fn or(&mut self, level: Level) -> Result<Expr, String> {
        let mut left = self.and(level)?;
        while self.eat_name("or") {
            let right = self.and(level)?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self, level: Level) -> Result<Expr, String> {
        let mut left = self.atom(level)?;
        while self.eat_name("and") {
            let right = self.atom(level)?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn bracketed(&mut self, level: Level) -> Result<Expr, String> {
        self.expect(Tok::LBrack)?;
        let e = self.or(level)?;
        self.expect(Tok::RBrack)?;
        Ok(e)
    }

    /// `Name[@Attr op lit]` at the System level.
    fn attr_pred(&mut self, element: &str) -> Result<Expr, String> {
        self.expect(Tok::LBrack)?;
        let e = match self.next() {
            Some(Tok::Attr(a)) => {
                let field = format!("{element}@{a}");
                let ok = matches!(
                    field.as_str(),
                    "Provider@Name"
                        | "Provider@EventSourceName"
                        | "Provider@Guid"
                        | "Security@UserID"
                        | "TimeCreated@SystemTime"
                );
                if !ok {
                    return Err(format!("{element}[@{a}] is not supported"));
                }
                // `Provider[@Name]` alone tests presence.
                if matches!(self.peek(), Some(Tok::RBrack)) {
                    Expr::Field(field, Op::Ne, Lit::Str(String::new()))
                } else {
                    let op = self.op()?;
                    Expr::Field(field, op, self.lit()?)
                }
            }
            Some(Tok::Name(f)) if f == "timediff" && element == "TimeCreated" => {
                self.expect(Tok::LParen)?;
                match self.next() {
                    Some(Tok::Attr(a)) if a == "SystemTime" => {}
                    other => return Err(format!("timediff takes @SystemTime, found {other:?}")),
                }
                self.expect(Tok::RParen)?;
                let op = self.op()?;
                match self.lit()? {
                    Lit::Num(n) => Expr::TimeDiff(op, n),
                    Lit::Str(_) => {
                        return Err("timediff compares with a number of milliseconds".into());
                    }
                }
            }
            other => {
                return Err(format!(
                    "unsupported predicate in {element}[...]: {other:?}"
                ));
            }
        };
        self.expect(Tok::RBrack)?;
        Ok(e)
    }

    fn system_atom(&mut self, name: &str) -> Result<Expr, String> {
        if NUMERIC.contains(&name) || TEXT.contains(&name) || name == "Keywords" {
            let op = self.op()?;
            return Ok(Expr::Field(name.to_string(), op, self.lit()?));
        }
        match name {
            "Provider" | "Security" | "TimeCreated" => self.attr_pred(name),
            "band" => {
                self.expect(Tok::LParen)?;
                if !self.eat_name("Keywords") {
                    return Err("band() takes Keywords as its first argument".into());
                }
                self.expect(Tok::Comma)?;
                let mask = match self.lit()? {
                    Lit::Num(n) => n,
                    Lit::Str(_) => return Err("band() takes a number mask".into()),
                };
                self.expect(Tok::RParen)?;
                Ok(Expr::Band(mask))
            }
            other => Err(format!("System field {other} is not supported")),
        }
    }

    fn data_atom(&mut self) -> Result<Expr, String> {
        if !self.eat_name("Data") {
            return Err("EventData[...] supports Data comparisons only".into());
        }
        let mut name = None;
        if matches!(self.peek(), Some(Tok::LBrack)) {
            self.expect(Tok::LBrack)?;
            match self.next() {
                Some(Tok::Attr(a)) if a == "Name" => {}
                other => return Err(format!("Data[...] takes @Name, found {other:?}")),
            }
            self.expect(Tok::Op(Op::Eq))?;
            match self.lit()? {
                Lit::Str(s) => name = Some(s),
                Lit::Num(n) => name = Some(n.to_string()),
            }
            self.expect(Tok::RBrack)?;
        }
        let op = self.op()?;
        Ok(Expr::Data(name, op, self.lit()?))
    }

    fn atom(&mut self, level: Level) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.pos += 1;
            let e = self.or(level)?;
            self.expect(Tok::RParen)?;
            return Ok(e);
        }
        if level == Level::Data {
            return self.data_atom();
        }
        let name = match self.next() {
            Some(Tok::Name(n)) => n,
            other => return Err(format!("unexpected {other:?} in query")),
        };
        if level == Level::System {
            return self.system_atom(&name);
        }
        match name.as_str() {
            "System" => match self.peek() {
                Some(Tok::LBrack) => self.bracketed(Level::System),
                Some(Tok::Slash) => {
                    self.pos += 1;
                    let field = match self.next() {
                        Some(Tok::Name(f)) => f,
                        other => {
                            return Err(format!(
                                "expected a System field after System/, found {other:?}"
                            ));
                        }
                    };
                    self.system_atom(&field)
                }
                _ => Ok(Expr::All),
            },
            "EventData" => match self.peek() {
                Some(Tok::LBrack) => self.bracketed(Level::Data),
                Some(Tok::Slash) => {
                    self.pos += 1;
                    self.data_atom()
                }
                _ => Ok(Expr::All),
            },
            "UserData" => Err("UserData queries are not supported".into()),
            "not" => Err("not() is not supported".into()),
            other => Err(format!("{other} is not supported in an event predicate")),
        }
    }

    /// The whole selector: `*`, `Event`, `Event/System`, with an optional predicate.
    fn selector(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::Star) => {}
            Some(Tok::Name(n)) if n == "Event" => {}
            other => return Err(format!("a query starts with * or Event, found {other:?}")),
        }
        let mut level = Level::Event;
        if matches!(self.peek(), Some(Tok::Slash)) {
            self.pos += 1;
            match self.next() {
                Some(Tok::Name(n)) if n == "System" => level = Level::System,
                Some(Tok::Name(n)) if n == "EventData" => level = Level::Data,
                other => return Err(format!("unsupported path step {other:?}")),
            }
        }
        let e = if matches!(self.peek(), Some(Tok::LBrack)) {
            self.bracketed(level)?
        } else {
            Expr::All
        };
        if self.pos != self.toks.len() {
            return Err(format!(
                "unexpected {:?} after the query",
                self.toks[self.pos]
            ));
        }
        Ok(e)
    }
}

pub fn parse_xpath(src: &str) -> Result<Expr, String> {
    let src = src.trim();
    if src.is_empty() {
        return Ok(Expr::All);
    }
    let mut p = P {
        toks: tokenize(src)?,
        pos: 0,
    };
    p.selector()
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Parse a query for one channel. A `<QueryList>` may hold several selects;
/// only those whose `Path` names `channel` (ignoring case) apply. `Ok(None)`
/// means the query selects nothing from this channel.
pub fn parse(src: &str, channel: &str) -> Result<Option<Expr>, String> {
    let s = src.trim();
    if !s.starts_with('<') {
        return parse_xpath(s).map(Some);
    }
    if s.contains("<Suppress") {
        return Err("Suppress elements are not supported".into());
    }
    let mut found: Option<Expr> = None;
    let mut rest = s;
    while let Some(start) = rest.find("<Select") {
        let after = &rest[start..];
        let tag_end = after.find('>').ok_or("unterminated <Select> tag")?;
        let tag = &after[..tag_end];
        let close = after
            .find("</Select>")
            .ok_or("<Select> without </Select>")?;
        let body = xml_unescape(&after[tag_end + 1..close]);
        let path = tag
            .split("Path=")
            .nth(1)
            .and_then(|p| {
                let q = p.chars().next()?;
                p[1..].split(q).next()
            })
            .ok_or("<Select> without a Path")?;
        if path.eq_ignore_ascii_case(channel) {
            let e = parse_xpath(&body)?;
            found = Some(match found {
                None => e,
                Some(prev) => Expr::Or(Box::new(prev), Box::new(e)),
            });
        }
        rest = &after[close + "</Select>".len()..];
    }
    if found.is_none() && !s.contains("<Select") {
        return Err("a QueryList needs at least one <Select>".into());
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Ev(Value);

    impl Subject for Ev {
        fn field(&self, name: &str) -> Option<Value> {
            self.0.get(name).cloned()
        }
        fn data(&self) -> Vec<(Option<&str>, &str)> {
            vec![
                (Some("TargetUserName"), "bob"),
                (Some("LogonType"), "3"),
                (None, "loose"),
            ]
        }
        fn age_ms(&self) -> Option<u64> {
            Some(5_000)
        }
    }

    fn ev() -> Ev {
        Ev(
            json!({"EventID": 4624, "Level": 0, "Task": 12544, "Keywords": "0x8020000000000000",
            "Provider@Name": "Microsoft-Windows-Security-Auditing", "Computer": "WIN-01",
            "Channel": "Security", "Security@UserID": "S-1-5-18",
            "TimeCreated@SystemTime": "2026-10-16T10:00:00.0000000Z", "EventRecordID": 7}),
        )
    }

    fn m(q: &str) -> bool {
        parse_xpath(q)
            .unwrap_or_else(|e| panic!("{q}: {e}"))
            .matches(&ev())
    }

    #[test]
    fn forms_that_match() {
        for q in [
            "*",
            "Event",
            "Event/System",
            "",
            "Event/System[EventID=4624]",
            "Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447]",
            "*[System[(EventID=4624 or EventID=4625) and Level<=3]]",
            "*[System/EventID=4624]",
            "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing']]]",
            "*[System[Provider[@Name]]]",
            "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]",
            "*[System[TimeCreated[@SystemTime>='2026-10-16T00:00:00Z']]]",
            "*[System[band(Keywords, 0x8000000000000000)]]",
            "*[System[Keywords=0x8020000000000000]]",
            "*[System[Security[@UserID='S-1-5-18']]]",
            "*[EventData[Data[@Name='TargetUserName']='bob']]",
            "*[EventData[Data='loose']]",
            "*[System[EventID=4624] and EventData[Data[@Name='LogonType']=3]]",
            "Event/EventData[Data[@Name='TargetUserName']='bob']",
            "*[System[Computer='WIN-01' and Channel=\"Security\" and EventRecordID>6]]",
        ] {
            assert!(m(q), "{q} should match");
        }
    }

    #[test]
    fn forms_that_do_not_match() {
        for q in [
            "Event/System[EventID=4625]",
            "*[System[Level>0]]",
            "*[System[band(Keywords, 0x0010000000000000)]]",
            "*[System[TimeCreated[timediff(@SystemTime) <= 1000]]]",
            "*[EventData[Data[@Name='TargetUserName']='alice']]",
            "*[System[Provider[@Name='Other']]]",
            "*[System[EventID=4624] and EventData[Data[@Name='LogonType']=2]]",
        ] {
            assert!(!m(q), "{q} should not match");
        }
    }

    #[test]
    fn unsupported_forms_are_errors() {
        for (q, why) in [
            ("*[System[not(EventID=1)]]", "not supported"),
            ("*[UserData[x]]", "UserData"),
            ("*[System[Correlation[@ActivityID='x']]]", "not supported"),
            ("Event/System[EventID=", "expected"),
            ("Event/System[EventID=4624]]", "after the query"),
            ("Foo", "starts with"),
            ("*[System[EventID='unterminated]]", "unterminated"),
        ] {
            let err = parse_xpath(q).unwrap_err();
            assert!(err.contains(why), "{q}: {err}");
        }
    }

    #[test]
    fn query_lists() {
        let q = r#"<QueryList><Query Id="0" Path="Security">
            <Select Path="Security">*[System[EventID=4624]]</Select>
            <Select Path="System">*[System[EventID=7036]]</Select>
            <Select Path="Security">*[System[EventID=4625]]</Select>
        </Query></QueryList>"#;
        let sec = parse(q, "security").unwrap().unwrap();
        assert!(sec.matches(&ev()));
        assert!(parse(q, "Application").unwrap().is_none());
        assert!(
            parse(
                "<QueryList><Query><Suppress Path='x'>*</Suppress></Query></QueryList>",
                "x"
            )
            .is_err()
        );
        let escaped = "<QueryList><Query><Select Path='Security'>*[System[Level &lt;= 3]]</Select></Query></QueryList>";
        assert!(parse(escaped, "Security").unwrap().unwrap().matches(&ev()));
    }
}
