//! Layered file system: shared base files, per-host profile changes, run-time changes.
//!
//! The engine holds every path's metadata. File bytes come from the
//! content-addressed blob store (`xvm-profile compile`), shared by every host
//! that carries the same file, or from a host's own run-time writes. Vendor
//! files from a golden capture carry metadata only (CLAUDE.md rule 1); reading
//! their bytes is a logged gap.
//!
//! Like the registry, a directory exists if it is listed or anything below it
//! is. Windows and macOS paths match without regard to case and keep the
//! base's spelling; Linux paths are case-sensitive.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::merge::merge_dict;
use crate::protocol::code;
use crate::runtime::Rejected;

/// Longest path component Windows and Linux allow.
const MAX_COMPONENT: usize = 255;
/// Metadata fields a run-time `file.set` may change.
pub const SETTABLE: [&str; 6] = [
    "attributes",
    "created",
    "modified",
    "accessed",
    "owner",
    "mode",
];
const ATTRIBUTES: [&str; 11] = [
    "readonly",
    "hidden",
    "system",
    "archive",
    "compressed",
    "encrypted",
    "temporary",
    "offline",
    "not_content_indexed",
    "sparse",
    "reparse_point",
];

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Path rules for one OS.
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    pub sep: char,
    pub fold: bool,
    pub windows: bool,
}

impl Rules {
    pub fn for_os(os: &str) -> Self {
        match os {
            "windows" => Rules {
                sep: '\\',
                fold: true,
                windows: true,
            },
            "macos" => Rules {
                sep: '/',
                fold: true,
                windows: false,
            },
            _ => Rules {
                sep: '/',
                fold: false,
                windows: false,
            },
        }
    }

    /// The normal form used to match paths: separators unified, trailing
    /// separators dropped, case folded where the OS ignores case. The root is
    /// `c:` on Windows and the empty string elsewhere.
    pub fn norm(&self, path: &str) -> String {
        let p = if self.windows {
            path.replace('/', "\\")
        } else {
            path.to_string()
        };
        let p = p.trim_end_matches(self.sep);
        if self.fold {
            p.to_lowercase()
        } else {
            p.to_string()
        }
    }

    /// The spelling to store for a new path given by a caller.
    fn spell(&self, path: &str) -> String {
        let p = if self.windows {
            path.replace('/', "\\")
        } else {
            path.to_string()
        };
        let trimmed = p.trim_end_matches(self.sep);
        if self.windows && trimmed.len() == 2 {
            return trimmed.to_uppercase();
        }
        trimmed.to_string()
    }

    /// Check that a path is absolute and every component is legal.
    pub fn check(&self, path: &str) -> Result<(), Rejected> {
        let bad = |why: &str| Rejected(code::BAD_REQUEST, format!("{why}: {path:?}"));
        let p = self.spell(path);
        let mut parts = p.split(self.sep);
        let first = parts.next().unwrap_or("");
        if self.windows {
            let b = first.as_bytes();
            if b.len() != 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
                return Err(bad("not an absolute Windows path"));
            }
        } else if !first.is_empty() || !path.starts_with('/') {
            return Err(bad("not an absolute path"));
        }
        for c in parts {
            if c.is_empty() {
                return Err(bad("empty path component"));
            }
            if c.chars().count() > MAX_COMPONENT {
                return Err(bad("path component longer than 255 characters"));
            }
            let illegal = if self.windows {
                c.chars().any(|ch| ch < ' ' || "<>:\"|?*".contains(ch))
            } else {
                c.contains('\0')
            };
            if illegal {
                return Err(bad("illegal character in path"));
            }
        }
        Ok(())
    }

    /// Normal form of the parent, or `None` for the root.
    pub fn parent(&self, nk: &str) -> Option<String> {
        if self.is_root(nk) {
            return None;
        }
        nk.rsplit_once(self.sep).map(|(p, _)| p.to_string())
    }

    pub fn is_root(&self, nk: &str) -> bool {
        if self.windows {
            !nk.contains('\\')
        } else {
            nk.is_empty()
        }
    }

    /// The path shown for a normal form that has no entry of its own.
    fn display_root(&self, spelled: &str) -> String {
        if self.windows {
            format!("{spelled}\\")
        } else if spelled.is_empty() {
            "/".to_string()
        } else {
            spelled.to_string()
        }
    }

    fn under(&self, nk: &str, prefix: &str) -> bool {
        nk == prefix
            || (nk.len() > prefix.len()
                && nk.starts_with(prefix)
                && nk[prefix.len()..].starts_with(self.sep))
    }
}

/// File bytes: shared from the blob store, or owned by one host's run-time layer.
#[derive(Debug, Clone)]
pub enum Content {
    /// Metadata only, or a directory.
    None,
    Shared(Arc<[u8]>),
    Owned(Vec<u8>),
}

impl Content {
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Content::None => None,
            Content::Shared(b) => Some(b),
            Content::Owned(v) => Some(v),
        }
    }
}

/// One listed path.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// The spelling to report.
    pub path: String,
    /// The profile entry as written, including `content`. Run-time edits update it.
    pub doc: Map<String, Value>,
    pub content: Content,
}

impl FileEntry {
    pub fn is_dir(&self) -> bool {
        self.doc.get("type").and_then(Value::as_str) == Some("dir")
    }

    /// Metadata as `file.stat` reports it.
    pub fn stat(&self) -> Value {
        let mut out = self.doc.clone();
        out.remove("content");
        out.insert("path".into(), self.path.clone().into());
        out.insert(
            "type".into(),
            if self.is_dir() { "dir" } else { "file" }.into(),
        );
        match &self.content {
            Content::Owned(v) => {
                out.insert("size".into(), v.len().into());
                out.insert("sha256".into(), sha256_hex(v).into());
            }
            Content::Shared(b) => {
                out.entry("size").or_insert(b.len().into());
                if !out.contains_key("sha256") {
                    out.insert("sha256".into(), sha256_hex(b).into());
                }
            }
            Content::None => {}
        }
        if !self.is_dir() {
            out.insert(
                "has_content".into(),
                (!matches!(self.content, Content::None)).into(),
            );
        }
        Value::Object(out)
    }

    /// The entry as `xvm-profile resolve` writes it. The profile's own path string is kept.
    pub fn resolved(&self) -> Value {
        let mut out = self.doc.clone();
        // Bytes written at run time (now, or before a restart) have no profile `content`.
        let written = matches!(self.content, Content::Owned(_)) || !out.contains_key("content");
        if written && let Some(b) = self.content.bytes() {
            out.remove("size");
            out.remove("sha256");
            out.insert("content".into(), json!({ "base64": B64.encode(b) }));
        }
        Value::Object(out)
    }
}

impl FileEntry {
    /// The entry for a snapshot: bytes go to the blob store through `put`.
    pub fn to_snapshot(
        &self,
        put: &mut dyn FnMut(&[u8]) -> std::io::Result<String>,
    ) -> std::io::Result<Value> {
        let content = match self.content.bytes() {
            Some(b) => json!({ "blob": put(b)? }),
            None => Value::Null,
        };
        Ok(json!({"path": self.path, "doc": self.doc, "content": content}))
    }

    pub fn from_snapshot(v: &Value, blobs: &dyn Blobs) -> Result<Self, String> {
        let path = v["path"]
            .as_str()
            .ok_or("snapshot file entry needs a path")?;
        let doc = v["doc"]
            .as_object()
            .ok_or("snapshot file entry needs a doc")?
            .clone();
        let content = match v["content"].get("blob").and_then(Value::as_str) {
            Some(sha) => Content::Shared(blobs.get(sha)?),
            None => Content::None,
        };
        Ok(FileEntry {
            path: path.to_string(),
            doc,
            content,
        })
    }
}

/// Resolves `{"blob": sha256}` content to bytes.
pub trait Blobs {
    fn get(&self, sha256: &str) -> Result<Arc<[u8]>, String>;
}

/// No blob store: only inline content is accepted.
pub struct NoBlobs;

impl Blobs for NoBlobs {
    fn get(&self, sha256: &str) -> Result<Arc<[u8]>, String> {
        Err(format!(
            "blob {sha256} referenced, but no blob store is loaded"
        ))
    }
}

fn content_of(doc: &Map<String, Value>, blobs: &dyn Blobs) -> Result<Content, String> {
    let Some(c) = doc.get("content") else {
        return Ok(Content::None);
    };
    if let Some(t) = c.get("text").and_then(Value::as_str) {
        return Ok(Content::Shared(Arc::from(t.as_bytes())));
    }
    if let Some(b) = c.get("base64").and_then(Value::as_str) {
        let bytes = B64.decode(b).map_err(|e| format!("bad base64: {e}"))?;
        return Ok(Content::Shared(Arc::from(bytes)));
    }
    if let Some(s) = c.get("blob").and_then(Value::as_str) {
        return blobs.get(s).map(Content::Shared);
    }
    Err("content needs text, base64 or blob".into())
}

fn entry_from(v: &Value, rules: Rules, blobs: &dyn Blobs) -> Result<(String, FileEntry), String> {
    let doc = v.as_object().ok_or("a file entry must be an object")?;
    let path = doc
        .get("path")
        .and_then(Value::as_str)
        .ok_or("a file entry needs a path")?;
    rules.check(path).map_err(|r| r.1)?;
    let content = content_of(doc, blobs).map_err(|e| format!("{path}: {e}"))?;
    let entry = FileEntry {
        path: rules.spell(path),
        doc: doc.clone(),
        content,
    };
    Ok((rules.norm(path), entry))
}

/// The files of a base image.
#[derive(Debug, Default)]
pub struct BaseFiles {
    pub(crate) map: BTreeMap<String, FileEntry>,
    present: bool,
}

/// One host's profile changes to its base files, applied in profile order.
#[derive(Debug, Default)]
pub struct FileDelta {
    /// Base subtrees the profile removed, as normal forms.
    removed: Vec<String>,
    /// Entries the profile changed or added. These win over the base.
    over: BTreeMap<String, FileEntry>,
    present: bool,
}

impl BaseFiles {
    pub fn from_section(
        section: Option<&Value>,
        rules: Rules,
        blobs: &dyn Blobs,
    ) -> Result<Self, String> {
        let mut out = BaseFiles {
            present: section.is_some(),
            ..Default::default()
        };
        for v in section.and_then(Value::as_array).into_iter().flatten() {
            if v.get("remove").is_some() {
                return Err("a base image cannot remove files".into());
            }
            let (nk, e) = entry_from(v, rules, blobs)?;
            if out.map.insert(nk, e).is_some() {
                return Err(format!("duplicate path {}", v["path"]));
            }
        }
        Ok(out)
    }

    pub fn is_present(&self) -> bool {
        self.present
    }
}

impl FileDelta {
    pub fn from_section(
        section: Option<&Value>,
        base: &BaseFiles,
        rules: Rules,
        blobs: &dyn Blobs,
    ) -> Result<Self, String> {
        let mut d = FileDelta {
            present: section.is_some(),
            ..Default::default()
        };
        for v in section.and_then(Value::as_array).into_iter().flatten() {
            let path = v
                .get("path")
                .and_then(Value::as_str)
                .ok_or("a file entry needs a path")?;
            let nk = rules.norm(path);
            if v.get("remove").and_then(Value::as_bool) == Some(true) {
                let base_hit = base
                    .map
                    .keys()
                    .any(|k| rules.under(k, &nk) && !d.is_removed(k, rules));
                let over_hit = d.over.keys().any(|k| rules.under(k, &nk));
                if !base_hit && !over_hit {
                    return Err(format!("cannot remove {path}: not in the base"));
                }
                d.over.retain(|k, _| !rules.under(k, &nk));
                d.removed.push(nk);
                continue;
            }
            let (nk, mut entry) = entry_from(v, rules, blobs)?;
            let earlier = d.over.get(&nk).cloned().or_else(|| {
                base.map
                    .get(&nk)
                    .filter(|_| !d.is_removed(&nk, rules))
                    .cloned()
            });
            if let Some(prev) = earlier {
                let doc = merge_dict(&prev.doc, &entry.doc);
                let content = if entry.doc.contains_key("content") {
                    entry.content
                } else {
                    prev.content
                };
                entry = FileEntry {
                    path: prev.path,
                    doc,
                    content,
                };
                entry.doc.insert("path".into(), entry.path.clone().into());
            }
            d.over.insert(nk, entry);
        }
        Ok(d)
    }

    fn is_removed(&self, nk: &str, rules: Rules) -> bool {
        self.removed.iter().any(|r| rules.under(nk, r))
    }

    pub fn is_present(&self) -> bool {
        self.present
    }
}

/// A host's files as its profile defines them.
#[derive(Clone, Copy)]
pub struct FilesView<'a> {
    pub base: &'a BaseFiles,
    pub delta: &'a FileDelta,
    pub rules: Rules,
}

impl<'a> FilesView<'a> {
    pub fn get(&self, nk: &str) -> Option<&'a FileEntry> {
        if let Some(e) = self.delta.over.get(nk) {
            return Some(e);
        }
        self.base
            .map
            .get(nk)
            .filter(|_| !self.delta.is_removed(nk, self.rules))
    }

    /// Listed entries strictly below `nk` (everything when `nk` is the unix root "").
    pub fn below(&self, nk: &str) -> BTreeMap<String, &'a FileEntry> {
        let mut out = BTreeMap::new();
        let start = format!("{nk}{}", self.rules.sep);
        let scan = |m: &'a BTreeMap<String, FileEntry>| {
            m.range(start.clone()..)
                .take_while(|(k, _)| k.starts_with(&start))
                .collect::<Vec<_>>()
        };
        for (k, e) in scan(&self.base.map) {
            if !self.delta.is_removed(k, self.rules) && !self.delta.over.contains_key(k) {
                out.insert(k.clone(), e);
            }
        }
        for (k, e) in scan(&self.delta.over) {
            out.insert(k.clone(), e);
        }
        out
    }

    /// Every listed entry.
    pub fn all(&self) -> BTreeMap<String, &'a FileEntry> {
        let mut out: BTreeMap<String, &FileEntry> = self
            .base
            .map
            .iter()
            .filter(|(k, _)| !self.delta.is_removed(k, self.rules))
            .map(|(k, e)| (k.clone(), e))
            .collect();
        for (k, e) in &self.delta.over {
            out.insert(k.clone(), e);
        }
        out
    }
}

/// Run-time file changes. `None` is a tombstone.
#[derive(Debug, Default, Clone)]
pub struct RtFiles {
    pub(crate) map: BTreeMap<String, Option<FileEntry>>,
}

/// Why a read failed.
#[derive(Debug, PartialEq)]
pub enum ReadError {
    NotFound,
    IsDirectory,
    /// Metadata only: the bytes were never captured (vendor file).
    NoContent,
}

/// A host's live files: profile plus run-time changes.
pub struct LiveFiles<'a> {
    pub lower: FilesView<'a>,
    pub rt: &'a RtFiles,
}

impl<'a> LiveFiles<'a> {
    fn rules(&self) -> Rules {
        self.lower.rules
    }

    pub fn get(&self, nk: &str) -> Option<&'a FileEntry> {
        match self.rt.map.get(nk) {
            Some(Some(e)) => Some(e),
            Some(None) => None,
            None => self.lower.get(nk),
        }
    }

    pub fn below(&self, nk: &str) -> BTreeMap<String, &'a FileEntry> {
        let mut out = self.lower.below(nk);
        out.retain(|k, _| !matches!(self.rt.map.get(k), Some(None)));
        let start = format!("{nk}{}", self.rules().sep);
        for (k, v) in self.rt.map.range(start.clone()..) {
            if !k.starts_with(&start) {
                break;
            }
            if let Some(e) = v {
                out.insert(k.clone(), e);
            }
        }
        out
    }

    pub fn all(&self) -> BTreeMap<String, &'a FileEntry> {
        let mut out = self.lower.all();
        out.retain(|k, _| !matches!(self.rt.map.get(k), Some(None)));
        for (k, v) in &self.rt.map {
            if let Some(e) = v {
                out.insert(k.clone(), e);
            }
        }
        out
    }

    pub fn exists(&self, path: &str) -> bool {
        let nk = self.rules().norm(path);
        self.get(&nk).is_some() || !self.below(&nk).is_empty()
    }

    pub fn is_dir(&self, path: &str) -> bool {
        let nk = self.rules().norm(path);
        match self.get(&nk) {
            Some(e) => e.is_dir(),
            None => !self.below(&nk).is_empty(),
        }
    }

    /// The spelling of an existing path, implied directories included.
    pub fn spelled(&self, path: &str) -> Option<String> {
        let nk = self.rules().norm(path);
        if let Some(e) = self.get(&nk) {
            return Some(e.path.clone());
        }
        let below = self.below(&nk);
        let (_, first) = below.iter().next()?;
        let sep = self.rules().sep;
        let depth = nk.split(sep).count();
        Some(
            first
                .path
                .split(sep)
                .take(depth)
                .collect::<Vec<_>>()
                .join(&sep.to_string()),
        )
    }

    pub fn stat(&self, path: &str) -> Option<Value> {
        let nk = self.rules().norm(path);
        if let Some(e) = self.get(&nk) {
            return Some(e.stat());
        }
        let spelled = self.spelled(path)?;
        let shown = if self.rules().is_root(&nk) {
            self.rules().display_root(&spelled)
        } else {
            spelled
        };
        Some(json!({"path": shown, "type": "dir", "implied": true}))
    }

    /// Immediate children, sorted by normal form.
    pub fn list(&self, path: &str) -> Option<Vec<Value>> {
        if !self.is_dir(path) {
            return None;
        }
        let nk = self.rules().norm(path);
        let sep = self.rules().sep;
        let mut children: BTreeMap<String, String> = BTreeMap::new();
        let prefix_len = nk.len() + sep.len_utf8();
        for (k, _) in self.below(&nk) {
            let rest = &k[prefix_len..];
            let child = rest.split(sep).next().unwrap_or(rest);
            children
                .entry(child.to_string())
                .or_insert_with(|| format!("{nk}{sep}{child}"));
        }
        Some(
            children
                .values()
                .filter_map(|child_nk| {
                    self.get(child_nk).map(FileEntry::stat).or_else(|| {
                        let spelled = self.spelled_norm(child_nk)?;
                        Some(json!({"path": spelled, "type": "dir", "implied": true}))
                    })
                })
                .collect(),
        )
    }

    fn spelled_norm(&self, nk: &str) -> Option<String> {
        let below = self.below(nk);
        let (_, first) = below.iter().next()?;
        let sep = self.rules().sep;
        let depth = nk.split(sep).count();
        Some(
            first
                .path
                .split(sep)
                .take(depth)
                .collect::<Vec<_>>()
                .join(&sep.to_string()),
        )
    }

    pub fn read(
        &self,
        path: &str,
        offset: usize,
        length: Option<usize>,
    ) -> Result<(&'a [u8], bool), ReadError> {
        let nk = self.rules().norm(path);
        let Some(e) = self.get(&nk) else {
            return Err(if self.exists(path) {
                ReadError::IsDirectory
            } else {
                ReadError::NotFound
            });
        };
        if e.is_dir() {
            return Err(ReadError::IsDirectory);
        }
        let bytes = e.content.bytes().ok_or(ReadError::NoContent)?;
        let start = offset.min(bytes.len());
        let end = length.map_or(bytes.len(), |n| start.saturating_add(n).min(bytes.len()));
        Ok((&bytes[start..end], end == bytes.len()))
    }

    pub fn materialize(&self) -> Vec<Value> {
        self.all().values().map(|e| e.resolved()).collect()
    }
}

fn reject(c: &'static str, msg: impl Into<String>) -> Rejected {
    Rejected(c, msg.into())
}

pub fn check_meta(patch: &Map<String, Value>) -> Result<(), Rejected> {
    for (k, v) in patch {
        let ok = match k.as_str() {
            "attributes" => v.as_array().is_some_and(|a| {
                a.iter()
                    .all(|x| x.as_str().is_some_and(|s| ATTRIBUTES.contains(&s)))
            }),
            "created" | "modified" | "accessed" => v
                .as_str()
                .is_some_and(|t| crate::runtime::check_time(t).is_ok()),
            "owner" => v.is_string(),
            "mode" => v.as_str().is_some_and(|m| {
                (3..=4).contains(&m.len()) && m.bytes().all(|c| (b'0'..=b'7').contains(&c))
            }),
            _ => {
                return Err(reject(
                    code::BAD_REQUEST,
                    format!("{k} cannot be set; settable: {SETTABLE:?}"),
                ));
            }
        };
        if !ok {
            return Err(reject(code::BAD_REQUEST, format!("bad value for {k}")));
        }
    }
    Ok(())
}

/// How a write lays its bytes into the file.
#[derive(Debug, Clone, Copy)]
pub enum WriteMode {
    /// Replace the whole file.
    Replace,
    Append,
    /// Overwrite at an offset, extending with zero bytes if past the end.
    At(usize),
}

/// Run-time file changes. Each op checks first and changes nothing when it rejects.
pub struct FileWriter<'a> {
    pub lower: FilesView<'a>,
    pub rt: &'a mut RtFiles,
}

impl FileWriter<'_> {
    fn live(&self) -> LiveFiles<'_> {
        LiveFiles {
            lower: self.lower,
            rt: self.rt,
        }
    }

    fn rules(&self) -> Rules {
        self.lower.rules
    }

    /// The parent must exist and be a directory. Returns the new entry's spelling.
    fn new_path(&self, path: &str) -> Result<String, Rejected> {
        let r = self.rules();
        r.check(path)?;
        let nk = r.norm(path);
        let Some(parent) = r.parent(&nk) else {
            return Err(reject(
                code::BAD_REQUEST,
                "the root cannot be created or written",
            ));
        };
        let live = self.live();
        // A root (a drive, or "/") exists once anything is listed under it.
        if !live.exists(&parent) {
            return Err(reject(
                code::NOT_FOUND,
                format!("parent directory of {path} does not exist"),
            ));
        }
        if !live.is_dir(&parent) {
            return Err(reject(
                code::NOT_A_DIRECTORY,
                format!("parent of {path} is a file"),
            ));
        }
        let spelled_parent = live.spelled(&parent).unwrap_or(parent);
        let leaf = r
            .spell(path)
            .rsplit(r.sep)
            .next()
            .unwrap_or_default()
            .to_string();
        Ok(format!("{spelled_parent}{}{leaf}", r.sep))
    }

    pub fn write(
        &mut self,
        path: &str,
        data: &[u8],
        mode: WriteMode,
        time: &str,
    ) -> Result<Value, Rejected> {
        let r = self.rules();
        r.check(path)?;
        let nk = r.norm(path);
        let existing = self.live().get(&nk).cloned();
        let mut entry = match existing {
            Some(e) if e.is_dir() => {
                return Err(reject(code::IS_DIRECTORY, format!("{path} is a directory")));
            }
            Some(e) => e,
            None => {
                if self.live().exists(path) {
                    return Err(reject(code::IS_DIRECTORY, format!("{path} is a directory")));
                }
                let spelled = self.new_path(path)?;
                let mut doc = Map::new();
                doc.insert("path".into(), spelled.clone().into());
                doc.insert("created".into(), time.into());
                if r.windows {
                    doc.insert("attributes".into(), json!(["archive"]));
                }
                FileEntry {
                    path: spelled,
                    doc,
                    content: Content::Owned(Vec::new()),
                }
            }
        };
        if entry
            .doc
            .get("attributes")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|x| x == "readonly"))
        {
            return Err(reject(code::ACCESS_DENIED, format!("{path} is read-only")));
        }
        let mut bytes = match (&entry.content, mode) {
            (_, WriteMode::Replace) => Vec::new(),
            (Content::None, _) => {
                return Err(reject(
                    code::NO_CONTENT,
                    format!("{path} has no captured content to change"),
                ));
            }
            (c, _) => c.bytes().unwrap_or_default().to_vec(),
        };
        match mode {
            WriteMode::Replace | WriteMode::Append => bytes.extend_from_slice(data),
            WriteMode::At(off) => {
                if bytes.len() < off + data.len() {
                    bytes.resize(off + data.len(), 0);
                }
                bytes[off..off + data.len()].copy_from_slice(data);
            }
        }
        let size = bytes.len();
        entry.content = Content::Owned(bytes);
        entry.doc.remove("content");
        entry.doc.remove("size");
        entry.doc.remove("sha256");
        entry.doc.insert("modified".into(), time.into());
        let shown = entry.path.clone();
        self.rt.map.insert(nk, Some(entry));
        Ok(json!({"path": shown, "size": size}))
    }

    pub fn mkdir(&mut self, path: &str, time: &str) -> Result<Value, Rejected> {
        if self.live().exists(path) {
            return Err(reject(code::EXISTS, format!("{path} already exists")));
        }
        let spelled = self.new_path(path)?;
        let mut doc = Map::new();
        doc.insert("path".into(), spelled.clone().into());
        doc.insert("type".into(), "dir".into());
        doc.insert("created".into(), time.into());
        doc.insert("modified".into(), time.into());
        let nk = self.rules().norm(path);
        self.rt.map.insert(
            nk,
            Some(FileEntry {
                path: spelled.clone(),
                doc,
                content: Content::None,
            }),
        );
        Ok(json!({"path": spelled}))
    }

    /// Make the implied ancestors of `nk` real directories, so they survive
    /// when the entries that implied them are deleted or moved away.
    fn keep_ancestors(&mut self, nk: &str) {
        let r = self.rules();
        let mut keep = Vec::new();
        let live = self.live();
        let mut cur = r.parent(nk);
        while let Some(p) = cur {
            if r.is_root(&p) {
                break;
            }
            if live.get(&p).is_none()
                && let Some(spelled) = live.spelled(&p)
            {
                keep.push((p.clone(), spelled));
            }
            cur = r.parent(&p);
        }
        for (p, spelled) in keep {
            let mut doc = Map::new();
            doc.insert("path".into(), spelled.clone().into());
            doc.insert("type".into(), "dir".into());
            self.rt.map.insert(
                p,
                Some(FileEntry {
                    path: spelled,
                    doc,
                    content: Content::None,
                }),
            );
        }
    }

    pub fn delete(&mut self, path: &str, recursive: bool) -> Result<Value, Rejected> {
        let r = self.rules();
        let nk = r.norm(path);
        if r.is_root(&nk) {
            return Err(reject(code::BAD_REQUEST, "the root cannot be deleted"));
        }
        let live = self.live();
        if !live.exists(path) {
            return Err(reject(code::NOT_FOUND, format!("{path} does not exist")));
        }
        let below: Vec<String> = live.below(&nk).into_keys().collect();
        let shown = live.spelled(path);
        // Entries removed: an implied directory has no entry of its own.
        let deleted = below.len() + usize::from(live.get(&nk).is_some());
        if !below.is_empty() && !recursive {
            return Err(reject(
                code::NOT_EMPTY,
                format!("{path} is not empty; pass recursive"),
            ));
        }
        self.keep_ancestors(&nk);
        for k in below.iter().chain(std::iter::once(&nk)) {
            self.rt.map.insert(k.clone(), None);
        }
        Ok(json!({"path": shown, "deleted": deleted}))
    }

    pub fn rename(&mut self, from: &str, to: &str, time: &str) -> Result<Value, Rejected> {
        let r = self.rules();
        r.check(from)?;
        r.check(to)?;
        let (nf, nt) = (r.norm(from), r.norm(to));
        let live = self.live();
        if !live.exists(from) {
            return Err(reject(code::NOT_FOUND, format!("{from} does not exist")));
        }
        if r.is_root(&nf) {
            return Err(reject(code::BAD_REQUEST, "the root cannot be moved"));
        }
        if r.under(&nt, &nf) {
            return Err(reject(
                code::BAD_REQUEST,
                "cannot move a directory into itself",
            ));
        }
        if live.exists(to) {
            return Err(reject(code::EXISTS, format!("{to} already exists")));
        }
        let new_root = self.new_path(to)?;
        self.keep_ancestors(&nf);
        let live = self.live();
        let mut moved: Vec<(String, FileEntry)> = Vec::new();
        if let Some(e) = live.get(&nf) {
            moved.push((nf.clone(), e.clone()));
        }
        for (k, e) in live.below(&nf) {
            moved.push((k, e.clone()));
        }
        let old_root = live.spelled(from).unwrap_or_else(|| from.to_string());
        let depth = nf.split(r.sep).count();
        for (k, mut e) in moved.clone() {
            // Keep each entry's own spelling below the moved directory.
            let tail: Vec<&str> = e.path.split(r.sep).skip(depth).collect();
            e.path = if tail.is_empty() {
                new_root.clone()
            } else {
                format!("{new_root}{}{}", r.sep, tail.join(&r.sep.to_string()))
            };
            e.doc.insert("path".into(), e.path.clone().into());
            if k == nf {
                e.doc.insert("modified".into(), time.into());
            }
            let new_key = format!("{nt}{}", &k[nf.len()..]);
            self.rt.map.insert(k, None);
            self.rt.map.insert(new_key, Some(e));
        }
        Ok(json!({"from": old_root, "to": new_root, "moved": moved.len()}))
    }

    pub fn set(&mut self, path: &str, patch: &Map<String, Value>) -> Result<Value, Rejected> {
        check_meta(patch)?;
        let r = self.rules();
        let nk = r.norm(path);
        let live = self.live();
        let mut entry = match live.get(&nk) {
            Some(e) => e.clone(),
            None => {
                let spelled = live
                    .spelled(path)
                    .ok_or_else(|| reject(code::NOT_FOUND, format!("{path} does not exist")))?;
                let mut doc = Map::new();
                doc.insert("path".into(), spelled.clone().into());
                doc.insert("type".into(), "dir".into());
                FileEntry {
                    path: spelled,
                    doc,
                    content: Content::None,
                }
            }
        };
        if !r.windows && patch.contains_key("attributes") {
            return Err(reject(code::BAD_REQUEST, "attributes are Windows only"));
        }
        for (k, v) in patch {
            entry.doc.insert(k.clone(), v.clone());
        }
        let shown = entry.path.clone();
        self.rt.map.insert(nk, Some(entry));
        Ok(json!({"path": shown}))
    }
}
