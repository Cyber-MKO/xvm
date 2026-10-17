//! Loads compiled profiles (`xvm-profile compile`) and answers per-host queries.
//!
//! Each base image is held once and shared by all of its hosts. A host keeps
//! only its own profile: the delta. Every fact is computed from the two on
//! request (CLAUDE.md rule 5: no hardcoded host facts).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

use serde_json::{Map, Value};

use crate::files::{BaseFiles, Blobs, FileDelta, FileWriter, FilesView, LiveFiles, NoBlobs, Rules};
use crate::merge::{merge_by_id, merge_dict, merge_keyed};
use crate::procs::{ProcTable, boot_table};
use crate::registry::{BaseRegistry, RegistryDelta, View};
use crate::runtime::{Live, Runtime, Writer};

/// Lists that merge entry by entry, keyed by `name`.
pub const KEYED_LISTS: [&str; 5] = ["users", "groups", "software", "hotfixes", "services"];
/// Object sections a host can ask for whole.
pub const SECTIONS: [&str; 6] = [
    "identity", "os_info", "hardware", "network", "agent", "windows",
];
/// Sections with their own layering, kept out of the generic object merge.
const LAYERED: [&str; 5] = [
    "network",
    "registry",
    "files",
    "processes",
    "event_messages",
];
/// Fields that belong to the file, not to the host.
const OWN_FIELDS: [&str; 6] = ["schema", "kind", "name", "description", "base", "source"];

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<crate::registry::RegistryError> for StoreError {
    fn from(e: crate::registry::RegistryError) -> Self {
        StoreError(e.0)
    }
}

/// A base image, shared by every host built on it.
#[derive(Debug)]
pub struct Base {
    pub name: String,
    /// SHA-256 of the compiled document. Changes when the base image changes.
    pub digest: String,
    /// The document without its registry and files, which have their own layers.
    doc: Map<String, Value>,
    registry: BaseRegistry,
    files: BaseFiles,
    rules: Rules,
}

/// One emulated host: a shared base, this host's delta, and its run-time changes.
#[derive(Debug)]
pub struct Host {
    pub name: String,
    pub base: Arc<Base>,
    /// SHA-256 over the base's digest and the compiled host profile. Saved
    /// run-time state is only reused while this stays the same.
    pub digest: String,
    delta: Map<String, Value>,
    registry: RegistryDelta,
    files: FileDelta,
    /// Process definitions, base and profile merged.
    processes: Option<Vec<Value>>,
    /// The process table at boot, restored by `reset`.
    boot_procs: ProcTable,
    /// Event message templates, base and profile merged: provider to "ID" or "ID/VERSION".
    pub event_messages: Value,
    runtime: RwLock<Runtime>,
    /// Event logs. Kept apart from `runtime` so high event rates do not touch
    /// the change journal or snapshots. Lock order: `runtime`, then `events`.
    events: RwLock<crate::eventlog::EventLogs>,
    /// Bumped on every event write and reset, to wake `evt.wait`.
    events_signal: (Mutex<EventSignal>, Condvar),
}

/// How many event writes and resets a host has seen. `evt.wait` compares
/// two of these to learn that something changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventSignal {
    pub writes: u64,
    pub resets: u64,
}

fn object(v: Value, what: &str) -> Result<Map<String, Value>, StoreError> {
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(StoreError(format!("{what}: expected a JSON object"))),
    }
}

fn kind_is(doc: &Map<String, Value>, kind: &str, what: &str) -> Result<(), StoreError> {
    match doc.get("schema").and_then(Value::as_u64) {
        Some(1) => {}
        other => return Err(StoreError(format!("{what}: unsupported schema {other:?}"))),
    }
    let got = doc.get("kind").and_then(Value::as_str).unwrap_or("");
    if got != kind {
        return Err(StoreError(format!(
            "{what}: expected kind {kind}, got {got:?}"
        )));
    }
    Ok(())
}

fn text(doc: &Map<String, Value>, field: &str, what: &str) -> Result<String, StoreError> {
    doc.get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| StoreError(format!("{what}: missing {field}")))
}

impl Base {
    /// A base with inline file content only (tests, vectors).
    pub fn from_value(v: Value) -> Result<Self, StoreError> {
        Self::from_value_with(v, &NoBlobs)
    }

    pub fn from_value_with(v: Value, blobs: &dyn Blobs) -> Result<Self, StoreError> {
        let digest = crate::files::sha256_hex(&serde_json::to_vec(&v).unwrap_or_default());
        let mut doc = object(v, "base image")?;
        kind_is(&doc, "base-image", "base image")?;
        let name = text(&doc, "name", "base image")?;
        let rules = Rules::for_os(doc.get("os").and_then(Value::as_str).unwrap_or(""));
        let registry = BaseRegistry::from_section(doc.get("registry"))?;
        let files = BaseFiles::from_section(doc.get("files"), rules, blobs)
            .map_err(|e| StoreError(format!("{name}: files: {e}")))?;
        doc.remove("registry");
        doc.remove("files");
        Ok(Base {
            name,
            digest,
            doc,
            registry,
            files,
            rules,
        })
    }
}

impl Host {
    /// A host with inline file content only, booted at its profile's
    /// `os_info.last_boot` or, without one, at the engine's clock.
    pub fn from_value(v: Value, base: Arc<Base>) -> Result<Self, StoreError> {
        Self::from_value_with(v, base, &NoBlobs, &crate::runtime::now())
    }

    pub fn from_value_with(
        v: Value,
        base: Arc<Base>,
        blobs: &dyn Blobs,
        boot_fallback: &str,
    ) -> Result<Self, StoreError> {
        let mut bytes = base.digest.clone().into_bytes();
        bytes.push(b'\n');
        bytes.extend(serde_json::to_vec(&v).unwrap_or_default());
        let digest = crate::files::sha256_hex(&bytes);
        let mut delta = object(v, "host profile")?;
        kind_is(&delta, "host-profile", "host profile")?;
        let name = text(&delta, "name", "host profile")?;
        let wanted = text(&delta, "base", &name)?;
        if wanted != base.name {
            return Err(StoreError(format!(
                "{name}: names base {wanted}, got {}",
                base.name
            )));
        }
        if delta.get("os") != base.doc.get("os") {
            return Err(StoreError(format!(
                "{name}: os does not match base {}",
                base.name
            )));
        }
        let registry = RegistryDelta::from_section(delta.get("registry"), &base.registry)
            .map_err(|e| StoreError(format!("{name}: {}", e.0)))?;
        let files = FileDelta::from_section(delta.get("files"), &base.files, base.rules, blobs)
            .map_err(|e| StoreError(format!("{name}: files: {e}")))?;
        delta.remove("registry");
        delta.remove("files");
        let list = |m: &Map<String, Value>| m.get("processes").and_then(Value::as_array).cloned();
        let processes = match (list(&base.doc), list(&delta)) {
            (None, None) => None,
            (b, d) => Some(merge_by_id(&b.unwrap_or_default(), &d.unwrap_or_default())),
        };
        let os_info = match (base.doc.get("os_info"), delta.get("os_info")) {
            (Some(Value::Object(b)), Some(Value::Object(d))) => Some(merge_dict(b, d)),
            (b, d) => d.or(b).and_then(Value::as_object).cloned(),
        };
        let boot = os_info
            .as_ref()
            .and_then(|o| o.get("last_boot"))
            .and_then(Value::as_str)
            .unwrap_or(boot_fallback)
            .to_string();
        let (live, pids) = boot_table(
            processes.as_deref().unwrap_or_default(),
            &name,
            base.rules.windows,
            &boot,
        )
        .map_err(|e| StoreError(format!("{name}: processes: {e}")))?;
        let boot_procs = ProcTable { live, pids };
        let mut runtime = Runtime::default();
        runtime.procs = boot_procs.clone();
        let event_messages = match (base.doc.get("event_messages"), delta.get("event_messages")) {
            (Some(Value::Object(b)), Some(Value::Object(d))) => Value::Object(merge_dict(b, d)),
            (b, d) => d.or(b).cloned().unwrap_or(Value::Object(Map::new())),
        };
        Ok(Host {
            name,
            base,
            digest,
            delta,
            registry,
            files,
            processes,
            boot_procs,
            event_messages,
            runtime: RwLock::new(runtime),
            events: RwLock::new(Default::default()),
            events_signal: Default::default(),
        })
    }

    pub fn rules(&self) -> Rules {
        self.base.rules
    }

    /// Files as the base and profile define them, without run-time changes.
    pub fn profile_files(&self) -> FilesView<'_> {
        FilesView {
            base: &self.base.files,
            delta: &self.files,
            rules: self.base.rules,
        }
    }

    pub fn files<'a>(&'a self, rt: &'a Runtime) -> LiveFiles<'a> {
        LiveFiles {
            lower: self.profile_files(),
            rt: &rt.files,
        }
    }

    pub fn files_writer<'a>(&'a self, rt: &'a mut Runtime) -> FileWriter<'a> {
        FileWriter {
            lower: self.profile_files(),
            rt: &mut rt.files,
        }
    }

    /// The process table as it was at boot.
    pub fn boot_procs(&self) -> &ProcTable {
        &self.boot_procs
    }

    /// Drop every run-time change, restore the boot process table and empty the event logs.
    pub fn reset(&self, rt: &mut Runtime, time: &str) -> Value {
        let out = rt.reset(time);
        rt.procs = self.boot_procs.clone();
        *self.events_write() = Default::default();
        self.signal_events(true);
        out
    }

    /// Wake every `evt.wait` on this host: an event was written, or the logs were reset.
    pub fn signal_events(&self, reset: bool) {
        let (lock, cv) = &self.events_signal;
        let mut s = lock.lock().unwrap_or_else(|e| e.into_inner());
        if reset {
            s.resets += 1;
        } else {
            s.writes += 1;
        }
        cv.notify_all();
    }

    pub fn event_signal(&self) -> EventSignal {
        *self
            .events_signal
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Block until the signal differs from `seen` or `deadline` passes. Returns the current signal.
    pub fn wait_events(&self, seen: EventSignal, deadline: Instant) -> EventSignal {
        let (lock, cv) = &self.events_signal;
        let mut s = lock.lock().unwrap_or_else(|e| e.into_inner());
        while *s == seen {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            s = cv
                .wait_timeout(s, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        *s
    }

    pub fn events_read(&self) -> std::sync::RwLockReadGuard<'_, crate::eventlog::EventLogs> {
        self.events.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn events_write(&self) -> std::sync::RwLockWriteGuard<'_, crate::eventlog::EventLogs> {
        self.events.write().unwrap_or_else(|e| e.into_inner())
    }

    /// The name events carry in `Computer`: the host name, with its DNS
    /// domain when the host is in one (rule 5: from the profile).
    pub fn computer(&self, rt: &Runtime) -> String {
        let id = self.section_with(rt, "identity").unwrap_or(Value::Null);
        let host = id["hostname"].as_str().unwrap_or(&self.name).to_string();
        match id["domain"].as_str() {
            Some(d) if !d.is_empty() && !d.eq_ignore_ascii_case("WORKGROUP") => {
                format!("{host}.{d}")
            }
            _ => host,
        }
    }

    pub fn os(&self) -> &str {
        self.base
            .doc
            .get("os")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    /// The registry as the base and profile define it, without run-time changes.
    pub fn profile_registry(&self) -> View<'_> {
        View {
            base: &self.base.registry,
            delta: &self.registry,
        }
    }

    /// Lock the run-time layer for reading. A poisoned lock still holds valid
    /// state (every change is applied in full or not at all), so it is used.
    pub fn read(&self) -> RwLockReadGuard<'_, Runtime> {
        self.runtime.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, Runtime> {
        self.runtime.write().unwrap_or_else(|e| e.into_inner())
    }

    /// The live registry: profile plus run-time changes.
    pub fn registry<'a>(&'a self, rt: &'a Runtime) -> Live<'a> {
        Live {
            lower: self.profile_registry(),
            rt,
        }
    }

    pub fn registry_writer<'a>(&'a self, rt: &'a mut Runtime) -> Writer<'a> {
        Writer {
            lower: self.profile_registry(),
            rt,
        }
    }

    /// A section with run-time changes applied.
    pub fn section_with(&self, rt: &Runtime, name: &str) -> Option<Value> {
        if name == "network" {
            let mut net = rt
                .sections
                .get("network")
                .cloned()
                .or_else(|| self.network());
            if let Some(ifs) = rt.lists.get("interfaces") {
                let n = net.get_or_insert_with(|| Value::Object(Map::new()));
                n["interfaces"] = Value::Array(ifs.clone());
            }
            return net;
        }
        rt.sections
            .get(name)
            .cloned()
            .or_else(|| self.profile_section(name))
    }

    /// A keyed list with run-time changes applied. `None` for an unknown list.
    pub fn list_with(&self, rt: &Runtime, name: &str) -> Option<Vec<Value>> {
        let profile = self.profile_list(name)?;
        Some(rt.lists.get(name).cloned().unwrap_or(profile))
    }

    /// A section, live. Takes the read lock.
    pub fn section(&self, name: &str) -> Option<Value> {
        self.section_with(&self.read(), name)
    }

    /// A keyed list, live. Takes the read lock.
    pub fn list(&self, name: &str) -> Option<Vec<Value>> {
        self.list_with(&self.read(), name)
    }

    /// A section as the base and profile define it.
    pub fn profile_section(&self, name: &str) -> Option<Value> {
        if name == "network" {
            return self.network();
        }
        let b = self.base.doc.get(name);
        let d = self.delta.get(name);
        match (b, d) {
            (Some(Value::Object(b)), Some(Value::Object(d))) => {
                Some(Value::Object(merge_dict(b, d)))
            }
            (_, Some(d)) => Some(d.clone()),
            (Some(b), None) => Some(b.clone()),
            (None, None) => None,
        }
    }

    fn network(&self) -> Option<Value> {
        let b = self.base.doc.get("network").and_then(Value::as_object);
        let d = self.delta.get("network").and_then(Value::as_object);
        if b.is_none() && d.is_none() {
            return None;
        }
        let empty = Map::new();
        let (b, d) = (b.unwrap_or(&empty), d.unwrap_or(&empty));
        let mut over = d.clone();
        over.remove("interfaces");
        let mut net = merge_dict(b, &over);
        net.insert(
            "interfaces".into(),
            Value::Array(Self::keyed(b, d, "interfaces")),
        );
        Some(Value::Object(net))
    }

    fn keyed(b: &Map<String, Value>, d: &Map<String, Value>, field: &str) -> Vec<Value> {
        let list = |m: &Map<String, Value>| {
            m.get(field)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        merge_keyed(&list(b), &list(d))
    }

    /// A keyed list as the base and profile define it. `interfaces` is the list inside `network`.
    pub fn profile_list(&self, name: &str) -> Option<Vec<Value>> {
        if name == "interfaces" {
            return self
                .network()
                .and_then(|n| n.get("interfaces").and_then(Value::as_array).cloned());
        }
        if !KEYED_LISTS.contains(&name) {
            return None;
        }
        if !self.base.doc.contains_key(name) && !self.delta.contains_key(name) {
            return Some(Vec::new());
        }
        Some(Self::keyed(&self.base.doc, &self.delta, name))
    }

    /// The whole host, as `xvm-profile resolve` writes it, with run-time changes.
    pub fn resolved(&self) -> Value {
        let rt = self.read();
        let mut out = Map::new();
        out.insert("schema".into(), 1.into());
        out.insert("kind".into(), "resolved-host".into());
        out.insert("name".into(), self.name.clone().into());
        out.insert("base".into(), self.base.name.clone().into());
        if let Some(src) = self.base.doc.get("source") {
            out.insert("source".into(), src.clone());
        }
        let skip = |k: &str| OWN_FIELDS.contains(&k);
        let host_fields: Map<String, Value> = self
            .base
            .doc
            .iter()
            .filter(|(k, _)| !skip(k) && *k != "processes")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let deltas: Map<String, Value> = self
            .delta
            .iter()
            .filter(|(k, _)| {
                !skip(k) && !KEYED_LISTS.contains(&k.as_str()) && !LAYERED.contains(&k.as_str())
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in merge_dict(&host_fields, &deltas) {
            out.insert(k, v);
        }
        for (k, v) in &rt.sections {
            if k != "network" {
                out.insert(k.clone(), v.clone());
            }
        }
        for field in KEYED_LISTS {
            let present = self.base.doc.contains_key(field)
                || self.delta.contains_key(field)
                || rt.lists.contains_key(field);
            if present {
                out.insert(
                    field.into(),
                    Value::Array(self.list_with(&rt, field).unwrap_or_default()),
                );
            }
        }
        if let Some(net) = self.section_with(&rt, "network") {
            out.insert("network".into(), net);
        }
        if self.base.registry_present() || self.registry_present() || !rt.reg.is_empty() {
            out.insert("registry".into(), self.registry(&rt).materialize());
        }
        if self.base.files.is_present() || self.files.is_present() || !rt.files.map.is_empty() {
            out.insert("files".into(), Value::Array(self.files(&rt).materialize()));
        }
        // Definitions, as in the profile. The running table is `proc.list`.
        if let Some(p) = &self.processes {
            out.insert("processes".into(), Value::Array(p.clone()));
        }
        if self.base.doc.contains_key("event_messages") || self.delta.contains_key("event_messages")
        {
            out.insert("event_messages".into(), self.event_messages.clone());
        }
        Value::Object(out)
    }

    fn registry_present(&self) -> bool {
        self.registry.is_present()
    }
}

impl Base {
    fn registry_present(&self) -> bool {
        self.registry.is_present()
    }
}

/// Every base image and host loaded from one compiled folder.
#[derive(Debug, Default)]
pub struct Store {
    pub bases: BTreeMap<String, Arc<Base>>,
    pub hosts: BTreeMap<String, Arc<Host>>,
}

/// The blob store written by `xvm-profile compile`. Each blob is read once,
/// checked against its name, and shared by every host that carries it.
struct DirBlobs {
    dir: std::path::PathBuf,
    cache: std::sync::Mutex<std::collections::HashMap<String, Arc<[u8]>>>,
}

impl Blobs for DirBlobs {
    fn get(&self, sha256: &str) -> Result<Arc<[u8]>, String> {
        let well_formed = sha256.len() == 64
            && sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if !well_formed {
            return Err(format!("bad blob name {sha256:?}"));
        }
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(b) = cache.get(sha256) {
            return Ok(b.clone());
        }
        let path = self.dir.join(sha256);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if crate::files::sha256_hex(&bytes) != sha256 {
            return Err(format!(
                "{}: content does not match its name",
                path.display()
            ));
        }
        let b: Arc<[u8]> = Arc::from(bytes);
        cache.insert(sha256.to_string(), b.clone());
        Ok(b)
    }
}

fn read_json(path: &Path) -> Result<Value, StoreError> {
    let text =
        fs::read_to_string(path).map_err(|e| StoreError(format!("{}: {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|e| StoreError(format!("{}: {e}", path.display())))
}

impl Store {
    /// Load the output of `xvm-profile compile`.
    pub fn load(dir: &Path) -> Result<Self, StoreError> {
        let index = object(read_json(&dir.join("compiled.json"))?, "compiled.json")?;
        if index.get("schema").and_then(Value::as_u64) != Some(1) {
            return Err(StoreError("compiled.json: unsupported schema".into()));
        }
        let names = |field: &str| -> Vec<String> {
            index
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        };
        let mut store = Store::default();
        let blobs = DirBlobs {
            dir: dir.join("blobs"),
            cache: Default::default(),
        };
        // Hosts without os_info.last_boot boot when the engine loads them.
        let boot = crate::runtime::now();
        for name in names("bases") {
            let base = Base::from_value_with(
                read_json(&dir.join("bases").join(format!("{name}.json")))?,
                &blobs,
            )?;
            store.bases.insert(base.name.clone(), Arc::new(base));
        }
        for name in names("hosts") {
            let doc = read_json(&dir.join("hosts").join(format!("{name}.json")))?;
            let base_name = doc
                .get("base")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let base = store
                .bases
                .get(&base_name)
                .cloned()
                .ok_or_else(|| StoreError(format!("{name}: unknown base {base_name:?}")))?;
            let host = Host::from_value_with(doc, base, &blobs, &boot)?;
            store.hosts.insert(host.name.clone(), Arc::new(host));
        }
        Ok(store)
    }
}
