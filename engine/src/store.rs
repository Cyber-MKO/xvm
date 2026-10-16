//! Loads compiled profiles (`xvm-profile compile`) and answers per-host queries.
//!
//! Each base image is held once and shared by all of its hosts. A host keeps
//! only its own profile: the delta. Every fact is computed from the two on
//! request (CLAUDE.md rule 5: no hardcoded host facts).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use serde_json::{Map, Value};

use crate::merge::{merge_dict, merge_keyed};
use crate::registry::{BaseRegistry, RegistryDelta, View};
use crate::runtime::{Live, Runtime, Writer};

/// Lists that merge entry by entry, keyed by `name`.
pub const KEYED_LISTS: [&str; 4] = ["users", "groups", "software", "services"];
/// Object sections a host can ask for whole.
pub const SECTIONS: [&str; 5] = ["identity", "os_info", "hardware", "network", "agent"];
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
    /// The document without its registry, which lives in `registry`.
    doc: Map<String, Value>,
    registry: BaseRegistry,
}

/// One emulated host: a shared base, this host's delta, and its run-time changes.
#[derive(Debug)]
pub struct Host {
    pub name: String,
    pub base: Arc<Base>,
    delta: Map<String, Value>,
    registry: RegistryDelta,
    runtime: RwLock<Runtime>,
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
    pub fn from_value(v: Value) -> Result<Self, StoreError> {
        let mut doc = object(v, "base image")?;
        kind_is(&doc, "base-image", "base image")?;
        let name = text(&doc, "name", "base image")?;
        let registry = BaseRegistry::from_section(doc.get("registry"))?;
        doc.remove("registry");
        Ok(Base {
            name,
            doc,
            registry,
        })
    }
}

impl Host {
    pub fn from_value(v: Value, base: Arc<Base>) -> Result<Self, StoreError> {
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
        delta.remove("registry");
        Ok(Host {
            name,
            base,
            delta,
            registry,
            runtime: RwLock::new(Runtime::default()),
        })
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
            .filter(|(k, _)| !skip(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let deltas: Map<String, Value> = self
            .delta
            .iter()
            .filter(|(k, _)| !skip(k) && !KEYED_LISTS.contains(&k.as_str()) && *k != "network")
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
        for name in names("bases") {
            let base =
                Base::from_value(read_json(&dir.join("bases").join(format!("{name}.json")))?)?;
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
            let host = Host::from_value(doc, base)?;
            store.hosts.insert(host.name.clone(), Arc::new(host));
        }
        Ok(store)
    }
}
