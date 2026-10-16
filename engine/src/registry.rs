//! Layered Windows registry: one shared base per image, a small delta per host.
//!
//! Lookups never copy the base. Paths and value names are case-insensitive and
//! keep the base's spelling. A key exists if a profile lists it or lists a key
//! below it, so `HKLM` and `HKLM\SOFTWARE` exist whenever anything under them does.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value};

use crate::merge::norm;

#[derive(Debug)]
pub struct RegistryError(pub String);

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Default)]
struct BaseKey {
    path: String,
    values: Vec<(String, Value)>,
    index: HashMap<String, usize>,
}

/// The registry of a base image. Shared by every host on that base.
#[derive(Debug, Default)]
pub struct BaseRegistry {
    keys: BTreeMap<String, BaseKey>,
    present: bool,
}

#[derive(Debug, Default)]
struct DeltaKey {
    path: String,
    /// In profile order. `None` deletes the value.
    values: Vec<(String, Option<Value>)>,
}

/// One host's changes to its base registry.
#[derive(Debug, Default)]
pub struct RegistryDelta {
    deleted: Vec<String>,
    keys: BTreeMap<String, DeltaKey>,
    present: bool,
}

fn keys_object(section: Option<&Value>) -> Result<Option<&Map<String, Value>>, RegistryError> {
    match section.and_then(|r| r.get("keys")) {
        None => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => Err(RegistryError("registry.keys must be an object".into())),
    }
}

impl BaseRegistry {
    pub fn from_section(section: Option<&Value>) -> Result<Self, RegistryError> {
        let mut reg = BaseRegistry {
            present: section.is_some(),
            ..Default::default()
        };
        for (path, values) in keys_object(section)?.into_iter().flatten() {
            let Value::Object(values) = values else {
                return Err(RegistryError(format!("{path}: values must be an object")));
            };
            let mut key = BaseKey {
                path: path.clone(),
                ..Default::default()
            };
            for (name, v) in values {
                if v.is_null() {
                    return Err(RegistryError(format!(
                        "{path}: a base image cannot delete {name}"
                    )));
                }
                key.index.insert(norm(name), key.values.len());
                key.values.push((name.clone(), v.clone()));
            }
            reg.keys.insert(norm(path), key);
        }
        Ok(reg)
    }
}

impl BaseRegistry {
    /// Did the base image have a registry section at all?
    pub fn is_present(&self) -> bool {
        self.present
    }
}

impl RegistryDelta {
    /// Did the host profile have a registry section at all?
    pub fn is_present(&self) -> bool {
        self.present
    }

    pub fn from_section(
        section: Option<&Value>,
        base: &BaseRegistry,
    ) -> Result<Self, RegistryError> {
        let mut delta = RegistryDelta {
            present: section.is_some(),
            ..Default::default()
        };
        if let Some(list) = section.and_then(|r| r.get("delete_keys")) {
            for d in list.as_array().into_iter().flatten() {
                let d = d
                    .as_str()
                    .ok_or_else(|| RegistryError("delete_keys entries must be text".into()))?;
                let nd = norm(d);
                if !base.keys.keys().any(|k| under(k, &nd)) {
                    return Err(RegistryError(format!("cannot delete {d}: not in the base")));
                }
                delta.deleted.push(nd);
            }
        }
        for (path, values) in keys_object(section)?.into_iter().flatten() {
            let Value::Object(values) = values else {
                return Err(RegistryError(format!("{path}: values must be an object")));
            };
            let entry = delta.keys.entry(norm(path)).or_insert_with(|| DeltaKey {
                path: path.clone(),
                values: Vec::new(),
            });
            for (name, v) in values {
                let op = if v.is_null() { None } else { Some(v.clone()) };
                entry.values.push((name.clone(), op));
            }
        }
        Ok(delta)
    }
}

/// True if `key` is `prefix` or below it. Both are normalised.
fn under(key: &str, prefix: &str) -> bool {
    key == prefix
        || (key.len() > prefix.len()
            && key.starts_with(prefix)
            && key.as_bytes()[prefix.len()] == b'\\')
}

/// Keys strictly below `prefix` in a sorted map.
fn descendants<'m, T>(
    map: &'m BTreeMap<String, T>,
    prefix: &str,
) -> impl Iterator<Item = (&'m String, &'m T)> {
    let start = format!("{prefix}\\");
    map.range(start.clone()..)
        .take_while(move |(k, _)| k.starts_with(&start))
}

/// A host's view of the registry: its base with its delta applied.
pub struct View<'a> {
    pub base: &'a BaseRegistry,
    pub delta: &'a RegistryDelta,
}

impl View<'_> {
    fn deleted(&self, nk: &str) -> bool {
        self.delta.deleted.iter().any(|d| under(nk, d))
    }

    fn base_alive(&self, nk: &str) -> Option<&BaseKey> {
        self.base.keys.get(nk).filter(|_| !self.deleted(nk))
    }

    /// Does the key exist, listed or implied by a key below it?
    pub fn key_exists(&self, path: &str) -> bool {
        let nk = norm(path);
        self.base_alive(&nk).is_some()
            || self.delta.keys.contains_key(&nk)
            || descendants(&self.base.keys, &nk).any(|(k, _)| !self.deleted(k))
            || descendants(&self.delta.keys, &nk).next().is_some()
    }

    /// The key's path as the base spells it.
    pub fn key_path(&self, path: &str) -> Option<String> {
        let nk = norm(path);
        if let Some(b) = self.base_alive(&nk) {
            return Some(b.path.clone());
        }
        if let Some(d) = self.delta.keys.get(&nk) {
            return Some(d.path.clone());
        }
        self.key_exists(path).then(|| {
            // An implied key: take the spelling from the first key below it.
            let below = descendants(&self.base.keys, &nk)
                .find(|(k, _)| !self.deleted(k))
                .map(|(_, b)| b.path.clone())
                .or_else(|| {
                    descendants(&self.delta.keys, &nk)
                        .next()
                        .map(|(_, d)| d.path.clone())
                })
                .unwrap_or_default();
            let depth = nk.split('\\').count();
            below.split('\\').take(depth).collect::<Vec<_>>().join("\\")
        })
    }

    /// All values of a key, in order: base values first, then values the host adds.
    pub fn values(&self, path: &str) -> Option<Vec<(String, Value)>> {
        if !self.key_exists(path) {
            return None;
        }
        let nk = norm(path);
        let mut out: Vec<(String, Value)> = self
            .base_alive(&nk)
            .map(|b| b.values.clone())
            .unwrap_or_default();
        if let Some(d) = self.delta.keys.get(&nk) {
            for (name, op) in &d.values {
                let pos = out.iter().position(|(n, _)| norm(n) == norm(name));
                match (pos, op) {
                    (Some(i), None) => {
                        out.remove(i);
                    }
                    (Some(i), Some(v)) => out[i].1 = v.clone(),
                    (None, Some(v)) => out.push((name.clone(), v.clone())),
                    (None, None) => {}
                }
            }
        }
        Some(out)
    }

    /// One value. `None` if the key or the value does not exist.
    pub fn value(&self, path: &str, name: &str) -> Option<(String, Value)> {
        let nk = norm(path);
        let nn = norm(name);
        if let Some(d) = self.delta.keys.get(&nk)
            && let Some((_, op)) = d.values.iter().rev().find(|(n, _)| norm(n) == nn)
        {
            let spelled = self
                .base_alive(&nk)
                .and_then(|b| b.index.get(&nn).map(|&i| b.values[i].0.clone()));
            return op.as_ref().map(|v| {
                let n = spelled.unwrap_or_else(|| name.to_string());
                (n, v.clone())
            });
        }
        let b = self.base_alive(&nk)?;
        b.index.get(&nn).map(|&i| b.values[i].clone())
    }

    /// Names of the immediate subkeys, sorted without regard to case.
    pub fn subkeys(&self, path: &str) -> Option<Vec<String>> {
        if !self.key_exists(path) {
            return None;
        }
        let nk = norm(path);
        let depth = nk.split('\\').count();
        let mut found: BTreeMap<String, String> = BTreeMap::new();
        let base = descendants(&self.base.keys, &nk)
            .filter(|(k, _)| !self.deleted(k))
            .map(|(_, b)| b.path.as_str());
        let delta = descendants(&self.delta.keys, &nk).map(|(_, d)| d.path.as_str());
        for p in base.chain(delta) {
            if let Some(child) = p.split('\\').nth(depth) {
                found
                    .entry(child.to_lowercase())
                    .or_insert_with(|| child.to_string());
            }
        }
        Some(found.into_values().collect())
    }

    /// The full registry section, as `xvm-profile resolve` writes it.
    pub fn materialize(&self) -> Value {
        let mut listed: BTreeMap<String, String> = BTreeMap::new();
        for (nk, b) in &self.base.keys {
            if !self.deleted(nk) {
                listed.insert(nk.clone(), b.path.clone());
            }
        }
        for (nk, d) in &self.delta.keys {
            listed.entry(nk.clone()).or_insert_with(|| d.path.clone());
        }
        let mut keys = Map::new();
        for (_, path) in listed {
            let values: Map<String, Value> =
                self.values(&path).unwrap_or_default().into_iter().collect();
            keys.insert(path, Value::Object(values));
        }
        let mut out = Map::new();
        out.insert("keys".into(), Value::Object(keys));
        Value::Object(out)
    }
}
