//! Merge rules shared with `xvm-profile resolve` (control/xvm_control/profile.py).
//!
//! The engine keeps base images and host deltas apart and merges on demand.
//! These helpers implement the same rules on JSON values; the test vectors in
//! `engine/tests/vectors` check that both implementations agree.

use serde_json::{Map, Value};

/// Lower-case form used for case-insensitive names and registry paths.
pub fn norm(s: &str) -> String {
    s.trim_end_matches('\\').to_lowercase()
}

/// Deep merge: objects merge key by key, anything else in `over` replaces `base`.
pub fn merge_dict(base: &Map<String, Value>, over: &Map<String, Value>) -> Map<String, Value> {
    let mut out = base.clone();
    for (k, v) in over {
        match (out.get(k), v) {
            (Some(Value::Object(b)), Value::Object(o)) => {
                let merged = merge_dict(b, o);
                out.insert(k.clone(), Value::Object(merged));
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    out
}

fn item_name(item: &Value) -> Option<&str> {
    item.get("name").and_then(Value::as_str)
}

fn is_removal(item: &Value) -> bool {
    item.get("remove").and_then(Value::as_bool) == Some(true)
}

/// Merge two process lists, keyed by `id`, the way `merge_keyed` merges by name.
pub fn merge_by_id(base: &[Value], delta: &[Value]) -> Vec<Value> {
    let id = |v: &Value| v.get("id").and_then(Value::as_str).map(str::to_string);
    let mut out: Vec<Value> = Vec::with_capacity(base.len() + delta.len());
    for b in base {
        let over = delta.iter().find(|d| id(d) == id(b));
        match over {
            Some(d) if is_removal(d) => {}
            Some(Value::Object(d)) => {
                if let Value::Object(bm) = b {
                    out.push(Value::Object(merge_dict(bm, d)));
                }
            }
            _ => out.push(b.clone()),
        }
    }
    for d in delta {
        if !base.iter().any(|b| id(b) == id(d)) && !is_removal(d) {
            out.push(d.clone());
        }
    }
    out
}

/// Merge two keyed lists (users, services, interfaces...).
///
/// Base entries keep their position and spelling of `name`. A delta entry with
/// `remove: true` deletes the base entry; other delta entries merge into the
/// base entry of the same name or are appended in delta order.
pub fn merge_keyed(base: &[Value], delta: &[Value]) -> Vec<Value> {
    let mut out = Vec::with_capacity(base.len() + delta.len());
    for b in base {
        let Some(name) = item_name(b) else { continue };
        let key = norm(name);
        let over = delta
            .iter()
            .find(|d| item_name(d).map(norm).as_deref() == Some(key.as_str()));
        match over {
            Some(d) if is_removal(d) => {}
            Some(Value::Object(d)) => {
                if let Value::Object(bm) = b {
                    let mut merged = merge_dict(bm, d);
                    merged.insert("name".into(), Value::String(name.to_string()));
                    out.push(Value::Object(merged));
                }
            }
            _ => out.push(b.clone()),
        }
    }
    for d in delta {
        let Some(name) = item_name(d) else { continue };
        let key = norm(name);
        let in_base = base
            .iter()
            .any(|b| item_name(b).map(norm).as_deref() == Some(key.as_str()));
        if !in_base && !is_removal(d) {
            out.push(d.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn deep_merge() {
        let m = merge_dict(
            &obj(json!({"a": {"x": 1, "y": 2}, "b": [1]})),
            &obj(json!({"a": {"y": 3}, "b": [2], "c": true})),
        );
        assert_eq!(
            Value::Object(m),
            json!({"a": {"x": 1, "y": 3}, "b": [2], "c": true})
        );
    }

    #[test]
    fn keyed() {
        let base = [json!({"name": "A", "v": 1}), json!({"name": "B"})];
        let delta = [
            json!({"name": "b", "remove": true}),
            json!({"name": "a", "v": 2}),
            json!({"name": "C"}),
        ];
        assert_eq!(
            merge_keyed(&base, &delta),
            vec![json!({"name": "A", "v": 2}), json!({"name": "C"})]
        );
    }
}
