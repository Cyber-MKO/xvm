# engine

The host-state engine (brief section 6, component 1). One process serves the facts of every emulated host: identity, OS, hardware, network, users, groups, software, services and the Windows registry. Personality runtimes ask it instead of hardcoding anything (CLAUDE.md rule 5).

## How it fits

| Step | Tool | Output |
| --- | --- | --- |
| 1 | `xvm-profile compile --bases DIR --hosts DIR --out DIR` | Validated JSON: `compiled.json`, `bases/*.json`, `hosts/*.json` |
| 2 | `xvm-engined --compiled DIR --socket PATH [--gap-log FILE]` | A daemon on a Unix socket |
| 3 | A personality runtime, using `xvm_engine::client::Client` | Answers for one host per connection |

`xvm-profile` is the only YAML parser and validator. The engine reads its JSON, so Python and Rust never disagree on YAML. The engine does the layering itself:

| Layer | Holds | Shared |
| --- | --- | --- |
| Base image | Facts common to many hosts | By every host on the base |
| Host profile | What differs for one host | No |
| Run time | Changes since the engine started: scenario events, the agent's own writes | No |

The run-time layer copies a key, list or section the first time it changes. The profile layers never change, so `reset` returns a host to its profile.

## Lookups

| Area | Behaviour |
| --- | --- |
| Sections | `identity`, `os_info`, `hardware`, `network`, `agent`. Objects merge key by key. |
| Lists | `users`, `groups`, `software`, `services`, `interfaces`. Merge by name, ignoring case, keeping the base's spelling. |
| Registry keys | Case-insensitive. A key exists if it is listed or a key below it is, so `HKLM\SOFTWARE` exists without being listed. |
| Registry values | Base values first in base order, then values the host adds. A `null` in the host deletes a value. |
| Subkeys | Immediate children, sorted without regard to case. |
| Deleted keys | `delete_keys` removes a key and everything below it. The host may re-add the key with new values. |

## Protocol

Each message is a 4-byte big-endian length, then JSON. A request is `{"id": N, "op": "...", ...parameters}`. An answer is `{"id": N, "ok": true, "result": ...}` or `{"id": N, "ok": false, "error": {"code": "...", "message": "..."}}`. The first request on a connection must be `hello`.

| Op | Parameters | Result |
| --- | --- | --- |
| `hello` | `host` | `{name, os, base}` |
| `section` | `name` | Object, or null if neither base nor host has it |
| `list` | `name` | Array |
| `reg.key_exists` | `key` | Boolean |
| `reg.key_path` | `key` | The key as the base spells it |
| `reg.query_value` | `key`, `name` | `{name, type, data}` |
| `reg.enum_values` | `key` | Array of `{name, type, data}` |
| `reg.enum_subkeys` | `key` | Array of names |
| `reg.key_info` | `key` | `{path, subkeys, values, last_write}` |
| `resolved` | none | The whole host: equal to `xvm-profile resolve` until something changes it at run time |

### Run-time changes

Every write takes an optional `time` (`2026-10-16T10:00:00Z`, fraction allowed). Scenarios pass their own clock so hosts can run on jittered clocks; without it the engine's clock is used. Every write returns the journal sequence number `seq` of its change.

| Op | Parameters | Effect |
| --- | --- | --- |
| `reg.create_key` | `key` | Like `RegCreateKeyEx`. Returns `created` false if the key already exists. |
| `reg.set_value` | `key`, `name`, `type`, `data` | Like `RegSetValueEx`. Creates the key if needed. An existing value keeps its spelling and place. |
| `reg.delete_value` | `key`, `name` | Like `RegDeleteValue` |
| `reg.delete_key` | `key`, optional `recursive` | Like `RegDeleteKey`: fails with `has_subkeys` unless `recursive` is true, which acts like `RegDeleteTree` |
| `list.upsert` | `name`, `item` | Merges `item` into the entry with the same name, or appends it |
| `list.remove` | `name`, `item` (a name) | Removes the entry |
| `section.update` | `name`, `patch` | Deep-merges `patch`. Nulls, `network.interfaces` (use the list ops) and `identity.hostname` are refused. |
| `changes` | optional `since` (default 0), `limit` (default 1000) | `{changes, last_seq, lost}`: journal entries after `since`, in order |
| `reset` | none | Drops every run-time change. The journal keeps counting and records the reset. |

Writes are checked like profiles: registry types and data, key paths (`HKLM`, `HKU` or `HKCR`, names of 1 to 255 characters), value names of at most 255 characters. A rejected write changes nothing and adds no journal entry.

New keys take the spelling of their existing ancestors: setting a value on `hklm\software\vendor\New` creates `HKLM\SOFTWARE\Vendor\New` when `HKLM\SOFTWARE\Vendor` exists. Changing a value updates the key's `last_write`; adding or deleting a subkey also updates the parent's. Keys that never changed at run time report `last_write` as null.

The journal keeps the last 10,000 changes per host. If a reader asks for entries that were dropped, `lost` is true and it should re-read the state it watches.

| Error code | Meaning |
| --- | --- |
| `bad_request` | Malformed request, missing parameter, unknown section or list |
| `no_host` | A request before `hello` |
| `unknown_host` | `hello` named a host that is not loaded |
| `not_found` | Registry key or value, or list entry, does not exist |
| `has_subkeys` | `reg.delete_key` without `recursive` on a key with subkeys |
| `unsupported` | The op is not implemented. Also written to the gap log with the host and agent (rule 4). |

## Tests

| Test | Checks |
| --- | --- |
| `tests/vectors.rs` | The layered view equals `xvm-profile resolve` on every case in `tests/vectors/`, including value and list order |
| `tests/server.rs` | Socket round trips, errors, `hello` first, gap logging |
| `tests/runtime.rs` | Every write op, rejected writes, the journal and lost entries, reset, hosts on one base staying separate, eight concurrent writers |
| CI | The same tests as a 32-bit (i686) build, since the Windows personality links the client |

The vectors are generated by `tests/control/test_vectors.py`. After changing a case, run `XVM_UPDATE_VECTORS=1 pytest tests/control/test_vectors.py`.

Not yet:

| Missing | Notes |
| --- | --- |
| Saving run-time changes | Changes are in memory and lost when the engine stops |
| File and process state | Needed for FIM and process inventory |
| Registry change notification | Personalities poll `changes`; a push channel may come later |
| Response actions | Handled by the response recorders, not the engine (CLAUDE.md rule 7) |
