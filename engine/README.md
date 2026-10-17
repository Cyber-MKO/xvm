# engine

The host-state engine (brief section 6, component 1). One process serves the facts of every emulated host: identity, OS, hardware, network, users, groups, software, services, the Windows registry, files, processes and Windows event logs. Personality runtimes ask it instead of hardcoding anything (CLAUDE.md rule 5).

## How it fits

| Step | Tool | Output |
| --- | --- | --- |
| 1 | `xvm-profile compile --bases DIR --hosts DIR --out DIR` | Validated JSON: `compiled.json`, `bases/*.json`, `hosts/*.json` |
| 2 | `xvm-engined --compiled DIR --socket PATH [--gap-log FILE] [--state DIR]` | A daemon on a Unix socket. With `--state`, run-time changes survive restarts. |
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
| Sections | `identity`, `os_info`, `hardware`, `network`, `agent`, `windows`. Objects merge key by key. |
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
| `file.stat` | `path` | Metadata: `path`, `type`, `size`, `sha256`, times, `attributes`, `owner`, `mode`, `has_content`. Implied directories add `implied: true`. |
| `file.list` | `path` | Array of the children's metadata, sorted by normal form |
| `file.read` | `path`, optional `offset`, `length` (at most 4 MiB) | `{data (base64), eof}` |
| `evt.channels` | none | Every channel the registry declares: `name`, `events`, `oldest_record_id`, `newest_record_id`, `bytes`, `max_size`, `max_size_from_registry` |
| `evt.query` | `channel`, optional `query` (default `*`), `after` (record ID, default 0), `limit` (1 to 1000, default 100), `format` (`xml` or `json`) | `{events, more, last_record_id}`. With `xml`, each event is `{record_id, xml}`. |
| `evt.get` | `channel`, `record_id` | The event as JSON, with `xml` |
| `evt.format_message` | `channel`, `record_id` | `{message, source}`: the event's own `message`, or the host's template filled in |
| `proc.list` | none | Running processes: `pid`, `ppid`, `image`, `path`, `command_line`, `user`, `session`, `start_time`, `profile_id` or `native_pid` |
| `proc.get` | `pid` | One running process |
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
| `file.write` | `path`, `data` (base64), optional `append` or `offset` | Without either, replaces the file. The parent must exist. A new file gets `created`, and on Windows the `archive` attribute. Read-only files refuse. |
| `file.mkdir` | `path` | Fails with `exists` if the path exists, `not_found` if the parent does not |
| `file.delete` | `path`, optional `recursive` | A non-empty directory needs `recursive` (`not_empty`) |
| `file.rename` | `from`, `to` | Moves a file or a whole directory. `to` must not exist. |
| `file.set` | `path`, `patch` | Changes `attributes` (Windows), `created`, `modified`, `accessed`, `owner` or `mode` |
| `proc.start` | `image`, optional `pid`, `path`, `command_line`, `user`, `session`, `parent_pid`, `native_pid` | The new process. Without `pid`, the engine assigns one. A requested `pid` must be free (`exists` otherwise) and valid for the OS (`bad_request` otherwise): on Windows a non-zero multiple of 4 below 65536. |
| `proc.exit` | `pid`, optional `exit_code` | Ends the process. Its children keep running with their old `ppid`, as on Windows. |
| `evt.write` | `channel`, `event`, optional `time` | Adds an event; returns `{record_id, channel}`. Not part of the change journal: readers follow `last_record_id`. |
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
| `exists` | `file.mkdir` or `file.rename` onto a path that exists |
| `not_empty` | `file.delete` without `recursive` on a non-empty directory |
| `is_directory` | Reading or writing a directory as a file |
| `not_a_directory` | Listing a file, or creating a path below a file |
| `access_denied` | Writing a read-only file |
| `bad_query` | `evt.query` with a form the engine does not support. Also written to the gap log. |
| `no_message` | `evt.format_message` without a message or a usable template. Also written to the gap log. |
| `no_content` | Reading or appending to a file whose bytes were never captured. Also written to the gap log. |
| `unsupported` | The op is not implemented. Also written to the gap log with the host and agent (rule 4). |

## Files

| Behaviour | Detail |
| --- | --- |
| Paths | Absolute. Windows paths take `\` or `/` and match without regard to case; macOS paths also ignore case; Linux paths are case-sensitive. The base's spelling is kept. |
| Directories | A directory exists if it is listed or anything below it is. The root (a drive, or `/`) exists once anything is listed under it. A directory implied only by its contents stays when they are deleted or moved, as on a real file system. |
| Bytes | Profile files share one copy per distinct content, from the blob store that `xvm-profile compile` writes (`blobs/SHA256`). Each blob is checked against its name at load. A host's first write copies the file into its run-time layer. |
| Vendor files | Files from a golden capture carry metadata and the captured SHA-256, never bytes (CLAUDE.md rule 1). `file.stat` reports `has_content: false`; reading them fails with `no_content` and is logged as a gap. |
| Hashes | `file.stat` reports the captured `sha256`, or computes it from the bytes. |

## Event logs

| Behaviour | Detail |
| --- | --- |
| Channels | The ones the host's registry declares: classic logs under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\NAME`, modern channels under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NAME`. Names ignore case. Writing to an undeclared channel is `not_found`. |
| Size | Each channel's limit is its key's `MaxSize`. Without one, the documented Windows default of 20480 KB, flagged as `max_size_from_registry: false`. An event counts as its stored JSON length. |
| Retention | When full, the oldest events are dropped and record IDs keep counting: Windows' "overwrite events as needed". A reader whose position fell out of the log continues at the oldest kept event. |
| Events | `provider` and `event_id` are required. Optional: `provider_guid`, `event_source`, `qualifiers`, `version`, `level`, `task`, `opcode`, `keywords` (hex text), `time`, `process_id`, `thread_id`, `user_id`, `data` (a list of `{name, value}` or an object), `message`. The engine adds `record_id`, `channel` and `computer` (the profile's host name, with its domain when the host is in one). |
| XML | Rendered in the Windows event schema, as `EvtRender` returns it, with `TimeCreated` to seven fractional digits |
| Queries | The XPath subset subscribers use, as a bare expression or a `QueryList`. See `src/evtquery.rs` for the supported forms. Anything else is `bad_query`. |
| Messages | An event's own `message` (golden corpus replay) wins. Otherwise the host's `event_messages` template for `ID/VERSION`, then `ID`, filled with the data values (`%1`, `%2`...). No template is `no_message`. |
| Subscriptions | Personalities poll: `evt.query` with `after` set to the last record ID they delivered. A blocking wait op is planned before scale tests (Phase 4). |
| Bookmarks | Not stored by the engine. A bookmark is a channel and record ID, which the personality renders for `EvtCreateBookmark` and `EvtRender`; Wazuh saves it itself. |
| Persistence | Per-channel segment files under `hosts/NAME/events/` in the state folder, outside the change log and snapshots. See Persistence. |
| `reset` | Empties every channel; record IDs start again at 1. |

## Processes

| Behaviour | Detail |
| --- | --- |
| Boot table | The profile's `processes` run from boot. Each starts at `os_info.last_boot` plus its `start_offset_s`. Without `last_boot`, a host boots when the engine loads it. |
| PIDs | Assigned by the engine, deterministic per host name, so a host gets the same PIDs every start and hosts differ from each other. Windows PIDs are multiples of 4 from 8 up; Linux and macOS PIDs count up from 1. A profile may pin a PID, for example System at 4, and `proc.start` may request one, as the loader does for the agent. A PID is not reused while unused ones remain; the generator never hands out a requested PID. |
| Run time | Personalities register the agent's real processes with `proc.start`, giving `native_pid`. Scenarios start and end processes the same way. Both go into the change journal. |
| `reset` | Restores the boot table with the same PIDs. |
| `resolved` | Shows the profile's process definitions. The running table is `proc.list`. |

## Persistence

With `--state DIR`, every run-time change is saved and restored on the next start.

| Path in the state folder | Holds |
| --- | --- |
| `hosts/NAME/snapshot.json` | The host's run-time layer, the profile digest it was made against, and the journal |
| `hosts/NAME/log.jsonl` | One line per change since that snapshot: the op and its parameters, with the time filled in |
| `blobs/SHA256` | Bytes of files written at run time, stored once. The log names the blob, not the bytes. |
| `discarded/NAME-TIME/` | A host's state moved aside after its profile or base changed |

| Behaviour | Detail |
| --- | --- |
| Writing | A change is applied, then appended to its host's log under the same lock, so the log order is the order of changes. A change that is rejected is not logged. |
| Durability | A flusher thread fsyncs new blobs, then the logs that name them, every `--flush-ms` (default 200). A power loss can drop the last batch. If saving fails, the request answers `not_saved` and the daemon prints the error. |
| Snapshots | After `--snapshot-every` changes (default 1000), the host gets a new snapshot and its log is emptied. Lines still buffered are discarded, not written into the new log. |
| Start | Each host's snapshot is loaded and its log replayed through the same code the server uses, so a replayed change takes the path the original did. Then the host is compacted: a new snapshot, an empty log. The socket opens only after every host is restored. |
| Damage | A torn last line, a missing blob, or a change that no longer applies ends the replay at that line, keeping everything before it. The daemon prints a warning naming the host and the line. |
| Profile drift | A snapshot records a digest of the host's compiled profile and base. If either changed, the saved changes were made against a different host: the state moves to `discarded/` and the host starts from its new profile, with a warning. |
| Other | PID allocation and the change journal are part of the snapshot, so PIDs and `seq` numbers continue where they stopped. State for a host that is no longer loaded is kept and reported. |

## Tests

| Test | Checks |
| --- | --- |
| `tests/vectors.rs` | The layered view equals `xvm-profile resolve` on every case in `tests/vectors/`, including value and list order |
| `tests/server.rs` | Socket round trips, errors, `hello` first, gap logging |
| `tests/runtime.rs` | Every write op, rejected writes, the journal and lost entries, reset, hosts on one base staying separate, eight concurrent writers, implied parent keys surviving their last subkey |
| `tests/eventlog.rs` | Channels from the registry, writing and XML, queries and paging (including Wazuh's default Security query), templates and per-event messages, gaps, retention, restart and reset, torn segment lines, old segments deleted |
| `tests/persist.rs` | A restart through log replay and through snapshots gives the same observable host, PIDs continue, blobs stored once, rejected writes not logged, torn lines, missing blobs, profile drift, reset saved |
| `tests/files_procs.rs` | Profile files and removals, listings and implied directories, every file op and error, vendor reads logged as gaps, Linux case rules, blobs shared between hosts and refused when tampered, the boot process table, PID rules, requested PIDs, start and exit |
| CI | The same tests as a 32-bit (i686) build, since the Windows personality links the client |

The vectors are generated by `tests/control/test_vectors.py`. After changing a case, run `XVM_UPDATE_VECTORS=1 pytest tests/control/test_vectors.py`.

Not yet:

| Missing | Notes |
| --- | --- |
| Directory change notification | Personalities poll `changes` for file events, as for the registry |
| Registry change notification | Personalities poll `changes`; a push channel may come later |
| Response actions | Handled by the response recorders, not the engine (CLAUDE.md rule 7) |
