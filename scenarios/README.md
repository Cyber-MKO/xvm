# scenarios

Scenario engine and golden corpora. See docs/BRIEF.md.

| Path | Contents |
| --- | --- |
| `golden/windows/` | Capture kit for the Windows golden baseline (Phase 0) |
| `xvm_golden/` | `xvm-golden` tool: verify a baseline, import manager events |
| `xvm_scenario/` | `xvm-scenario` tool: check scenarios and play them on emulated hosts |
| `library/` | Ready-made scenarios |

## Scenario runner

A scenario is a YAML list of steps. Each step names an action and when it happens. The runner plays it on one or more hosts served by `xvm-engined`. An action changes the host's state in the engine and writes the events the real operation writes, so the agent sees both.

```yaml
schema: 1
kind: scenario
name: new-admin
os: windows
defaults:
  actor: Administrator
steps:
  - {at: 0s, action: user.create, params: {name: eve}}
  - {at: 30s, action: group.add, params: {user: eve, group: Administrators}}
  - {at: 2m, action: logon.failed, params: {user: eve, count: 5, ip_address: 192.0.2.9}}
```

| Field | Meaning |
| --- | --- |
| `at` | Offset from the scenario start: `500ms`, `5s`, `2m`, `1h`, or seconds. Steps may not go back in time. |
| `action` | A named action, below |
| `params` | The action's parameters. Unknown or missing ones fail the check. |
| `name` | Optional label for the run log |
| `defaults.actor` | Account the steps act as (the Subject fields of Security events). A step may set its own `actor`. |

The schema is `xvm_scenario/schema/scenario.schema.json`.

### Commands

| Command | Does |
| --- | --- |
| `xvm-scenario validate FILE...` | Checks files against the schema and each action's parameters |
| `xvm-scenario run FILE --socket S --host H [--host H2...]` | Plays the scenario |
| `xvm-scenario run FILE --host H --dry-run` | Prints the timeline only |
| `xvm-scenario actions` | Lists the actions and their parameters |

| `run` option | Default | Meaning |
| --- | --- | --- |
| `--start` | now | Scenario start, RFC 3339 |
| `--speed` | 1 | 1 is real time; 10 is ten times faster; 0 runs without waiting |
| `--seed` | scenario name | Seed for skew and jitter |
| `--max-skew` | 0s | Largest fixed clock offset per host |
| `--jitter` | 0s | Largest extra delay per step |
| `--log` | none | Appends the run log here |
| `--stop-on-error` | off | Stops at the first failed step |

### Time

Each host has its own clock: a fixed skew in `[-max-skew, +max-skew]` and a per-step jitter in `[0, jitter]`. Both come from a hash of the seed and host name, so a run is repeatable and a fleet does not act in lockstep. A host's own steps keep their order. Steps run across hosts in the order of their host times. Every engine write carries that time, so events and journal entries show it. Events from one step are 1 ms apart.

### Actions (Windows)

| Action | State change | Events |
| --- | --- | --- |
| `marker` | none | Application (or `log`) event `event_id` from `source`, as `eventcreate` writes it |
| `user.create` | Adds the user. The SID is the machine prefix of the host's local accounts plus the next RID from 1000. | Security 4720, 4722 (if enabled), 4724, 4738; 4732 per `groups` entry |
| `user.delete` | Removes the user | Security 4726 |
| `group.add`, `group.remove` | Changes the user's `groups`. `group` is a name or SID. | Security 4732, 4733 |
| `logon.failed` | none | Security 4625, `count` times. Defaults: status 0xc000006d, sub-status 0xc000006a, type 3. |
| `logon.success` | none | Security 4624 v2, `count` times, each with its own logon ID |
| `service.stop`, `service.start`, `service.restart` | Service state | System 7036 with the display name |
| `file.write`, `file.append`, `file.delete`, `file.mkdir`, `file.rename` | Files | none: the agent's FIM sees the change |
| `process.start`, `process.exit` | Process table | none: process auditing is off by default |
| `registry.set`, `registry.delete_value`, `registry.delete_key` | Registry | none |
| `event` | none | Any event, as given |

Event layouts are in `xvm_scenario/events/windows.yaml`. Field names and order follow the public Microsoft Learn event reference. Every value comes from the host's state in the engine or from the step (CLAUDE.md rule 5): SIDs, the computer name, display names, and the `process_id` of `lsass.exe` or `services.exe` from the engine's process table. The golden capture is the authority: the fidelity diff checks these layouts against what Windows wrote.

### Run log

One JSON object per line:

| `record` | Holds |
| --- | --- |
| `start` | Scenario, start time, seed, each host's skew |
| `call` | One engine write: host, step, op, parameters, and the result or error. Reads are left out. |
| `gap` | Something a step needed and the host lacked, such as no `lsass.exe` for `process_id` (CLAUDE.md rule 4) |
| `step` | Host, step, action, host time, `ok`, and the error if it failed |
| `end` | Failed steps and gaps |

A failed step does not stop the run unless `--stop-on-error` is set. `run` exits 1 if any step failed.

### Library

| Scenario | Mirrors |
| --- | --- |
| `library/golden-windows.yaml` | The golden capture's scenario in `golden/windows/capture.ps1`, step for step |

### Not yet

| Missing | Notes |
| --- | --- |
| macOS and Linux actions | The format takes `os: linux` and `os: macos`; there are no actions for them yet |
| RID history | A deleted account's RID can be reused, since the engine keeps no record of it. Windows never reuses one. |
| Per-host steps | Every step runs on every host |
| Fidelity diff | Comparing a run with the golden capture is a later step (T5) |
