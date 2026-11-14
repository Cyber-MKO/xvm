# control

Control plane: CLI and API, host profiles, Habeny provider (Phase 4). See docs/BRIEF.md.

| Path | Contents |
| --- | --- |
| `xvm_control/` | `xvm-profile`, `xvm-host`, `xvm-check` and `xvm-mock-authd` tools, the host profile schema, the `.reg` parser and the golden capture converter |
| `profiles/bases/` | Base images built from golden captures |
| `profiles/examples/` | Illustrative base and host profile |

The format is described in [docs/host-profiles.md](../docs/host-profiles.md).

## Running hosts: `xvm-host`

`xvm-host` starts, stops, resets and watches emulated hosts. All state for a set of hosts lives in one run folder (`--root`, default `run/`).

```
xvm-host --bases control/profiles/bases up win-web-01 --hosts control/profiles/hosts --msi wazuh-agent-4.14.2-1.msi
xvm-host status
xvm-host down win-web-01
xvm-host reset win-web-01 --msi wazuh-agent-4.14.2-1.msi
xvm-host engine stop
```

| Command | Does |
| --- | --- |
| `up NAME... [--hosts DIR] [--msi FILE] [--corpus CAPTURE]` | Starts the engine if it is down (on freshly compiled profiles, with saved state), installs the MSI onto the host's drive once per MSI, fills a new host's event logs from the corpus, and starts the host's supervisor |
| `down NAME...` or `down --all` | SIGTERM to the supervisor, which passes it to the agent. A service stops through its own handler. After 30 s the agent is killed. |
| `reset NAME... [--msi FILE]` | For a stopped host: drops its run-time changes in the engine (`reset`), empties its drive and installs again. The next `up` fills its logs again. |
| `status [NAME...] [--json]` | The engine and each host: state, PID, starts, restarts, since when |
| `engine start`, `stop`, `restart` | The engine alone. `stop` refuses while hosts are up, unless `--force`. |

The profile folders (`--bases`, `--hosts`) are saved in the run folder on first use, so later commands need only `--root`.

A real host's logs hold history when an agent first reads them. With `--corpus`, a host's first start replays the capture's newest events (`evtx/rendered/LOG.xml`) into its logs: same spacing, rewritten to name the host (computer name, machine SID, process IDs), and shifted so the last event lands at the start time. `hosts/NAME/seeded.json` records that it ran; the replay log is `hosts/NAME/seed.jsonl`.

| Path in the run folder | Holds |
| --- | --- |
| `compiled/`, `state/` | Compiled profiles; the engine's saved state (`--state`) |
| `engine.sock`, `engine.pid`, `engine.json`, `engine.log`, `gaps.jsonl` | The engine daemon, its compiled-profile digest, its output and its gap log |
| `hosts/NAME/drive-c/` | The host's C: drive (`--drive C=...`) |
| `hosts/NAME/installed.json` | The installed MSI and its SHA-256 |
| `hosts/NAME/seeded.json`, `seed.jsonl` | The first-start log fill and its replay log |
| `hosts/NAME/supervisor.pid`, `status.json`, `host.log` | The supervisor, the host's state, the agent's output and installer gaps |

How hosts are supervised (`--supervisor`, saved in the run folder):

| Mode | How | When |
| --- | --- | --- |
| `systemd` | Each host's agent is a transient unit from `systemd-run` (`xvm-SITE-NAME.service`): no unit file and no process of ours per host. `Restart=on-failure`, backoff from 1 s to 60 s (systemd 254 and later), no start limit, SIGTERM then SIGKILL after 30 s, output appended to `host.log`. User manager, or the system manager as root. | `auto` picks it when systemd is the machine's init |
| `python` | One small Python supervisor per host, with the same restart and stop rules | Containers and machines without systemd |

| Host state | Meaning |
| --- | --- |
| `running` | The agent process runs |
| `restarting` | It exited with an error; the supervisor waits, then starts it again. The wait doubles from 1 s to 60 s while it keeps failing within a minute. |
| `exited` | It exited with code 0 on its own, as a stopped service does. Not restarted. |
| `stopped` | `down` stopped it |
| `dead` | The supervisor itself is gone without stopping the host |
| `failed` | The supervisor could not find `xvm-windows-run` |
| `down` | Never started in this run folder |

Binaries: `xvm-engined` from `target/release` or `target/debug`, and `xvm-windows-run` from `target/i686-unknown-linux-gnu/release` or `debug`. `XVM_ENGINED` and `XVM_RUNNER` override them. `ProgramFiles` for the installer comes from the profile's `agent.environment`.

The engine loads profiles when it starts. After changing a profile, run `xvm-host engine restart`; a changed profile discards that host's saved state (see `engine/README.md`, Persistence).

## Enrolling a host with a manager

The agent enrolls on its first start, when its `client.keys` is empty. It reads the manager's address from `ossec.conf`, which the installer step fills from the host profile's `agent.manager`.

### Against your Wazuh manager

1. Set `agent.manager` in the host profile (`control/profiles/hosts/xvm-win-01.yaml`) to the manager's address.
2. Check that this machine reaches the manager: `nc -vz MANAGER 1515` (enrollment) and `nc -vz MANAGER 1514` (events).
3. If the manager wants an enrollment password (`<use_password>yes</use_password>` in its `<auth>` block), put it in the host's drive at `Program Files (x86)/ossec-agent/authd.pass` after the install. The agent reads it on its own.
4. Start the host. A host installed with another manager needs a reset first, so that `ossec.conf` gets the new address:

```
xvm-host engine restart                       # after editing the profile
xvm-host down xvm-win-01
xvm-host reset xvm-win-01 --msi wazuh-agent-4.14.2-1.msi
xvm-host up xvm-win-01 --msi wazuh-agent-4.14.2-1.msi
```

5. Watch it enroll:

| Where | What success looks like |
| --- | --- |
| `run/hosts/xvm-win-01/drive-c/Program Files (x86)/ossec-agent/ossec.log` | `Requesting a key from server: MANAGER`, then `Valid key received` |
| The same folder, `client.keys` | One line: `ID XVM-WIN-01 any KEY` |
| On the manager: `/var/ossec/bin/agent_control -l` | `XVM-WIN-01`, Active once the agent connects on 1514 |
| `xvm-check t2 ...` (below) | Active within 10 minutes |

| Symptom in `ossec.log` | Cause |
| --- | --- |
| `Unable to connect to enrollment service at '[MANAGER]:1515'` | The manager is not reachable from this machine, or authd is off |
| `ERROR: Invalid password (from manager)` | `authd.pass` is missing or wrong |
| `ERROR: Agent version must be lower or equal to manager version` | The manager is older than 4.14.2 |
| `Duplicate agent name: XVM-WIN-01` | An agent with that name exists: remove it on the manager, or set `<force>` in its `<auth>` block |

### Against the mock: `xvm-mock-authd`

`xvm-mock-authd` answers enrollment requests the way `wazuh-authd` does, without a manager. It has no `wazuh-remoted`, so the agent's event connection on 1514 still fails after it enrolls.

```
xvm-mock-authd --listen 127.0.0.1:1515 --log run/authd.jsonl [--password-file FILE]
```

Set the profile's `agent.manager` to `127.0.0.1` and start the host as above. Each request is a JSON line in the log, with the key it issued.

`tests/control/test_enrollment_live.py` does all of this with the real MSI and checks that the agent stores the issued key. It runs when `XVM_WAZUH_MSI` names the MSI; the `Enrollment` workflow runs it on GitHub.

## Phase 1 checks: `xvm-check`

`xvm-check` runs T2 and T3 (docs/BRIEF.md section 11) against the Wazuh manager's REST API. The API password comes from `$WAZUH_API_PASSWORD` (`--password-env` names another variable), never from the command line. `--insecure` accepts the manager's default self-signed certificate; `--ca FILE` checks it instead.

```
export WAZUH_API_PASSWORD=...
xvm-check t2 --manager https://manager:55000 --insecure --agent WIN-WEB-01 --log run/t2.jsonl
xvm-check t3 --manager https://manager:55000 --insecure --profile control/profiles/examples/hosts/win-web-01.yaml
```

| Test | Pass condition | How |
| --- | --- | --- |
| T2 | Agent Active with no disconnects over 24 hours | Samples `GET /agents?name=NAME` every `--interval` (60 s). The agent must reach `active` within `--enroll-timeout` (10 min), then stay `active` for `--duration` (24 h) from that moment, with no keepalive older than `--max-keepalive` (120 s) and no gap between samples over three intervals. API errors are counted, not taken as disconnects. |
| T3 | Manager shows the OS name and version from the host profile | `os.name` contains `os_info.product_name`; `os.version` starts with `os_info.version` and `build` (such as `10.0.20348`); `os.platform` is the profile's `os`; the agent version is `agent.version` |

T2 writes every sample to `--log`; `--from-log` scores a recorded log again. Both commands exit 0 on a pass, 1 on a fail and 2 when they cannot run, and take `--json` for a result file. Agent fields follow Wazuh's public API reference. The first run against a real manager confirms them.
