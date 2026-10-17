# control

Control plane: CLI and API, host profiles, Habeny provider (Phase 4). See docs/BRIEF.md.

| Path | Contents |
| --- | --- |
| `xvm_control/` | `xvm-profile` and `xvm-host` tools, the host profile schema, the `.reg` parser and the golden capture converter |
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
| `up NAME... [--hosts DIR] [--msi FILE]` | Starts the engine if it is down (on freshly compiled profiles, with saved state), installs the MSI onto the host's drive once per MSI, and starts the host's supervisor |
| `down NAME...` or `down --all` | SIGTERM to the supervisor, which passes it to the agent. A service stops through its own handler. After 30 s the agent is killed. |
| `reset NAME... [--msi FILE]` | For a stopped host: drops its run-time changes in the engine (`reset`), empties its drive and installs again |
| `status [NAME...] [--json]` | The engine and each host: state, PID, starts, restarts, since when |
| `engine start`, `stop`, `restart` | The engine alone. `stop` refuses while hosts are up, unless `--force`. |

The profile folders (`--bases`, `--hosts`) are saved in the run folder on first use, so later commands need only `--root`.

| Path in the run folder | Holds |
| --- | --- |
| `compiled/`, `state/` | Compiled profiles; the engine's saved state (`--state`) |
| `engine.sock`, `engine.pid`, `engine.json`, `engine.log`, `gaps.jsonl` | The engine daemon, its compiled-profile digest, its output and its gap log |
| `hosts/NAME/drive-c/` | The host's C: drive (`--drive C=...`) |
| `hosts/NAME/installed.json` | The installed MSI and its SHA-256 |
| `hosts/NAME/supervisor.pid`, `status.json`, `host.log` | The supervisor, the host's state, the agent's output and installer gaps |

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
