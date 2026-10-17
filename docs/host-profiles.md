# Host profiles

A host profile describes one emulated host. It is a TOML file. Python reads it with `tomllib`; the Windows personality reads it with the `toml` crate (`personalities/windows/src/profile.rs`). Later the host-state engine serves the same data, and profiles become its input.

Profiles are where host facts live (CLAUDE.md rule 5). An example is in `control/profiles/example-windows.toml`.

## Schema 1

| Key | Type | Meaning |
| --- | --- | --- |
| `schema` | integer | Must be 1 |
| `host.name` | string | Host name |
| `host.os` | string | `windows`, `macos` or `linux` |
| `windows.drives` | table | Drive letter (one upper-case letter) to host directory. Relative directories are resolved against the profile file. |
| `windows.agent.command_line` | string | The agent process's full command line, as `GetCommandLine` returns it. Its program name picks the executable to load. |
| `windows.agent.pid` | integer | The agent's process ID: not 0 and a multiple of 4. `GetCurrentProcessId` and `_getpid` return it |
| `windows.agent.current_directory` | string | The agent's starting directory, as a Windows path |
| `windows.agent.service` | string, optional | The service the Service Control Manager started the agent as. Without it, `StartServiceCtrlDispatcherA` fails as it does for a console process. |
| `windows.cert_stores` | table, optional | System certificate store name (`ROOT`, `CA`, `MY`) to a list of DER certificate files, relative to the profile. Read and checked when the profile loads. Store names are compared ignoring case. |
| `windows.system_module_directory` | string, optional | The directory emulated system DLLs report as their location, such as `C:\Windows\SysWOW64` for a 32-bit process on 64-bit Windows |
| `windows.trusted_files` | table, optional | Windows path to the SHA-256 (64 hex digits) of a file whose signature is valid on this host. `WinVerifyTrust` answers from this list |
| `windows.environment` | table | The agent's environment variables. The runtime sorts them by name, ignoring case, as Windows keeps its environment block. |

Rules:

- Unknown keys are errors.
- Windows strings must be ASCII until code-page conversion exists (it comes with `GetACP`).
- `host.os` must be `windows` when a `windows` section is present.

## Windows paths

A Windows path maps to the host through the drive table. Existing components match without regard to case; new ones keep the agent's spelling. Supported forms are `C:\dir`, `\dir` (current drive) and `dir` (current directory), with either separator, plus the `\\?\` prefix. UNC and drive-relative (`C:file`) paths are refused.

## Running

```
cargo run --target i686-unknown-linux-gnu --bin xvm-windows-run -- PROFILE
```

The drive must already hold the agent's files. The MSI installer step will put them there.

SIGTERM or SIGINT stops the host. A service process gets `SERVICE_CONTROL_STOP` and stops through its own handler; any other process exits at once. A second signal always exits at once.
