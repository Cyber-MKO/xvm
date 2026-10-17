# Host profiles

Every host fact an emulated host reports comes from a host profile (CLAUDE.md rule 5). A profile is a YAML file validated against [the JSON Schema](../control/xvm_control/schema/host-profile.schema.json).

## Kinds

| Kind | Holds | Where |
| --- | --- | --- |
| `base-image` | Facts shared by many hosts: OS version, default users and services, registry | `control/profiles/bases/`, built from golden captures |
| `host-profile` | Only what differs for one host: identity, network, extra users and software | Anywhere; names its base with `base:` |
| `resolved-host` | The base with the profile applied. Produced by `xvm-profile resolve`, never written by hand | Output only |

Examples live in [control/profiles/examples/](../control/profiles/examples/). Their values are illustrative, not captured.

## Sections

| Section | Contents |
| --- | --- |
| `identity` | Host name, domain, machine ID |
| `os_info` | Product name, edition, version, build, UBR, display version, architecture, install date, locale, time zone |
| `hardware` | CPU, memory, system and BIOS details |
| `network` | Interfaces (MAC, IPv4, gateway, DNS) and DNS suffix |
| `users`, `groups` | Local accounts with SIDs (Windows) or UIDs and GIDs |
| `software` | Installed packages |
| `services` | Services with state and start mode |
| `registry` | Windows only. Keys under `HKLM`, `HKU` or `HKCR`, typed values |
| `files` | Files and directories: path, type, size, sha256, times, attributes (Windows), owner, mode (Unix), and `content` for bytes we author |
| `processes` | Processes running at boot: id, image, path, command line, user, session, parent (an id), optional pinned pid, `start_offset_s` after boot |
| `event_messages` | Windows only. Event message templates: provider name, then `"ID"` or `"ID/VERSION"`, then text with `%1`, `%2`... for the event's data values |
| `agent` | SIEM agent product, version, manager and group; how the agent is started (see below) |
| `windows` | Windows only. Settings that are neither registry values nor files (see below) |

## Merge rules

| Field | Rule |
| --- | --- |
| Scalars and objects | The profile value wins. Objects merge key by key. |
| `users`, `groups`, `software`, `services`, `network.interfaces` | Entries merge by `name`, ignoring case and keeping the base's spelling. `remove: true` deletes the base entry. Removing an entry the base lacks is an error. |
| `registry.keys` | Merge key by key, then value by value, ignoring case and keeping the base's spelling. A value of `null` deletes it. |
| `registry.delete_keys` | Deletes the key and all subkeys. Deleting a key the base lacks is an error. |

| `files` | Entries merge by path, in profile order. Windows and macOS paths ignore case; Linux paths do not. The base's spelling is kept. `remove: true` deletes the entry and, for a directory, everything below it. The result is sorted by the path's normal form. |
| `processes` | Entries merge by `id`. `remove: true` deletes the base entry. Every `parent` must name a process that remains. |

A base image may not use `remove`, `null` values or `delete_keys`.

## File content

| Form | Meaning |
| --- | --- |
| `content: {text: ...}` | UTF-8 text we author |
| `content: {base64: ...}` | Bytes we author |
| No `content` | Metadata only, for example a vendor file from a golden capture |

`xvm-profile compile` moves content into the blob store (`blobs/SHA256`), stores identical bytes once, and fills in `size` and `sha256`. A declared `size` or `sha256` that does not match the content is an error. Never put vendor bytes in a profile (CLAUDE.md rule 1).

Process owners written as `.\user` name a local account on the host itself, whatever the host is called.

## Agent launch settings

The personality starts the agent from these `agent` fields and registers it with the engine under `pid` (`proc.start`).

| Field | Meaning |
| --- | --- |
| `pid` | The agent's process ID. On Windows a non-zero multiple of 4. `GetCurrentProcessId` returns it. |
| `command_line` | The full command line, as `GetCommandLine` returns it. Its program name picks the executable. |
| `current_directory` | The starting directory |
| `service` | Windows: the service the Service Control Manager starts the agent as. Without it, the agent runs as a console process. |
| `environment` | Environment variables. Windows sorts them by name, ignoring case. Merges key by key. |

## The `windows` section

| Field | Meaning |
| --- | --- |
| `system_module_directory` | Where emulated system DLLs report they were loaded from, such as `C:\Windows\SysWOW64` for a 32-bit process on 64-bit Windows |
| `cert_stores` | System store name (`ROOT`, `CA`, `MY`) to a list of `{name, der}`, with `der` the certificate in base64. A host's list replaces the base's for that store. |
| `trusted_files` | Windows path to the SHA-256 of a file whose signature is valid on this host. `WinVerifyTrust` answers from it. Merges path by path. |

## Facts read from the registry

Windows keeps these in the registry, so the profile does too. The capture kit exports the keys, and the personality reads them through the engine.

| Fact | Key | Values |
| --- | --- | --- |
| Time zone rules | `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | `Bias`, `StandardBias`, `DaylightBias` (signed minutes stored as `REG_DWORD`; UTC = local + bias), `StandardStart`, `DaylightStart` (16-byte `SYSTEMTIME`), `TimeZoneKeyName`, `DynamicDaylightTimeDisabled` |
| Time zone names | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\KEY` | `Std`, `Dlt`. `StandardName` in `TimeZoneInformation` is often a resource reference (`@tzres.dll,-NNN`), so the names come from here. |
| Code pages | `HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage` | `ACP` (ANSI), `OEMCP` (OEM), as `REG_SZ` |
| Product type | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `InstallationType` (`Server`, `Client`) |

Where the agent's files live on the real disk (the drive mapping) is not part of the profile. It is a launch setting, so a profile describes the emulated host on any machine.

## Registry values

| Type | `data` |
| --- | --- |
| `REG_SZ`, `REG_EXPAND_SZ` | String |
| `REG_MULTI_SZ` | List of strings |
| `REG_DWORD` | Integer, 0 to 4294967295 |
| `REG_QWORD` | Integer, 0 to 2^64 - 1 |
| `REG_BINARY` | Lowercase hex string |

## Commands

| Task | Command |
| --- | --- |
| Validate files | `xvm-profile validate FILE... [--bases DIR]` |
| Print the resolved host | `xvm-profile resolve FILE [--bases DIR] [--format yaml\|json]` |

| Compile for the engine | `xvm-profile compile --bases DIR --hosts DIR --out DIR` |

`--bases` defaults to `control/profiles/bases` and can be repeated.

`compile` validates every file, checks that each host resolves, and writes `compiled.json`, `bases/NAME.json` and `hosts/NAME.json`. Hosts stay unmerged: the engine layers them over their base. See [engine/README.md](../engine/README.md).

Quote timestamps in YAML, for example `"2026-01-01T00:00:00Z"`. Unquoted timestamps are rejected, so every reader sees the same text.

## Building a base from a golden capture

`xvm-profile base-from-golden CAPTURE --name NAME [--out FILE]` writes `control/profiles/bases/NAME.yaml`. It refuses a capture that fails `xvm-golden verify`. Notes on skipped data go to standard error.

| Base section | Source in the capture |
| --- | --- |
| `os_info` | `host/os.json`, `host/locale.json`, the `CurrentVersion` registry key |
| `hardware` | `host/cpu.json`, `computer.json`, `bios.json` |
| `network.interfaces` | `host/netadapters.json` and `network.json`: names, descriptions, DHCP only |
| `users`, `groups` | `host/users.json`, `groups.json`, `group-members.json` (local members only) |
| `software` | `registry/uninstall.reg` (x86_64) and `uninstall-wow64.reg` (x86), entries with a `DisplayName` that are not system components |
| `files` | `host/files.json`: metadata and SHA-256 of the folders the agent's FIM configuration watches, the hosts file folder and the top of the Windows folder. No bytes. |
| `processes` | `host/processes.json`, with start offsets from the boot time. System Idle and System keep PIDs 0 and 4; the engine assigns the rest. |
| `event_messages` | `evtx/rendered/*.xml` and `evtx/scenario/*.rendered.xml`: each event's data values and the message Windows rendered, turned into templates. A template is kept only if it reproduces another event of the same provider, ID and version exactly (or is the only one). See `control/xvm_control/evtmsg.py`. |
| `services` | `host/services.json` |
| `registry.keys` | The identity exports: CurrentVersion, ComputerName, TCP/IP parameters, ProfileList, time zone, Event Log |

These facts identify one machine, so the base leaves them out and each host profile supplies them:

| Left out | Where it comes from instead |
| --- | --- |
| Host name and domain, including the registry values that hold them | `identity` and `registry` in the host profile |
| MAC and IP addresses, gateway, DNS servers, per-interface TCP/IP keys | `network.interfaces` in the host profile |
| BIOS and system serial numbers | `hardware` in the host profile |
| The `WazuhSvc` service and the Wazuh Agent package | Our installer step, from `agent` in the host profile |
| The scenario test user `xvmgolden` | Deleted during the capture |
| The capture's PowerShell process tree, and the Wazuh agent's processes | Not part of the OS at boot; the personality registers the agent |
| The boot time | The host profile's `os_info.last_boot`, or the engine's clock |
| The VM's name in process owners | Written as `.\user` |

The `.reg` parser follows Microsoft's public description of the format. It reads `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD` and `REG_BINARY`. Any other type, and keys under `HKEY_CURRENT_USER`, are reported as skipped.

## Loader profile (TOML, stopgap)

The Windows loader (`xvm-windows-run`) still reads its own TOML file (`personalities/windows/src/profile.rs`; example `control/profiles/example-windows.toml`). Kasim decided (2026-10-17) that its settings move to the YAML profile, served by the engine:

| TOML key | Moves to |
| --- | --- |
| `host.name`, `host.os` | `identity.hostname`, `os` |
| `windows.agent.*`, `windows.environment` | `agent.pid`, `command_line`, `current_directory`, `service`, `environment` |
| `windows.system_module_directory`, `cert_stores`, `trusted_files` | The `windows` section (certificates inline as base64 DER) |
| `windows.time_zone` | Registry: `TimeZoneInformation` and `Time Zones\KEY` |
| `windows.ansi_code_page`, `oem_code_page` | Registry: `Nls\CodePage` |
| `windows.drives` | A launch setting, not part of the profile |

The TOML file goes once the loader reads these from the engine. Until then its format is:

### Schema 1

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
| `windows.time_zone` | table | What `GetTimeZoneInformation` returns: `key_name`, `standard_name`, `daylight_name` (31 characters at most), `bias`, `standard_bias`, `daylight_bias` (minutes; UTC = local + bias), and optionally `standard_date` and `daylight_date` as `{ month, day_of_week, week, hour, minute, second }` (week 5 is the last). Local time follows these rules |
| `windows.ansi_code_page` | integer | The ANSI code page (`CP_ACP`, `CP_THREAD_ACP`). Must be one we have a table for: 1252 |
| `windows.oem_code_page` | integer | The OEM code page (`CP_OEMCP`). Must be one we have a table for: 437 |
| `windows.environment` | table | The agent's environment variables. The runtime sorts them by name, ignoring case, as Windows keeps its environment block. |

Rules:

- Unknown keys are errors.
- Windows strings must be ASCII for now: the functions that return them do not convert them to the ANSI code page yet.
- `host.os` must be `windows` when a `windows` section is present.

### Windows paths

A Windows path maps to the host through the drive table. Existing components match without regard to case; new ones keep the agent's spelling. Supported forms are `C:\dir`, `\dir` (current drive) and `dir` (current directory), with either separator, plus the `\\?\` prefix. UNC and drive-relative (`C:file`) paths are refused.

### Running

```
cargo run --target i686-unknown-linux-gnu --bin xvm-windows-run -- [--engine SOCKET --host NAME] PROFILE
```

With `--engine` and `--host`, host facts (such as the OS version) come from `xvm-engined` on that socket, for that host. Without them, functions that need host facts fail and log a gap.

The drive must already hold the agent's files. The MSI installer step will put them there.

SIGTERM or SIGINT stops the host. A service process gets `SERVICE_CONTROL_STOP` and stops through its own handler; any other process exits at once. A second signal always exits at once.
