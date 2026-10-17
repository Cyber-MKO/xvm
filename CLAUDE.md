# CLAUDE.md

## Project

A container-like platform that runs many lightweight emulated hosts (Windows, macOS, Linux) on one shared Linux kernel. Unmodified SIEM agents run inside each host and see a believable OS. Built standalone, with Habeny (github.com/Cyber-MKO/Habeny) as the primary consumer.

**Read `docs/BRIEF.md` before any design or implementation work.** It holds the requirements, decisions, architecture, roadmap and tests.

## Hard rules

1. **No Wine, Darling or ReactOS.** Do not use, vendor, link or copy code from them. Do not copy code from Microsoft or Apple binaries. Implement clean-room from public documentation (Microsoft Learn, Apple developer docs, published file-format specs). Apple's open-source Darwin releases may be used only after checking license compatibility, and only with a note in `docs/LICENSES.md`.
2. **Never modify an agent.** Agents run as shipped. If an agent fails, the fix goes in the personality runtime or the state engine.
3. **Implement only what the API census shows.** Every new emulated API needs: an entry in the census report showing which agent calls it, a test, and a doc line in the personality's API table.
4. **Log every gap.** Unimplemented imports, `GetProcAddress` lookups, syscalls and commands are logged with the calling agent, never silently stubbed.
5. **No hardcoded host facts.** OS identity, registry values, files, users, packages and network data come from the host-state engine and host profiles.
6. **No GUI subsystems** in any personality.
7. **Response actions never touch the real machine.** Response commands and APIs record the call and arguments only.
8. **Documentation style:** no em-dashes; short sentences; tables for comparisons.

## Stack (decided 2026-10-16)

- Rust for loaders and personality runtimes. The Windows personality builds for `i686-unknown-linux-gnu`, because Wazuh's Windows binaries are 32-bit.
- Python for the API census tool, control plane, scenario engine and test harness.
- Phase 1 decisions (target version, CRT, `user32` subset) are in `docs/phase1-sizing.md`.

## Repo layout

```
docs/            BRIEF.md, architecture notes, API tables per personality
census/          API census tool and generated reports
engine/          host-state engine (Rust): base images, per-host deltas, run-time state
personalities/
  windows/       PE loader, NT and Win32 subset, registry, Event Log, services
  macos/         Mach-O loader, libSystem subset, sysctl, log command
  linux/         namespaces, FUSE views, seccomp notify
scenarios/       scenario engine, golden corpora
response/        response recorders
external/        agentless sources (syslog, WEF, cloud API fakes)
control/         CLI and API, host profiles, Habeny provider
tests/           T1 to T8, fidelity, resource and calibration harnesses
```

## Status (2026-10-17)

### Phase 0 (Foundations): one exit item open

| Item | State |
| --- | --- |
| Repo, CI, lint, tests | Done |
| API census tool (`census/`) | Done |
| Wazuh Windows census | Done: 4.14.2 (the target) and 4.14.9, in `census/reports/` |
| Golden baseline | **Open.** Kasim runs the kit in `scenarios/golden/windows/` on a Windows evaluation VM |

### Phase 1 (Windows personality, first boot): in progress

Kasim reviewed the census, accepted the four decisions in `docs/phase1-sizing.md`, and asked for the PE loader to start (2026-10-16).

| Decision | Detail |
| --- | --- |
| Target | Wazuh agent 4.14.2, PE32 i386 |
| Runtime | The Windows personality is a 32-bit Linux process (`i686-unknown-linux-gnu`) |
| CRT | We provide `msvcrt.dll` on top of host libc, function by function from the census |
| `user32` | Only the census functions, no window system |

Phase 1 work lives in `personalities/windows/`. The exit check is in `docs/BRIEF.md` section 10.

Loader status:

| Part | Status |
| --- | --- |
| PE32 i386 header and section parsing | Done |
| Layout, base relocations, exports, TLS directory | Done |
| Import binding with gap records | Done |
| Mapping into a 32-bit process and running code | Done |
| TEB, `fs` segment, implicit TLS, TLS callbacks | Done (fields in `docs/api/windows.md`) |
| Module table: dependency order, bundled DLLs from the agent directory, forwarders | Done (`process.rs`) |
| Emulated module layer: in-memory PE images with thunks, call-time gap traps | Done (`emu.rs`, `trap.rs`). Calls pass through a trampoline that realigns the stack to 16 bytes |
| Start-up: TLS callbacks, `DllMain`, entry point (`runtime.rs`, `xvm-windows-run`) | Done |
| Host profiles, Windows path mapping, command line and environment (`profile.rs`, `paths.rs`, `cmdline.rs`) | Done. Example: `control/profiles/example-windows.toml`. TOML is a stopgap for loader-only settings until the profile decision; host facts move to the engine |
| Windows threads with attach and detach notifications (`Runtime::spawn`) | Done, with `CreateThread` |
| Service Control Manager, service side (`win/advapi32/service.rs`) | Done. SIGTERM stops a service |
| Certificate stores from the profile, X.509 reader (`x509.rs`, `win/crypt32`) | Done |
| Signature verdicts from the profile, SHA-256 (`sha256.rs`, `win/wintrust`) | Done |
| Kernel handle table, file I/O (`handles.rs`, `win/kernel32/file.rs`) | Started: open, read, close |
| C streams (`win/msvcrt/stdio.rs`) | Started: `_fdopen`, reading, buffered writing, `fflush`, `fclose`, standard streams in `_iob` |
| `LoadLibrary`, `FreeLibrary`, DLL load notifications | Done. Late-loaded DLLs get no TLS slot on existing threads (logged gap) |
| Waitable objects (`sync.rs`): events, threads, semaphores, mutexes; dynamic TLS slots | Done |
| Image page map, `VirtualQuery`, `VirtualProtect` (`memory.rs`) | Done for image pages |
| Emulated functions | 163 of 617 plus `ntdll!LdrRegisterDllNotification`, and 2 data exports. Table in `docs/api/windows.md` |
| `wazuh-agent.exe` start-up | Installed by `xvm-msi-install`, it runs as `WazuhSvc`, registers its PID, logs "Started" and the OS identity from the engine, reads the registry, sets up file integrity monitoring and starts log collection. Next gap: the Event Log API (`wevtapi!EvtSubscribe`) |
| Exception dispatch (signals and `RaiseException` to handlers) | Not started. Handlers are only registered |
| TLS slots for DLLs loaded after a thread started | Not started. Wazuh's late DLLs have only MinGW's 4-byte TLS placeholder |
| `GetModuleHandle`, `GetProcAddress` | Done |
| Host facts from the engine (`win/facts.rs`; `xvm-windows-run --engine SOCKET --host NAME`) | Started: `os_info` and the registry (open, query, close) |
| The agent in the engine's process list (`registration.rs`) | Done: `proc.start` with the profile's PID and the real PID, parent `services.exe` for a service; `proc.exit` on every exit path |
| MSI installer step (`installer/xvm_msi`, `xvm-msi-install`) | Done: folders, files and components from the MSI tables, AppSearch registry searches, conditions from the host profile, `WAZUH_MANAGER` and enrollment properties in `ossec.conf`. Custom actions, registry, services, shortcuts and permissions are reported as gaps |

Build and test the loader for both targets: `cargo test` and `cargo test --target i686-unknown-linux-gnu`. The i686 run needs `gcc-multilib`. Fixtures are built from source with clang, lld-link and llvm-dlltool.

### Built so far

| Component | Where | Notes |
| --- | --- | --- |
| Host profiles | `control/`, `docs/host-profiles.md` | YAML base images plus per-host deltas; `xvm-profile validate`, `resolve`, `compile`, `base-from-golden` |
| Host-state engine | `engine/`, `engine/README.md` | Registry, sections, lists, files, processes, Windows event logs (query subset, XML, message templates); run-time changes with a change journal; persistence with `--state`. Personalities connect with `xvm_engine::client::Client`. |
| Golden capture kit | `scenarios/golden/windows/` | `capture.ps1`, `manager-capture.sh`, `xvm-golden` |
| Scenario runner | `scenarios/xvm_scenario/`, `scenarios/README.md` | `xvm-scenario validate`, `run`, `replay`, `diff-events`; YAML steps with named actions, a seeded clock per host, JSON Lines run log; golden corpus replay with identity rewriting; event-layout diff against the capture; `library/golden-windows.yaml` mirrors the capture |
| Manager-side checks | `scenarios/xvm_golden/fidelity.py` | `xvm-golden diff-manager` (fidelity test, T6) and `delivery` (T5) on the manager's `archives.json` and `alerts.json` |

Every host fact a personality reports must come from the engine (rule 5). Every write it makes goes through the engine's ops.

## Working style

- Small, test-backed steps; each roadmap phase ends with its exit check from `docs/BRIEF.md`.
- When a design choice is not covered by the brief, list the options and ask Kasim before building.
- Keep `docs/BRIEF.md` current: record new decisions in its Decisions table.
