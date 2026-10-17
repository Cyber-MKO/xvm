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

### Phase 1 (Windows personality): may start

Kasim reviewed the census, accepted the four decisions in `docs/phase1-sizing.md`, and asked for the PE loader to start (2026-10-16).

| Decision | Detail |
| --- | --- |
| Target | Wazuh agent 4.14.2, PE32 i386 |
| Runtime | The Windows personality is a 32-bit Linux process (`i686-unknown-linux-gnu`) |
| CRT | We provide `msvcrt.dll` on top of host libc, function by function from the census |
| `user32` | Only the census functions, no window system |

### Built so far

| Component | Where | Notes |
| --- | --- | --- |
| Host profiles | `control/`, `docs/host-profiles.md` | YAML base images plus per-host deltas; `xvm-profile validate`, `resolve`, `compile`, `base-from-golden` |
| Host-state engine | `engine/`, `engine/README.md` | Registry, sections, lists, files, processes; run-time changes with a change journal; persistence with `--state`. Personalities connect with `xvm_engine::client::Client`. |
| Golden capture kit | `scenarios/golden/windows/` | `capture.ps1`, `manager-capture.sh`, `xvm-golden` |

Every host fact a personality reports must come from the engine (rule 5). Every write it makes goes through the engine's ops.

## Working style

- Small, test-backed steps; each roadmap phase ends with its exit check from `docs/BRIEF.md`.
- When a design choice is not covered by the brief, list the options and ask Kasim before building.
- Keep `docs/BRIEF.md` current: record new decisions in its Decisions table.
