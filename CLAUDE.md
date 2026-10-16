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

## Proposed repo layout

```
docs/            BRIEF.md, architecture notes, API tables per personality
census/          API census tool and generated reports
engine/          host-state engine (base images, per-host deltas)
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

## Current phase: Phase 1 (Windows personality, first boot)

Phase 0 is done: the census tool exists, and Kasim reviewed the Wazuh 4.14.2 census on 2026-10-16. The census report is `census/reports/wazuh-agent-4.14.2-windows.md`; the findings and the four Phase 1 decisions are in `docs/phase1-sizing.md`. The golden baseline capture from Phase 0 is still open.

Phase 1 work lives in `personalities/windows/`. The exit check is in `docs/BRIEF.md` section 10.

Loader status:

| Part | Status |
| --- | --- |
| PE32 i386 header and section parsing | Done |
| Layout, base relocations, exports, TLS directory | Done |
| Import binding with gap records | Done |
| Mapping into a 32-bit process and running code | Done |
| TEB, `fs` segment, implicit TLS, TLS callbacks | Done (fields in `docs/api/windows.md`) |
| Process and thread start-up, DLL load order, `DllMain` | Not started |
| Emulated DLLs (`kernel32`, `msvcrt` and the rest) | Not started. Design decided: Rust functions plus a minimal in-memory PE header per module (brief, Decisions). |
| MSI installer step | Not started |

Build and test the loader for both targets: `cargo test` and `cargo test --target i686-unknown-linux-gnu`. The i686 run needs `gcc-multilib`. Fixtures are built from source with clang, lld-link and llvm-dlltool.

## Working style

- Small, test-backed steps; each roadmap phase ends with its exit check from `docs/BRIEF.md`.
- When a design choice is not covered by the brief, list the options and ask Kasim before building.
- Keep `docs/BRIEF.md` current: record new decisions in its Decisions table.
