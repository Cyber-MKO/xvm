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

## Proposed stack (confirm with Kasim before scaffolding)

- Rust for loaders and personality runtimes.
- Python for the API census tool, control plane, scenario engine and test harness.

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

## Current phase: Phase 0 (Foundations)

Start here, in order:

1. Scaffold the repo with the layout above, CI, linting and a test runner.
2. Build the **API census tool** (`census/`):
   - Unpack agent packages: MSI (msitools), PKG, DEB, RPM.
   - Parse PE import tables, including delay-load imports (`pefile`), and later Mach-O load commands and imports.
   - Flag dynamic loading (`LoadLibrary*`, `GetProcAddress`, `dlopen`) and strings that look like DLL or function names.
   - Output per-DLL function lists per agent as JSON plus a Markdown summary in `census/reports/`.
3. Run the census on the Wazuh Windows agent MSI and write the report. This sizes Phase 1.

Do not start the Windows PE loader until the census report exists and Kasim has reviewed it.

## Working style

- Small, test-backed steps; each roadmap phase ends with its exit check from `docs/BRIEF.md`.
- When a design choice is not covered by the brief, list the options and ask Kasim before building.
- Keep `docs/BRIEF.md` current: record new decisions in its Decisions table.
