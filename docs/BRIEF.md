# Project Brief: Lightweight Emulated Hosts for SIEM Agents

- Name: xvm
- Owner: Kasim
- As of: 2026-10-16
- Status: pre-build

## 1. What we are building

A container-like platform that runs many lightweight emulated hosts (Windows, macOS, Linux) on one machine. Real, unmodified SIEM agents install and run inside each host and believe they are on a real system. Each host behaves like a real endpoint for SIEM monitoring and response: it produces realistic logs and events, answers the agent's questions about itself (OS, hardware, software, users, network), and carries out or records response actions.

The platform is standalone and usable by anyone, and it is built to be Habeny-centric: Habeny is its first and most important consumer.

## 2. Requirements as stated by Kasim

1. An emulated environment, like a container, where SIEM agents can be installed with the least amount of resources.
2. The environment emulates a real environment with respect to SIEM monitoring, and possibly response.
3. Cover macOS, Windows and Linux for now.
4. No GUI for Windows or macOS.
5. Every emulated environment is as light as possible and as functional as possible.
6. An emulated OS should be able to perform the regular operations SIEM agents rely on, with minimal parts, because the focus is SIEM monitoring and possibly response.
7. SIEM monitoring mostly means sending logs from files and file monitoring; other collection paths must be researched and covered.
8. SIEM agents check specific locations to learn about the host (OS and the like), and spec commands usually read a file where that information is stored. These must be emulated.
9. The Windows registry is also stored as files somewhere; it must be emulated.
10. Scale to all SIEM tools.
11. LXC-like, but also emulating Windows and macOS.
12. Lighter than the current LXC approach so that more hosts can be deployed without the current CPU constraint.
13. Emulate API calls, both internally (what the agent calls into) and externally (what the SIEM sees and talks to).
14. Integrate with Habeny and be very Habeny-centric, while staying standalone so others can use it.
15. No Wine. Build the OS layer from the ground up to achieve these aims.

## 3. Decisions so far

| Decision | Status | Notes |
| --- | --- | --- |
| No Wine, Darling or ReactOS; our own runtime | Decided | The Wazuh Windows agent did not work under Wine (2026-09-30). The cause was not diagnosed. |
| First agent is Wazuh | Decided | Best-known agent, and Habeny already has Wazuh baselines. |
| Golden baseline comes from a Windows evaluation VM | Decided | Real Windows host used once to capture reference data. |
| Standalone repo; Habeny consumes it as a provider | Decided | Confirmed by Kasim (2026-10-16). Repo: Cyber-MKO/xvm. |
| Shared Linux kernel underneath all hosts | Proposed | See section 5. |
| Rust for runtimes, Python for tooling and control plane | Decided | Confirmed by Kasim (2026-10-16). Cargo workspace at the root; one Python package per tool. |
| Project name is xvm | Decided | Confirmed by Kasim (2026-10-16). |
| CI on GitHub Actions | Decided | Python: ruff and pytest. Rust: fmt, clippy and test. |
| Phase 1 target is Wazuh agent 4.14.2 for Windows | Decided | Habeny's default version. Census in `census/reports/`; findings in `docs/phase1-sizing.md`. |
| Windows personality runs as a 32-bit Linux process | Decided | Wazuh's Windows binaries are all PE32 i386. Needs IA32 emulation in the host kernel. |
| We provide `msvcrt.dll` ourselves, on top of host libc | Decided | Windows semantics added per function, from the census. |
| A non-GUI `user32` subset is allowed | Decided | Only census functions, no window system. Consistent with rule 6. |
| Host profiles are YAML, validated by a JSON Schema | Decided | Kasim, 2026-10-16. See `docs/host-profiles.md`. |
| Host profiles are a base image plus per-host deltas | Decided | Kasim, 2026-10-16. Bases are built from golden captures. |
| Golden captures are stored with Git LFS in this repo | Decided | Kasim, 2026-10-16. `.evtx` and manager logs go to LFS; manifests stay in plain git. |
| Host-state engine is written in Rust | Decided | Kasim, 2026-10-16. Crate `engine/` (`xvm-engine`, daemon `xvm-engined`). |
| The engine layers base images and host deltas itself | Decided | Kasim, 2026-10-16. Bases are held once and shared. Test vectors check it against `xvm-profile resolve`. |
| Personalities reach the engine over a Unix socket | Decided | Kasim, 2026-10-16. One daemon for all hosts, one connection per host, length-prefixed JSON. |
| `xvm-profile` is the only YAML parser; the engine reads compiled JSON | Decided | 2026-10-16. Avoids YAML 1.1 and 1.2 disagreements between Python and Rust. Unquoted timestamps are rejected. |
| Run-time changes live in a third engine layer above the profile | Proposed | 2026-10-16. In memory only; `reset` returns to the profile. Saving changes across restarts is not built yet. |
| Personality and control connections may both write | Proposed | 2026-10-16. The agent's own registry writes and scenario events go through the same ops and one journal. |
| Scenarios pass their own clock on each write | Proposed | 2026-10-16. Optional `time` parameter, so hosts can run on jittered clocks (section 8). |
| A host's name cannot change at run time | Proposed | 2026-10-16. `identity.hostname` is refused by `section.update`, since every component knows the host by name. |
| Census test fixtures are built from source | Decided | Headerless C built with clang and lld-link (no SDK, no CRT), so no vendor binaries enter the repo. |

## 4. Core insight: emulate the API surface, not just the files

Requirement 8 is right for host facts: much of what agents learn about a host comes from files (`/etc/os-release`, `/proc/cpuinfo`, package databases, `SystemVersion.plist`). The most important data paths, however, are OS APIs and kernel interfaces, not files:

- **Windows registry.** The hives are files (`C:\Windows\System32\config\SYSTEM`, `SOFTWARE`, `NTUSER.DAT`), but no agent reads them directly. Agents call `RegOpenKeyEx` and `RegQueryValueEx`, which go to the kernel's configuration manager. We emulate the API and back it with our own store.
- **Windows Event Log.** Events are stored in `.evtx` files, but agents subscribe through `wevtapi` (`EvtSubscribe`, `EvtRender`, bookmarks), which talks to the EventLog service. We emulate the API and the service.
- **macOS.** Wazuh collects unified logs by running the `log stream` command, which we can provide. EDR-style agents use the Endpoint Security framework, which needs the real XNU kernel and an Apple entitlement.
- **Linux.** auditd uses netlink, EDR agents use eBPF, FIM uses inotify or fanotify. These are kernel interfaces; containers share the host kernel, and the audit subsystem is not namespaced.

### Data paths every host personality must cover

| Path | Windows | macOS | Linux |
| --- | --- | --- | --- |
| Log files | Files plus rotation | Files plus rotation | Files plus rotation |
| OS log system | Event Log via `wevtapi`; later ETW, Sysmon | Unified logging via `log stream` | journald, syslog |
| Kernel telemetry | Out of scope (drivers) | Out of scope (Endpoint Security) | auditd netlink; eBPF out of scope |
| File integrity monitoring | `ReadDirectoryChangesW`, polling | FSEvents, polling | inotify, fanotify, polling |
| Host state queries | Registry, WMI, system-information APIs | `sysctl`, plists, package receipts | `/proc`, `/sys`, `/etc`, package databases |
| Commands the agent runs and parses | `netsh`, `sc`, PowerShell, etc. | `system_profiler`, `pkgutil`, etc. | `ps`, `netstat`, `ss`, etc. |
| Response actions | `netsh`, `route` | `pfctl`, `route` | `iptables`, `nftables`, `route` |

## 5. What "build the OS from the ground up" means here

We build our own **OS personalities**: the layer an agent sees as Windows, macOS or Linux. They run on one **shared Linux kernel**, the same way LXC containers do.

Why a shared kernel and not a bare-metal OS per host: a separate kernel per host means a VM per host, which brings back the per-host overhead we are trying to remove. Sharing the kernel is what lets LXC pack hundreds of hosts on one machine, and it is what lets us beat the current CPU ceiling.

Why only a subset of each OS: a complete Windows or macOS reimplementation is a decades-long effort. We implement only the APIs SIEM agents actually call. An **API census** of the target agents (section 10, Phase 0) defines that surface, and the runtime logs every call it does not implement, so the surface grows only from evidence.

Per personality:

- **Windows personality.** Our own PE32 loader (PE32+ later if an agent needs it), running as a 32-bit Linux process, plus a minimal implementation of the system DLL surface the census shows (for example parts of `kernel32`, `msvcrt`, `advapi32`, `wevtapi`, `wsock32`, `ws2_32`, `crypt32`, `iphlpapi`). Registry, Event Log, services and system information are served by the host-state engine. Networking maps to host sockets. No GUI subsystems at all.
- **macOS personality.** Our own Mach-O loader plus a minimal `libSystem` and syscall surface, `sysctl` values, plists, and a `log` command fed by the scenario engine. Constraint: macOS agents are arm64 or universal binaries. x86_64 slices can run natively on an x86 host; arm64-only binaries need an arm64 Linux host or CPU emulation. Apple has moved to Apple silicon only, so the x86_64 path will narrow over time.
- **Linux personality.** Real binaries run natively. Host identity comes from namespaces, FUSE views of `/proc` and `/sys` (LXCFS-style) and `/etc`, and seccomp user notification to intercept selected calls such as audit netlink.

All implementation is clean-room from public documentation. No code is copied from Windows, Wine, Darling or ReactOS.

## 6. Architecture

```
                      +--------------------------------------------+
  Host profiles  ---> |            Host-state engine               |
  Golden corpus  ---> |  base image + per-host deltas: identity,   |
                      |  registry, files, users, packages,         |
                      |  processes, network                        |
                      +----+-------------------+-------------------+
                           |                   |
               +-----------v------+   +--------v---------+   +------------------+
               | Windows          |   | macOS            |   | Linux            |
               | personality      |   | personality      |   | personality      |
               | PE loader + API  |   | Mach-O loader +  |   | namespaces, FUSE,|
               | subset           |   | libSystem subset |   | seccomp notify   |
               +--------+---------+   +--------+---------+   +--------+---------+
                        |   unmodified SIEM agents run here  |
                        +------------------+-----------------+
                                           |  agent protocol (untouched)
  Scenario engine ---> events into each    v
  personality's log APIs           +----------------+      +-------------------+
                                   |  Real SIEM     | <--- | External emulation|
  Response capture <--- shimmed    |  manager       |      | syslog, WEF, cloud|
  commands and calls               +----------------+      | API sources       |
                                                           +-------------------+
       Control plane: LXC-like CLI and API (create, start, stop, exec,
       snapshot, inject-scenario), declarative host profiles, Habeny provider
```

Components:

1. **Host-state engine.** One process serves state for many hosts: a shared base image per OS plus small per-host deltas (hostname, IPs, installed software, registry differences). Keeps state internally consistent: a process that generated an event must exist when the agent lists processes.
2. **Personality runtimes.** One per OS, as in section 5.
3. **Scenario engine.** Generates background activity (logons, service starts, package installs) and ATT&CK-mapped attack scenarios, and replays golden corpora captured from real hosts.
4. **Response capture.** Commands and APIs used for response (`netsh`, `route`, `iptables`, `pfctl`) are implemented as recorders: they log the call and its arguments and change nothing on the real machine. This makes response measurable.
5. **External emulation.** Agentless sources driven by the same engine: syslog senders, Windows Event Forwarding, network device logs, and fake cloud tenants (for example O365 Management API, CloudTrail to S3, Azure Event Hubs) for API-ingest SIEMs.
6. **Control plane.** LXC-like CLI and API, a declarative host profile format, and an image format for personalities.
7. **Habeny provider.** A backend beside Habeny's LXC provider so existing experiments can switch to emulated hosts.

## 7. Coverage classes for "all SIEM tools"

| Class | Examples | How covered |
| --- | --- | --- |
| User-mode agents and log shippers | Wazuh, OSSEC, Splunk Universal Forwarder, Elastic Agent (Beats), Winlogbeat, NXLog, Fluent Bit, Graylog Sidecar, UTMStack agent, Bindplane | Personality runtimes. The bulk of the project. |
| Kernel or driver-based EDR agents | CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Elastic Defend, Cortex XDR | Cannot be hosted by a user-space runtime (kernel drivers, system extensions, eBPF). Options: a small pool of real VMs, or protocol-level simulation. State this clearly in user docs. |
| Agentless or API-ingest SIEMs | Microsoft Sentinel connectors, Google SecOps feeds, syslog-based SIEMs | External emulation only. Cheapest class, scales furthest. |

Every SIEM can be fed. Most agents can be hosted. Kernel-level EDR agents cannot be hosted by any lightweight emulator.

## 8. Performance goals and the Habeny context

Habeny results (two-host test bed: Intel Core Ultra 9 agent host, AMD Ryzen 5 SIEM host over LAN):

- Wazuh: stable to 185 containers; the manager's CPU was the binding constraint.
- Elastic: crashed the agent host at 90 containers (load average 804 on a 24-core machine).
- UTMStack: degraded gracefully to 83 agents.

Implications:

- A lighter host does not move a manager-side ceiling (Wazuh). That ceiling is the measurement itself.
- A lighter host helps agent-host ceilings (Elastic), but only by removing per-host OS overhead. The agent's own CPU cost stays.

Where the savings come from:

1. **No per-host OS.** No systemd, cron, sshd or journald per host; agents run against the emulated API surface directly.
2. **Shared state.** One engine serves thousands of hosts; each host stores only its deltas.
3. **De-synchronized schedules.** Agents run periodic heavy jobs (inventory, rootcheck, full FIM scans, SCA). Hundreds of identical hosts started together scan together. The platform jitters clocks and schedules so the load looks like a real fleet.

**Validity rule:** emulated hosts must cost the SIEM manager exactly what real hosts cost, while costing the agent host much less. This is proven by calibration (section 11).

## 9. Monitoring and response emulation

- **Monitoring.** The scenario engine feeds events into each personality's log APIs (`wevtapi`, `log stream`, journald, files) and changes host state through the state engine, so FIM, inventory and SCA see consistent changes.
- **Golden corpora.** Real events captured from reference hosts (Windows evaluation VM first) are replayed so emulated output can be diffed against real output.
- **Response.** When a SIEM triggers a response (for example Wazuh `firewall-drop`), the recorder logs what was called, with which arguments and when. Responses become measurable: did the SIEM respond, how fast, with the right action.

## 10. Roadmap

Each phase ends with an exit check before the next starts.

1. **Phase 0: Foundations.**
   - Create the repo, CI and coding conventions.
   - Build the **API census tool**: extract target agents (MSI with msitools, PKG, DEB and RPM), parse PE and Mach-O import tables including delay-loaded imports, and output per-DLL and per-library function lists as JSON and Markdown. Also flag dynamic loading (`LoadLibrary`, `GetProcAddress`, `dlopen`) for runtime tracing.
   - Capture the Windows golden baseline from an evaluation VM: `.evtx` exports (Security, System, Application), `reg export` of the identity keys, manager `archives.json` (enable `logall_json`) and `alerts.json` for a scripted scenario.
   - Exit: census report for the Wazuh Windows agent; golden baseline stored.
2. **Phase 1: Windows personality, first boot.** PE loader, process and thread basics, filesystem mapping, registry API backed by the state engine, sockets, and every unimplemented call logged. Install the agent by unpacking the MSI with our own installer step.
   - Exit: the unmodified Wazuh agent starts, enrolls and stays Active for 24 hours, and the manager shows the OS identity from the host profile.
3. **Phase 2: Event Log subsystem.** `wevtapi` subscribe, render, bookmarks and message formatting, fed by the scenario engine and golden corpus.
   - Exit: detection parity and fidelity diff pass (section 11).
4. **Phase 3: Inventory, FIM and response.** System information and installed-software APIs, directory change notification, response recorders.
   - Exit: inventory matches the golden host; FIM alerts fire; response recorder shows the expected command and source IP.
5. **Phase 4: Scale and Habeny.** Shared state engine at scale, schedule jitter, Habeny provider, calibration run, density measurement on the Core Ultra 9.
   - Exit: calibration passes; per-host cost and density are measured against a Windows Server Core container and Habeny's LXC Linux agents.
6. **Phase 5: Linux personality.**
7. **Phase 6: macOS personality.** Wazuh macOS agent first.
8. **Phase 7: More agents and agentless sources.** Second Windows agent (Winlogbeat or Splunk Universal Forwarder) to prove the Event Log layer is agent-agnostic, then the external emulation sources.

## 11. Testing and validation

| ID | Test | Pass condition |
| --- | --- | --- |
| T1 | Install | Agent files and configuration in place without modifying the agent |
| T2 | Enrollment and keepalive | Agent Active with no disconnects over 24 hours |
| T3 | Identity | Manager shows the OS name and version from the host profile |
| T4 | Inventory | Hardware, OS and software inventory match the golden host; differences explained |
| T5 | Event delivery | Every injected event arrives exactly once, including across an agent restart |
| T6 | Detection parity | Same rule IDs fire the same number of times as in the golden run |
| T7 | FIM | A file change in a monitored folder raises the expected alert |
| T8 | Response | Recorder shows the expected command and arguments |

- **Fidelity test.** Replay the golden corpus through an emulated host and diff `archives.json` field by field against the golden run. Pass: only host-identity fields differ (agent ID, name, IP, receive timestamps).
- **Resource test.** Measure RAM, CPU, disk and start-up time per host, and maximum density on one machine, against a Windows Server Core container and Habeny's LXC agents.
- **Calibration test.** Run N real hosts and N emulated hosts against the same manager. Manager-side EPS, CPU, bytes received and alert counts must match within an agreed tolerance.

## 12. Risks

| Risk | Mitigation |
| --- | --- |
| The Windows API surface agents need is larger than expected | Census first; implement only what is called; log every gap. Wazuh bundles OpenSSL but not its CRT: it imports 188 `msvcrt.dll` functions (census 2026-10-16). |
| Dynamic loading hides calls from the census | Runtime logging of every unresolved import and `GetProcAddress` lookup |
| Agents depend on behaviour, not just signatures (error codes, ordering, handle semantics) | Golden baseline and fidelity diffs catch behavioural drift |
| macOS arm64-only agent binaries | arm64 Linux host or CPU emulation; prefer x86_64 slices while vendors still ship them |
| Kernel-level EDR agents | Out of scope for runtimes; real-VM pool or protocol simulation |
| Licensing | Clean-room implementation from public documentation; check each vendor's EULA before supporting its agent |
| Effort | Projects that reimplement whole OS APIs take many years. Keep strict scope: SIEM agent surface only, driven by census and tests |

## 13. Open questions

1. Resolved: the name is xvm.
2. Resolved: standalone repo.
3. Resolved: Rust and Python.
4. Resource targets: what per-host RAM and CPU numbers count as success?
5. Host hardware for macOS arm64 agents.
6. Which agents follow Wazuh, and in what order?

## Appendix A: SIEM landscape (researched 2026-09-27)

- **Gartner Magic Quadrant for SIEM 2025** (published 2025-10-08) evaluated: CrowdStrike, Datadog, Elastic, Exabeam, Fortinet, Google, Graylog, Gurucul, Huawei, ManageEngine, Microsoft, Palo Alto Networks, QAX, Rapid7, Securonix, Splunk, Sumo Logic.
  - Leaders include Microsoft Sentinel, Splunk (Cisco), Google SecOps, Securonix, Exabeam, Gurucul.
  - Fortinet FortiSIEM and Rapid7 InsightIDR: Challengers. CrowdStrike Falcon Next-Gen SIEM: Visionary. Sumo Logic: Niche Player.
- **Not in the 2025 MQ:** IBM (QRadar SaaS assets went to Palo Alto Networks in 2024), LogRhythm (merged into Exabeam, Axon end-of-lifed), Logpoint, OpenText (ArcSight), Odyssey.
- **Newer platforms outside the MQ:** Hunters, Panther, Anvilogic.
- **Other commercial (verify individually):** SentinelOne AI SIEM, Palo Alto Cortex XSIAM, Stellar Cyber, NetWitness, Trellix, Devo, Sekoia, Blumira, Arctic Wolf, LevelBlue USM (formerly AlienVault), SolarWinds SEM, Coralogix, Kaspersky KUMA, Positive Technologies MaxPatrol SIEM.
- **Free and open source:** Wazuh, Security Onion, UTMStack, Graylog Open, Elastic Security (free tier), OpenSearch Security Analytics, OSSEC. ELK and OpenSearch are foundations to build a SIEM on. OSSIM's open edition stopped receiving updates in 2024. MozDef and Apache Metron are retired. Splunk Free has a daily ingest cap.
- **Market direction:** consolidation into platforms (CrowdStrike Next-Gen SIEM, Palo Alto XSIAM). EDR-first SIEMs rely most on kernel-level agents, so they are the hardest to host.
