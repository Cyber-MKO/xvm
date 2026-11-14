# Claude Project kit for xvm

A claude.ai Project for planning, reviews and questions about xvm, outside the code sessions. Claude Code sessions in the repo read `CLAUDE.md` themselves and need none of this.

## Set it up

1. In claude.ai, choose **Projects**, then **Create project**. Name it `xvm`.
2. Open **Project instructions** and paste the text of [`instructions.md`](instructions.md) below its title.
3. Under **Project knowledge**, upload the files in the table. Upload them from the latest `claude/cool-cannon-rv2e4f` (or `main`, once merged).
4. When a file in the table changes in the repo, upload the new copy and delete the old one. The Project does not follow the repo.

| File | Why it is in the Project | Size |
| --- | --- | --- |
| `CLAUDE.md` | Hard rules, stack, layout, current status | 11 KB |
| `docs/BRIEF.md` | Requirements, decisions table, architecture, roadmap, tests | 34 KB |
| `docs/phase1-sizing.md` | Phase 1 scope from the census | 6 KB |
| `docs/host-profiles.md` | Profile sections, merge rules, golden import | 13 KB |
| `engine/README.md` | Engine operations and data model | 19 KB |
| `control/README.md` | `xvm-host` and `xvm-check` | 6 KB |
| `scenarios/README.md` | Scenario format and actions | 10 KB |
| `census/README.md` | How the census is made, run-time lookups | 2 KB |
| `docs/api/windows.md` | Every emulated Windows function and why | 68 KB |
| `docs/LICENSES.md` | Licence notes | 3 KB |

All ten come to about 172 KB. If the Project's knowledge limit is lower on your plan, leave out `docs/api/windows.md` first: it is the largest, and Claude Code sessions read it from the repo anyway.

## What the Project is for

| Use | Example ask |
| --- | --- |
| Decide | "List the options for modelling open ports, with a recommendation." |
| Review | "Check this scenario YAML against the BRIEF's rules." |
| Explain | "Why does `CreateProcess` fail instead of running commands?" |
| Plan | "What is left before the Phase 1 exit check?" |

Code changes still happen in Claude Code sessions on the repo. A decision made in the Project goes into the BRIEF's Decisions table through one of those sessions, so every session sees it.
