# xvm

Lightweight emulated hosts (Windows, macOS, Linux) for unmodified SIEM agents, on one shared Linux kernel. Habeny is the first consumer.

Start with [docs/BRIEF.md](docs/BRIEF.md). Rules for contributors and agents are in [CLAUDE.md](CLAUDE.md).

## Status

Phase 0 (Foundations). The API census tool is in [census/](census/). The golden baseline capture kit is in [scenarios/golden/windows/](scenarios/golden/windows/). Host profiles are described in [docs/host-profiles.md](docs/host-profiles.md). The host-state engine is in [engine/](engine/).

## Layout

| Path | Contents |
| --- | --- |
| `docs/` | Brief, architecture notes, API table per personality |
| `census/` | API census tool and generated reports |
| `engine/` | Host-state engine |
| `personalities/` | Windows, macOS and Linux personalities |
| `scenarios/` | Scenario engine and golden corpora |
| `response/` | Response recorders |
| `external/` | Agentless sources |
| `control/` | CLI, API, host profiles, Habeny provider |
| `tests/` | T1 to T8, fidelity, resource and calibration harnesses |

## Development

| Task | Command |
| --- | --- |
| Python setup | `uv venv && uv pip install -e '.[dev]'` |
| Python lint | `ruff check . && ruff format --check .` |
| Python tests | `pytest` |
| Rust lint | `cargo fmt --check && cargo clippy --all-targets -- -D warnings` |
| Rust tests | `cargo test` |

System tools for the census and its tests (Ubuntu): `msitools wixl libarchive-tools rpm2cpio cpio clang lld llvm jq`. Tests that need a missing tool are skipped.
