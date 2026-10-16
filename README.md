# xvm

Lightweight emulated hosts (Windows, macOS, Linux) for unmodified SIEM agents, on one shared Linux kernel. Habeny is the first consumer.

Start with [docs/BRIEF.md](docs/BRIEF.md). Rules for contributors and agents are in [CLAUDE.md](CLAUDE.md).

## Status

Phase 1: the Windows personality's PE32 loader, in [personalities/windows/](personalities/windows/). The API census tool is in [census/](census/).

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
| List a Windows image's import gaps | `cargo run --target i686-unknown-linux-gnu --bin xvm-windows-load -- IMAGE` |
| Run a Windows executable until its first gap | `cargo run --target i686-unknown-linux-gnu --bin xvm-windows-run -- IMAGE` |
| Rust tests, 32-bit (runs PE code) | `rustup target add i686-unknown-linux-gnu && cargo test --target i686-unknown-linux-gnu` |

System tools for the census, the loader and their tests (Ubuntu): `msitools wixl libarchive-tools rpm2cpio cpio clang lld llvm gcc-multilib`. Tests that need a missing tool are skipped. Set `XVM_REQUIRE_FIXTURES=1` to make the Rust loader tests fail instead.
