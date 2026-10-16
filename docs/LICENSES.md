# Licenses and third-party code

Record every third-party source used, and every Apple open-source Darwin release consulted, with its license and why it is compatible.

| Component | Used for | License | Notes |
| --- | --- | --- | --- |
| DigiCert Assured ID Root CA certificate | Example profile's `ROOT` store (`control/profiles/example-windows/certs/`) | Public CA certificate | Downloaded from cacerts.digicert.com (2026-10-16). SHA-256 `3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c` matches DigiCert's published fingerprint |
| pefile | PE parsing in the census tool | MIT | Python dependency, not shipped in runtimes |
| serde, toml (Rust crates) | Reading host profiles | MIT or Apache-2.0 | Dependencies: winnow (MIT), memchr (Unlicense or MIT), unicode-ident (MIT or Apache-2.0, plus Unicode-3.0 for its data), the rest MIT or Apache-2.0. Checked with `cargo metadata` (2026-10-16). |
| libc (Rust crate) | `mmap` and `mprotect` in the Windows loader | MIT or Apache-2.0 | Bindings only, no OS code |
| msitools, libarchive, rpm2cpio, cpio | Unpacking packages in the census tool | LGPL-2.1, BSD-2-Clause, GPL | Invoked as external programs |
| wixl, clang, lld, llvm-dlltool | Building test fixtures | LGPL-2.1, Apache-2.0 with LLVM exception | Test-time only |
