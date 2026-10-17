# Licenses and third-party code

Record every third-party source used, and every Apple open-source Darwin release consulted, with its license and why it is compatible.

| Component | Used for | License | Notes |
| --- | --- | --- | --- |
| DigiCert Assured ID Root CA certificate | Test data for the X.509 reader and certificate stores (`control/profiles/example-windows/certs/`); the example base carries it inline | Public CA certificate | Downloaded from cacerts.digicert.com (2026-10-16). SHA-256 `3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c` matches DigiCert's published fingerprint |
| pefile | PE parsing in the census tool | MIT | Python dependency, not shipped in runtimes |
| serde, serde_json, base64 (Rust crates) | The Windows loader's engine data | MIT or Apache-2.0 | Dependencies: memchr (Unlicense or MIT), unicode-ident (MIT or Apache-2.0, plus Unicode-3.0 for its data), the rest MIT or Apache-2.0. Checked with `cargo metadata` (2026-10-17). |
| Unicode mapping files for Microsoft code pages (`bestfit1252.txt`, `CP437.TXT`) | Code page tables (`personalities/windows/data/codepages/`, generated `src/codepage/tables.rs`) | Unicode License v3 | Downloaded from unicode.org/Public/MAPPINGS/VENDORS/MICSFT/ (2026-10-17). Data files under /Public/ are under the Unicode License v3, a permissive license that needs the notice kept; the notice is in `data/codepages/LICENSE`. Tables only, no Microsoft code |
| libc (Rust crate) | `mmap` and `mprotect` in the Windows loader | MIT or Apache-2.0 | Bindings only, no OS code |
| serde, serde_json (with indexmap) | Engine data model and wire format | MIT or Apache-2.0 | Rust dependencies |
| Event message templates | `event_messages` in base images | Derived data | Taken from the rendered output of the golden capture's own Windows host (`wevtutil qe /f:RenderedXml`), the same kind of runtime capture as the golden corpus. No Microsoft binary or message file is read or copied (CLAUDE.md rule 1). |
| Scenario event layouts | `scenarios/xvm_scenario/events/windows.yaml` | Public documentation | Field names, order and constant values from the public Microsoft Learn event reference (Security 4720 and siblings, Service Control Manager 7036). No Microsoft binary or message file is read or copied (CLAUDE.md rule 1). The golden capture is the authority; the fidelity diff checks the layouts against it. |
| PyYAML | Reading host profiles | MIT | Python dependency |
| jsonschema | Validating host profiles | MIT | Python dependency |
| msitools, libarchive, rpm2cpio, cpio | Unpacking packages in the census tool | LGPL-2.1, BSD-2-Clause, GPL | Invoked as external programs |
| wixl, clang, lld, llvm-dlltool | Building test fixtures | LGPL-2.1, Apache-2.0 with LLVM exception | Test-time only |
