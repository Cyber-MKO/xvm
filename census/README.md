# API census

Finds which OS APIs an agent package uses. The report sizes each personality: we implement only what the census shows (CLAUDE.md rule 3).

## What it does

1. Unpacks the package: MSI (msiextract), PKG (xar via bsdtar, gzip or cpio payloads), DEB (bsdtar), RPM (rpm2cpio and cpio). Nested archives are unpacked too, up to depth 4.
2. Parses every PE image: static imports, delay-load imports, ordinal imports and exports (pefile).
3. Classifies each imported DLL as `system`, `api-set` or `bundled` (shipped in the package).
4. Flags dynamic loading (`LoadLibrary*`, `GetProcAddress`, `GetModuleHandle*`, `Ldr*`) and lists DLL names and function-like strings that are not in the import table.
5. Reads Mach-O slices and linked dylibs. Symbol-level Mach-O imports come in Phase 6.
6. Writes `<name>.json` (full per-binary detail) and `<name>.md` (summary) to `census/reports/`.

Identical binaries are analysed once and listed under `also_at`.

## Run

```sh
xvm-census scan path/to/wazuh-agent-4.13.1-1.msi --agent wazuh-agent-4.13.1-windows
```

Options: `--out DIR` (default `census/reports`), `--name STEM`, `--keep` (keep the unpacked tree next to the report). A directory can be passed instead of a package.

## Limits

| Limit | Effect | Covered by |
| --- | --- | --- |
| Function-like strings are a heuristic | False positives and misses | Runtime gap log (rule 4) |
| Names built at run time | Not visible to static analysis | Runtime gap log |
| PKG `pbzx` payloads | Reported in unpack notes, not unpacked | Phase 6 |
| Mach-O symbol imports | Not parsed | Phase 6 |
| ELF | Counted only; Linux agents run natively | Phase 5 |

Agent packages are never committed. Fetch them from the vendor and check the EULA first.
