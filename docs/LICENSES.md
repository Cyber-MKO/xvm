# Licenses and third-party code

Record every third-party source used, and every Apple open-source Darwin release consulted, with its license and why it is compatible.

| Component | Used for | License | Notes |
| --- | --- | --- | --- |
| pefile | PE parsing in the census tool | MIT | Python dependency, not shipped in runtimes |
| PyYAML | Reading host profiles | MIT | Python dependency |
| jsonschema | Validating host profiles | MIT | Python dependency |
| msitools, libarchive, rpm2cpio, cpio | Unpacking packages in the census tool | LGPL-2.1, BSD-2-Clause, GPL | Invoked as external programs |
| wixl, clang, lld, llvm-dlltool | Building test fixtures | LGPL-2.1, Apache-2.0 with LLVM exception | Test-time only |
