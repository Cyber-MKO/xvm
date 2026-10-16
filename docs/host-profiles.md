# Host profiles

Every host fact an emulated host reports comes from a host profile (CLAUDE.md rule 5). A profile is a YAML file validated against [the JSON Schema](../control/xvm_control/schema/host-profile.schema.json).

## Kinds

| Kind | Holds | Where |
| --- | --- | --- |
| `base-image` | Facts shared by many hosts: OS version, default users and services, registry | `control/profiles/bases/`, built from golden captures |
| `host-profile` | Only what differs for one host: identity, network, extra users and software | Anywhere; names its base with `base:` |
| `resolved-host` | The base with the profile applied. Produced by `xvm-profile resolve`, never written by hand | Output only |

Examples live in [control/profiles/examples/](../control/profiles/examples/). Their values are illustrative, not captured.

## Sections

| Section | Contents |
| --- | --- |
| `identity` | Host name, domain, machine ID |
| `os_info` | Product name, edition, version, build, UBR, display version, architecture, install date, locale, time zone |
| `hardware` | CPU, memory, system and BIOS details |
| `network` | Interfaces (MAC, IPv4, gateway, DNS) and DNS suffix |
| `users`, `groups` | Local accounts with SIDs (Windows) or UIDs and GIDs |
| `software` | Installed packages |
| `services` | Services with state and start mode |
| `registry` | Windows only. Keys under `HKLM`, `HKU` or `HKCR`, typed values |
| `agent` | SIEM agent product, version, manager and group |

## Merge rules

| Field | Rule |
| --- | --- |
| Scalars and objects | The profile value wins. Objects merge key by key. |
| `users`, `groups`, `software`, `services`, `network.interfaces` | Entries merge by `name`, ignoring case. `remove: true` deletes the base entry. Removing an entry the base lacks is an error. |
| `registry.keys` | Merge key by key, then value by value, ignoring case. A value of `null` deletes it. |
| `registry.delete_keys` | Deletes the key and all subkeys. Deleting a key the base lacks is an error. |

A base image may not use `remove`, `null` values or `delete_keys`.

## Registry values

| Type | `data` |
| --- | --- |
| `REG_SZ`, `REG_EXPAND_SZ` | String |
| `REG_MULTI_SZ` | List of strings |
| `REG_DWORD` | Integer, 0 to 4294967295 |
| `REG_QWORD` | Integer, 0 to 2^64 - 1 |
| `REG_BINARY` | Lowercase hex string |

## Commands

| Task | Command |
| --- | --- |
| Validate files | `xvm-profile validate FILE... [--bases DIR]` |
| Print the resolved host | `xvm-profile resolve FILE [--bases DIR] [--format yaml\|json]` |

`--bases` defaults to `control/profiles/bases` and can be repeated.

Quote timestamps in YAML. Unquoted ones are accepted and converted to UTC text.
