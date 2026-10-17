//! The agent process's parameters, from the host-state engine.
//!
//! Decision (docs/BRIEF.md): the loader's settings live in the YAML host
//! profile and the engine serves them. The mapping is in
//! docs/host-profiles.md:
//!
//! | Parameter | Engine source |
//! | --- | --- |
//! | Command line, current directory, PID, service, environment | `agent` section |
//! | System module directory, certificate stores, trusted files | `windows` section (absent: none) |
//! | Time zone | `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, names from `...\Time Zones\KEY` |
//! | ANSI and OEM code pages | `HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage`, `ACP` and `OEMCP` |
//!
//! Drives are a launch setting, given by the caller.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use serde_json::Value;
use xvm_engine::client::{Client, ClientError};
use xvm_engine::protocol::code;

use crate::codepage::{self, CodePages};
use crate::paths::DriveMap;
use crate::process::ProcessParams;
use crate::timezone::{TimeZone, Transition};
use crate::x509::Certificate;

const TIME_ZONE: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation";
const TIME_ZONES: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones";
const CODE_PAGE: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage";

fn section(client: &mut Client, name: &str) -> Result<Value, String> {
    client
        .section(name)
        .map_err(|e| format!("section {name}: {e}"))
}

/// A registry value's data, or None if it does not exist.
fn reg(client: &mut Client, key: &str, name: &str) -> Result<Option<Value>, String> {
    match client.reg_query_value(key, name) {
        Ok(v) => Ok(v.get("data").cloned()),
        Err(ClientError::Engine(e)) if e.code == code::NOT_FOUND => Ok(None),
        Err(e) => Err(format!("{key}\\{name}: {e}")),
    }
}

fn reg_required(client: &mut Client, key: &str, name: &str) -> Result<Value, String> {
    reg(client, key, name)?.ok_or_else(|| format!("the host has no {key}\\{name}"))
}

fn text(v: &Value, what: &str) -> Result<String, String> {
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{what} is not a string"))
}

/// The ANSI functions return these strings unconverted, so they must be
/// ASCII without NULs (docs/host-profiles.md).
fn ascii(s: String, what: &str) -> Result<String, String> {
    if s.is_ascii() && !s.contains('\0') {
        Ok(s)
    } else {
        Err(format!("{what} {s:?} is not plain ASCII"))
    }
}

/// A REG_DWORD holding signed minutes.
fn minutes(client: &mut Client, name: &str) -> Result<i32, String> {
    let v = reg_required(client, TIME_ZONE, name)?;
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .map(|n| n as i32)
        .ok_or_else(|| format!("{TIME_ZONE}\\{name} is not a DWORD"))
}

/// A 16-byte SYSTEMTIME in day-in-month form; month 0 means none.
fn transition(client: &mut Client, name: &str) -> Result<Option<Transition>, String> {
    let hex = text(&reg_required(client, TIME_ZONE, name)?, name)?;
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| format!("{name} is not hex"))?;
    if bytes.len() != 16 {
        return Err(format!("{name} is {} bytes, not a SYSTEMTIME", bytes.len()));
    }
    let word = |i: usize| u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    if word(1) == 0 {
        return Ok(None);
    }
    if word(0) != 0 {
        return Err(format!(
            "{name}: absolute dates (wYear set) are not supported"
        ));
    }
    Ok(Some(Transition {
        month: word(1),
        day_of_week: word(2),
        week: word(3),
        hour: word(4),
        minute: word(5),
        second: word(6),
    }))
}

fn time_zone(client: &mut Client) -> Result<TimeZone, String> {
    let key_name = text(
        &reg_required(client, TIME_ZONE, "TimeZoneKeyName")?,
        "TimeZoneKeyName",
    )?;
    let names = format!("{TIME_ZONES}\\{key_name}");
    let mut name = |value: &str, fallback: &str| -> Result<String, String> {
        if let Some(v) = reg(client, &names, value)? {
            return text(&v, value);
        }
        match reg(client, TIME_ZONE, fallback)? {
            Some(Value::String(s)) if !s.starts_with('@') => Ok(s),
            _ => Err(format!("no {value} under {names}")),
        }
    };
    let standard_name = name("Std", "StandardName")?;
    let daylight_name = name("Dlt", "DaylightName")?;
    let mut zone = TimeZone {
        key_name,
        standard_name,
        daylight_name,
        bias: minutes(client, "Bias")?,
        standard_bias: minutes(client, "StandardBias")?,
        daylight_bias: minutes(client, "DaylightBias")?,
        standard_date: transition(client, "StandardStart")?,
        daylight_date: transition(client, "DaylightStart")?,
    };
    // "Adjust for daylight saving time automatically" switched off.
    if reg(client, TIME_ZONE, "DynamicDaylightTimeDisabled")?.and_then(|v| v.as_u64()) == Some(1) {
        zone.standard_date = None;
        zone.daylight_date = None;
    }
    zone.validate().map_err(|e| format!("time zone: {e}"))?;
    Ok(zone)
}

fn code_pages(client: &mut Client) -> Result<CodePages, String> {
    let mut page = |name: &str| -> Result<u16, String> {
        let v = text(&reg_required(client, CODE_PAGE, name)?, name)?;
        let number: u16 = v
            .trim()
            .parse()
            .map_err(|_| format!("{name} {v:?} is not a number"))?;
        if codepage::single_byte(number).is_none() {
            return Err(format!(
                "{name}: no table for code page {number}; have {:?}",
                codepage::supported()
            ));
        }
        Ok(number)
    };
    Ok(CodePages {
        ansi: page("ACP")?,
        oem: page("OEMCP")?,
    })
}

fn windows_section(client: &mut Client, params: &mut ProcessParams) -> Result<(), String> {
    let windows = section(client, "windows")?;
    if windows.is_null() {
        return Ok(());
    }
    if let Some(dir) = windows
        .get("system_module_directory")
        .filter(|v| !v.is_null())
    {
        params.system_module_directory = Some(ascii(
            text(dir, "system_module_directory")?,
            "system_module_directory",
        )?);
    }
    for (store, certs) in windows
        .get("cert_stores")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let mut parsed = Vec::new();
        for cert in certs.as_array().into_iter().flatten() {
            let name = cert.get("name").and_then(Value::as_str).unwrap_or("?");
            let der = base64::engine::general_purpose::STANDARD
                .decode(text(cert.get("der").unwrap_or(&Value::Null), "der")?)
                .map_err(|e| format!("certificate {name}: {e}"))?;
            parsed.push(Certificate::parse(&der).map_err(|e| format!("certificate {name}: {e}"))?);
        }
        params
            .cert_stores
            .insert(store.to_ascii_uppercase(), parsed);
    }
    for (path, hash) in windows
        .get("trusted_files")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let path = ascii(path.clone(), "trusted file")?;
        let hash = hash
            .as_str()
            .and_then(crate::sha256::parse_hex)
            .ok_or_else(|| format!("trusted file {path:?}: hash is not 64 hex digits"))?;
        let full = DriveMap::full_path(&path, r"C:\").map_err(|e| format!("{path}: {e}"))?;
        params.trusted_files.insert(full.to_ascii_uppercase(), hash);
    }
    Ok(())
}

/// The process parameters for the host `client` is bound to, with
/// `drives` mapping drive letters to host folders.
pub fn load(
    client: &mut Client,
    drives: &BTreeMap<String, PathBuf>,
) -> Result<ProcessParams, String> {
    let agent = section(client, "agent")?;
    if agent.is_null() {
        return Err("the host has no agent section".into());
    }
    let field = |name: &str| -> Result<String, String> {
        let v = agent
            .get(name)
            .ok_or_else(|| format!("agent.{name} is missing"))?;
        ascii(text(v, &format!("agent.{name}"))?, &format!("agent.{name}"))
    };
    let pid = agent
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|p| u32::try_from(p).ok())
        .filter(|&p| p != 0 && p % 4 == 0)
        .ok_or("agent.pid must be a non-zero multiple of 4")?;
    let service = match agent.get("service") {
        None | Some(Value::Null) => None,
        Some(v) => Some(ascii(text(v, "agent.service")?, "agent.service")?),
    };
    let mut environment = Vec::new();
    for (k, v) in agent
        .get("environment")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let v = ascii(text(v, k)?, k)?;
        environment.push(format!("{}={v}", ascii(k.clone(), "variable name")?));
    }
    // Windows keeps its environment block sorted by name, ignoring case.
    environment.sort_by_key(|e| e.split('=').next().unwrap_or("").to_ascii_uppercase());
    for letter in drives.keys() {
        let mut chars = letter.chars();
        if !matches!((chars.next(), chars.next()), (Some(c), None) if c.is_ascii_uppercase()) {
            return Err(format!("drive {letter:?} is not one upper-case letter"));
        }
    }
    let mut params = ProcessParams {
        command_line: field("command_line")?,
        environment,
        current_directory: field("current_directory")?,
        drives: DriveMap::new(drives),
        service,
        pid,
        time_zone: time_zone(client)?,
        code_pages: code_pages(client)?,
        ..ProcessParams::default()
    };
    windows_section(client, &mut params)?;
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CERT: &[u8] = include_bytes!(
        "../../../control/profiles/example-windows/certs/digicert-assured-id-root-ca.der"
    );

    fn base(extra: Value) -> Value {
        let mut base = json!({
            "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
            "source": {"golden_capture": "synthetic"},
            "registry": {"keys": {
                TIME_ZONE: {
                    "TimeZoneKeyName": {"type": "REG_SZ", "data": "W. Europe Standard Time"},
                    "StandardName": {"type": "REG_SZ", "data": "@tzres.dll,-321"},
                    "Bias": {"type": "REG_DWORD", "data": 4294967236u64},
                    "StandardBias": {"type": "REG_DWORD", "data": 0},
                    "DaylightBias": {"type": "REG_DWORD", "data": 4294967236u64},
                    "StandardStart": {"type": "REG_BINARY", "data": "00000a00000005000300000000000000"},
                    "DaylightStart": {"type": "REG_BINARY", "data": "00000300000005000200000000000000"},
                },
                format!("{TIME_ZONES}\\W. Europe Standard Time"): {
                    "Std": {"type": "REG_SZ", "data": "W. Europe Standard Time"},
                    "Dlt": {"type": "REG_SZ", "data": "W. Europe Daylight Time"},
                },
                CODE_PAGE: {
                    "ACP": {"type": "REG_SZ", "data": "1252"},
                    "OEMCP": {"type": "REG_SZ", "data": "437"},
                },
            }},
        });
        if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        base
    }

    fn host(agent: Value) -> Value {
        json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b", "os": "windows",
               "identity": {"hostname": "H"}, "agent": agent})
    }

    fn agent() -> Value {
        json!({"product": "wazuh", "version": "4.14.2", "pid": 4812,
               "command_line": "\"C:\\a\\agent.exe\" -f", "current_directory": "C:\\a",
               "service": "WazuhSvc", "environment": {"windir": "C:\\Windows", "ComSpec": "x"}})
    }

    fn client(base: Value, host: Value) -> Client {
        let (socket, name) = crate::testing::serve(base, host);
        Client::connect(&socket, &name).unwrap()
    }

    #[test]
    fn reads_every_parameter_from_the_engine() {
        let windows = json!({"windows": {
            "system_module_directory": "C:\\Windows\\SysWOW64",
            "cert_stores": {"root": [{"name": "DigiCert",
                "der": base64::engine::general_purpose::STANDARD.encode(CERT)}]},
            "trusted_files": {"c:/a/agent.exe": "ab".repeat(32)},
        }});
        let mut c = client(base(windows), host(agent()));
        let drives = BTreeMap::from([("C".to_string(), PathBuf::from("/tmp/c"))]);
        let p = load(&mut c, &drives).unwrap();
        assert_eq!(p.command_line, "\"C:\\a\\agent.exe\" -f");
        assert_eq!((p.pid, p.service.as_deref()), (4812, Some("WazuhSvc")));
        assert_eq!(p.environment, ["ComSpec=x", "windir=C:\\Windows"]);
        assert_eq!(p.time_zone.bias, -60);
        assert_eq!(p.time_zone.daylight_name, "W. Europe Daylight Time");
        assert_eq!(p.time_zone.standard_date.unwrap().month, 10);
        assert_eq!(p.time_zone.daylight_date.unwrap().hour, 2);
        assert_eq!((p.code_pages.ansi, p.code_pages.oem), (1252, 437));
        assert_eq!(
            p.system_module_directory.as_deref(),
            Some("C:\\Windows\\SysWOW64")
        );
        assert_eq!(p.cert_stores["ROOT"].len(), 1);
        assert_eq!(p.trusted_files[r"C:\A\AGENT.EXE"], [0xab; 32]);
    }

    #[test]
    fn refuses_hosts_it_cannot_run() {
        let drives = BTreeMap::new();
        let mut bad_pid = agent();
        bad_pid["pid"] = json!(4813);
        assert!(load(&mut client(base(json!({})), host(bad_pid)), &drives).is_err());
        let mut no_agent = host(agent());
        no_agent.as_object_mut().unwrap().remove("agent");
        let err = load(&mut client(base(json!({})), no_agent), &drives).unwrap_err();
        assert!(err.contains("agent"), "{err}");
        let mut cp = base(json!({}));
        cp["registry"]["keys"][CODE_PAGE]["ACP"]["data"] = json!("932");
        let err = load(&mut client(cp, host(agent())), &drives).unwrap_err();
        assert!(err.contains("932"), "{err}");
    }
}
