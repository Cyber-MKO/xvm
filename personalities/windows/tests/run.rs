//! End-to-end tests of the `xvm-windows-run` binary. 32-bit only.

#![cfg(all(target_arch = "x86", target_os = "linux"))]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use serde_json::json;

use common::fixtures;

#[test]
fn sigterm_stops_a_service_through_the_dispatcher() {
    let Some(dir) = fixtures() else { return };
    let base = json!({
        "schema": 1, "kind": "base-image", "name": "test-base", "os": "windows",
        "source": {"golden_capture": "synthetic"},
        "registry": {"keys": {
            r"HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation": {
                "TimeZoneKeyName": {"type": "REG_SZ", "data": "UTC"},
                "Bias": {"type": "REG_DWORD", "data": 0},
                "StandardBias": {"type": "REG_DWORD", "data": 0},
                "DaylightBias": {"type": "REG_DWORD", "data": 0},
                "StandardStart": {"type": "REG_BINARY", "data": "00".repeat(16)},
                "DaylightStart": {"type": "REG_BINARY", "data": "00".repeat(16)},
            },
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\UTC": {
                "Std": {"type": "REG_SZ", "data": "Coordinated Universal Time"},
                "Dlt": {"type": "REG_SZ", "data": "Coordinated Universal Time"},
            },
            r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage": {
                "ACP": {"type": "REG_SZ", "data": "1252"},
                "OEMCP": {"type": "REG_SZ", "data": "437"},
            },
        }},
    });
    let host = json!({
        "schema": 1, "kind": "host-profile", "name": "xvm-test", "base": "test-base",
        "os": "windows", "identity": {"hostname": "XVM-TEST"},
        "agent": {"product": "wazuh", "version": "4.14.2", "pid": 4812,
                  "command_line": "C:\\service.exe", "current_directory": "C:\\",
                  "service": "XvmTestSvc"},
    });
    let (socket, name) = xvm_windows::testing::serve(base, host);

    let mut child = Command::new(env!("CARGO_BIN_EXE_xvm-windows-run"))
        .arg("--engine")
        .arg(&socket)
        .args(["--host", &name, "--drive"])
        .arg(format!("C={}", dir.display()))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut seen = Vec::new();
    for line in lines.by_ref() {
        let line = line.unwrap();
        let running = line == "service XvmTestSvc: SERVICE_RUNNING";
        seen.push(line);
        if running {
            break;
        }
    }
    assert!(
        seen.iter().any(|l| l.ends_with("SERVICE_RUNNING")),
        "{seen:?}"
    );

    // SAFETY: signalling our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    seen.extend(lines.map(Result::unwrap));
    let status = child.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(1),
        "start() returns 1 after a clean stop: {seen:?}"
    );
    assert!(
        seen.contains(&"service XvmTestSvc: SERVICE_STOPPED".to_string()),
        "{seen:?}"
    );
}
