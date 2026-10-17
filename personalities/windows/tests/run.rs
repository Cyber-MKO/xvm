//! End-to-end tests of the `xvm-windows-run` binary. 32-bit only.

#![cfg(all(target_arch = "x86", target_os = "linux"))]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use common::fixtures;

#[test]
fn sigterm_stops_a_service_through_the_dispatcher() {
    let Some(dir) = fixtures() else { return };
    let profile = dir.join("service-profile.toml");
    std::fs::write(
        &profile,
        format!(
            r#"
schema = 1
[host]
name = "XVM-TEST"
os = "windows"
[windows]
drives = {{ C = "{}" }}
[windows.agent]
command_line = 'C:\service.exe'
current_directory = 'C:\'
pid = 4812
service = 'XvmTestSvc'
[windows.time_zone]
key_name = 'UTC'
standard_name = 'Coordinated Universal Time'
daylight_name = 'Coordinated Universal Time'
bias = 0
"#,
            dir.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_xvm-windows-run"))
        .arg(&profile)
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
