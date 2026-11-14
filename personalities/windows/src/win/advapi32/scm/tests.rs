use super::*;
use crate::process::Process;
use crate::runtime::Runtime;
use crate::win::kernel32::error::GetLastError;

fn host() -> (Runtime, crate::runtime::Attached) {
    let base = json!({
        "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
        "source": {"golden_capture": "synthetic"},
        "services": [
            {"name": "LSM", "display_name": "Local Session Manager", "state": "running",
             "start_mode": "auto", "type": "share_process", "error_control": "critical",
             "path": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
             "account": "LocalSystem", "description": "Core Windows Service that manages local user sessions."},
            {"name": "Spooler", "display_name": "Print Spooler", "state": "running",
             "start_mode": "auto", "type": "own_process", "error_control": "normal",
             "path": "C:\\Windows\\System32\\spoolsv.exe", "account": "LocalSystem"},
            {"name": "W32Time", "display_name": "Windows Time", "state": "stopped",
             "start_mode": "manual"},
        ],
        "processes": [
            {"id": "system", "image": "System", "pid": 4, "user": "NT AUTHORITY\\SYSTEM"},
            {"id": "lsm", "image": "svchost.exe", "pid": 900, "parent": "system", "session": 0,
             "command_line": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p -s LSM",
             "user": "NT AUTHORITY\\SYSTEM", "start_offset_s": 3},
            {"id": "spool", "image": "spoolsv.exe", "pid": 1500, "parent": "system", "session": 0,
             "command_line": "C:\\Windows\\System32\\spoolsv.exe",
             "user": "NT AUTHORITY\\SYSTEM", "start_offset_s": 5},
        ],
    });
    let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                      "os": "windows", "identity": {"hostname": "H"}});
    let mut process = Process::new(Vec::new());
    process.engine = Some(facts::test_engine(base, host));
    let runtime = Runtime::new(process);
    let thread = runtime.attach().unwrap();
    (runtime, thread)
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn at(p: *const u8, o: usize) -> u32 {
    // SAFETY: inside the test's buffer.
    unsafe { p.add(o).cast::<u32>().read_unaligned() }
}

fn str_at(p: u32) -> String {
    // SAFETY: a NUL-terminated string inside the test's buffer.
    unsafe { wide(p as usize as *const u16) }.unwrap()
}

#[test]
fn services_from_the_profile() {
    let (runtime, _thread) = host();
    let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), 4);
    assert_ne!(scm, 0);
    let none = std::ptr::null();
    let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
    // Running Win32 services: the size first, then the records.
    assert_eq!(
        EnumServicesStatusExW(
            scm,
            0,
            0x30,
            1,
            std::ptr::null_mut(),
            0,
            &mut needed,
            &mut count,
            &mut resume,
            none
        ),
        0
    );
    assert_eq!(GetLastError(), ERROR_MORE_DATA);
    let mut buf = vec![0u8; needed as usize];
    assert_eq!(
        EnumServicesStatusExW(
            scm,
            0,
            0x30,
            1,
            buf.as_mut_ptr(),
            needed,
            &mut needed,
            &mut count,
            &mut resume,
            none
        ),
        1
    );
    assert_eq!(count, 2);
    let p = buf.as_ptr();
    let names: Vec<String> = (0..2).map(|i| str_at(at(p, 44 * i))).collect();
    assert_eq!(names, ["LSM", "Spooler"]);
    assert_eq!(str_at(at(p, 4)), "Local Session Manager");
    assert_eq!(
        (at(p, 8), at(p, 12), at(p, 36)),
        (0x20, SERVICE_RUNNING, 900),
        "-s LSM"
    );
    assert_eq!(
        (at(p, 44 + 8), at(p, 44 + 36)),
        (0x10, 1500),
        "its own path"
    );

    // Stopped services only: W32Time, whose type is not in the profile.
    let mut buf = vec![0u8; 512];
    assert_eq!(
        EnumServicesStatusExW(
            scm,
            0,
            0x30,
            2,
            buf.as_mut_ptr(),
            512,
            &mut needed,
            &mut count,
            &mut resume,
            none
        ),
        1
    );
    assert_eq!(
        (count, str_at(at(buf.as_ptr(), 0)), at(buf.as_ptr(), 12)),
        (1, "W32Time".into(), SERVICE_STOPPED)
    );

    let lsm = OpenServiceW(scm, w("lsm").as_ptr(), 1);
    assert_ne!(lsm, 0);
    let mut config = vec![0u8; 1024];
    assert_eq!(
        QueryServiceConfigW(lsm, config.as_mut_ptr(), 1024, &mut needed),
        1
    );
    let c = config.as_ptr();
    assert_eq!(
        (at(c, 0), at(c, 4), at(c, 8)),
        (0x20, 2, 3),
        "share, auto, critical"
    );
    assert_eq!(
        str_at(at(c, 12)),
        "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p"
    );
    assert_eq!(
        (str_at(at(c, 28)), str_at(at(c, 32))),
        ("LocalSystem".into(), "Local Session Manager".into())
    );
    assert_eq!(
        QueryServiceConfigW(lsm, config.as_mut_ptr(), 10, &mut needed),
        0
    );
    assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    assert!(needed > 36);

    let mut desc = vec![0u8; 256];
    assert_eq!(
        QueryServiceConfig2W(lsm, 1, desc.as_mut_ptr(), 256, &mut needed),
        1
    );
    assert!(str_at(at(desc.as_ptr(), 0)).starts_with("Core Windows Service"));
    let spooler = OpenServiceW(scm, w("Spooler").as_ptr(), 1);
    assert_eq!(
        QueryServiceConfig2W(spooler, 1, desc.as_mut_ptr(), 256, &mut needed),
        1
    );
    assert_eq!(str_at(at(desc.as_ptr(), 0)), "", "no description: empty");
    assert_eq!(
        QueryServiceConfig2W(spooler, 2, desc.as_mut_ptr(), 256, &mut needed),
        0
    );

    assert_eq!(OpenServiceW(scm, w("Nothing").as_ptr(), 1), 0);
    assert_eq!(GetLastError(), ERROR_SERVICE_DOES_NOT_EXIST);
    for h in [lsm, spooler, scm] {
        assert_eq!(CloseServiceHandle(h), 1);
    }
    assert_eq!(CloseServiceHandle(scm), 0);
    let gaps: Vec<String> = runtime
        .lock()
        .gaps()
        .iter()
        .map(|g| g.symbol.clone())
        .collect();
    assert_eq!(gaps.len(), 3, "{gaps:?}");
}
