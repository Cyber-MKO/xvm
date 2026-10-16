//! Module table tests: emulated system DLLs, bundled DLLs from the search
//! path, calls into emulated functions and call-time traps. 32-bit only.

#![cfg(all(target_arch = "x86", target_os = "linux"))]

mod common;

use std::path::Path;
use std::process::Command;

use common::fixtures;
use xvm_windows::gap::{Gap, GapKind};
use xvm_windows::image::{ExportTarget, Image};
use xvm_windows::process::{Module, Process};
use xvm_windows::thread::ThreadEnv;

fn process(dir: &Path, file: &str) -> Process {
    let mut process = Process::new(vec![dir.to_path_buf()]);
    process.load(&dir.join(file)).unwrap();
    process
}

fn export(module: &Module, name: &str) -> u32 {
    match module.exports.by_name(name).unwrap().target {
        ExportTarget::Rva(rva) => module.base() + rva,
        ref other => panic!("{other:?}"),
    }
}

fn gap(module: &str, symbol: &str) -> Gap {
    Gap {
        module: module.into(),
        kind: GapKind::Import,
        dll: "kernel32.dll".into(),
        symbol: symbol.into(),
    }
}

#[test]
fn loads_dependencies_first_and_records_gaps() {
    let Some(dir) = fixtures() else { return };
    let p = process(dir, "importer.exe");

    let order: Vec<_> = p.modules().iter().map(|m| m.name.as_str()).collect();
    assert_eq!(order.last(), Some(&"importer.exe"));
    assert_eq!(order.len(), 3, "{order:?}");
    assert!(order.contains(&"kernel32.dll") && order.contains(&"sample.dll"));

    let kernel32 = p.module("KERNEL32.DLL").unwrap();
    assert!(kernel32.emulated && kernel32.path.is_none());
    let sample = p.module("sample").unwrap();
    assert!(!sample.emulated && sample.is_dll);
    let exe = p.module("importer.exe").unwrap();
    assert!(!exe.is_dll && exe.entry_point.is_some());

    // GetLastError is implemented; the other two kernel32 imports are not.
    let mut gaps = p.gaps().to_vec();
    gaps.sort_by(|a, b| a.symbol.cmp(&b.symbol));
    assert_eq!(
        gaps,
        [
            gap("importer.exe", "#99"),
            gap("importer.exe", "GetTickCount")
        ]
    );

    // The IAT, read back from the mapped executable.
    let file = Image::layout(
        "importer.exe",
        &std::fs::read(dir.join("importer.exe")).unwrap(),
    )
    .unwrap();
    let slot = |dll: &str, symbol: &str| {
        let d = file
            .imports()
            .unwrap()
            .into_iter()
            .find(|d| d.dll == dll)
            .unwrap();
        let i = d
            .imports
            .iter()
            .find(|i| i.symbol.to_string() == symbol)
            .unwrap();
        // SAFETY: the slot lies inside the committed, readable image.
        unsafe { *((exe.base() + i.iat_rva) as *const u32) }
    };
    assert_eq!(slot("sample.dll", "add"), export(sample, "add"));
    assert_eq!(
        slot("kernel32.dll", "GetLastError"),
        export(kernel32, "GetLastError")
    );
    assert_ne!(slot("kernel32.dll", "GetTickCount"), 0);
    assert_ne!(
        slot("kernel32.dll", "GetTickCount"),
        slot("kernel32.dll", "#99")
    );
}

#[test]
fn emulated_module_has_a_walkable_pe_image() {
    let Some(dir) = fixtures() else { return };
    let p = process(dir, "calls.dll");
    let kernel32 = p.module("kernel32.dll").unwrap();

    // SAFETY: SizeOfImage bytes from the base are mapped and readable; the
    // headers say how many.
    let image = unsafe {
        let base = kernel32.base() as *const u8;
        let lfanew = *(base.add(0x3c) as *const u32) as usize;
        let size = *(base.add(lfanew + 24 + 56) as *const u32) as usize;
        Image::layout("kernel32.dll", std::slice::from_raw_parts(base, size)).unwrap()
    };
    assert_eq!(image.base, kernel32.base());
    let exports = image.exports().unwrap().unwrap();
    assert_eq!(exports.dll_name, "kernel32.dll");
    assert_eq!(exports, kernel32.exports);
}

#[test]
fn agent_code_calls_emulated_functions() {
    let Some(dir) = fixtures() else { return };
    let p = process(dir, "calls.dll");
    let calls = p.module("calls.dll").unwrap();
    // SAFETY: cdecl export taking and returning a 32-bit value.
    let round_trip: extern "C" fn(u32) -> u32 =
        unsafe { std::mem::transmute(export(calls, "last_error_round_trip") as usize) };

    let env = ThreadEnv::install(p.tls()).unwrap();
    assert_eq!(round_trip(1234), 1234);
    assert_eq!(round_trip(0), 0);
    // The code lives in this thread's TEB.
    // SAFETY: the TEB page is mapped while env lives.
    let stored = unsafe { *((env.teb() + 0x34) as *const u32) };
    assert_eq!(stored, 0);
    assert_eq!(round_trip(0xdead), 0xdead);

    // Another thread has its own last-error value.
    std::thread::scope(|s| {
        s.spawn(|| {
            let _env = ThreadEnv::install(p.tls()).unwrap();
            assert_eq!(round_trip(7), 7);
        });
    });
    // SAFETY: as above.
    assert_eq!(unsafe { *((env.teb() + 0x34) as *const u32) }, 0xdead);
}

/// Child half of `calling_a_gap_reports_it_and_aborts`.
#[test]
fn trap_child() {
    if std::env::var_os("XVM_TRAP_CHILD").is_none() {
        return;
    }
    let dir = fixtures().unwrap();
    let p = process(dir, "calls.dll");
    let call_missing: extern "C" fn() -> u32 = unsafe {
        // SAFETY: cdecl export with no arguments.
        std::mem::transmute(export(p.module("calls.dll").unwrap(), "call_missing") as usize)
    };
    let _env = ThreadEnv::install(p.tls()).unwrap();
    call_missing();
    unreachable!("the trap returned");
}

#[test]
fn calling_a_gap_reports_it_and_aborts() {
    if fixtures().is_none() {
        return;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "trap_child", "--nocapture", "--test-threads=1"])
        .env("XVM_TRAP_CHILD", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("gap call kernel32.dll!GetTickCount from calls.dll at 0x"),
        "{stderr}"
    );
}

#[test]
fn start_up_runs_dll_main_before_the_entry_point() {
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let runtime = Runtime::new(process(dir, "startup.exe"));
    let thread = runtime.attach().unwrap();
    // The exit code is DllMain's reason * 10 + how often it ran.
    assert_eq!(runtime.run_main(&thread).unwrap(), 11);
    assert!(runtime.lock().modules().iter().all(|m| m.initialized));
    // Initialising again runs nothing twice.
    runtime.initialize(&thread).unwrap();
    assert_eq!(runtime.run_main(&thread).unwrap(), 11);
}

#[test]
fn start_up_stops_when_dll_main_fails() {
    use xvm_windows::runtime::{Runtime, StartError};

    let Some(dir) = fixtures() else { return };
    let runtime = Runtime::new(process(dir, "failing.exe"));
    let thread = runtime.attach().unwrap();
    assert_eq!(
        runtime.run_main(&thread),
        Err(StartError::DllMainFailed("faildll.dll".into()))
    );
}
