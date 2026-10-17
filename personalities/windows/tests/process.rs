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
    // ntdll.dll and kernel32.dll come first in every process, as on Windows.
    assert_eq!(
        order,
        ["ntdll.dll", "kernel32.dll", "sample.dll", "importer.exe"]
    );

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
        [gap("importer.exe", "#99"), gap("importer.exe", "Beep")]
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
    assert_ne!(slot("kernel32.dll", "Beep"), 0);
    assert_ne!(slot("kernel32.dll", "Beep"), slot("kernel32.dll", "#99"));
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
        stderr.contains("gap call kernel32.dll!Beep from calls.dll at 0x"),
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
fn setjmp_and_longjmp_cross_agent_frames() {
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let runtime = Runtime::new(process(dir, "jump.exe"));
    let thread = runtime.attach().unwrap();
    assert_eq!(runtime.run_main(&thread).unwrap(), 71);
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

#[test]
fn module_handles_and_proc_addresses_through_kernel32() {
    use std::collections::BTreeMap;
    use std::ffi::c_char;
    use xvm_windows::paths::DriveMap;
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let mut p = process(dir, "importer.exe");
    p.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), dir.to_path_buf())]));
    p.params.current_directory = r"C:\".into();
    let runtime = Runtime::new(p);
    let _thread = runtime.attach().unwrap();

    let (k32, exe, sample) = {
        let p = runtime.lock();
        let base = |n: &str| p.module(n).unwrap().base();
        let k32 = p.module("kernel32.dll").unwrap();
        let f = |n: &str| k32.export_address(n).unwrap() as usize;
        (
            [
                f("GetModuleHandleA"),
                f("GetProcAddress"),
                f("GetLastError"),
                f("GetModuleHandleW"),
                f("GetModuleHandleExW"),
            ],
            base("importer.exe"),
            base("sample.dll"),
        )
    };
    // SAFETY: the emulated exports have these stdcall signatures.
    let (get_module_a, get_proc, get_last_error, get_module_w) = unsafe {
        (
            std::mem::transmute::<usize, extern "stdcall" fn(*const c_char) -> u32>(k32[0]),
            std::mem::transmute::<usize, extern "stdcall" fn(u32, *const c_char) -> u32>(k32[1]),
            std::mem::transmute::<usize, extern "stdcall" fn() -> u32>(k32[2]),
            std::mem::transmute::<usize, extern "stdcall" fn(*const u16) -> u32>(k32[3]),
        )
    };

    assert_eq!(get_module_a(std::ptr::null()), exe);
    assert_eq!(get_module_a(c"SAMPLE".as_ptr()), sample);
    let wide: Vec<u16> = "Sample.DLL\0".encode_utf16().collect();
    assert_eq!(get_module_w(wide.as_ptr()), sample);
    assert_eq!(get_module_a(c"c:\\IMPORTER.EXE".as_ptr()), exe);
    // A trailing dot means "no extension".
    assert_eq!(get_module_a(c"sample.".as_ptr()), 0);
    assert_eq!(get_last_error(), 126);

    let add = runtime
        .lock()
        .module("sample.dll")
        .unwrap()
        .export_address("add")
        .unwrap();
    assert_eq!(get_proc(sample, c"add".as_ptr()), add);
    // Ordinal 7 is exported without a name.
    assert_ne!(get_proc(sample, 7 as *const c_char), 0);
    assert_eq!(get_proc(sample, c"missing".as_ptr()), 0);
    assert_eq!(get_last_error(), 127);
    let k32_base = runtime.lock().module("kernel32.dll").unwrap().base();
    assert_eq!(get_proc(k32_base, c"GetLastError".as_ptr()), k32[2] as u32);
    assert_eq!(get_proc(0x1234, c"add".as_ptr()), 0);

    // GetModuleHandleExW: by an address inside the image, or by name.
    // SAFETY: the emulated export has this stdcall signature.
    let get_module_ex = unsafe {
        std::mem::transmute::<usize, extern "stdcall" fn(u32, *const u16, *mut u32) -> i32>(k32[4])
    };
    let count = || runtime.lock().module("sample.dll").unwrap().load_count;
    let before = count();
    let mut found = 0;
    assert_eq!(get_module_ex(6, add as *const u16, &mut found), 1);
    assert_eq!((found, count()), (sample, before), "unchanged refcount");
    assert_eq!(get_module_ex(0, wide.as_ptr(), &mut found), 1);
    assert_eq!((found, count()), (sample, before + 1));
    assert_eq!(get_module_ex(4, 0x10 as *const u16, &mut found), 0);
    assert_eq!((found, get_last_error()), (0, 126));
    found = 1;
    assert_eq!(get_module_ex(3, wide.as_ptr(), &mut found), 0);
    assert_eq!((found, get_last_error()), (0, 87));

    // Misses that Windows would answer are gaps; ordinary misses are not.
    let before = runtime.lock().gaps().len();
    assert_eq!(get_proc(k32_base, c"Beep".as_ptr()), 0);
    assert_ne!(get_module_a(c"ntdll.dll".as_ptr()), 0, "always loaded");
    assert_eq!(get_module_a(c"kernelbase.dll".as_ptr()), 0);
    let p = runtime.lock();
    let new: Vec<_> = p.gaps()[before..]
        .iter()
        .map(|g| (g.kind, g.dll.as_str(), g.symbol.as_str()))
        .collect();
    assert!(
        new.contains(&(GapKind::ProcAddress, "kernel32.dll", "Beep")),
        "{new:?}"
    );
    assert!(
        new.contains(&(GapKind::Module, "kernelbase.dll", "*")),
        "{new:?}"
    );
    assert!(!new.iter().any(|g| g.2 == "missing"));
}

/// Call a cdecl export of the main module that takes nothing.
fn call_export(runtime: &xvm_windows::runtime::Runtime, module: &str, name: &str) -> u32 {
    let address = runtime
        .lock()
        .module(module)
        .unwrap()
        .export_address(name)
        .unwrap();
    // SAFETY: fixture exports used this way are cdecl, take nothing and
    // return a 32-bit value.
    let f: extern "C" fn() -> u32 = unsafe { std::mem::transmute(address as usize) };
    f()
}

#[test]
fn service_dispatcher_runs_service_main_and_delivers_stop() {
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let mut p = process(dir, "service.exe");
    p.params.service = Some("XvmTestSvc".into());
    let runtime = Runtime::new(p);

    let main = {
        let runtime = runtime.clone();
        std::thread::spawn(move || {
            let thread = runtime.attach().unwrap();
            runtime.run_main(&thread).unwrap()
        })
    };
    // Wait for the service to report SERVICE_RUNNING (4).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while runtime.lock().services.status.map(|s| s.current_state) != Some(4) {
        assert!(
            std::time::Instant::now() < deadline,
            "service never reported RUNNING"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    runtime.service_control(1);
    assert_eq!(
        main.join().unwrap(),
        1,
        "dispatcher returns TRUE after STOPPED"
    );

    let _thread = runtime.attach().unwrap();
    assert_eq!(call_export(&runtime, "service.exe", "service_argc"), 1);
    let name = call_export(&runtime, "service.exe", "service_name");
    // SAFETY: the fixture returns a NUL-terminated buffer of its own.
    let name = unsafe { std::ffi::CStr::from_ptr(name as usize as *const std::ffi::c_char) };
    assert_eq!(name.to_str().unwrap(), "XvmTestSvc");
    assert_eq!(call_export(&runtime, "service.exe", "service_controls"), 1);
    let main_teb = call_export(&runtime, "service.exe", "service_main_teb");
    let dispatcher_teb = call_export(&runtime, "service.exe", "service_dispatcher_teb");
    assert!(main_teb != 0 && dispatcher_teb != 0);
    assert_ne!(
        main_teb, dispatcher_teb,
        "ServiceMain runs on its own thread"
    );
    assert_eq!(
        call_export(&runtime, "service.exe", "service_handler_teb"),
        dispatcher_teb,
        "the handler runs on the dispatcher thread"
    );
    assert_eq!(runtime.lock().services.status.unwrap().current_state, 1);
}

#[test]
fn service_dispatcher_fails_outside_the_service_manager() {
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let runtime = Runtime::new(process(dir, "service.exe"));
    let thread = runtime.attach().unwrap();
    // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
    assert_eq!(runtime.run_main(&thread).unwrap(), 1063);
}

#[test]
fn new_threads_send_thread_attach_and_detach() {
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let runtime = Runtime::new(process(dir, "startup.exe"));
    let thread = runtime.attach().unwrap();
    runtime.run_main(&thread).unwrap();

    let count = |reason: u32| {
        let address = runtime
            .lock()
            .module("initdll.dll")
            .unwrap()
            .export_address("dll_reason_count")
            .unwrap();
        // SAFETY: int dll_reason_count(unsigned long), cdecl.
        let f: extern "C" fn(u32) -> i32 = unsafe { std::mem::transmute(address as usize) };
        f(reason)
    };
    assert_eq!((count(1), count(2), count(3)), (1, 0, 0));
    let teb = runtime
        .spawn(|| {
            let teb: u32;
            // SAFETY: reading fs:0x18 on a thread with a TEB.
            unsafe { std::arch::asm!("mov {0}, dword ptr fs:[0x18]", out(reg) teb) };
            teb
        })
        .unwrap()
        .join()
        .unwrap();
    assert_ne!(teb, 0);
    assert_ne!(teb, thread.teb());
    assert_eq!((count(1), count(2), count(3)), (1, 1, 1));
}

#[test]
fn enum_process_modules_lists_the_executable_first() {
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let runtime = Runtime::new(process(dir, "modules.exe"));
    let _thread = runtime.attach().unwrap();
    let (address, mut bases, exe) = {
        let p = runtime.lock();
        let psapi = p.module("psapi.dll").unwrap();
        let address = psapi.export_address("EnumProcessModules").unwrap();
        let bases: Vec<u32> = p.modules().iter().map(|m| m.base()).collect();
        (address, bases, p.module("modules.exe").unwrap().base())
    };
    // SAFETY: BOOL WINAPI EnumProcessModules(HANDLE, HMODULE*, DWORD, LPDWORD).
    let f: extern "stdcall" fn(u32, *mut u32, u32, *mut u32) -> i32 =
        unsafe { std::mem::transmute(address as usize) };
    let mut needed = 0;
    assert_eq!(f(u32::MAX, std::ptr::null_mut(), 0, &mut needed), 1);
    assert_eq!(needed as usize, bases.len() * 4);

    let mut short = [0u32; 1];
    assert_eq!(
        f(u32::MAX, short.as_mut_ptr(), 4, &mut needed),
        1,
        "TRUE even when short"
    );
    assert_eq!(short[0], exe);

    let mut list = vec![0u32; bases.len()];
    assert_eq!(f(u32::MAX, list.as_mut_ptr(), needed, &mut needed), 1);
    assert_eq!(list[0], exe);
    list.sort();
    bases.sort();
    assert_eq!(list, bases);
}

#[test]
fn module_file_names_come_from_drives_and_the_system_directory() {
    use std::collections::BTreeMap;
    use xvm_windows::paths::DriveMap;
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let mut p = process(dir, "modules.exe");
    p.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), dir.to_path_buf())]));
    p.params.current_directory = r"C:\".into();
    let runtime = Runtime::new(p);
    let _thread = runtime.attach().unwrap();
    let (address, psapi) = {
        let p = runtime.lock();
        let m = p.module("psapi.dll").unwrap();
        (m.export_address("GetModuleFileNameExW").unwrap(), m.base())
    };
    // SAFETY: DWORD WINAPI GetModuleFileNameExW(HANDLE, HMODULE, LPWSTR, DWORD).
    let f: extern "stdcall" fn(u32, u32, *mut u16, u32) -> u32 =
        unsafe { std::mem::transmute(address as usize) };
    let name = |module: u32, size: usize| {
        let mut buf = vec![0xffffu16; size];
        let n = f(u32::MAX, module, buf.as_mut_ptr(), size as u32);
        assert_eq!(buf[n as usize], 0, "NUL-terminated");
        String::from_utf16(&buf[..n as usize]).unwrap()
    };

    assert_eq!(name(0, 260), r"C:\modules.exe");
    assert_eq!(name(0, 5), r"C:\m", "truncated to the buffer");

    // Without a system module directory, emulated modules have no path.
    let before = runtime.lock().gaps().len();
    let mut buf = [0u16; 260];
    assert_eq!(f(u32::MAX, psapi, buf.as_mut_ptr(), 260), 0);
    assert_eq!(runtime.lock().gaps().len(), before + 1);

    runtime.lock().params.system_module_directory = Some(r"C:\Windows\SysWOW64".into());
    assert_eq!(name(psapi, 260), r"C:\Windows\SysWOW64\psapi.dll");
}

static NOTICES: std::sync::Mutex<Vec<(u32, String, u32)>> = std::sync::Mutex::new(Vec::new());

/// A DLL notification callback that records the reason, the full name as
/// a C string, and the context.
extern "stdcall" fn record_notice(reason: u32, data: *const u32, context: u32) {
    // SAFETY: LDR_DLL_NOTIFICATION_DATA { Flags, FullDllName, ... } and a
    // UNICODE_STRING { Length, MaximumLength, Buffer }, read as callers do.
    let name = unsafe {
        let full = *data.add(1) as *const u32;
        let mut p = *full.add(1) as *const u16;
        let mut units = Vec::new();
        while *p != 0 {
            units.push(*p);
            p = p.add(1);
        }
        String::from_utf16(&units).unwrap()
    };
    NOTICES.lock().unwrap().push((reason, name, context));
}

#[test]
fn load_library_maps_initialises_and_notifies() {
    use std::collections::BTreeMap;
    use std::ffi::c_char;
    use xvm_windows::paths::DriveMap;
    use xvm_windows::process::DllNotification;
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let mut p = process(dir, "importer.exe");
    p.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), dir.to_path_buf())]));
    p.params.current_directory = r"C:\".into();
    p.dll_notifications.push(DllNotification {
        cookie: 1,
        function: record_notice as *const () as u32,
        context: 0x77,
    });
    let runtime = Runtime::new(p);
    let thread = runtime.attach().unwrap();
    runtime.initialize(&thread).unwrap();

    let k32 = |n: &str| {
        let p = runtime.lock();
        p.module("kernel32.dll").unwrap().export_address(n).unwrap() as usize
    };
    // SAFETY: the emulated exports have these stdcall signatures.
    let (load, get_proc, last_error) = unsafe {
        (
            std::mem::transmute::<usize, extern "stdcall" fn(*const c_char) -> u32>(k32(
                "LoadLibraryA",
            )),
            std::mem::transmute::<usize, extern "stdcall" fn(u32, *const c_char) -> u32>(k32(
                "GetProcAddress",
            )),
            std::mem::transmute::<usize, extern "stdcall" fn() -> u32>(k32("GetLastError")),
        )
    };

    let base = load(c"INITDLL".as_ptr());
    assert_ne!(base, 0);
    let count = get_proc(base, c"dll_reason_count".as_ptr());
    // SAFETY: int dll_reason_count(unsigned long), cdecl.
    let count: extern "C" fn(u32) -> i32 = unsafe { std::mem::transmute(count as usize) };
    assert_eq!(count(1), 1, "DllMain ran with DLL_PROCESS_ATTACH");
    assert_eq!(load(c"initdll.dll".as_ptr()), base, "already loaded");
    assert_eq!(count(1), 1, "and not initialised twice");
    assert_eq!(runtime.lock().module("initdll.dll").unwrap().load_count, 2);

    let notices = NOTICES.lock().unwrap().clone();
    assert!(
        notices.contains(&(1, r"C:\initdll.dll".to_string(), 0x77)),
        "{notices:?}"
    );

    assert_eq!(load(c"missing.dll".as_ptr()), 0);
    assert_eq!(last_error(), 126);
    assert!(runtime.lock().gaps().iter().any(|g| g.dll == "missing.dll"));
    let advapi = load(c"advapi32".as_ptr());
    assert_eq!(
        Some(advapi),
        runtime.lock().module("advapi32.dll").map(|m| m.base())
    );
}

#[test]
fn virtual_query_and_protect_work_on_image_pages() {
    use xvm_windows::runtime::Runtime;

    let Some(dir) = fixtures() else { return };
    let runtime = Runtime::new(process(dir, "importer.exe"));
    let _thread = runtime.attach().unwrap();
    let (query, protect, sample, add) = {
        let p = runtime.lock();
        let k32 = p.module("kernel32.dll").unwrap();
        let sample = p.module("sample.dll").unwrap();
        (
            k32.export_address("VirtualQuery").unwrap() as usize,
            k32.export_address("VirtualProtect").unwrap() as usize,
            sample.base(),
            sample.export_address("add").unwrap(),
        )
    };
    // SAFETY: the emulated exports have these stdcall signatures.
    let (query, protect) = unsafe {
        (
            std::mem::transmute::<usize, extern "stdcall" fn(u32, *mut u32, u32) -> u32>(query),
            std::mem::transmute::<usize, extern "stdcall" fn(u32, u32, u32, *mut u32) -> i32>(
                protect,
            ),
        )
    };
    let mut info = [0u32; 7];
    assert_eq!(query(add, info.as_mut_ptr(), 28), 28);
    let [base, alloc_base, _, size, state, prot, kind] = info;
    assert_eq!(base, add & !0xfff);
    assert_eq!(alloc_base, sample);
    assert!(size >= 0x1000);
    assert_eq!(
        (state, prot, kind),
        (0x1000, 0x20, 0x100_0000),
        "committed, PAGE_EXECUTE_READ, image"
    );

    // The pseudo-relocation dance: make the code page writable, write,
    // then restore it.
    let mut old = 0;
    assert_eq!(protect(add, 4, 0x40, &mut old), 1);
    assert_eq!(old, 0x20);
    // SAFETY: the page is writable now; the byte is put back unchanged.
    unsafe {
        let p = add as *mut u8;
        let byte = p.read();
        p.write(byte);
    }
    assert_eq!(protect(add, 4, old, &mut old), 1);
    assert_eq!(old, 0x40);
    query(sample, info.as_mut_ptr(), 28);
    assert_eq!(info[5], 0x02, "headers are read only");
    assert_eq!(query(0x10, info.as_mut_ptr(), 28), 0, "outside images");
}
