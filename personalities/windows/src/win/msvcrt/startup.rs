//! Start-up support called by the MinGW CRT start-up code.

use std::ffi::{CString, c_char};

use crate::cmdline;
use crate::gap::GapKind;
use crate::process::{AnsiCommandLine, MainArgs};
use crate::runtime::with_current;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("__getmainargs", __getmainargs as *const () as u32),
        ("__p__acmdln", __p__acmdln as *const () as u32),
        ("_onexit", _onexit as *const () as u32),
        ("exit", exit as *const () as u32),
        ("_exit", _exit as *const () as u32),
        ("_beginthreadex", _beginthreadex as *const () as u32),
        ("_endthreadex", _endthreadex as *const () as u32),
        ("_getpid", _getpid as *const () as u32),
        ("_initterm", _initterm as *const () as u32),
        ("__set_app_type", __set_app_type as *const () as u32),
        ("__p__fmode", __p__fmode as *const () as u32),
        ("__p__commode", __p__commode as *const () as u32),
        ("__lconv_init", __lconv_init as *const () as u32),
    ]
}

/// Exported variables, as (name, size in bytes).
pub(super) fn data() -> Vec<(&'static str, u32)> {
    // char **__initenv: the initial environment. The MinGW start-up code
    // stores envp from __getmainargs here.
    vec![("__initenv", 4)]
}

/// Splits the process command line into `argv` and gives the environment
/// as `envp`, both NULL-terminated, and sets `_newmode` from `start_info`.
/// Every call returns the same arrays. Returns 0.
extern "C" fn __getmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut c_char,
    envp: *mut *mut *mut c_char,
    do_wildcard: i32,
    start_info: *const i32,
) -> i32 {
    with_current(|p| {
        if do_wildcard != 0 {
            p.record_runtime_gap(
                GapKind::Feature,
                "msvcrt.dll",
                "__getmainargs wildcard expansion",
            );
        }
        if !start_info.is_null() {
            // SAFETY: _startupinfo is { int newmode; }.
            p.crt.newmode = unsafe { *start_info };
        }
        let params = &p.params;
        let args = p.crt.main_args.get_or_insert_with(|| {
            main_args(&cmdline::split(&params.command_line), &params.environment)
        });
        // SAFETY: the caller passes writable out-pointers.
        unsafe {
            *argc = (args.argv.len() - 1) as i32;
            *argv = args.argv.as_mut_ptr();
            *envp = args.envp.as_mut_ptr();
        }
    });
    0
}

/// Address of `_acmdln`, which points at the process command line.
#[allow(non_snake_case)]
extern "C" fn __p__acmdln() -> *mut *mut c_char {
    with_current(|p| {
        let command_line = &p.params.command_line;
        let acmdln = p.crt.acmdln.get_or_insert_with(|| {
            let string = CString::new(command_line.as_str()).expect("validated profile string");
            let variable = Box::new(string.as_ptr().cast_mut());
            AnsiCommandLine { string, variable }
        });
        &mut *acmdln.variable as *mut *mut c_char
    })
}

/// The process ID from the host profile, as `GetCurrentProcessId`.
extern "C" fn _getpid() -> i32 {
    with_current(|p| p.params.pid as i32)
}

/// Registers `function` to be called at normal process exit, after
/// functions registered later. Returns `function`.
extern "C" fn _onexit(function: u32) -> u32 {
    if function != 0 {
        with_current(|p| p.crt.onexit.push(function));
    }
    function
}

/// What `exit` does before the process ends: calls the `_onexit`
/// functions, last registered first, then writes every stream's waiting
/// output.
fn exit_steps() {
    while let Some(function) = with_current(|p| p.crt.onexit.pop()) {
        // SAFETY: _onexit_t is int (__cdecl *)(void).
        let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(function as usize) };
        f();
    }
    super::stdio::flush_all();
}

/// Ends the process normally with `status`, after `exit_steps`. Windows
/// would then stop the other threads and send `DLL_PROCESS_DETACH`; we
/// cannot stop threads yet, so the notifications are a logged gap.
extern "C" fn exit(status: i32) -> ! {
    exit_steps();
    with_current(|p| {
        p.record_runtime_gap(
            GapKind::Feature,
            "msvcrt.dll",
            "DLL_PROCESS_DETACH at process exit",
        );
        crate::registration::exit(p, status as u32);
    });
    std::process::exit(status)
}

/// Starts `start(arg)`, an `unsigned __stdcall` routine, on a new thread,
/// as `CreateThread` does. Returns the thread's handle (close it with
/// `CloseHandle`) and writes its ID to `id`; 0 with `errno` on failure.
extern "C" fn _beginthreadex(
    security: u32,
    stack_size: u32,
    start: u32,
    arg: u32,
    flags: u32,
    id: *mut u32,
) -> u32 {
    use crate::win::kernel32::thread::create_thread;
    match create_thread("_beginthreadex", security, stack_size, start, arg, flags) {
        Ok((handle, thread)) => {
            if !id.is_null() {
                // SAFETY: writable (the function's contract).
                unsafe { *id = thread };
            }
            handle
        }
        Err(code) => {
            super::errno::set(if code == 8 {
                super::errno::EAGAIN
            } else {
                super::errno::EINVAL
            });
            0
        }
    }
}

/// Ends the calling thread with `code`, as its routine's return would.
/// On the main thread, which no routine started, it is a logged gap and
/// the process ends.
extern "C" fn _endthreadex(code: u32) {
    crate::runtime::exit_thread(code);
    with_current(|p| {
        p.record_runtime_gap(
            GapKind::Feature,
            "msvcrt.dll",
            "_endthreadex on the main thread",
        );
        crate::registration::exit(p, code);
    });
    std::process::exit(code as i32)
}

/// Ends the process at once, without `exit_steps`.
extern "C" fn _exit(status: i32) -> ! {
    if crate::runtime::current().is_some() {
        with_current(|p| crate::registration::exit(p, status as u32));
    }
    // SAFETY: _exit has no preconditions.
    unsafe { libc::_exit(status) }
}

fn main_args(argv: &[String], environment: &[String]) -> MainArgs {
    // The profile only holds ASCII without NULs (hostconfig::load checks it).
    let mut strings: Vec<CString> = argv
        .iter()
        .chain(environment)
        .map(|s| CString::new(s.as_str()).expect("validated profile string"))
        .collect();
    let mut pointers: Vec<*mut c_char> =
        strings.iter_mut().map(|s| s.as_ptr().cast_mut()).collect();
    let env_pointers = pointers.split_off(argv.len());
    let terminate = |mut v: Vec<*mut c_char>| {
        v.push(std::ptr::null_mut());
        v
    };
    MainArgs {
        strings,
        argv: terminate(pointers),
        envp: terminate(env_pointers),
    }
}

/// Undocumented. Prepares the data `localeconv` returns. Ours builds that
/// data when `localeconv` is called, so there is nothing to prepare.
extern "C" fn __lconv_init() -> i32 {
    0
}

/// Address of `_fmode`, the default file translation mode.
#[allow(non_snake_case)]
extern "C" fn __p__fmode() -> *mut i32 {
    with_current(|p| &mut *p.crt.fmode as *mut i32)
}

/// Address of `_commode`, the default stream commit mode.
#[allow(non_snake_case)]
extern "C" fn __p__commode() -> *mut i32 {
    with_current(|p| &mut *p.crt.commode as *mut i32)
}

/// Records whether the program is a console (1) or GUI (2) application.
/// The CRT uses it to choose where runtime error messages go; ours always
/// go to stderr, since there is no GUI (rule 6).
extern "C" fn __set_app_type(app_type: u32) {
    with_current(|p| p.crt.app_type = app_type);
}

type Initializer = Option<extern "C" fn()>;

/// Calls every non-null function pointer in `[begin, end)`, in order.
extern "C" fn _initterm(begin: *const Initializer, end: *const Initializer) {
    let mut at = begin;
    while at < end {
        // SAFETY: the caller passes a table of function pointers, with NULL
        // entries allowed.
        if let Some(f) = unsafe { at.read() } {
            f();
        }
        // SAFETY: still inside or one past the table.
        at = unsafe { at.add(1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::sync::Mutex;

    #[test]
    fn set_app_type_is_kept_per_process() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        __set_app_type(1);
        assert_eq!(runtime.lock().crt.app_type, 1);
    }

    fn attached_with(command_line: &str, env: &[&str]) -> (Runtime, crate::runtime::Attached) {
        let mut process = Process::new(Vec::new());
        process.params.command_line = command_line.into();
        process.params.environment = env.iter().map(|s| s.to_string()).collect();
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        (runtime, thread)
    }

    fn strings(mut p: *mut *mut c_char) -> Vec<String> {
        let mut out = Vec::new();
        // SAFETY: a NULL-terminated array of C strings.
        unsafe {
            while !(*p).is_null() {
                out.push(std::ffi::CStr::from_ptr(*p).to_str().unwrap().to_string());
                p = p.add(1);
            }
        }
        out
    }

    #[test]
    fn getmainargs_splits_the_command_line_and_passes_the_environment() {
        let (runtime, _thread) = attached_with(
            r#""C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" -f "a b""#,
            &["A=1", r"Path=C:\Windows"],
        );
        let (mut argc, mut argv, mut envp) = (0, std::ptr::null_mut(), std::ptr::null_mut());
        let newmode = 1i32;
        assert_eq!(
            __getmainargs(&mut argc, &mut argv, &mut envp, 0, &newmode),
            0
        );
        assert_eq!(argc, 3);
        assert_eq!(
            strings(argv),
            [
                r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe",
                "-f",
                "a b"
            ]
        );
        assert_eq!(strings(envp), ["A=1", r"Path=C:\Windows"]);
        assert_eq!(runtime.lock().crt.newmode, 1);

        // A second call hands out the same arrays.
        let (mut argc2, mut argv2, mut envp2) = (0, std::ptr::null_mut(), std::ptr::null_mut());
        __getmainargs(&mut argc2, &mut argv2, &mut envp2, 0, std::ptr::null());
        assert_eq!((argc2, argv2, envp2), (argc, argv, envp));
        assert!(runtime.lock().gaps().is_empty());
    }

    #[test]
    fn getmainargs_logs_wildcard_expansion_as_a_gap_once() {
        let (runtime, _thread) = attached_with("prog *.log", &[]);
        let (mut argc, mut argv, mut envp) = (0, std::ptr::null_mut(), std::ptr::null_mut());
        for _ in 0..2 {
            __getmainargs(&mut argc, &mut argv, &mut envp, 1, std::ptr::null());
        }
        assert_eq!(strings(argv), ["prog", "*.log"]);
        let gaps = runtime.lock().gaps().to_vec();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].kind, GapKind::Feature);
    }

    #[test]
    fn acmdln_points_at_the_whole_command_line() {
        let line = r#""C:\a b\x.exe" -f  "q""#;
        let (_runtime, _thread) = attached_with(line, &[]);
        let variable = __p__acmdln();
        // SAFETY: points at the process's _acmdln, which points at a C string.
        let text = unsafe { std::ffi::CStr::from_ptr(*variable) };
        assert_eq!(text.to_str().unwrap(), line);
        assert_eq!(__p__acmdln(), variable);
    }

    #[test]
    fn getpid_reports_the_profile_pid() {
        let (runtime, _thread) = attached_with("prog", &[]);
        runtime.lock().params.pid = 1234 * 4;
        assert_eq!(_getpid(), 4936);
    }

    #[test]
    fn onexit_registers_in_order() {
        let (runtime, _thread) = attached_with("prog", &[]);
        assert_eq!(_onexit(0x1000), 0x1000);
        assert_eq!(_onexit(0x2000), 0x2000);
        assert_eq!(runtime.lock().crt.onexit, [0x1000, 0x2000]);
    }

    static EXITS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    extern "C" fn first() -> i32 {
        EXITS.lock().unwrap().push(1);
        0
    }
    extern "C" fn second() -> i32 {
        EXITS.lock().unwrap().push(2);
        // Registered while exiting: runs next.
        _onexit(third as *const () as u32);
        0
    }
    extern "C" fn third() -> i32 {
        EXITS.lock().unwrap().push(3);
        0
    }

    #[test]
    fn exit_runs_onexit_functions_last_first() {
        let (runtime, _thread) = attached_with("prog", &[]);
        _onexit(first as *const () as u32);
        _onexit(second as *const () as u32);
        exit_steps();
        assert_eq!(*EXITS.lock().unwrap(), [2, 3, 1]);
        assert!(runtime.lock().crt.onexit.is_empty());
    }

    #[test]
    fn underscore_exit_ends_the_process_with_its_status() {
        // SAFETY: the child only calls _exit.
        let child = unsafe { libc::fork() };
        if child == 0 {
            _exit(7);
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 7);
    }

    extern "stdcall" fn doubles(arg: u32) -> u32 {
        arg * 2
    }

    extern "stdcall" fn ends_early(arg: u32) -> u32 {
        _endthreadex(arg + 1);
        0
    }

    #[test]
    fn beginthreadex_runs_routines_that_return_or_end_early() {
        use crate::win::kernel32::sync::WaitForSingleObject;
        use crate::win::kernel32::thread::thread_of;
        let (_runtime, _thread) = attached_with("prog", &[]);
        let mut id = 0;
        let h = _beginthreadex(0, 0, doubles as *const () as u32, 21, 0, &mut id);
        assert_ne!((h, id), (0, 0));
        assert_eq!(WaitForSingleObject(h, u32::MAX), 0);
        assert_eq!(thread_of(h).unwrap().exit_code(), Some(42));
        let h = _beginthreadex(
            0,
            0,
            ends_early as *const () as u32,
            6,
            0,
            std::ptr::null_mut(),
        );
        WaitForSingleObject(h, u32::MAX);
        assert_eq!(thread_of(h).unwrap().exit_code(), Some(7));
        assert_eq!(_beginthreadex(0, 0, 0, 0, 0, std::ptr::null_mut()), 0);
        assert_eq!(super::super::errno::get(), super::super::errno::EINVAL);
    }

    #[test]
    fn lconv_init_succeeds() {
        assert_eq!(__lconv_init(), 0);
    }

    #[test]
    fn mode_globals_have_documented_defaults_and_stable_addresses() {
        let runtime = Runtime::new(Process::new(Vec::new()));
        let _thread = runtime.attach().unwrap();
        let fmode = __p__fmode();
        // SAFETY: points into the process's CRT state, alive with runtime.
        unsafe {
            assert_eq!(*fmode, crate::process::O_TEXT);
            assert_eq!(*__p__commode(), 0);
            *fmode = 0x8000;
        }
        assert_eq!(__p__fmode(), fmode);
        assert_eq!(*runtime.lock().crt.fmode, 0x8000);
    }

    static CALLS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    extern "C" fn one() {
        CALLS.lock().unwrap().push(1);
    }
    extern "C" fn two() {
        CALLS.lock().unwrap().push(2);
    }

    #[test]
    fn calls_entries_in_order_and_skips_null() {
        let table: [Initializer; 4] = [None, Some(one), None, Some(two)];
        let range = table.as_ptr_range();
        _initterm(range.start, range.end);
        assert_eq!(*CALLS.lock().unwrap(), [1, 2]);
        _initterm(range.start, range.start);
        assert_eq!(CALLS.lock().unwrap().len(), 2);
    }
}
