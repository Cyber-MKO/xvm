//! Running a loaded process.
//!
//! In production one Linux process hosts one Windows process. Tests run
//! several side by side, so emulated functions do not use a global: each
//! thread that enters a process with `Runtime::attach` records it, and
//! `with_current` finds it again from inside an emulated call.
//!
//! Start-up follows the order the PE format and the DllMain documentation
//! describe. For each module, dependencies first, its TLS callbacks run and
//! then its `DllMain`, with `DLL_PROCESS_ATTACH`. The executable's entry
//! point runs last. Agent code always runs with the process lock released,
//! because it calls back into emulated functions that take it.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

use crate::process::{InitStep, Process};
use crate::sync::{SyncHub, ThreadObject};
use crate::thread::{DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, ThreadEnv};

/// Smallest stack a new thread gets, whatever the image asks for.
const MIN_STACK: usize = 256 * 1024;

thread_local! {
    static CURRENT: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    NoMainModule,
    /// `DllMain` returned FALSE for this module.
    DllMainFailed(String),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::NoMainModule => write!(f, "no executable loaded"),
            StartError::DllMainFailed(m) => write!(f, "DllMain of {m} returned FALSE"),
        }
    }
}

impl std::error::Error for StartError {}

/// A shared handle to one process.
#[derive(Clone)]
pub struct Runtime {
    process: Arc<Mutex<Process>>,
    services: Arc<ServiceEvents>,
    sync: Arc<SyncHub>,
    file_locks: Arc<crate::filelock::FileLocks>,
}

/// What the service control dispatcher waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEvent {
    /// A control code for the service's handler, such as
    /// `SERVICE_CONTROL_STOP` (1).
    Control(u32),
    /// The service registered its handler; held controls can go out.
    HandlerRegistered,
    /// The service reported `SERVICE_STOPPED`.
    Stopped,
}

#[derive(Default)]
struct ServiceEvents {
    queue: Mutex<VecDeque<ServiceEvent>>,
    ready: Condvar,
}

/// The calling thread, inside a process. Leaves it on drop.
pub struct Attached {
    env: ThreadEnv,
    previous: Option<Runtime>,
    runtime: Runtime,
    thread: Arc<ThreadObject>,
}

impl Attached {
    pub fn teb(&self) -> u32 {
        self.env.teb()
    }

    /// The thread object other threads wait on.
    pub fn thread(&self) -> &Arc<ThreadObject> {
        &self.thread
    }
}

thread_local! {
    static THREAD: RefCell<Option<Arc<ThreadObject>>> = const { RefCell::new(None) };
}

/// The calling thread's object, while it is attached to a process.
pub fn current_thread() -> Option<Arc<ThreadObject>> {
    THREAD.with(|t| t.borrow().clone())
}

impl Drop for Attached {
    fn drop(&mut self) {
        let teb = self.env.teb();
        self.runtime.lock().tebs.retain(|&t| t != teb);
        // A thread that ends without an exit code of its own exits with 0.
        self.runtime.sync().finish_thread(&self.thread, 0);
        THREAD.with(|t| *t.borrow_mut() = None);
        CURRENT.with(|c| *c.borrow_mut() = self.previous.take());
    }
}

impl Runtime {
    pub fn new(process: Process) -> Runtime {
        Runtime {
            process: Arc::new(Mutex::new(process)),
            services: Arc::default(),
            sync: Arc::default(),
            file_locks: Arc::default(),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, Process> {
        self.process.lock().unwrap()
    }

    /// The process's waitable-object hub.
    pub fn sync(&self) -> &SyncHub {
        &self.sync
    }

    /// The process's byte-range file locks.
    pub fn file_locks(&self) -> &crate::filelock::FileLocks {
        &self.file_locks
    }

    /// Give the calling thread a TEB with this process's TLS and make the
    /// process current for emulated calls on it.
    pub fn attach(&self) -> io::Result<Attached> {
        let env = {
            let mut process = self.lock();
            process.threads_started = true;
            let env = ThreadEnv::install(process.tls())?;
            process.tebs.push(env.teb());
            env
        };
        let previous = CURRENT.with(|c| c.borrow_mut().replace(self.clone()));
        // SAFETY: gettid has no preconditions. IDs match GetCurrentThreadId.
        let thread = Arc::new(ThreadObject::new((unsafe { libc::gettid() } as u32) << 2));
        THREAD.with(|t| *t.borrow_mut() = Some(thread.clone()));
        Ok(Attached {
            env,
            previous,
            runtime: self.clone(),
            thread,
        })
    }

    /// Hand a control code to the process's service, as the Service Control
    /// Manager does. The control plane uses this to stop a host.
    pub fn service_control(&self, code: u32) {
        self.post_service_event(ServiceEvent::Control(code));
    }

    pub(crate) fn post_service_event(&self, event: ServiceEvent) {
        self.services.queue.lock().unwrap().push_back(event);
        self.services.ready.notify_all();
    }

    /// Block until the next service event.
    pub(crate) fn next_service_event(&self) -> ServiceEvent {
        let mut queue = self.services.queue.lock().unwrap();
        loop {
            if let Some(event) = queue.pop_front() {
                return event;
            }
            queue = self.services.ready.wait(queue).unwrap();
        }
    }

    /// Start a Windows thread running `start`. The thread gets a TEB and
    /// TLS, and every initialised module sees `DLL_THREAD_ATTACH` before
    /// `start` and `DLL_THREAD_DETACH` after it, last module first. The
    /// stack is the main module's `SizeOfStackReserve`.
    pub fn spawn<F>(&self, start: F) -> io::Result<JoinHandle<u32>>
    where
        F: FnOnce() -> u32 + Send + 'static,
    {
        self.spawn_thread(0, start).map(|(handle, _)| handle)
    }

    /// As `spawn`, with a stack of at least `stack` bytes. Returns once
    /// the thread exists, with the object other threads wait on.
    pub fn spawn_thread<F>(
        &self,
        stack: usize,
        start: F,
    ) -> io::Result<(JoinHandle<u32>, Arc<ThreadObject>)>
    where
        F: FnOnce() -> u32 + Send + 'static,
    {
        self.spawn_suspendable(stack, false, start)
    }

    /// As `spawn_thread`; with `suspended`, the thread does nothing, not
    /// even its attach notifications, until it is resumed.
    pub fn spawn_suspendable<F>(
        &self,
        stack: usize,
        suspended: bool,
        start: F,
    ) -> io::Result<(JoinHandle<u32>, Arc<ThreadObject>)>
    where
        F: FnOnce() -> u32 + Send + 'static,
    {
        let runtime = self.clone();
        let stack = self
            .lock()
            .main_module()
            .map_or(0, |m| m.stack_reserve as usize)
            .max(stack)
            .max(MIN_STACK);
        let (tell, told) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .stack_size(stack)
            .spawn(move || {
                let thread = runtime.attach().expect("thread environment");
                if suspended {
                    thread.thread().suspend_at_start();
                }
                let _ = tell.send(thread.thread().clone());
                thread.thread().wait_until_resumed();
                let steps = runtime.lock().thread_steps();
                for step in &steps {
                    // SAFETY: initialised modules, and this thread has a TEB.
                    unsafe { notify(step, DLL_THREAD_ATTACH) };
                }
                let code = run_exitable(start);
                for step in steps.iter().rev() {
                    // SAFETY: as above.
                    unsafe { notify(step, DLL_THREAD_DETACH) };
                }
                // Signaled only after the detach notifications, as on
                // Windows.
                runtime.sync().finish_thread(thread.thread(), code);
                drop(thread);
                code
            })?;
        let object = told
            .recv()
            .map_err(|_| io::Error::other("the new thread could not enter the process"))?;
        Ok((handle, object))
    }

    /// Initialise every module that is not yet initialised.
    pub fn initialize(&self, _thread: &Attached) -> Result<(), StartError> {
        let steps = self.lock().take_pending_init();
        for step in steps {
            // SAFETY: steps only name committed modules with bound imports,
            // and `_thread` proves this thread has a TEB.
            unsafe { run_init(&step)? };
        }
        Ok(())
    }

    /// Initialise everything, then call the executable's entry point and
    /// return its result as the exit code.
    pub fn run_main(&self, thread: &Attached) -> Result<u32, StartError> {
        self.initialize(thread)?;
        let entry = {
            let process = self.lock();
            let main = process.main_module().ok_or(StartError::NoMainModule)?;
            main.entry_point.ok_or(StartError::NoMainModule)?
        };
        // SAFETY: an executable's entry point takes no arguments; with none,
        // stdcall and cdecl agree.
        let entry: extern "stdcall" fn() -> u32 = unsafe { std::mem::transmute(entry as usize) };
        Ok(entry())
    }
}

// A thread ends early (`_endthreadex`, `ExitThread`) by jumping back to
// the frame that started its routine, the way `longjmp` does. Only agent
// frames and the emulated function's own frame lie in between, and none
// of them holds anything to drop. `xvm_call_exitable(f, arg, slot)` saves
// its frame pointer in `*slot` and calls `f(arg)` with a 16-byte aligned
// stack; `xvm_exit_to(frame, code)` returns `code` from that call.
#[cfg(all(target_arch = "x86", target_os = "linux"))]
std::arch::global_asm!(
    ".globl xvm_call_exitable",
    "xvm_call_exitable:",
    "push ebp",
    "mov ebp, esp",
    "push ebx",
    "push esi",
    "push edi",
    "mov eax, [ebp + 16]",
    "mov [eax], ebp",
    "mov ecx, [ebp + 12]",
    "and esp, -16",
    "sub esp, 12",
    "push ecx",
    "call [ebp + 8]",
    "lea esp, [ebp - 12]",
    "pop edi",
    "pop esi",
    "pop ebx",
    "pop ebp",
    "ret",
    ".globl xvm_exit_to",
    "xvm_exit_to:",
    "mov eax, [esp + 8]",
    "mov ebp, [esp + 4]",
    "lea esp, [ebp - 12]",
    "pop edi",
    "pop esi",
    "pop ebx",
    "pop ebp",
    "ret",
);

unsafe extern "C" {
    fn xvm_call_exitable(
        f: extern "C" fn(*mut std::ffi::c_void) -> u32,
        arg: *mut std::ffi::c_void,
        slot: *mut u32,
    ) -> u32;
    fn xvm_exit_to(frame: u32, code: u32) -> !;
}

thread_local! {
    /// Where `run_exitable` keeps the frame `exit_thread` returns to; 0
    /// outside a thread routine.
    static EXIT_SLOT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Run `start` so that `exit_thread` can end it early with an exit code.
fn run_exitable<F: FnOnce() -> u32>(start: F) -> u32 {
    extern "C" fn call<F: FnOnce() -> u32>(arg: *mut std::ffi::c_void) -> u32 {
        // SAFETY: arg is the Option<F> below, taken once.
        let start = unsafe { (*arg.cast::<Option<F>>()).take() }.expect("routine");
        start()
    }
    let mut start = Some(start);
    let mut frame = 0u32;
    let slot: *mut u32 = &mut frame;
    EXIT_SLOT.with(|s| s.set(slot as u32));
    // SAFETY: the assembly keeps the C calling convention and fills the
    // slot before `call` runs.
    let code = unsafe { xvm_call_exitable(call::<F>, (&mut start as *mut Option<F>).cast(), slot) };
    EXIT_SLOT.with(|s| s.set(0));
    code
}

/// End the calling Windows thread's routine with `code`, as `ExitThread`
/// does. Returns only if the thread did not start through `spawn_thread`
/// (the main thread), so the caller can handle that.
pub(crate) fn exit_thread(code: u32) {
    let slot = EXIT_SLOT.with(|s| s.get());
    if slot == 0 {
        return;
    }
    // SAFETY: slot points at run_exitable's frame variable, still live
    // because this thread is inside it.
    let frame = unsafe { *(slot as *const u32) };
    // SAFETY: the frame belongs to this thread's xvm_call_exitable call.
    unsafe { xvm_exit_to(frame, code) }
}

/// The process the calling thread is attached to.
pub fn current() -> Option<Runtime> {
    CURRENT.with(|c| c.borrow().clone())
}

/// Run `f` on the process the calling thread is attached to. For emulated
/// functions, which agent code only reaches from an attached thread.
pub fn with_current<R>(f: impl FnOnce(&mut Process) -> R) -> R {
    let runtime = CURRENT.with(|c| c.borrow().clone());
    let runtime = runtime.expect("emulated call from a thread outside any process");
    let mut process = runtime.lock();
    f(&mut process)
}

/// # Safety
///
/// The module must be committed with its imports bound, and the calling
/// thread must have a TEB.
pub(crate) unsafe fn run_init(step: &InitStep) -> Result<(), StartError> {
    // SAFETY: the caller's contract.
    match unsafe { notify(step, DLL_PROCESS_ATTACH) } {
        0 => Err(StartError::DllMainFailed(step.module.clone())),
        _ => Ok(()),
    }
}

/// Run a module's TLS callbacks, then its `DllMain`, with `reason`.
/// Returns what `DllMain` returned, or TRUE if there is none.
///
/// # Safety
///
/// As for `run_init`.
unsafe fn notify(step: &InitStep, reason: u32) -> i32 {
    for &callback in &step.tls_callbacks {
        // SAFETY: PIMAGE_TLS_CALLBACK is
        // void NTAPI (PVOID DllHandle, DWORD Reason, PVOID Reserved).
        let f: extern "stdcall" fn(u32, u32, u32) =
            unsafe { std::mem::transmute(callback as usize) };
        f(step.base, reason, 0);
    }
    match step.dll_main {
        Some(dll_main) => {
            // SAFETY: BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID).
            let f: extern "stdcall" fn(u32, u32, u32) -> i32 =
                unsafe { std::mem::transmute(dll_main as usize) };
            f(step.base, reason, 0)
        }
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_can_end_from_deep_inside_its_routine() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static AFTER: AtomicBool = AtomicBool::new(false);
        #[inline(never)]
        fn deep(n: u32) -> u32 {
            if n == 0 {
                exit_thread(7);
                AFTER.store(true, Ordering::SeqCst);
                return 1;
            }
            deep(n - 1) + 1
        }
        let runtime = Runtime::new(crate::process::Process::new(Vec::new()));
        let (handle, thread) = runtime.spawn_thread(0, || deep(5)).unwrap();
        assert_eq!(handle.join().unwrap(), 7);
        assert_eq!(thread.exit_code(), Some(7));
        assert!(!AFTER.load(Ordering::SeqCst), "nothing after the exit runs");
        let (handle, _) = runtime.spawn_thread(0, || 3).unwrap();
        assert_eq!(handle.join().unwrap(), 3, "a normal return still works");
    }
}
