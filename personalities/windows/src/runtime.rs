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
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, Process> {
        self.process.lock().unwrap()
    }

    /// The process's waitable-object hub.
    pub fn sync(&self) -> &SyncHub {
        &self.sync
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
                let _ = tell.send(thread.thread().clone());
                let steps = runtime.lock().thread_steps();
                for step in &steps {
                    // SAFETY: initialised modules, and this thread has a TEB.
                    unsafe { notify(step, DLL_THREAD_ATTACH) };
                }
                let code = start();
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
