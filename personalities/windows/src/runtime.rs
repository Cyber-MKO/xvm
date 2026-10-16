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
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::process::{InitStep, Process};
use crate::thread::{DLL_PROCESS_ATTACH, ThreadEnv};

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
}

/// The calling thread, inside a process. Leaves it on drop.
pub struct Attached {
    env: ThreadEnv,
    previous: Option<Runtime>,
}

impl Attached {
    pub fn teb(&self) -> u32 {
        self.env.teb()
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = self.previous.take());
    }
}

impl Runtime {
    pub fn new(process: Process) -> Runtime {
        Runtime {
            process: Arc::new(Mutex::new(process)),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, Process> {
        self.process.lock().unwrap()
    }

    /// Give the calling thread a TEB with this process's TLS and make the
    /// process current for emulated calls on it.
    pub fn attach(&self) -> io::Result<Attached> {
        let env = ThreadEnv::install(self.lock().tls())?;
        let previous = CURRENT.with(|c| c.borrow_mut().replace(self.clone()));
        Ok(Attached { env, previous })
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
unsafe fn run_init(step: &InitStep) -> Result<(), StartError> {
    for &callback in &step.tls_callbacks {
        // SAFETY: PIMAGE_TLS_CALLBACK is
        // void NTAPI (PVOID DllHandle, DWORD Reason, PVOID Reserved).
        let f: extern "stdcall" fn(u32, u32, u32) =
            unsafe { std::mem::transmute(callback as usize) };
        f(step.base, DLL_PROCESS_ATTACH, 0);
    }
    if let Some(dll_main) = step.dll_main {
        // SAFETY: BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID).
        let f: extern "stdcall" fn(u32, u32, u32) -> i32 =
            unsafe { std::mem::transmute(dll_main as usize) };
        if f(step.base, DLL_PROCESS_ATTACH, 0) == 0 {
            return Err(StartError::DllMainFailed(step.module.clone()));
        }
    }
    Ok(())
}
