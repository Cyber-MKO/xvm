//! Per-thread Windows environment: a TEB reachable through `fs`.
//!
//! On i386 Windows, `fs` addresses the current thread's TEB. glibc on i386
//! uses `gs` for its own thread pointer, so `fs` is free. We give each thread
//! a TEB page and point a per-thread GDT TLS entry at it with
//! `set_thread_area(2)`, then load `fs` with that entry's selector.

use std::io;
use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::teb::{self, TEB_SIZE, TebInit};
use crate::tls::{ProcessTls, TlsBlock};

/// `fdwReason` values for DLL entry points and TLS callbacks.
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

/// GDT entry used for `fs` in every thread. The kernel picks it on first use.
/// GDT TLS entries are per thread, so each thread sets the same entry to
/// its own TEB.
static FS_ENTRY: AtomicU32 = AtomicU32::new(u32::MAX);

/// `struct user_desc` from asm/ldt.h.
#[repr(C)]
struct UserDesc {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    /// seg_32bit (bit 0), contents (1-2), read_exec_only (3),
    /// limit_in_pages (4), seg_not_present (5), useable (6).
    flags: u32,
}

const SEG_32BIT: u32 = 1 << 0;
const LIMIT_IN_PAGES: u32 = 1 << 4;
const USEABLE: u32 = 1 << 6;

/// The Windows view of the calling thread. Restores the previous `fs` and
/// frees the TEB on drop, so it must stay on the thread that installed it.
pub struct ThreadEnv {
    teb: *mut [u8; TEB_SIZE],
    previous_fs: u16,
    _tls_array: Box<[u32]>,
    _tls_blocks: Vec<TlsBlock>,
    _not_send: PhantomData<*const ()>,
}

impl ThreadEnv {
    /// Build a TEB for the calling thread, with a copy of every TLS template
    /// in `tls`, and point `fs` at it.
    pub fn install(tls: &ProcessTls) -> io::Result<ThreadEnv> {
        let (stack_limit, stack_base) = current_stack()?;
        let blocks: Vec<TlsBlock> = tls.templates().iter().map(TlsBlock::new).collect();
        let tls_array: Box<[u32]> = blocks.iter().map(|b| b.as_ptr() as u32).collect();

        // SAFETY: anonymous private page; checked for failure below.
        let page = unsafe {
            libc::mmap(
                ptr::null_mut(),
                TEB_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if page == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let env = ThreadEnv {
            teb: page.cast(),
            previous_fs: read_fs(),
            _tls_array: tls_array,
            _tls_blocks: blocks,
            _not_send: PhantomData,
        };
        let init = TebInit {
            teb: env.teb as u32,
            stack_base,
            stack_limit,
            tls_pointer: env._tls_array.as_ptr() as u32,
        };
        // SAFETY: the page is TEB_SIZE bytes, writable and only ours.
        teb::write(unsafe { &mut *env.teb }, &init);
        let selector = point_fs_entry_at(init.teb)?;
        // SAFETY: the selector names a present 32-bit data segment covering
        // the TEB page. glibc and Rust do not use fs on i386.
        unsafe { write_fs(selector) };
        Ok(env)
    }

    /// Address of this thread's TEB, as `NtCurrentTeb()` returns it.
    pub fn teb(&self) -> u32 {
        self.teb as u32
    }

    /// Call every TLS callback of every module with `reason`.
    ///
    /// # Safety
    ///
    /// Every module in `tls` must be mapped and committed, with imports
    /// bound, and its callbacks must be safe to run on this thread.
    pub unsafe fn run_tls_callbacks(&self, tls: &ProcessTls, reason: u32) {
        for template in tls.templates() {
            for &callback in &template.callbacks {
                // SAFETY: PIMAGE_TLS_CALLBACK is
                // void NTAPI (PVOID DllHandle, DWORD Reason, PVOID Reserved).
                let f: extern "stdcall" fn(u32, u32, u32) =
                    unsafe { std::mem::transmute(callback as usize) };
                f(template.module_base, reason, 0);
            }
        }
    }
}

impl Drop for ThreadEnv {
    fn drop(&mut self) {
        // SAFETY: restores the selector this thread had before install, then
        // frees the page nothing refers to any more.
        unsafe {
            write_fs(self.previous_fs);
            libc::munmap(self.teb.cast(), TEB_SIZE);
        }
    }
}

/// Lowest and one-past-highest address of the calling thread's stack.
fn current_stack() -> io::Result<(u32, u32)> {
    // SAFETY: attr is initialised by pthread_getattr_np and destroyed after.
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        let rc = libc::pthread_getattr_np(libc::pthread_self(), &mut attr);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        let mut addr = ptr::null_mut();
        let mut size = 0;
        let rc = libc::pthread_attr_getstack(&attr, &mut addr, &mut size);
        libc::pthread_attr_destroy(&mut attr);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok((addr as u32, (addr as usize + size) as u32))
    }
}

/// Point this thread's `fs` GDT entry at `base` and return its selector.
fn point_fs_entry_at(base: u32) -> io::Result<u16> {
    let mut desc = UserDesc {
        entry_number: FS_ENTRY.load(Ordering::Acquire),
        base_addr: base,
        // One page: limit 0 counted in 4 KiB pages.
        limit: 0,
        flags: SEG_32BIT | LIMIT_IN_PAGES | USEABLE,
    };
    // SAFETY: desc is a valid user_desc for the duration of the call.
    if unsafe { libc::syscall(libc::SYS_set_thread_area, &mut desc) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // The first thread fixes the entry. Another first-time thread can only
    // get the same free entry, since its GDT TLS entries mirror ours.
    let entry = match FS_ENTRY.compare_exchange(
        u32::MAX,
        desc.entry_number,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => desc.entry_number,
        Err(fixed) if fixed == desc.entry_number => fixed,
        Err(fixed) => {
            return Err(io::Error::other(format!(
                "fs GDT entry {fixed} already chosen, kernel gave {}",
                desc.entry_number
            )));
        }
    };
    // GDT selector, requested privilege level 3.
    Ok(((entry << 3) | 3) as u16)
}

fn read_fs() -> u16 {
    let fs: u16;
    // SAFETY: reading a segment register has no side effects.
    unsafe {
        std::arch::asm!("mov {0:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags))
    };
    fs
}

/// # Safety
///
/// `selector` must be null or name a usable data segment.
unsafe fn write_fs(selector: u16) {
    // SAFETY: the caller guarantees the selector is loadable.
    unsafe {
        std::arch::asm!("mov fs, {0:x}", in(reg) selector, options(nostack, preserves_flags))
    };
}
