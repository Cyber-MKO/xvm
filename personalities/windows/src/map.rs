//! Map a laid-out image into this process so its code can run natively.
//!
//! Only built for `i686-unknown-linux-gnu`: the agent's i386 code runs inside
//! a 32-bit Linux process (docs/phase1-sizing.md, decision 1).

use std::fmt;
use std::io;
use std::ptr;

use crate::image::Image;
use crate::pe::{PeError, Protection};

#[derive(Debug)]
pub enum MapError {
    Io(io::Error),
    Pe(PeError),
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapError::Io(e) => write!(f, "mapping image: {e}"),
            MapError::Pe(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for MapError {}

impl From<PeError> for MapError {
    fn from(e: PeError) -> Self {
        MapError::Pe(e)
    }
}

/// An image mapped into the address space. Unmapped on drop.
#[derive(Debug)]
pub struct Mapped {
    base: u32,
    len: usize,
}

impl Mapped {
    pub fn base(&self) -> u32 {
        self.base
    }

    /// Address of `rva` inside the mapping.
    pub fn address(&self, rva: u32) -> *const u8 {
        (self.base as usize + rva as usize) as *const u8
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        // SAFETY: base and len describe the mapping created in `reserve`.
        unsafe { libc::munmap(self.base as usize as *mut libc::c_void, self.len) };
    }
}

/// Reserve, rebase and commit in one step. Use `reserve` and
/// `Mapped::commit` when imports or TLS must be set up in between.
pub fn map(image: &mut Image) -> Result<Mapped, MapError> {
    let mapped = reserve(image)?;
    mapped.commit(image)?;
    Ok(mapped)
}

/// Reserve memory at the preferred base, or anywhere else and rebase the
/// image to it. Nothing is copied yet: the image can still be bound and
/// have its TLS index assigned, at its final address, before `commit`.
pub fn reserve(image: &mut Image) -> Result<Mapped, MapError> {
    let page = page_size();
    if (image.headers.section_alignment as usize) < page {
        return Err(PeError::Unsupported("section alignment below the page size").into());
    }
    let len = round_up(image.memory.len(), page);
    let mapped = Mapped {
        base: reserve_at(image.base, len)?,
        len,
    };
    image.rebase(mapped.base)?;
    Ok(mapped)
}

impl Mapped {
    /// Copy the image in and apply section protections.
    pub fn commit(&self, image: &Image) -> Result<(), MapError> {
        if image.base != self.base || image.memory.len() > self.len {
            return Err(PeError::Unsupported("committing an image to another reservation").into());
        }
        // SAFETY: the mapping is len >= memory.len() bytes and ours. It is
        // writable until the protections below are applied.
        unsafe {
            ptr::copy_nonoverlapping(
                image.memory.as_ptr(),
                self.base as usize as *mut u8,
                image.memory.len(),
            );
        }
        let page = page_size();
        protect(self, 0, image.headers.size_of_headers as usize, READ_ONLY)?;
        for s in &image.headers.sections {
            let start = s.virtual_address as usize;
            let end = round_up(start + s.mapped_size() as usize, page);
            protect(self, start, end - start, s.protection())?;
        }
        Ok(())
    }
}

const READ_ONLY: Protection = Protection {
    read: true,
    write: false,
    execute: false,
};

fn reserve_at(preferred: u32, len: usize) -> Result<u32, MapError> {
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let hint = preferred as usize as *mut libc::c_void;
    // SAFETY: anonymous mapping; MAP_FIXED_NOREPLACE never clobbers others.
    let at = unsafe { libc::mmap(hint, len, prot, flags | libc::MAP_FIXED_NOREPLACE, -1, 0) };
    if at == hint {
        return Ok(preferred);
    }
    if at != libc::MAP_FAILED {
        // Kernels before 4.17 treat the flag as a hint and may map elsewhere.
        // SAFETY: `at` is the mapping just created.
        unsafe { libc::munmap(at, len) };
    }
    // SAFETY: anonymous mapping at an address the kernel picks.
    let at = unsafe { libc::mmap(ptr::null_mut(), len, prot, flags, -1, 0) };
    if at == libc::MAP_FAILED {
        return Err(MapError::Io(io::Error::last_os_error()));
    }
    Ok(at as usize as u32)
}

fn protect(mapped: &Mapped, offset: usize, len: usize, p: Protection) -> Result<(), MapError> {
    if len == 0 {
        return Ok(());
    }
    let mut prot = libc::PROT_NONE;
    if p.read {
        prot |= libc::PROT_READ;
    }
    if p.write {
        prot |= libc::PROT_WRITE;
    }
    if p.execute {
        prot |= libc::PROT_EXEC;
    }
    let addr = (mapped.base as usize + offset) as *mut libc::c_void;
    // SAFETY: the range lies inside the mapping (sections are validated
    // against SizeOfImage and len is rounded to whole pages of it).
    if unsafe { libc::mprotect(addr, len.min(mapped.len - offset), prot) } != 0 {
        return Err(MapError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

fn round_up(n: usize, align: usize) -> usize {
    n.div_ceil(align) * align
}
