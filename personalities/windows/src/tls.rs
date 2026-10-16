//! Implicit TLS: the `.tls` templates of loaded modules.
//!
//! Follows "The .tls Section" in the PE format specification. Each module
//! with a TLS directory gets the next index, written to its
//! `AddressOfIndex`. Every thread gets a copy of each template, reached
//! through `ThreadLocalStoragePointer[index]` in its TEB.

use std::alloc::{self, Layout};

use crate::image::Image;
use crate::pe::PeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsTemplate {
    pub module: String,
    /// Final load address of the module, passed to its callbacks.
    pub module_base: u32,
    pub index: u32,
    /// Initialised data copied for each thread.
    pub data: Vec<u8>,
    /// Zero bytes that follow the data.
    pub zero_fill: u32,
    pub alignment: usize,
    /// TLS callbacks (virtual addresses), called on attach and detach.
    pub callbacks: Vec<u32>,
}

/// The TLS templates of every loaded module, in index order.
#[derive(Debug, Default)]
pub struct ProcessTls {
    templates: Vec<TlsTemplate>,
}

impl ProcessTls {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn templates(&self) -> &[TlsTemplate] {
        &self.templates
    }

    /// Give `image` the next TLS index and record its template. Call after
    /// the image is rebased to its final address and before it is copied
    /// into place. Returns the index, or `None` if the image has no TLS.
    pub fn register(&mut self, image: &mut Image) -> Result<Option<u32>, PeError> {
        let Some(tls) = image.tls()? else {
            return Ok(None);
        };
        let start = image.va_to_rva(tls.raw_data_start)? as usize;
        let end = match tls.raw_data_end {
            va if va == tls.raw_data_start => start,
            va => image.va_to_rva(va)? as usize,
        };
        if end < start {
            return Err(PeError::Malformed("TLS data ends before it starts".into()));
        }
        let index = self.templates.len() as u32;
        if tls.index_address != 0 {
            let rva = image.va_to_rva(tls.index_address)?;
            image.write_u32(rva, index)?;
        }
        self.templates.push(TlsTemplate {
            module: image.module.clone(),
            module_base: image.base,
            index,
            data: image.memory[start..end].to_vec(),
            zero_fill: tls.zero_fill,
            alignment: tls.alignment(),
            callbacks: tls.callbacks.clone(),
        });
        Ok(Some(index))
    }
}

/// One thread's copy of a TLS template.
#[derive(Debug)]
pub struct TlsBlock {
    ptr: *mut u8,
    layout: Layout,
}

impl TlsBlock {
    pub fn new(template: &TlsTemplate) -> TlsBlock {
        let len = template.data.len() + template.zero_fill as usize;
        let layout = Layout::from_size_align(len.max(1), template.alignment)
            .expect("TLS alignment is a power of two up to 8 KiB");
        // SAFETY: layout has a non-zero size.
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        // SAFETY: ptr holds at least data.len() bytes; zero fill is done.
        unsafe { ptr.copy_from_nonoverlapping(template.data.as_ptr(), template.data.len()) };
        TlsBlock { ptr, layout }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn bytes(&self) -> &[u8] {
        // SAFETY: ptr holds layout.size() initialised bytes.
        unsafe { std::slice::from_raw_parts(self.ptr, self.layout.size()) }
    }
}

impl Drop for TlsBlock {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout.
        unsafe { alloc::dealloc(self.ptr, self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_copies_data_then_zero_fill() {
        let template = TlsTemplate {
            module: "a.dll".into(),
            module_base: 0x1000_0000,
            index: 0,
            data: vec![1, 2, 3],
            zero_fill: 5,
            alignment: 64,
            callbacks: Vec::new(),
        };
        let block = TlsBlock::new(&template);
        assert_eq!(block.bytes(), [1, 2, 3, 0, 0, 0, 0, 0]);
        assert_eq!(block.as_ptr() as usize % 64, 0);
    }
}
