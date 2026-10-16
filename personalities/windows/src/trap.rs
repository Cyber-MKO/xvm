//! Call-time traps for imports we do not implement.
//!
//! Binding logs each gap once. Its IAT slots then point at a stub of its
//! own, so a call to it is reported too, with the address it came from,
//! and the process stops (CLAUDE.md rule 4: never silently stubbed).
//!
//! ```text
//! 68 imm32    push gap id
//! B8 imm32    mov eax, trap_called
//! FF D0       call eax
//! ```

use std::sync::Mutex;

use crate::gap::Gap;
use crate::map::{MapError, Mapped};
use crate::pe::Protection;

const STUB_SIZE: usize = 16;
const PAGE: usize = 0x1000;

/// Gaps by trap id, for the handler. Shared by every process table.
static GAPS: Mutex<Vec<Gap>> = Mutex::new(Vec::new());

const READ_EXECUTE: Protection = Protection {
    read: true,
    write: false,
    execute: true,
};

const READ_WRITE: Protection = Protection {
    read: true,
    write: true,
    execute: false,
};

/// Pages of trap stubs.
#[derive(Debug, Default)]
pub struct Traps {
    pages: Vec<Mapped>,
    used: usize,
}

impl Traps {
    pub fn new() -> Self {
        Self::default()
    }

    /// A stub that reports `gap` when called.
    pub fn stub(&mut self, gap: &Gap) -> Result<u32, MapError> {
        let id = {
            let mut gaps = GAPS.lock().unwrap();
            gaps.push(gap.clone());
            (gaps.len() - 1) as u32
        };
        if self.pages.is_empty() || self.used + STUB_SIZE > PAGE {
            self.pages.push(Mapped::anonymous(0, PAGE)?);
            self.used = 0;
        }
        let page = self.pages.last().unwrap();
        let mut code = [0xccu8; STUB_SIZE];
        code[0] = 0x68;
        code[1..5].copy_from_slice(&id.to_le_bytes());
        code[5] = 0xb8;
        code[6..10].copy_from_slice(&(trap_called as *const () as u32).to_le_bytes());
        code[10..12].copy_from_slice(&[0xff, 0xd0]);

        page.set_protection(0, PAGE, READ_WRITE)?;
        // SAFETY: the page is writable now, and no stub in it can run while
        // the loader is still binding.
        unsafe { page.write(self.used, &code) };
        page.set_protection(0, PAGE, READ_EXECUTE)?;
        let address = page.base() + self.used as u32;
        self.used += STUB_SIZE;
        Ok(address)
    }
}

/// Reached from a stub through `call`, so as a cdecl function its first
/// argument is the id the stub pushed and its second is the return address
/// of the agent's own call.
extern "C" fn trap_called(id: u32, caller: u32) -> ! {
    let gap = GAPS
        .lock()
        .ok()
        .and_then(|gaps| gaps.get(id as usize).cloned());
    match gap {
        Some(gap) => eprintln!(
            "gap call {}!{} from {} at 0x{caller:08x}",
            gap.dll, gap.symbol, gap.module
        ),
        None => eprintln!("gap call with unknown trap id {id} at 0x{caller:08x}"),
    }
    std::process::abort()
}
