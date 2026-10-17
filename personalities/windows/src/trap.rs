//! Call-time traps for imports we do not implement.
//!
//! Binding logs each gap once. Its IAT slots then point at a stub of its
//! own, so a call to it is reported too, with the address it came from,
//! and the process stops (CLAUDE.md rule 4: never silently stubbed).
//!
//! The stub realigns the stack first: agent code keeps it only 4-byte
//! aligned, and the Rust handler expects 16. The handler never returns,
//! so nothing needs restoring.
//!
//! ```text
//! 8B 0C 24    mov ecx, [esp]      ; the agent's return address
//! 83 E4 F0    and esp, -16
//! 83 EC 08    sub esp, 8
//! 51          push ecx
//! 68 imm32    push gap id
//! B8 imm32    mov eax, trap_called
//! FF D0       call eax
//! ```

use std::sync::Mutex;

use crate::gap::Gap;
use crate::map::{MapError, Mapped};
use crate::pe::Protection;

const STUB_SIZE: usize = 32;
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
        code[0..10].copy_from_slice(&[0x8b, 0x0c, 0x24, 0x83, 0xe4, 0xf0, 0x83, 0xec, 0x08, 0x51]);
        code[10] = 0x68;
        code[11..15].copy_from_slice(&id.to_le_bytes());
        code[15] = 0xb8;
        code[16..20].copy_from_slice(&(trap_called as *const () as u32).to_le_bytes());
        code[20..22].copy_from_slice(&[0xff, 0xd0]);

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
