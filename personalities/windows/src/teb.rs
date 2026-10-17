//! Thread environment block layout.
//!
//! Field offsets come from the `NT_TIB` structure (winnt.h) and the `TEB`
//! structure (winternl.h) on Microsoft Learn. We fill only the fields agent
//! code reads directly through `fs`; see "TEB fields" in docs/api/windows.md.

/// One page, like Windows. Covers everything up to the TLS slots.
pub const TEB_SIZE: usize = 0x1000;

pub const EXCEPTION_LIST: usize = 0x00;
pub const STACK_BASE: usize = 0x04;
pub const STACK_LIMIT: usize = 0x08;
pub const FIBER_DATA: usize = 0x10;
pub const SELF: usize = 0x18;
pub const THREAD_LOCAL_STORAGE_POINTER: usize = 0x2c;
/// Behind `GetLastError` and `SetLastError`.
pub const LAST_ERROR_VALUE: usize = 0x34;
/// `TlsSlots[64]`, behind `TlsAlloc` and `TlsGetValue`.
pub const TLS_SLOTS: usize = 0xe10;

/// Marks the end of the SEH chain in `ExceptionList`.
pub const SEH_CHAIN_END: u32 = 0xffff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TebInit {
    /// Address the TEB lives at; stored in `Self`.
    pub teb: u32,
    /// Highest stack address (exclusive), as `NT_TIB.StackBase`.
    pub stack_base: u32,
    /// Lowest stack address, as `NT_TIB.StackLimit`.
    pub stack_limit: u32,
    /// Array of per-module implicit TLS blocks, indexed by TLS index.
    pub tls_pointer: u32,
}

/// Write a fresh TEB into `buf`. Fields we do not model stay zero.
pub fn write(buf: &mut [u8; TEB_SIZE], init: &TebInit) {
    buf.fill(0);
    let mut put = |off: usize, value: u32| buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    put(EXCEPTION_LIST, SEH_CHAIN_END);
    put(STACK_BASE, init.stack_base);
    put(STACK_LIMIT, init.stack_limit);
    // FiberData stays 0 until ConvertThreadToFiber is implemented.
    put(SELF, init.teb);
    put(THREAD_LOCAL_STORAGE_POINTER, init.tls_pointer);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn writes_tib_fields() {
        let mut buf = [0xaau8; TEB_SIZE];
        let init = TebInit {
            teb: 0x7ffd_e000,
            stack_base: 0x0030_0000,
            stack_limit: 0x0020_0000,
            tls_pointer: 0x0050_0000,
        };
        write(&mut buf, &init);
        assert_eq!(read(&buf, EXCEPTION_LIST), SEH_CHAIN_END);
        assert_eq!(read(&buf, STACK_BASE), 0x0030_0000);
        assert_eq!(read(&buf, STACK_LIMIT), 0x0020_0000);
        assert_eq!(read(&buf, FIBER_DATA), 0);
        assert_eq!(read(&buf, SELF), 0x7ffd_e000);
        assert_eq!(read(&buf, THREAD_LOCAL_STORAGE_POINTER), 0x0050_0000);
        assert!(buf[TLS_SLOTS..TLS_SLOTS + 64 * 4].iter().all(|&b| b == 0));
    }
}
