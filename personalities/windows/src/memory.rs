//! The pages of mapped images and their Windows protections, for
//! `VirtualQuery` and `VirtualProtect`.
//!
//! Values are the `PAGE_*` and `MEM_*` constants from "Memory Protection
//! Constants" and `MEMORY_BASIC_INFORMATION` on Microsoft Learn. Writable
//! image pages report `PAGE_READWRITE`, not the copy-on-write variants
//! Windows shows before the first write.

use std::collections::BTreeMap;

use crate::pe::Protection;

pub const PAGE: u32 = 0x1000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_IMAGE: u32 = 0x100_0000;

/// The `PAGE_*` value for a section's protection.
pub fn page_protect(p: Protection) -> u32 {
    match (p.read || p.write, p.write, p.execute) {
        (_, true, true) => PAGE_EXECUTE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, false, true) => PAGE_EXECUTE,
        (_, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        (false, false, false) => PAGE_NOACCESS,
    }
}

/// The host protection for a `PAGE_*` value, or None for a value we do
/// not support (guard pages, caching flags, combinations).
pub fn host_protection(protect: u32) -> Option<Protection> {
    let (read, write, execute) = match protect {
        PAGE_NOACCESS => (false, false, false),
        PAGE_READONLY => (true, false, false),
        PAGE_READWRITE | 0x08 => (true, true, false),
        PAGE_EXECUTE => (false, false, true),
        PAGE_EXECUTE_READ => (true, false, true),
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => (true, true, true),
        _ => return None,
    };
    Some(Protection {
        read,
        write,
        execute,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageInfo {
    pub protect: u32,
    pub allocation_base: u32,
    pub allocation_protect: u32,
    pub kind: u32,
}

/// A run of pages with the same attributes, as `VirtualQuery` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub base: u32,
    pub size: u32,
    pub info: PageInfo,
}

#[derive(Debug, Default)]
pub struct MemoryMap {
    pages: BTreeMap<u32, PageInfo>,
}

impl MemoryMap {
    /// Record an image of `size` bytes at `base`. Every page starts read
    /// only (the headers and the space between sections); `sections`
    /// gives (rva, length, protection) for the rest.
    pub fn add_image(&mut self, base: u32, size: u32, sections: &[(u32, u32, Protection)]) {
        let page = |protect| PageInfo {
            protect,
            allocation_base: base,
            allocation_protect: PAGE_EXECUTE_WRITECOPY,
            kind: MEM_IMAGE,
        };
        for offset in (0..size).step_by(PAGE as usize) {
            self.pages.insert(base + offset, page(PAGE_READONLY));
        }
        for &(rva, len, protection) in sections {
            let end = (rva + len).div_ceil(PAGE) * PAGE;
            for offset in (rva..end.min(size)).step_by(PAGE as usize) {
                self.pages
                    .insert(base + offset, page(page_protect(protection)));
            }
        }
    }

    pub fn region(&self, address: u32) -> Option<Region> {
        let first = address & !(PAGE - 1);
        let info = *self.pages.get(&first)?;
        let mut next = first;
        while self.pages.get(&next) == Some(&info) {
            next += PAGE;
        }
        Some(Region {
            base: first,
            size: next - first,
            info,
        })
    }

    /// The pages `[address, address + len)` covers, if all are known.
    pub fn pages_of(&self, address: u32, len: u32) -> Option<Vec<u32>> {
        let first = address & !(PAGE - 1);
        let end = address.checked_add(len.max(1))?.div_ceil(PAGE) * PAGE;
        let pages: Vec<u32> = (first..end).step_by(PAGE as usize).collect();
        pages
            .iter()
            .all(|p| self.pages.contains_key(p))
            .then_some(pages)
    }

    /// Set the protection of known pages; returns the first page's old one.
    pub fn set_protect(&mut self, pages: &[u32], protect: u32) -> Option<u32> {
        let old = self.pages.get(pages.first()?)?.protect;
        for page in pages {
            if let Some(info) = self.pages.get_mut(page) {
                info.protect = protect;
            }
        }
        Some(old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RX: Protection = Protection {
        read: true,
        write: false,
        execute: true,
    };
    const RW: Protection = Protection {
        read: true,
        write: true,
        execute: false,
    };

    #[test]
    fn regions_follow_sections_and_protection_changes() {
        let mut map = MemoryMap::default();
        map.add_image(
            0x1000_0000,
            0x5000,
            &[(0x1000, 0x1800, RX), (0x3000, 0x10, RW)],
        );

        let header = map.region(0x1000_0010).unwrap();
        assert_eq!((header.base, header.size), (0x1000_0000, 0x1000));
        assert_eq!(header.info.protect, PAGE_READONLY);
        assert_eq!(header.info.kind, MEM_IMAGE);

        let text = map.region(0x1000_1abc).unwrap();
        assert_eq!(
            (text.base, text.size, text.info.protect),
            (0x1000_1000, 0x2000, PAGE_EXECUTE_READ)
        );
        let data = map.region(0x1000_3000).unwrap();
        assert_eq!((data.size, data.info.protect), (0x1000, PAGE_READWRITE));
        assert_eq!(map.region(0x1000_4000).unwrap().info.protect, PAGE_READONLY);
        assert!(map.region(0x1000_5000).is_none());

        let pages = map.pages_of(0x1000_1ffc, 8).unwrap();
        assert_eq!(pages, [0x1000_1000, 0x1000_2000]);
        assert_eq!(
            map.set_protect(&pages, PAGE_EXECUTE_READWRITE),
            Some(PAGE_EXECUTE_READ)
        );
        assert_eq!(map.region(0x1000_1000).unwrap().size, 0x2000);
        assert_eq!(
            map.region(0x1000_1000).unwrap().info.protect,
            PAGE_EXECUTE_READWRITE
        );
        assert!(
            map.pages_of(0x1000_4ff0, 0x20).is_none(),
            "runs past the image"
        );
    }

    #[test]
    fn protection_values_round_trip() {
        for p in [
            PAGE_NOACCESS,
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
        ] {
            assert_eq!(page_protect(host_protection(p).unwrap()), p);
        }
        assert_eq!(host_protection(PAGE_READWRITE | 0x100), None, "guard pages");
    }
}
