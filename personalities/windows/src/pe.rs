//! PE32 header parsing.
//!
//! Written from the Microsoft PE format specification
//! (learn.microsoft.com/windows/win32/debug/pe-format). Only PE32 for i386 is
//! accepted: every Wazuh 4.14.2 image is PE32 i386 (docs/phase1-sizing.md).

use std::fmt;

pub const MACHINE_I386: u16 = 0x014c;
pub const OPTIONAL_MAGIC_PE32: u16 = 0x010b;
pub const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020b;

pub const FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const FILE_DLL: u16 = 0x2000;

pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Data directory indexes used by the loader.
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_TLS: usize = 9;
pub const DIR_DELAY_IMPORT: usize = 13;

/// Largest image we agree to lay out. Wazuh's biggest image is a few MiB.
pub const MAX_IMAGE_SIZE: u32 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    Truncated(&'static str),
    BadDosMagic,
    BadPeSignature,
    UnsupportedMachine(u16),
    UnsupportedOptionalMagic(u16),
    Malformed(String),
    UnsupportedRelocation { kind: u16, rva: u32 },
    Unsupported(&'static str),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::Truncated(what) => write!(f, "truncated {what}"),
            PeError::BadDosMagic => write!(f, "missing MZ signature"),
            PeError::BadPeSignature => write!(f, "missing PE signature"),
            PeError::UnsupportedMachine(m) => write!(f, "unsupported machine 0x{m:04x}"),
            PeError::UnsupportedOptionalMagic(m) => {
                write!(f, "unsupported optional header magic 0x{m:04x}")
            }
            PeError::Malformed(msg) => write!(f, "malformed image: {msg}"),
            PeError::UnsupportedRelocation { kind, rva } => {
                write!(f, "unsupported relocation type {kind} at RVA 0x{rva:08x}")
            }
            PeError::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for PeError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

impl DataDirectory {
    pub fn is_present(&self) -> bool {
        self.rva != 0 && self.size != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    /// Bytes the section occupies in memory before alignment.
    pub fn mapped_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    pub fn protection(&self) -> Protection {
        Protection {
            read: self.characteristics & SCN_MEM_READ != 0,
            write: self.characteristics & SCN_MEM_WRITE != 0,
            execute: self.characteristics & SCN_MEM_EXECUTE != 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Protection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headers {
    pub machine: u16,
    pub characteristics: u16,
    pub image_base: u32,
    pub entry_point: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub stack_reserve: u32,
    pub stack_commit: u32,
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
}

impl Headers {
    pub fn parse(file: &[u8]) -> Result<Headers, PeError> {
        if file.get(0..2) != Some(b"MZ") {
            return Err(PeError::BadDosMagic);
        }
        let pe = u32_at(file, 0x3c, "DOS header")? as usize;
        if file.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err(PeError::BadPeSignature);
        }
        let coff = pe + 4;
        let machine = u16_at(file, coff, "COFF header")?;
        if machine != MACHINE_I386 {
            return Err(PeError::UnsupportedMachine(machine));
        }
        let section_count = u16_at(file, coff + 2, "COFF header")? as usize;
        let optional_size = u16_at(file, coff + 16, "COFF header")? as usize;
        let characteristics = u16_at(file, coff + 18, "COFF header")?;

        let opt = coff + 20;
        let magic = u16_at(file, opt, "optional header")?;
        if magic != OPTIONAL_MAGIC_PE32 {
            return Err(PeError::UnsupportedOptionalMagic(magic));
        }
        let field = |off: usize| u32_at(file, opt + off, "optional header");
        let dir_count = field(92)? as usize;
        if 96 + dir_count * 8 > optional_size {
            return Err(PeError::Malformed(format!(
                "{dir_count} data directories do not fit in a {optional_size}-byte optional header"
            )));
        }
        let directories = (0..dir_count)
            .map(|i| {
                Ok(DataDirectory {
                    rva: field(96 + i * 8)?,
                    size: field(100 + i * 8)?,
                })
            })
            .collect::<Result<Vec<_>, PeError>>()?;

        let table = opt + optional_size;
        let sections = (0..section_count)
            .map(|i| parse_section(file, table + i * 40))
            .collect::<Result<Vec<_>, PeError>>()?;

        let headers = Headers {
            machine,
            characteristics,
            image_base: field(28)?,
            entry_point: field(16)?,
            section_alignment: field(32)?,
            file_alignment: field(36)?,
            size_of_image: field(56)?,
            size_of_headers: field(60)?,
            subsystem: u16_at(file, opt + 68, "optional header")?,
            dll_characteristics: u16_at(file, opt + 70, "optional header")?,
            stack_reserve: field(72)?,
            stack_commit: field(76)?,
            directories,
            sections,
        };
        headers.validate()?;
        Ok(headers)
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & FILE_DLL != 0
    }

    pub fn relocs_stripped(&self) -> bool {
        self.characteristics & FILE_RELOCS_STRIPPED != 0
    }

    /// The directory at `index`, or an empty one if the image has fewer.
    pub fn directory(&self, index: usize) -> DataDirectory {
        self.directories.get(index).copied().unwrap_or_default()
    }

    fn validate(&self) -> Result<(), PeError> {
        if self.size_of_image == 0 || self.size_of_image > MAX_IMAGE_SIZE {
            return Err(PeError::Malformed(format!(
                "SizeOfImage 0x{:x} out of range",
                self.size_of_image
            )));
        }
        if !self.section_alignment.is_power_of_two() {
            return Err(PeError::Malformed(format!(
                "SectionAlignment 0x{:x} is not a power of two",
                self.section_alignment
            )));
        }
        if self.size_of_headers > self.size_of_image {
            return Err(PeError::Malformed("headers larger than image".into()));
        }
        for s in &self.sections {
            let end = s.virtual_address as u64 + s.mapped_size() as u64;
            if end > self.size_of_image as u64 {
                return Err(PeError::Malformed(format!(
                    "section {} ends past SizeOfImage",
                    s.name
                )));
            }
        }
        Ok(())
    }
}

fn parse_section(file: &[u8], off: usize) -> Result<Section, PeError> {
    let raw_name = file
        .get(off..off + 8)
        .ok_or(PeError::Truncated("section table"))?;
    let len = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
    Ok(Section {
        name: String::from_utf8_lossy(&raw_name[..len]).into_owned(),
        virtual_size: u32_at(file, off + 8, "section table")?,
        virtual_address: u32_at(file, off + 12, "section table")?,
        raw_size: u32_at(file, off + 16, "section table")?,
        raw_offset: u32_at(file, off + 20, "section table")?,
        characteristics: u32_at(file, off + 36, "section table")?,
    })
}

pub(crate) fn u16_at(buf: &[u8], off: usize, what: &'static str) -> Result<u16, PeError> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(PeError::Truncated(what))
}

pub(crate) fn u32_at(buf: &[u8], off: usize, what: &'static str) -> Result<u32, PeError> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(PeError::Truncated(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert_eq!(Headers::parse(b"ELF"), Err(PeError::BadDosMagic));
        let mut dos = vec![0u8; 0x80];
        dos[0..2].copy_from_slice(b"MZ");
        dos[0x3c] = 0x40;
        assert_eq!(Headers::parse(&dos), Err(PeError::BadPeSignature));
    }

    #[test]
    fn rejects_truncated_dos_header() {
        assert_eq!(
            Headers::parse(b"MZ\0\0"),
            Err(PeError::Truncated("DOS header"))
        );
    }

    #[test]
    fn rejects_other_machines() {
        let mut file = vec![0u8; 0x100];
        file[0..2].copy_from_slice(b"MZ");
        file[0x3c] = 0x40;
        file[0x40..0x44].copy_from_slice(b"PE\0\0");
        file[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        assert_eq!(
            Headers::parse(&file),
            Err(PeError::UnsupportedMachine(0x8664))
        );
    }
}
