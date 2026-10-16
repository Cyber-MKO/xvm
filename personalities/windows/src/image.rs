//! In-memory layout of a PE32 image: sections placed at their RVAs, base
//! relocations, import binding, exports and the TLS directory.
//!
//! All of this works on a byte buffer and runs on any host. Mapping the
//! buffer into the address space and running it is in `map`.

use std::collections::HashSet;

use crate::gap::{Gap, GapKind};
use crate::pe::{
    DIR_BASERELOC, DIR_DELAY_IMPORT, DIR_EXPORT, DIR_IMPORT, DIR_TLS, Headers, PeError, u16_at,
    u32_at,
};

/// Base relocation types (PE format, "Base Relocation Types").
const REL_BASED_ABSOLUTE: u16 = 0;
const REL_BASED_HIGHLOW: u16 = 3;

const ORDINAL_FLAG: u32 = 0x8000_0000;

/// One imported symbol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Symbol {
    Name { hint: u16, name: String },
    Ordinal(u16),
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Symbol::Name { name, .. } => f.write_str(name),
            Symbol::Ordinal(n) => write!(f, "#{n}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub symbol: Symbol,
    /// RVA of the IAT slot the loader fills in.
    pub iat_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDll {
    pub dll: String,
    pub imports: Vec<Import>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportTarget {
    Rva(u32),
    /// `OTHERDLL.Function` or `OTHERDLL.#12`.
    Forwarder(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub ordinal: u16,
    pub name: Option<String>,
    pub target: ExportTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exports {
    pub dll_name: String,
    pub ordinal_base: u32,
    pub entries: Vec<Export>,
}

impl Exports {
    pub fn by_name(&self, name: &str) -> Option<&Export> {
        self.entries
            .iter()
            .find(|e| e.name.as_deref() == Some(name))
    }

    pub fn by_ordinal(&self, ordinal: u16) -> Option<&Export> {
        self.entries.iter().find(|e| e.ordinal == ordinal)
    }

    pub fn lookup(&self, symbol: &Symbol) -> Option<&Export> {
        match symbol {
            Symbol::Name { name, .. } => self.by_name(name),
            Symbol::Ordinal(n) => self.by_ordinal(*n),
        }
    }
}

/// TLS directory with addresses as virtual addresses at the current base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    pub raw_data_start: u32,
    pub raw_data_end: u32,
    pub index_address: u32,
    pub zero_fill: u32,
    pub callbacks: Vec<u32>,
}

/// Finds the address of an imported symbol. Implemented by the personality
/// runtime (emulated system DLLs) and by the module list (bundled DLLs).
pub trait Resolver {
    fn resolve(&mut self, dll: &str, symbol: &Symbol) -> Option<u32>;
}

/// A PE32 image laid out in memory order at `base`.
#[derive(Debug, Clone)]
pub struct Image {
    /// File name of the module, used in gap reports.
    pub module: String,
    pub headers: Headers,
    pub base: u32,
    pub memory: Vec<u8>,
}

impl Image {
    /// Place headers and sections at their RVAs, at the preferred base.
    pub fn layout(module: &str, file: &[u8]) -> Result<Image, PeError> {
        let headers = Headers::parse(file)?;
        let mut memory = vec![0u8; headers.size_of_image as usize];

        let header_len = (headers.size_of_headers as usize).min(file.len());
        memory[..header_len].copy_from_slice(&file[..header_len]);

        for s in &headers.sections {
            let len = s.raw_size.min(s.mapped_size()) as usize;
            if len == 0 {
                continue;
            }
            let src = s.raw_offset as usize;
            let raw = file.get(src..src + len).ok_or_else(|| {
                PeError::Malformed(format!("section {} raw data past end of file", s.name))
            })?;
            let dst = s.virtual_address as usize;
            memory[dst..dst + len].copy_from_slice(raw);
        }

        Ok(Image {
            module: module.to_string(),
            base: headers.image_base,
            headers,
            memory,
        })
    }

    pub fn entry_point(&self) -> Option<u32> {
        match self.headers.entry_point {
            0 => None,
            rva => Some(self.base.wrapping_add(rva)),
        }
    }

    /// Apply base relocations so the image runs at `new_base`.
    pub fn rebase(&mut self, new_base: u32) -> Result<(), PeError> {
        let delta = new_base.wrapping_sub(self.base);
        if delta == 0 {
            return Ok(());
        }
        let dir = self.headers.directory(DIR_BASERELOC);
        if self.headers.relocs_stripped() || !dir.is_present() {
            return Err(PeError::Unsupported(
                "rebasing an image without relocations",
            ));
        }
        let mut block = dir.rva as usize;
        let end = block + dir.size as usize;
        while block + 8 <= end {
            let page = self.u32(block as u32)?;
            let size = self.u32(block as u32 + 4)? as usize;
            if size < 8 || block + size > end {
                return Err(PeError::Malformed(format!(
                    "relocation block at RVA 0x{block:x} has size {size}"
                )));
            }
            for entry in (block + 8..block + size).step_by(2) {
                let raw = u16_at(&self.memory, entry, "relocation block")?;
                let (kind, offset) = (raw >> 12, raw & 0x0fff);
                let rva = page + offset as u32;
                match kind {
                    REL_BASED_ABSOLUTE => {}
                    REL_BASED_HIGHLOW => {
                        let value = self.u32(rva)?.wrapping_add(delta);
                        self.write_u32(rva, value)?;
                    }
                    _ => return Err(PeError::UnsupportedRelocation { kind, rva }),
                }
            }
            block += size;
        }
        self.base = new_base;
        Ok(())
    }

    pub fn imports(&self) -> Result<Vec<ImportDll>, PeError> {
        let dir = self.headers.directory(DIR_IMPORT);
        if !dir.is_present() {
            return Ok(Vec::new());
        }
        let mut dlls = Vec::new();
        for desc in (dir.rva..).step_by(20) {
            let lookup = self.u32(desc)?;
            let name_rva = self.u32(desc + 12)?;
            let iat = self.u32(desc + 16)?;
            if lookup == 0 && name_rva == 0 && iat == 0 {
                break;
            }
            // Some linkers leave the lookup table out; the IAT then holds it.
            let table = if lookup != 0 { lookup } else { iat };
            let mut imports = Vec::new();
            for i in 0.. {
                let thunk = self.u32(table + i * 4)?;
                if thunk == 0 {
                    break;
                }
                let symbol = if thunk & ORDINAL_FLAG != 0 {
                    Symbol::Ordinal(thunk as u16)
                } else {
                    Symbol::Name {
                        hint: u16_at(&self.memory, thunk as usize, "import hint")?,
                        name: self.cstr(thunk + 2)?,
                    }
                };
                imports.push(Import {
                    symbol,
                    iat_rva: iat + i * 4,
                });
            }
            dlls.push(ImportDll {
                dll: self.cstr(name_rva)?,
                imports,
            });
        }
        Ok(dlls)
    }

    /// Fill every IAT slot. Unresolved slots get `trap` and are returned as
    /// gaps, once per DLL and symbol; the caller logs them (CLAUDE.md rule 4).
    pub fn bind(&mut self, resolver: &mut dyn Resolver, trap: u32) -> Result<Vec<Gap>, PeError> {
        if self.headers.directory(DIR_DELAY_IMPORT).is_present() {
            // The 4.14.2 census found no delay-load imports. Fail loudly if
            // that ever changes rather than leave slots unbound.
            return Err(PeError::Unsupported("delay-load imports"));
        }
        let mut gaps = Vec::new();
        // MinGW can import the same symbol through several descriptors.
        let mut seen = HashSet::new();
        for dll in self.imports()? {
            for import in dll.imports {
                let address = match resolver.resolve(&dll.dll, &import.symbol) {
                    Some(address) => address,
                    None => {
                        let symbol = import.symbol.to_string();
                        if seen.insert((dll.dll.to_ascii_lowercase(), symbol.clone())) {
                            gaps.push(Gap {
                                module: self.module.clone(),
                                kind: GapKind::Import,
                                dll: dll.dll.clone(),
                                symbol,
                            });
                        }
                        trap
                    }
                };
                self.write_u32(import.iat_rva, address)?;
            }
        }
        Ok(gaps)
    }

    pub fn exports(&self) -> Result<Option<Exports>, PeError> {
        let dir = self.headers.directory(DIR_EXPORT);
        if !dir.is_present() {
            return Ok(None);
        }
        let d = dir.rva;
        let ordinal_base = self.u32(d + 16)?;
        let function_count = self.u32(d + 20)?;
        let name_count = self.u32(d + 24)?;
        let functions = self.u32(d + 28)?;
        let names = self.u32(d + 32)?;
        let name_ordinals = self.u32(d + 36)?;

        let mut entry_names = vec![None; function_count as usize];
        for i in 0..name_count {
            let index = u16_at(
                &self.memory,
                (name_ordinals + i * 2) as usize,
                "export ordinals",
            )?;
            let slot = entry_names.get_mut(index as usize).ok_or_else(|| {
                PeError::Malformed(format!("export name points at function {index}"))
            })?;
            *slot = Some(self.cstr(self.u32(names + i * 4)?)?);
        }

        let mut entries = Vec::new();
        for (i, name) in entry_names.into_iter().enumerate() {
            let rva = self.u32(functions + i as u32 * 4)?;
            if rva == 0 {
                continue;
            }
            let target = if rva >= dir.rva && rva < dir.rva + dir.size {
                ExportTarget::Forwarder(self.cstr(rva)?)
            } else {
                ExportTarget::Rva(rva)
            };
            entries.push(Export {
                ordinal: (ordinal_base + i as u32) as u16,
                name,
                target,
            });
        }
        Ok(Some(Exports {
            dll_name: self.cstr(self.u32(d + 12)?)?,
            ordinal_base,
            entries,
        }))
    }

    pub fn tls(&self) -> Result<Option<Tls>, PeError> {
        let dir = self.headers.directory(DIR_TLS);
        if !dir.is_present() {
            return Ok(None);
        }
        let d = dir.rva;
        let callbacks_va = self.u32(d + 12)?;
        let mut callbacks = Vec::new();
        if callbacks_va != 0 {
            let mut rva = self.va_to_rva(callbacks_va)?;
            loop {
                let callback = self.u32(rva)?;
                if callback == 0 {
                    break;
                }
                callbacks.push(callback);
                rva += 4;
            }
        }
        Ok(Some(Tls {
            raw_data_start: self.u32(d)?,
            raw_data_end: self.u32(d + 4)?,
            index_address: self.u32(d + 8)?,
            zero_fill: self.u32(d + 16)?,
            callbacks,
        }))
    }

    pub fn va_to_rva(&self, va: u32) -> Result<u32, PeError> {
        let rva = va.wrapping_sub(self.base);
        if rva as usize >= self.memory.len() {
            return Err(PeError::Malformed(format!(
                "address 0x{va:08x} outside image"
            )));
        }
        Ok(rva)
    }

    pub fn u32(&self, rva: u32) -> Result<u32, PeError> {
        u32_at(&self.memory, rva as usize, "image")
    }

    fn write_u32(&mut self, rva: u32, value: u32) -> Result<(), PeError> {
        let slot = self
            .memory
            .get_mut(rva as usize..rva as usize + 4)
            .ok_or(PeError::Truncated("image"))?;
        slot.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn cstr(&self, rva: u32) -> Result<String, PeError> {
        let tail = self
            .memory
            .get(rva as usize..)
            .ok_or(PeError::Truncated("string"))?;
        let len = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(PeError::Truncated("string"))?;
        Ok(String::from_utf8_lossy(&tail[..len]).into_owned())
    }
}
