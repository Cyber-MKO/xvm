//! A Windows process: its loaded modules, TLS templates and gaps.
//!
//! `load` maps an executable or DLL and, depth first, everything it imports.
//! System DLLs from the census become emulated modules (`emu`, `win`).
//! Every other DLL is looked up as a file in the search directories, which
//! hold the agent's own bundled DLLs. Dependencies are always placed before
//! the modules that import them.
//!
//! Loading runs no agent code. `runtime::Runtime` runs TLS callbacks,
//! `DllMain` and the entry point afterwards.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::emu;
use crate::gap::Gap;
use crate::image::{ExportTarget, Exports, Image, Resolver, Symbol};
use crate::map::{self, MapError, Mapped};
use crate::pe::PeError;
use crate::tls::ProcessTls;
use crate::trap::Traps;
use crate::win;

/// Forwarders can chain; real chains are one or two links long.
const MAX_FORWARDS: usize = 8;

#[derive(Debug)]
pub enum LoadError {
    Io(PathBuf, io::Error),
    Pe(String, PeError),
    Map(String, MapError),
    CircularImport(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io(path, e) => write!(f, "reading {}: {e}", path.display()),
            LoadError::Pe(module, e) => write!(f, "{module}: {e}"),
            LoadError::Map(module, e) => write!(f, "{module}: {e}"),
            LoadError::CircularImport(module) => write!(f, "{module} imports itself"),
        }
    }
}

impl std::error::Error for LoadError {}

#[derive(Debug)]
pub struct Module {
    /// File name in lower case, as `GetModuleHandle` compares it.
    pub name: String,
    /// Where the image came from; `None` for emulated modules.
    pub path: Option<PathBuf>,
    pub emulated: bool,
    pub is_dll: bool,
    pub entry_point: Option<u32>,
    pub exports: Exports,
    /// TLS callbacks and `DllMain` have run (always true when emulated).
    pub initialized: bool,
    mapped: Mapped,
}

/// What `Runtime` must run, in order, to initialise one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitStep {
    pub module: String,
    pub base: u32,
    pub tls_callbacks: Vec<u32>,
    /// `DllMain`, for DLLs with an entry point.
    pub dll_main: Option<u32>,
}

impl Module {
    pub fn base(&self) -> u32 {
        self.mapped.base()
    }

    /// Address of an export, following forwarders inside `modules`.
    fn resolve(&self, modules: &[Module], symbol: &Symbol, depth: usize) -> Option<u32> {
        match &self.exports.lookup(symbol)?.target {
            ExportTarget::Rva(rva) => Some(self.base().wrapping_add(*rva)),
            ExportTarget::Forwarder(_) if depth >= MAX_FORWARDS => None,
            ExportTarget::Forwarder(to) => {
                let (dll, name) = to.rsplit_once('.')?;
                let symbol = match name.strip_prefix('#') {
                    Some(n) => Symbol::Ordinal(n.parse().ok()?),
                    None => Symbol::Name {
                        hint: 0,
                        name: name.to_string(),
                    },
                };
                find(modules, dll)?.resolve(modules, &symbol, depth + 1)
            }
        }
    }
}

/// Vectored exception handlers, in call order. Registered by
/// `AddVectoredExceptionHandler`; nothing dispatches to them yet.
#[derive(Debug, Default)]
pub struct VectoredHandlers {
    /// (handle, handler address)
    entries: Vec<(u32, u32)>,
    next_handle: u32,
}

impl VectoredHandlers {
    /// Add a handler, first or last in call order. Returns its handle.
    pub fn add(&mut self, handler: u32, first: bool) -> u32 {
        self.next_handle += 1;
        let handle = self.next_handle;
        if first {
            self.entries.insert(0, (handle, handler));
        } else {
            self.entries.push((handle, handler));
        }
        handle
    }

    pub fn remove(&mut self, handle: u32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|&(h, _)| h != handle);
        self.entries.len() != before
    }

    /// Handler addresses in call order.
    pub fn handlers(&self) -> Vec<u32> {
        self.entries.iter().map(|&(_, f)| f).collect()
    }
}

/// `msvcrt.dll` state that belongs to the process. Globals that agent code
/// reaches through pointers are boxed, so their addresses never move.
#[derive(Debug)]
pub struct CrtState {
    /// From `__set_app_type`: 1 console, 2 GUI.
    pub app_type: u32,
    /// `_fmode`: default translation mode for new files.
    pub fmode: Box<i32>,
    /// `_commode`: default commit mode for new streams.
    pub commode: Box<i32>,
}

/// `_O_TEXT` from fcntl.h, the documented default for `_fmode`.
pub const O_TEXT: i32 = 0x4000;

impl Default for CrtState {
    fn default() -> Self {
        CrtState {
            app_type: 0,
            fmode: Box::new(O_TEXT),
            commode: Box::new(0),
        }
    }
}

pub struct Process {
    search: Vec<PathBuf>,
    modules: Vec<Module>,
    tls: ProcessTls,
    traps: Traps,
    gaps: Vec<Gap>,
    loading: Vec<String>,
    main: Option<usize>,
    pub vectored_handlers: VectoredHandlers,
    pub crt: CrtState,
}

impl Process {
    /// `search` holds the directories bundled DLLs are loaded from.
    pub fn new(search: Vec<PathBuf>) -> Self {
        Process {
            search,
            modules: Vec::new(),
            tls: ProcessTls::new(),
            traps: Traps::new(),
            gaps: Vec::new(),
            loading: Vec::new(),
            main: None,
            vectored_handlers: VectoredHandlers::default(),
            crt: CrtState::default(),
        }
    }

    /// The first executable loaded: the process image.
    pub fn main_module(&self) -> Option<&Module> {
        self.modules.get(self.main?)
    }

    /// Record a gap and log it on stderr (CLAUDE.md rule 4).
    pub fn record_gap(&mut self, gap: Gap) {
        eprintln!("{gap}");
        self.gaps.push(gap);
    }

    /// Modules not initialised yet, dependencies first, marked as
    /// initialised. The caller runs the steps outside any lock, since
    /// agent code may call back into the process.
    pub fn take_pending_init(&mut self) -> Vec<InitStep> {
        let mut steps = Vec::new();
        for m in self.modules.iter_mut().filter(|m| !m.initialized) {
            m.initialized = true;
            let tls_callbacks = self
                .tls
                .templates()
                .iter()
                .filter(|t| t.module == m.name)
                .flat_map(|t| t.callbacks.iter().copied())
                .collect();
            steps.push(InitStep {
                module: m.name.clone(),
                base: m.base(),
                tls_callbacks,
                dll_main: m.entry_point.filter(|_| m.is_dll),
            });
        }
        steps
    }

    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    pub fn module(&self, name: &str) -> Option<&Module> {
        find(&self.modules, name)
    }

    /// Every import gap found so far, in load order.
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    pub fn tls(&self) -> &ProcessTls {
        &self.tls
    }

    /// Load `path` and its imports. Returns the module's index.
    pub fn load(&mut self, path: &Path) -> Result<usize, LoadError> {
        let name = file_name(path);
        if let Some(i) = self.index(&name) {
            return Ok(i);
        }
        if self.loading.contains(&name) {
            return Err(LoadError::CircularImport(name));
        }
        let bytes = std::fs::read(path).map_err(|e| LoadError::Io(path.to_path_buf(), e))?;
        let pe = |e| LoadError::Pe(name.clone(), e);
        let mut image = Image::layout(&name, &bytes).map_err(pe)?;
        let mapped = map::reserve(&mut image).map_err(|e| LoadError::Map(name.clone(), e))?;

        self.loading.push(name.clone());
        let imports = image.imports().map_err(pe);
        let loaded = imports.and_then(|imports| {
            imports
                .iter()
                .try_for_each(|dll| self.ensure(&dll.dll).map(|_| ()))
        });
        self.loading.pop();
        loaded?;

        let mut trap_error = None;
        let Process {
            modules,
            traps,
            tls,
            ..
        } = self;
        let gaps = image
            .bind(&mut ModuleResolver(modules), &mut |gap| {
                traps.stub(gap).unwrap_or_else(|e| {
                    trap_error.get_or_insert(e);
                    0
                })
            })
            .map_err(pe)?;
        if let Some(e) = trap_error {
            return Err(LoadError::Map(name, e));
        }
        tls.register(&mut image).map_err(pe)?;
        mapped
            .commit(&image)
            .map_err(|e| LoadError::Map(name.clone(), e))?;

        gaps.into_iter().for_each(|gap| self.record_gap(gap));
        if !image.headers.is_dll() && self.main.is_none() {
            self.main = Some(self.modules.len());
        }
        self.modules.push(Module {
            path: Some(path.to_path_buf()),
            emulated: false,
            initialized: false,
            is_dll: image.headers.is_dll(),
            entry_point: image.entry_point(),
            exports: image
                .exports()
                .map_err(pe)?
                .unwrap_or_else(|| no_exports(&name)),
            name,
            mapped,
        });
        Ok(self.modules.len() - 1)
    }

    /// Make sure the DLL an import names is loaded. Returns false if it is
    /// neither a system DLL nor a file in the search path; its imports then
    /// all become gaps.
    fn ensure(&mut self, dll: &str) -> Result<bool, LoadError> {
        let name = normalize(dll);
        if self.index(&name).is_some() {
            return Ok(true);
        }
        if emu::is_system_dll(&name) {
            self.load_emulated(&name)?;
            return Ok(true);
        }
        match self.find_file(&name) {
            Some(path) => self.load(&path).map(|_| true),
            None => Ok(false),
        }
    }

    fn load_emulated(&mut self, name: &str) -> Result<(), LoadError> {
        let map_err = |e| LoadError::Map(name.to_string(), e);
        let exports = win::exports(name);
        // The image size does not depend on the base, so size it first.
        let len = emu::build_image(name, 0, &exports).len();
        let mapped = Mapped::anonymous(0, len).map_err(map_err)?;
        let bytes = emu::build_image(name, mapped.base(), &exports);
        let pe = |e| LoadError::Pe(name.to_string(), e);
        let image = Image::layout(name, &bytes).map_err(pe)?;
        mapped.commit(&image).map_err(map_err)?;
        self.modules.push(Module {
            name: name.to_string(),
            path: None,
            emulated: true,
            initialized: true,
            is_dll: true,
            entry_point: None,
            exports: image
                .exports()
                .map_err(pe)?
                .unwrap_or_else(|| no_exports(name)),
            mapped,
        });
        Ok(())
    }

    fn find_file(&self, name: &str) -> Option<PathBuf> {
        // Windows file names are case-insensitive; the host's are not.
        self.search.iter().find_map(|dir| {
            std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
                let file = entry.file_name();
                file.to_str()?
                    .eq_ignore_ascii_case(name)
                    .then(|| entry.path())
            })
        })
    }

    fn index(&self, name: &str) -> Option<usize> {
        let name = normalize(name);
        self.modules.iter().position(|m| m.name == name)
    }
}

struct ModuleResolver<'a>(&'a [Module]);

impl Resolver for ModuleResolver<'_> {
    fn resolve(&mut self, dll: &str, symbol: &Symbol) -> Option<u32> {
        find(self.0, dll)?.resolve(self.0, symbol, 0)
    }
}

fn find<'a>(modules: &'a [Module], name: &str) -> Option<&'a Module> {
    let name = normalize(name);
    modules.iter().find(|m| m.name == name)
}

/// Lower case, with `.dll` added when there is no extension, as the
/// LoadLibrary documentation describes for module names.
fn normalize(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.contains('.') {
        lower
    } else {
        lower + ".dll"
    }
}

fn file_name(path: &Path) -> String {
    normalize(&path.file_name().unwrap_or_default().to_string_lossy())
}

fn no_exports(name: &str) -> Exports {
    Exports {
        dll_name: name.to_string(),
        ordinal_base: 1,
        entries: Vec::new(),
    }
}
