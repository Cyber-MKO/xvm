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

use std::collections::BTreeMap;
use std::ffi::{CString, c_char};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::emu;
use crate::gap::{Gap, GapKind};
use crate::handles::HandleTable;
use crate::image::{ExportTarget, Exports, Image, Resolver, Symbol};
use crate::map::{self, MapError, Mapped};
use crate::memory::MemoryMap;
use crate::paths::DriveMap;
use crate::pe::PeError;
use crate::profile;
use crate::tls::ProcessTls;
use crate::trap::Traps;
use crate::win;
use crate::x509::Certificate;

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
    /// `LoadLibrary` calls minus `FreeLibrary` calls. Modules are never
    /// unmapped.
    pub load_count: u32,
    /// `SizeOfStackReserve`: the default stack size of new threads, when
    /// this is the main module.
    pub stack_reserve: u32,
    pub size_of_image: u32,
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

    /// The module's full Windows path: through the drive table for an
    /// image, in the profile's system module directory when emulated.
    pub fn windows_path(&self, params: &ProcessParams) -> Option<String> {
        match &self.path {
            Some(host) => params.drives.to_windows(host),
            None => {
                let dir = params.system_module_directory.as_deref()?;
                Some(format!("{}\\{}", dir.trim_end_matches('\\'), self.name))
            }
        }
    }

    /// Address of an export inside this module (not a forwarder).
    pub fn export_address(&self, name: &str) -> Option<u32> {
        match self.exports.by_name(name)?.target {
            ExportTarget::Rva(rva) => Some(self.base().wrapping_add(rva)),
            ExportTarget::Forwarder(_) => None,
        }
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

/// What the process is started with: from the host profile today, from
/// the host-state engine later.
#[derive(Debug, Clone, Default)]
pub struct ProcessParams {
    pub command_line: String,
    /// `NAME=value` strings in environment block order.
    pub environment: Vec<String>,
    pub current_directory: String,
    pub drives: DriveMap,
    /// The service the Service Control Manager started this process as,
    /// or `None` for a process started any other way.
    pub service: Option<String>,
    /// The process ID the agent sees.
    pub pid: u32,
    /// System certificate stores by upper-case name.
    pub cert_stores: BTreeMap<String, Vec<Certificate>>,
    /// Where emulated system DLLs say they were loaded from.
    pub system_module_directory: Option<String>,
    /// Upper-case full Windows path to the SHA-256 of a trusted file.
    pub trusted_files: BTreeMap<String, [u8; 32]>,
}

impl ProcessParams {
    pub fn from_profile(windows: &profile::Windows) -> ProcessParams {
        ProcessParams {
            command_line: windows.agent.command_line.clone(),
            environment: windows.environment_block(),
            current_directory: windows.agent.current_directory.clone(),
            drives: DriveMap::new(&windows.drives),
            service: windows.agent.service.clone(),
            pid: windows.agent.pid,
            cert_stores: windows.certificates.clone(),
            system_module_directory: windows.system_module_directory.clone(),
            trusted_files: windows
                .trusted_files
                .iter()
                .filter_map(|(path, hash)| {
                    let full = DriveMap::full_path(path, r"C:\").ok()?;
                    Some((full.to_ascii_uppercase(), crate::sha256::parse_hex(hash)?))
                })
                .collect(),
        }
    }
}

/// `argv` and `envp` as built by `__getmainargs`. The vectors own the
/// strings; agent code holds pointers into them, so they never change.
#[derive(Debug)]
pub struct MainArgs {
    pub strings: Vec<CString>,
    /// NULL-terminated `argv`.
    pub argv: Vec<*mut c_char>,
    /// NULL-terminated `envp`.
    pub envp: Vec<*mut c_char>,
}

// SAFETY: the pointers point into `strings`, which the struct owns. Neither changes after it is built.
unsafe impl Send for MainArgs {}
// SAFETY: as for Send.
unsafe impl Sync for MainArgs {}

/// `_acmdln`: a pointer to the command line, behind `__p__acmdln`.
#[derive(Debug)]
pub struct AnsiCommandLine {
    pub string: CString,
    /// The `_acmdln` variable itself; boxed so its address never moves.
    pub variable: Box<*mut c_char>,
}

// SAFETY: `variable` points into `string`, which the struct owns. Neither changes after it is built.
unsafe impl Send for AnsiCommandLine {}
// SAFETY: as for Send.
unsafe impl Sync for AnsiCommandLine {}

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
    /// `_newmode` from `__getmainargs`' start-up info.
    pub newmode: i32,
    pub main_args: Option<MainArgs>,
    pub acmdln: Option<AnsiCommandLine>,
    /// Functions registered with `_onexit`, in registration order. `exit`
    /// calls them last first.
    pub onexit: Vec<u32>,
    /// Low-level I/O: file descriptor to its OS handle and `_O_*` flags.
    pub fds: Vec<Option<CrtFd>>,
    /// Open `FILE *` streams.
    pub streams: Vec<crate::win::msvcrt::stdio::Stream>,
    /// The CRT's numbered internal locks, as `CRITICAL_SECTION`s (24 bytes
    /// each). All zero is unlocked.
    pub locks: Box<[[u32; 6]; 64]>,
}

/// One CRT file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrtFd {
    pub handle: u32,
    pub flags: i32,
}

impl CrtState {
    /// Give `fd` the lowest free descriptor, as `msvcrt` does.
    pub fn insert_fd(&mut self, fd: CrtFd) -> i32 {
        match self.fds.iter().position(Option::is_none) {
            Some(i) => {
                self.fds[i] = Some(fd);
                i as i32
            }
            None => {
                self.fds.push(Some(fd));
                self.fds.len() as i32 - 1
            }
        }
    }

    pub fn fd(&self, fd: i32) -> Option<CrtFd> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.fds.get(i).copied().flatten())
    }
}

/// `_O_TEXT` from fcntl.h, the documented default for `_fmode`.
pub const O_TEXT: i32 = 0x4000;

impl Default for CrtState {
    fn default() -> Self {
        CrtState {
            app_type: 0,
            fmode: Box::new(O_TEXT),
            commode: Box::new(0),
            newmode: 0,
            main_args: None,
            acmdln: None,
            onexit: Vec::new(),
            fds: Vec::new(),
            streams: Vec::new(),
            locks: Box::new([[0; 6]; 64]),
        }
    }
}

/// `SERVICE_STATUS`, as the service last reported it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceStatus {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
}

/// The service this process runs, once `StartServiceCtrlDispatcher` has
/// started it.
#[derive(Debug, Default)]
pub struct ServiceState {
    pub dispatcher_started: bool,
    /// From `RegisterServiceCtrlHandler`; 0 until then.
    pub handler: u32,
    pub status: Option<ServiceStatus>,
    /// Controls that arrived before a handler was registered.
    pub pending_controls: Vec<u32>,
    /// `argv` for `ServiceMain`: the service name.
    pub argv: Option<MainArgs>,
}

/// One certificate as CryptoAPI hands it out: a `CERT_CONTEXT` and the
/// `CERT_INFO` and buffers it points to. Boxed, so agent pointers into it
/// stay valid; kept for the life of the process.
pub struct CertEntry {
    pub cert: Certificate,
    pub context: Box<[u32; 5]>,
    pub info: Box<[u32; 28]>,
    pub buffers: Vec<Box<[u8]>>,
}

// SAFETY: the raw addresses inside point into the entry's own boxes.
unsafe impl Send for CertEntry {}
// SAFETY: as for Send; nothing changes after the entry is built.
unsafe impl Sync for CertEntry {}

/// An open certificate store.
pub struct CertStore {
    pub name: String,
    pub entries: Vec<CertEntry>,
    pub open: bool,
}

/// `crypt32.dll` state: open stores by handle.
#[derive(Default)]
pub struct CryptState {
    pub stores: Vec<(u32, CertStore)>,
    pub next_handle: u32,
}

/// A callback from `LdrRegisterDllNotification`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DllNotification {
    pub cookie: u32,
    pub function: u32,
    pub context: u32,
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
    /// From `SetUnhandledExceptionFilter`; 0 for none.
    pub unhandled_exception_filter: u32,
    pub crt: CrtState,
    pub params: ProcessParams,
    pub services: ServiceState,
    pub crypt: CryptState,
    /// Registered DLL load notifications, in registration order.
    pub dll_notifications: Vec<DllNotification>,
    pub handles: HandleTable,
    /// Set once a thread has a TEB: TLS slots of modules loaded later do
    /// not reach existing threads.
    pub threads_started: bool,
    /// TEB addresses of the threads attached now.
    pub tebs: Vec<u32>,
    /// `TlsAlloc` slots in use (`TlsSlots`, 64 entries).
    pub tls_slots: [bool; 64],
    /// Pages of mapped images, for `VirtualQuery` and `VirtualProtect`.
    pub memory: MemoryMap,
    /// `WSAStartup` calls not yet matched by `WSACleanup`.
    pub winsock_starts: u32,
}

/// Why `Process::load_library` failed.
#[derive(Debug)]
pub enum LoadLibraryError {
    /// No such DLL in the search path, the system DLLs or at the path.
    NotFound,
    Load(LoadError),
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
            unhandled_exception_filter: 0,
            crt: CrtState::default(),
            params: ProcessParams::default(),
            services: ServiceState::default(),
            crypt: CryptState::default(),
            dll_notifications: Vec::new(),
            handles: HandleTable::default(),
            threads_started: false,
            tebs: Vec::new(),
            tls_slots: [false; 64],
            memory: MemoryMap::default(),
            winsock_starts: 0,
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

    /// Record a gap found at run time, once however often it recurs.
    /// Run-time gaps name the main module: the caller is not tracked yet.
    pub fn record_runtime_gap(&mut self, kind: GapKind, dll: &str, symbol: &str) {
        let gap = Gap {
            module: self
                .main_module()
                .map(|m| m.name.clone())
                .unwrap_or_default(),
            kind,
            dll: dll.to_string(),
            symbol: symbol.to_string(),
        };
        if !self.gaps.contains(&gap) {
            self.record_gap(gap);
        }
    }

    /// Modules not initialised yet, dependencies first, marked as
    /// initialised. The caller runs the steps outside any lock, since
    /// agent code may call back into the process.
    pub fn take_pending_init(&mut self) -> Vec<InitStep> {
        let pending: Vec<usize> = (0..self.modules.len())
            .filter(|&i| !self.modules[i].initialized)
            .collect();
        pending
            .into_iter()
            .map(|i| {
                self.modules[i].initialized = true;
                self.init_step(&self.modules[i])
            })
            .collect()
    }

    /// The notifications a new thread sends, dependencies first: every
    /// initialised module with TLS callbacks or a `DllMain`.
    pub fn thread_steps(&self) -> Vec<InitStep> {
        self.modules
            .iter()
            .filter(|m| m.initialized && !m.emulated)
            .map(|m| self.init_step(m))
            .filter(|s| !s.tls_callbacks.is_empty() || s.dll_main.is_some())
            .collect()
    }

    fn init_step(&self, m: &Module) -> InitStep {
        InitStep {
            module: m.name.clone(),
            base: m.base(),
            tls_callbacks: self
                .tls
                .templates()
                .iter()
                .filter(|t| t.module == m.name)
                .flat_map(|t| t.callbacks.iter().copied())
                .collect(),
            dll_main: m.entry_point.filter(|_| m.is_dll),
        }
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
        for dll in emu::ALWAYS_LOADED {
            if self.index(dll).is_none() {
                self.load_emulated(dll)?;
            }
        }
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
        let tls_index = tls.register(&mut image).map_err(pe)?;
        mapped
            .commit(&image)
            .map_err(|e| LoadError::Map(name.clone(), e))?;

        gaps.into_iter().for_each(|gap| self.record_gap(gap));
        self.memory.add_image(
            mapped.base(),
            image.headers.size_of_image,
            &sections(&image),
        );
        if tls_index.is_some() && self.threads_started {
            self.record_runtime_gap(
                GapKind::Feature,
                &name,
                "implicit TLS for a DLL loaded after threads started",
            );
        }
        if !image.headers.is_dll() && self.main.is_none() {
            self.main = Some(self.modules.len());
        }
        self.modules.push(Module {
            path: Some(path.to_path_buf()),
            emulated: false,
            initialized: false,
            load_count: 0,
            stack_reserve: image.headers.stack_reserve,
            size_of_image: image.headers.size_of_image,
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
        self.memory.add_image(
            mapped.base(),
            image.headers.size_of_image,
            &sections(&image),
        );
        self.modules.push(Module {
            name: name.to_string(),
            path: None,
            emulated: true,
            initialized: true,
            load_count: 0,
            stack_reserve: 0,
            size_of_image: image.headers.size_of_image,
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

    /// `GetModuleHandle`: the base of a loaded module, by file name or by
    /// full Windows path. `None` asks for the main module.
    pub fn module_handle(&self, name: Option<&str>) -> Option<u32> {
        let Some(name) = name else {
            return self.main_module().map(Module::base);
        };
        if !name.contains(['\\', '/']) {
            return self.module(name).map(Module::base);
        }
        let params = &self.params;
        let wanted = DriveMap::full_path(name, &params.current_directory).ok()?;
        self.modules
            .iter()
            .find(|m| {
                m.path
                    .as_deref()
                    .and_then(|p| params.drives.to_windows(p))
                    .is_some_and(|p| p.eq_ignore_ascii_case(&wanted))
            })
            .map(Module::base)
    }

    pub fn module_at(&self, base: u32) -> Option<&Module> {
        self.modules.iter().find(|m| m.base() == base)
    }

    pub fn module_at_mut(&mut self, base: u32) -> Option<&mut Module> {
        self.modules.iter_mut().find(|m| m.base() == base)
    }

    /// `GetProcAddress`: an export of the module at `base`, following
    /// forwarders.
    pub fn proc_address(&self, base: u32, symbol: &Symbol) -> Option<u32> {
        self.module_at(base)?.resolve(&self.modules, symbol, 0)
    }

    /// Whether `name` is a DLL file the agent ships, loaded or not.
    /// `LoadLibrary`: a loaded module by name, a system DLL, a DLL in the
    /// application directory or the current directory, or one at a full
    /// path. Returns the module's index; modules past the old length are
    /// new and need initialising.
    pub fn load_library(&mut self, name: &str) -> Result<usize, LoadLibraryError> {
        let index = if name.contains(['\\', '/']) {
            let params = &self.params;
            let host = params
                .drives
                .to_host(name, &params.current_directory)
                .map_err(|_| LoadLibraryError::NotFound)?;
            if !host.is_file() {
                return Err(LoadLibraryError::NotFound);
            }
            self.load(&host).map_err(LoadLibraryError::Load)?
        } else if let Some(i) = self.index(name) {
            i
        } else if emu::is_system_dll(&normalize(name)) {
            self.load_emulated(&normalize(name))
                .map_err(LoadLibraryError::Load)?;
            self.modules.len() - 1
        } else {
            let cwd = self
                .params
                .drives
                .to_host(&self.params.current_directory, r"C:\")
                .ok();
            let path = self
                .find_file(&normalize(name))
                .or_else(|| cwd.and_then(|dir| find_in(&dir, &normalize(name))))
                .ok_or(LoadLibraryError::NotFound)?;
            self.load(&path).map_err(LoadLibraryError::Load)?
        };
        self.modules[index].load_count += 1;
        Ok(index)
    }

    pub fn is_bundled(&self, name: &str) -> bool {
        self.find_file(&normalize(name)).is_some()
    }

    fn find_file(&self, name: &str) -> Option<PathBuf> {
        self.search.iter().find_map(|dir| find_in(dir, name))
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

/// A file in `dir` named `name`, ignoring case: Windows file names are
/// case-insensitive and the host's are not.
fn find_in(dir: &Path, name: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let file = entry.file_name();
        file.to_str()?
            .eq_ignore_ascii_case(name)
            .then(|| entry.path())
    })
}

fn find<'a>(modules: &'a [Module], name: &str) -> Option<&'a Module> {
    let name = normalize(name);
    modules.iter().find(|m| m.name == name)
}

/// Lower case, with `.dll` added when there is no extension. A trailing
/// dot means "no extension" and is dropped. Both rules are from the
/// GetModuleHandle and LoadLibrary documentation.
fn normalize(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if let Some(bare) = lower.strip_suffix('.') {
        bare.to_string()
    } else if lower.contains('.') {
        lower
    } else {
        lower + ".dll"
    }
}

fn file_name(path: &Path) -> String {
    normalize(&path.file_name().unwrap_or_default().to_string_lossy())
}

/// (rva, length, protection) of each section, for the memory map.
fn sections(image: &Image) -> Vec<(u32, u32, crate::pe::Protection)> {
    image
        .headers
        .sections
        .iter()
        .map(|s| (s.virtual_address, s.mapped_size(), s.protection()))
        .collect()
}

fn no_exports(name: &str) -> Exports {
    Exports {
        dll_name: name.to_string(),
        ordinal_base: 1,
        entries: Vec::new(),
    }
}
