//! Loader tests against PE32 i386 fixtures built from `tests/fixtures`.
//!
//! The fixtures need clang, lld-link and llvm-dlltool. Without them the tests
//! skip, unless XVM_REQUIRE_FIXTURES is set (CI sets it).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use xvm_windows::gap::{Gap, GapKind};
use xvm_windows::image::{ExportTarget, Image, Resolver, Symbol};
use xvm_windows::tls::ProcessTls;

fn fixtures() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let missing: Vec<_> = ["clang", "lld-link", "llvm-dlltool"]
            .into_iter()
            .filter(|tool| Command::new(tool).arg("--version").output().is_err())
            .collect();
        if !missing.is_empty() {
            assert!(
                std::env::var_os("XVM_REQUIRE_FIXTURES").is_none(),
                "missing fixture tools: {missing:?}"
            );
            eprintln!("skipping: missing fixture tools {missing:?}");
            return None;
        }
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("loader-fixtures");
        let status = Command::new("sh")
            .arg(src.join("build.sh"))
            .arg(&out)
            .status()
            .expect("run build.sh");
        assert!(status.success(), "fixture build failed");
        Some(out)
    })
    .as_deref()
}

fn load(name: &str) -> Option<Image> {
    let bytes = std::fs::read(fixtures()?.join(name)).unwrap();
    Some(Image::layout(name, &bytes).unwrap())
}

/// Resolves only what a test lists, like a module table would.
struct Table(HashMap<(String, Symbol), u32>);

impl Resolver for Table {
    fn resolve(&mut self, dll: &str, symbol: &Symbol) -> Option<u32> {
        self.0
            .get(&(dll.to_ascii_lowercase(), symbol.clone()))
            .copied()
    }
}

fn name(n: &str) -> Symbol {
    Symbol::Name {
        hint: 0,
        name: n.into(),
    }
}

#[test]
fn parses_headers_and_sections() {
    let Some(dll) = load("sample.dll") else {
        return;
    };
    assert!(dll.headers.is_dll());
    assert_eq!(dll.base, 0x1000_0000);
    assert_eq!(dll.entry_point(), None);
    let names: Vec<_> = dll
        .headers
        .sections
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert!(names.contains(&".text"), "{names:?}");
    let text = dll
        .headers
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .unwrap();
    assert!(text.protection().execute && !text.protection().write);
}

#[test]
fn reads_exports_by_name_ordinal_and_forwarder() {
    let Some(dll) = load("sample.dll") else {
        return;
    };
    let exports = dll.exports().unwrap().unwrap();
    assert_eq!(exports.dll_name, "sample.dll");
    assert!(matches!(
        exports.by_name("add").unwrap().target,
        ExportTarget::Rva(_)
    ));
    let hidden = exports.by_ordinal(7).unwrap();
    assert_eq!(hidden.name, None);
    assert_eq!(
        exports.by_name("Ticks").unwrap().target,
        ExportTarget::Forwarder("kernel32.GetTickCount".into())
    );
}

#[test]
fn rebase_applies_highlow_relocations() {
    let Some(mut dll) = load("sample.dll") else {
        return;
    };
    let before = dll.memory.clone();
    dll.rebase(0x2000_0000).unwrap();
    assert_eq!(dll.base, 0x2000_0000);
    // Every changed dword in a data section moved by exactly the delta. Code
    // relocations can sit at unaligned offsets, so only data is scanned.
    let data = dll
        .headers
        .sections
        .iter()
        .filter(|s| !s.protection().execute);
    let mut changed = 0;
    for rva in
        data.flat_map(|s| (s.virtual_address..s.virtual_address + s.mapped_size() - 3).step_by(4))
    {
        let rva = rva as usize;
        let old = u32::from_le_bytes(before[rva..rva + 4].try_into().unwrap());
        let new = dll.u32(rva as u32).unwrap();
        if old != new {
            assert_eq!(new.wrapping_sub(old), 0x1000_0000, "RVA 0x{rva:x}");
            changed += 1;
        }
    }
    assert!(changed > 0, "fixture has no relocations");
}

#[test]
fn binds_imports_and_reports_gaps() {
    let (Some(mut exe), Some(dll)) = (load("importer.exe"), load("sample.dll")) else {
        return;
    };
    let imports = exe.imports().unwrap();
    let kernel32 = imports.iter().find(|d| d.dll == "kernel32.dll").unwrap();
    let mut symbols: Vec<_> = kernel32
        .imports
        .iter()
        .map(|i| i.symbol.to_string())
        .collect();
    symbols.sort();
    assert_eq!(symbols, ["#99", "GetLastError", "GetTickCount"]);

    let add = match dll
        .exports()
        .unwrap()
        .unwrap()
        .by_name("add")
        .unwrap()
        .target
    {
        ExportTarget::Rva(rva) => dll.base + rva,
        ref other => panic!("{other:?}"),
    };
    let mut table = Table(HashMap::from([
        (("sample.dll".into(), name("add")), add),
        (("kernel32.dll".into(), name("GetTickCount")), 0x7000_0010),
    ]));
    let trap = 0xdead_0000;
    let mut gaps = exe.bind(&mut table, trap).unwrap();
    gaps.sort_by(|a, b| a.symbol.cmp(&b.symbol));

    let gap = |symbol: &str| Gap {
        module: "importer.exe".into(),
        kind: GapKind::Import,
        dll: "kernel32.dll".into(),
        symbol: symbol.into(),
    };
    assert_eq!(gaps, [gap("#99"), gap("GetLastError")]);
    assert_eq!(
        gaps[1].to_string(),
        "gap import kernel32.dll!GetLastError from importer.exe"
    );

    let slot = |dll: &str, symbol: &str| {
        let d = imports.iter().find(|d| d.dll == dll).unwrap();
        let i = d
            .imports
            .iter()
            .find(|i| i.symbol.to_string() == symbol)
            .unwrap();
        exe.u32(i.iat_rva).unwrap()
    };
    assert_eq!(slot("sample.dll", "add"), add);
    assert_eq!(slot("kernel32.dll", "GetTickCount"), 0x7000_0010);
    assert_eq!(slot("kernel32.dll", "GetLastError"), trap);
    assert_eq!(slot("kernel32.dll", "#99"), trap);
}

/// Map the DLL into this 32-bit process and call its code natively.
#[cfg(all(target_arch = "x86", target_os = "linux"))]
#[test]
fn maps_and_runs_i386_code() {
    let Some(mut dll) = load("sample.dll") else {
        return;
    };
    // Take the preferred base first so the loader has to relocate.
    let squatter = xvm_windows::map::map(&mut load("sample.dll").unwrap()).unwrap();
    let mapped = xvm_windows::map::map(&mut dll).unwrap();
    assert_eq!(squatter.base(), 0x1000_0000);
    assert_ne!(mapped.base(), 0x1000_0000);

    let exports = dll.exports().unwrap().unwrap();
    let rva = |n: &str| match exports.by_name(n).unwrap().target {
        ExportTarget::Rva(rva) => rva,
        ref other => panic!("{other:?}"),
    };
    // SAFETY: the exports are cdecl functions with these signatures, and
    // i386 cdecl is the same on Windows and Linux for integer arguments.
    let (add, bump) = unsafe {
        (
            std::mem::transmute::<*const u8, extern "C" fn(i32, i32) -> i32>(
                mapped.address(rva("add")),
            ),
            std::mem::transmute::<*const u8, extern "C" fn() -> i32>(mapped.address(rva("bump"))),
        )
    };
    assert_eq!(add(2, 3), 5);
    // bump goes through a relocated pointer; a wrong fixup would fault.
    assert_eq!(bump(), 41);
    assert_eq!(bump(), 42);
}

#[test]
fn registers_tls_templates_in_load_order() {
    let (Some(mut first), Some(mut second)) = (load("tls.dll"), load("tls.dll")) else {
        return;
    };
    let mut tls = ProcessTls::new();
    assert_eq!(tls.register(&mut first).unwrap(), Some(0));
    assert_eq!(tls.register(&mut second).unwrap(), Some(1));
    // A module without a TLS directory takes no index.
    assert_eq!(
        tls.register(&mut load("sample.dll").unwrap()).unwrap(),
        None
    );

    let dir = second.tls().unwrap().unwrap();
    assert_eq!(
        second
            .u32(second.va_to_rva(dir.index_address).unwrap())
            .unwrap(),
        1
    );
    let template = &tls.templates()[1];
    assert_eq!(template.module_base, 0x3000_0000);
    assert_eq!(template.callbacks.len(), 1);
    // tls_counter starts at 5.
    assert!(template.data.windows(4).any(|w| w == 5u32.to_le_bytes()));
}

/// Run fixture code that reads the TEB and implicit TLS through fs.
#[cfg(all(target_arch = "x86", target_os = "linux"))]
#[test]
fn code_reaches_teb_and_tls_through_fs() {
    use xvm_windows::map;
    use xvm_windows::teb::SEH_CHAIN_END;
    use xvm_windows::thread::{DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, ThreadEnv};

    let Some(mut dll) = load("tls.dll") else {
        return;
    };
    let mut tls = ProcessTls::new();
    let mapped = map::reserve(&mut dll).unwrap();
    tls.register(&mut dll).unwrap();
    mapped.commit(&dll).unwrap();

    let exports = dll.exports().unwrap().unwrap();
    let f = |n: &str| match exports.by_name(n).unwrap().target {
        // SAFETY: every fixture export used here is cdecl, takes nothing
        // and returns a 32-bit value.
        ExportTarget::Rva(rva) => unsafe {
            std::mem::transmute::<*const u8, extern "C" fn() -> u32>(mapped.address(rva))
        },
        ref other => panic!("{other:?}"),
    };

    let env = ThreadEnv::install(&tls).unwrap();
    // SAFETY: the module is committed and has no imports.
    unsafe { env.run_tls_callbacks(&tls, DLL_PROCESS_ATTACH) };
    assert_eq!(f("tls_callback_calls")(), 1);
    assert_eq!(f("tls_last_reason")(), DLL_PROCESS_ATTACH);
    assert_eq!(f("tls_callback_handle")(), mapped.base());

    assert_eq!(f("teb_self")(), env.teb());
    assert_eq!(f("seh_head")(), SEH_CHAIN_END);
    assert_eq!(f("fiber_data")(), 0);
    let local = 0u32;
    let here = &local as *const u32 as u32;
    let stack_base = f("teb_stack_base")();
    assert!(
        here < stack_base && stack_base - here < 64 << 20,
        "{here:#x} {stack_base:#x}"
    );

    assert_eq!(f("tls_index")(), 0);
    assert_eq!(f("bump_tls")(), 6);
    assert_eq!(f("bump_tls")(), 7);

    // A second thread gets its own TEB and a fresh copy of the TLS block.
    let other_teb = std::thread::scope(|s| {
        s.spawn(|| {
            let env = ThreadEnv::install(&tls).unwrap();
            // SAFETY: as above.
            unsafe { env.run_tls_callbacks(&tls, DLL_THREAD_ATTACH) };
            assert_eq!(f("tls_last_reason")(), DLL_THREAD_ATTACH);
            assert_eq!(f("teb_self")(), env.teb());
            assert_eq!(f("bump_tls")(), 6);
            env.teb()
        })
        .join()
        .unwrap()
    });
    assert_ne!(other_teb, env.teb());
    assert_eq!(f("teb_self")(), env.teb());
    assert_eq!(f("bump_tls")(), 8);
}
