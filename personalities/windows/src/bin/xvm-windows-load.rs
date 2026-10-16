//! Load a Windows executable or DLL with its imports and report the module
//! table. Import gaps go to stderr as they are found. Runs no agent code.
//!
//! Usage: xvm-windows-load IMAGE [SEARCH_DIR...]
//! The image's own directory is always searched first.

#[cfg(all(target_arch = "x86", target_os = "linux"))]
fn main() -> std::process::ExitCode {
    use std::path::PathBuf;

    use xvm_windows::process::Process;

    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let Some(image) = args.next() else {
        eprintln!("usage: xvm-windows-load IMAGE [SEARCH_DIR...]");
        return std::process::ExitCode::from(2);
    };
    let mut search = vec![image.parent().unwrap_or(".".as_ref()).to_path_buf()];
    search.extend(args);

    let mut process = Process::new(search);
    if let Err(e) = process.load(&image) {
        eprintln!("error: {e}");
        return std::process::ExitCode::FAILURE;
    }
    for m in process.modules() {
        let kind = if m.emulated { "emulated" } else { "image" };
        println!("module 0x{:08x} {kind:8} {}", m.base(), m.name);
    }
    let emulated = process.modules().iter().filter(|m| m.emulated).count();
    println!(
        "{} modules ({emulated} emulated), {} gaps",
        process.modules().len(),
        process.gaps().len()
    );
    std::process::ExitCode::SUCCESS
}

#[cfg(not(all(target_arch = "x86", target_os = "linux")))]
fn main() -> std::process::ExitCode {
    eprintln!("xvm-windows-load runs i386 code: build it for i686-unknown-linux-gnu");
    std::process::ExitCode::from(2)
}
