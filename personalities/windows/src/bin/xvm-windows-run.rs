//! Load a Windows executable, run its start-up and entry point, and exit
//! with its exit code. Gaps go to stderr; calling one aborts.
//!
//! Usage: xvm-windows-run IMAGE [SEARCH_DIR...]
//! The image's own directory is always searched first.

#[cfg(all(target_arch = "x86", target_os = "linux"))]
fn main() -> std::process::ExitCode {
    use std::path::PathBuf;

    use xvm_windows::process::Process;
    use xvm_windows::runtime::Runtime;

    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let Some(image) = args.next() else {
        eprintln!("usage: xvm-windows-run IMAGE [SEARCH_DIR...]");
        return std::process::ExitCode::from(2);
    };
    let mut search = vec![image.parent().unwrap_or(".".as_ref()).to_path_buf()];
    search.extend(args);

    let mut process = Process::new(search);
    if let Err(e) = process.load(&image) {
        eprintln!("error: {e}");
        return std::process::ExitCode::FAILURE;
    }
    let runtime = Runtime::new(process);
    let thread = match runtime.attach() {
        Ok(thread) => thread,
        Err(e) => {
            eprintln!("error: entering the process: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.run_main(&thread) {
        // Exit codes above 255 are truncated, as a Linux exit status is.
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(target_arch = "x86", target_os = "linux")))]
fn main() -> std::process::ExitCode {
    eprintln!("xvm-windows-run runs i386 code: build it for i686-unknown-linux-gnu");
    std::process::ExitCode::from(2)
}
