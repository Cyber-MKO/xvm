//! Run the agent process a host profile describes: load the executable its
//! command line names, run start-up and the entry point, and exit with the
//! entry point's result. Gaps go to stderr; calling one aborts.
//!
//! Usage: xvm-windows-run PROFILE

#[cfg(all(target_arch = "x86", target_os = "linux"))]
fn main() -> std::process::ExitCode {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use xvm_windows::cmdline;
    use xvm_windows::process::{Process, ProcessParams};
    use xvm_windows::profile::Profile;
    use xvm_windows::runtime::Runtime;

    let fail = |msg: String| {
        eprintln!("error: {msg}");
        ExitCode::FAILURE
    };
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(profile_path), None) = (args.next(), args.next()) else {
        eprintln!("usage: xvm-windows-run PROFILE");
        return ExitCode::from(2);
    };
    let profile = match Profile::load(&profile_path) {
        Ok(p) => p,
        Err(e) => return fail(e.to_string()),
    };
    let windows = match profile.windows() {
        Ok(w) => w,
        Err(e) => return fail(e.to_string()),
    };
    let params = ProcessParams::from_profile(windows);
    let program = cmdline::split(&params.command_line).remove(0);
    let image = match params.drives.to_host(&program, &params.current_directory) {
        Ok(path) => path,
        Err(e) => return fail(format!("{program}: {e}")),
    };
    let search = vec![image.parent().unwrap_or(".".as_ref()).to_path_buf()];

    let mut process = Process::new(search);
    process.params = params;
    if let Err(e) = process.load(&image) {
        return fail(e.to_string());
    }
    let runtime = Runtime::new(process);
    let thread = match runtime.attach() {
        Ok(thread) => thread,
        Err(e) => return fail(format!("entering the process: {e}")),
    };
    match runtime.run_main(&thread) {
        // Exit codes above 255 are truncated, as a Linux exit status is.
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => fail(e.to_string()),
    }
}

#[cfg(not(all(target_arch = "x86", target_os = "linux")))]
fn main() -> std::process::ExitCode {
    eprintln!("xvm-windows-run runs i386 code: build it for i686-unknown-linux-gnu");
    std::process::ExitCode::from(2)
}
