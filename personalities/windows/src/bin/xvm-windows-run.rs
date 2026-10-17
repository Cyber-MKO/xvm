//! Run the agent process a host profile describes: load the executable its
//! command line names, run start-up and the entry point, and exit with the
//! entry point's result. Gaps go to stderr; calling one aborts.
//!
//! SIGTERM or SIGINT stops the host: a service process gets
//! `SERVICE_CONTROL_STOP`, any other process exits at once. A second
//! signal always exits at once.
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
    if let Err(e) = stop_on_signal(runtime.clone()) {
        return fail(format!("signal handling: {e}"));
    }
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

/// Block SIGTERM and SIGINT in every thread and wait for them on one.
#[cfg(all(target_arch = "x86", target_os = "linux"))]
fn stop_on_signal(runtime: xvm_windows::runtime::Runtime) -> std::io::Result<()> {
    const SERVICE_CONTROL_STOP: u32 = 1;
    // SAFETY: a sigset_t built and used only here; threads spawned later
    // inherit the mask, so only the waiter below receives these signals.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        set
    };
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            let mut stopping = false;
            loop {
                let mut signal = 0;
                // SAFETY: waits on the set built above.
                if unsafe { libc::sigwait(&set, &mut signal) } != 0 {
                    continue;
                }
                let is_service = runtime.lock().params.service.is_some();
                if stopping || !is_service {
                    std::process::exit(128 + signal);
                }
                eprintln!("signal {signal}: sending SERVICE_CONTROL_STOP");
                runtime.service_control(SERVICE_CONTROL_STOP);
                stopping = true;
            }
        })?;
    Ok(())
}

#[cfg(not(all(target_arch = "x86", target_os = "linux")))]
fn main() -> std::process::ExitCode {
    eprintln!("xvm-windows-run runs i386 code: build it for i686-unknown-linux-gnu");
    std::process::ExitCode::from(2)
}
