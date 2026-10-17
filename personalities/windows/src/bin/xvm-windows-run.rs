//! Run the agent process of one emulated host: read its parameters from
//! the host-state engine, load the executable its command line names, run
//! start-up and the entry point, and exit with the entry point's result.
//! Gaps go to stderr; calling one aborts.
//!
//! SIGTERM or SIGINT stops the host: a service process gets
//! `SERVICE_CONTROL_STOP`, any other process exits at once. A second
//! signal always exits at once.
//!
//! Usage: xvm-windows-run --engine SOCKET --host NAME --drive C=FOLDER...

#[cfg(all(target_arch = "x86", target_os = "linux"))]
fn main() -> std::process::ExitCode {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::{Arc, Mutex};

    use xvm_engine::client::Client;
    use xvm_windows::cmdline;
    use xvm_windows::hostconfig;
    use xvm_windows::process::Process;
    use xvm_windows::registration;
    use xvm_windows::runtime::Runtime;

    let fail = |msg: String| {
        eprintln!("error: {msg}");
        ExitCode::FAILURE
    };
    let usage = || {
        eprintln!("usage: xvm-windows-run --engine SOCKET --host NAME --drive C=FOLDER...");
        ExitCode::from(2)
    };
    let (mut socket, mut host, mut drives) = (None, None, BTreeMap::new());
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next();
        match (arg.to_str(), value) {
            (Some("--engine"), Some(v)) => socket = Some(PathBuf::from(v)),
            (Some("--host"), Some(v)) => host = v.into_string().ok(),
            (Some("--drive"), Some(v)) => {
                let Some((letter, folder)) = v.to_str().and_then(|v| v.split_once('=')) else {
                    return usage();
                };
                drives.insert(letter.to_ascii_uppercase(), PathBuf::from(folder));
            }
            _ => return usage(),
        }
    }
    let (Some(socket), Some(host)) = (socket, host) else {
        return usage();
    };
    if drives.is_empty() {
        return usage();
    }
    let mut client = match Client::connect(&socket, &host) {
        Ok(client) => client,
        Err(e) => return fail(format!("{}: {e}", socket.display())),
    };
    let params = match hostconfig::load(&mut client, &drives) {
        Ok(p) => p,
        Err(e) => return fail(format!("host {host}: {e}")),
    };
    let engine = Some(Arc::new(Mutex::new(client)));
    let Some(program) = cmdline::split(&params.command_line).into_iter().next() else {
        return fail("the agent's command line is empty".into());
    };
    let image = match params.drives.to_host(&program, &params.current_directory) {
        Ok(path) => path,
        Err(e) => return fail(format!("{program}: {e}")),
    };
    let search = vec![image.parent().unwrap_or(".".as_ref()).to_path_buf()];

    let mut process = Process::new(search);
    process.params = params;
    process.engine = engine;
    process.engine_addr = Some((socket.clone(), host.clone()));
    if let Err(e) = process.load(&image) {
        return fail(e.to_string());
    }
    if let Err(e) = registration::start(&mut process) {
        return fail(e);
    }
    let runtime = Runtime::new(process);
    if let Err(e) = stop_on_signal(runtime.clone()) {
        return fail(format!("signal handling: {e}"));
    }
    let thread = match runtime.attach() {
        Ok(thread) => thread,
        Err(e) => return fail(format!("entering the process: {e}")),
    };
    let result = runtime.run_main(&thread);
    registration::exit(&mut runtime.lock(), *result.as_ref().unwrap_or(&1));
    match result {
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
                    xvm_windows::registration::exit(&mut runtime.lock(), 128 + signal as u32);
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
