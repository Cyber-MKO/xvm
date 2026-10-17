//! Readiness: `select`, `__WSAFDIsSet`.
//!
//! A Winsock `fd_set` is a count followed by that many SOCKETs, not a bit
//! map. `select` waits with the host's `poll` and rewrites each set to
//! hold only the sockets that are ready, following the select page on
//! Microsoft Learn:
//!
//! | Set | A socket is in it when |
//! | --- | --- |
//! | Read | Data, end of stream, an error, or a connection to accept is waiting |
//! | Write | It can send, including a non-blocking `connect` that succeeded |
//! | Except | Out-of-band data waits, or a non-blocking `connect` failed |
//!
//! It returns the number of sockets in all sets, 0 on timeout, or
//! SOCKET_ERROR. No sockets at all is WSAEINVAL, as documented.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::sockets::{
    SOCKET_ERROR, WSAEFAULT, WSAEINVAL, connected, fail, socket_of, started, wsa_error,
};

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("select", select as *const () as u32),
        ("__WSAFDIsSet", __WSAFDIsSet as *const () as u32),
    ]
}

/// The SOCKETs in the `fd_set` at `set`.
///
/// # Safety
///
/// `set` must be NULL or point at a valid `fd_set`.
unsafe fn members(set: *const u32) -> Vec<u32> {
    if set.is_null() {
        return Vec::new();
    }
    // SAFETY: the caller's contract: a count, then the sockets.
    unsafe {
        let count = *set as usize;
        std::slice::from_raw_parts(set.add(1), count).to_vec()
    }
}

/// Rewrites the `fd_set` at `set` to hold `ready`.
///
/// # Safety
///
/// As for `members`; `ready` is a subset of its sockets.
unsafe fn store(set: *mut u32, ready: &[u32]) {
    if set.is_null() {
        return;
    }
    // SAFETY: the set had room for at least these sockets.
    unsafe {
        *set = ready.len() as u32;
        std::ptr::copy_nonoverlapping(ready.as_ptr(), set.add(1), ready.len());
    }
}

/// `timeval` (two 32-bit longs) as a wait; None for NULL, which waits
/// for ever.
fn wait_of(timeout: *const i32) -> Result<Option<Duration>, ()> {
    if timeout.is_null() {
        return Ok(None);
    }
    // SAFETY: a readable timeval (the API's contract).
    let (sec, usec) = unsafe { (*timeout, *timeout.add(1)) };
    if sec < 0 || usec < 0 {
        return Err(());
    }
    Ok(Some(
        Duration::from_secs(sec as u64) + Duration::from_micros(usec as u64),
    ))
}

extern "stdcall" fn select(
    _nfds: i32,
    read: *mut u32,
    write: *mut u32,
    except: *mut u32,
    timeout: *const i32,
) -> i32 {
    if !started() {
        return SOCKET_ERROR;
    }
    // SAFETY: NULL or fd_sets (the API's contract).
    let sets = unsafe { [members(read), members(write), members(except)] };
    if sets.iter().all(Vec::is_empty) {
        return fail(WSAEINVAL);
    }
    let Ok(wait) = wait_of(timeout) else {
        return fail(WSAEINVAL);
    };
    // One pollfd per distinct socket, with the events any set asks for.
    let mut sockets = Vec::new();
    let mut polls: Vec<libc::pollfd> = Vec::new();
    for (i, set) in sets.iter().enumerate() {
        for &s in set {
            let o = match socket_of(s) {
                Ok(o) => o,
                Err(code) => return fail(code),
            };
            let events = [libc::POLLIN, libc::POLLOUT, libc::POLLPRI][i];
            match sockets.iter().position(|&(x, _)| x == s) {
                Some(k) => polls[k].events |= events,
                None => {
                    polls.push(libc::pollfd {
                        fd: o.fd,
                        events,
                        revents: 0,
                    });
                    sockets.push((s, o));
                }
            }
        }
    }
    let deadline = wait.map(|w| Instant::now() + w);
    let n = loop {
        let ms = match deadline {
            None => -1,
            Some(d) => d
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32,
        };
        // SAFETY: `polls` holds valid descriptors owned by the sockets.
        let n = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, ms) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if n >= 0 || e != libc::EINTR {
            break if n < 0 { return fail(wsa_error(e)) } else { n };
        }
    };
    let mut ready: [Vec<u32>; 3] = Default::default();
    if n > 0 {
        for (k, (s, o)) in sockets.iter().enumerate() {
            let r = polls[k].revents;
            let failed = r & libc::POLLERR != 0;
            let pending = o.connecting.load(Ordering::SeqCst);
            if sets[0].contains(s) && r & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                ready[0].push(*s);
            }
            if sets[1].contains(s) && r & libc::POLLOUT != 0 && !(pending && failed) {
                if pending {
                    connected(o);
                }
                ready[1].push(*s);
            }
            if sets[2].contains(s) && (r & libc::POLLPRI != 0 || (pending && failed)) {
                ready[2].push(*s);
            }
        }
    }
    for (set, r) in [read, write, except].into_iter().zip(&ready) {
        // SAFETY: as above.
        unsafe { store(set, r) };
    }
    ready.iter().map(Vec::len).sum::<usize>() as i32
}

/// Whether `s` is in the `fd_set` at `set`.
#[allow(non_snake_case)]
extern "stdcall" fn __WSAFDIsSet(s: u32, set: *const u32) -> i32 {
    if set.is_null() {
        super::sockets::fail(WSAEFAULT);
        return 0;
    }
    // SAFETY: an fd_set (the API's contract).
    i32::from(unsafe { members(set) }.contains(&s))
}

/// `select` with only read or write sets, for the socket tests.
#[cfg(test)]
pub(super) fn tests_select(read: *mut u32, write: *mut u32, timeout: *const i32) -> i32 {
    select(0, read, write, std::ptr::null_mut(), timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_in_a_winsock_fd_set() {
        let set = [2u32, 0x40, 0x44, 0x48];
        assert_eq!(__WSAFDIsSet(0x44, set.as_ptr()), 1);
        assert_eq!(__WSAFDIsSet(0x48, set.as_ptr()), 0, "past the count");
        assert_eq!(wait_of(std::ptr::null()), Ok(None));
        let t = [1i32, 500_000];
        assert_eq!(wait_of(t.as_ptr()), Ok(Some(Duration::from_millis(1500))));
    }
}
