//! Sockets on host sockets: `socket`, `bind`, `listen`, `accept`,
//! `connect`, `send`, `recv`, `shutdown`, `closesocket`, `getsockname`,
//! `getpeername`, `setsockopt`, `getsockopt`, `ioctlsocket`,
//! `WSAGetLastError`, `WSASetLastError`.
//!
//! The brief maps networking to host sockets. A SOCKET is a kernel handle
//! that owns a host socket. Each function follows its page on Microsoft
//! Learn, translating what Winsock and Linux spell differently:
//!
//! | Item | Translation |
//! | --- | --- |
//! | Address families | `AF_INET` (2) is the same; `AF_INET6` is 23 in Winsock, 10 on Linux. `sockaddr_in` and `sockaddr_in6` share their layouts |
//! | Errors | Linux errno values become the "Windows Sockets Error Codes" (WSAE...) in the last error, with SOCKET_ERROR (-1) returned |
//! | Non-blocking `connect` | Linux EINPROGRESS is WSAEWOULDBLOCK, as Winsock reports it |
//! | `recv` flags | `MSG_OOB`, `MSG_PEEK` the same; `MSG_WAITALL` 8 is 0x100 on Linux |
//! | `send` | Never raises SIGPIPE: a closed peer is WSAECONNRESET |
//! | `SOL_SOCKET` options | Level 0xffff and option numbers differ; `SO_LINGER` holds two u16 values, and `SO_RCVTIMEO` and `SO_SNDTIMEO` hold milliseconds, not a `timeval`. `SO_ERROR` reads as a WSAE code |
//! | `IPPROTO_TCP` options | `TCP_NODELAY` |
//! | `ioctlsocket` | `FIONBIO` and `FIONREAD` |
//!
//! Every function but the byte-order helpers needs a prior `WSAStartup`.
//! Other families, options, flags and commands are logged gaps.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::gap::GapKind;
use crate::handles::{Object, SocketObject};
use crate::runtime::with_current;
use crate::win::kernel32::error::{GetLastError, set_last_error};

pub(super) const SOCKET_ERROR: i32 = -1;
const INVALID_SOCKET: u32 = u32::MAX;

// From "Windows Sockets Error Codes" on Microsoft Learn.
pub(super) const WSAEINTR: u32 = 10004;
pub(super) const WSAEFAULT: u32 = 10014;
pub(super) const WSAEINVAL: u32 = 10022;
const WSAEMFILE: u32 = 10024;
pub(super) const WSAEWOULDBLOCK: u32 = 10035;
const WSAEALREADY: u32 = 10037;
pub(super) const WSAENOTSOCK: u32 = 10038;
const WSAEDESTADDRREQ: u32 = 10039;
const WSAEMSGSIZE: u32 = 10040;
const WSAEPROTOTYPE: u32 = 10041;
const WSAENOPROTOOPT: u32 = 10042;
const WSAEPROTONOSUPPORT: u32 = 10043;
const WSAEOPNOTSUPP: u32 = 10045;
const WSAEAFNOSUPPORT: u32 = 10047;
const WSAEADDRINUSE: u32 = 10048;
const WSAEADDRNOTAVAIL: u32 = 10049;
const WSAENETDOWN: u32 = 10050;
const WSAENETUNREACH: u32 = 10051;
const WSAECONNABORTED: u32 = 10053;
const WSAECONNRESET: u32 = 10054;
const WSAENOBUFS: u32 = 10055;
const WSAEISCONN: u32 = 10056;
const WSAENOTCONN: u32 = 10057;
const WSAESHUTDOWN: u32 = 10058;
const WSAETIMEDOUT: u32 = 10060;
const WSAECONNREFUSED: u32 = 10061;
const WSAEHOSTUNREACH: u32 = 10065;
const WSAEACCES: u32 = 10013;
pub(super) const WSANOTINITIALISED: u32 = 10093;

const WIN_AF_INET6: u16 = 23;
const SOCKADDR_IN: usize = 16;
const SOCKADDR_IN6: usize = 28;

const WIN_SOL_SOCKET: i32 = 0xffff;
const IPPROTO_TCP: i32 = 6;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("socket", socket as *const () as u32),
        ("bind", bind as *const () as u32),
        ("listen", listen as *const () as u32),
        ("accept", accept as *const () as u32),
        ("connect", connect as *const () as u32),
        ("send", send as *const () as u32),
        ("recv", recv as *const () as u32),
        ("shutdown", shutdown as *const () as u32),
        ("closesocket", closesocket as *const () as u32),
        ("getsockname", getsockname as *const () as u32),
        ("getpeername", getpeername as *const () as u32),
        ("setsockopt", setsockopt as *const () as u32),
        ("getsockopt", getsockopt as *const () as u32),
        ("ioctlsocket", ioctlsocket as *const () as u32),
        ("WSAGetLastError", WSAGetLastError as *const () as u32),
        ("WSASetLastError", WSASetLastError as *const () as u32),
    ]
}

pub(super) fn gap(what: &str) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "wsock32.dll", what));
}

/// The Winsock error for a Linux errno.
pub(super) fn wsa_error(errno: i32) -> u32 {
    match errno {
        libc::EINTR => WSAEINTR,
        libc::EBADF | libc::ENOTSOCK => WSAENOTSOCK,
        libc::EACCES | libc::EPERM => WSAEACCES,
        libc::EFAULT => WSAEFAULT,
        libc::EINVAL => WSAEINVAL,
        libc::EMFILE | libc::ENFILE => WSAEMFILE,
        libc::EAGAIN | libc::EINPROGRESS => WSAEWOULDBLOCK,
        libc::EALREADY => WSAEALREADY,
        libc::EDESTADDRREQ => WSAEDESTADDRREQ,
        libc::EMSGSIZE => WSAEMSGSIZE,
        libc::EPROTOTYPE => WSAEPROTOTYPE,
        libc::ENOPROTOOPT => WSAENOPROTOOPT,
        libc::EPROTONOSUPPORT => WSAEPROTONOSUPPORT,
        libc::EOPNOTSUPP => WSAEOPNOTSUPP,
        libc::EAFNOSUPPORT => WSAEAFNOSUPPORT,
        libc::EADDRINUSE => WSAEADDRINUSE,
        libc::EADDRNOTAVAIL => WSAEADDRNOTAVAIL,
        libc::ENETDOWN => WSAENETDOWN,
        libc::ENETUNREACH => WSAENETUNREACH,
        libc::ECONNABORTED => WSAECONNABORTED,
        libc::ECONNRESET | libc::EPIPE => WSAECONNRESET,
        libc::ENOBUFS | libc::ENOMEM => WSAENOBUFS,
        libc::EISCONN => WSAEISCONN,
        libc::ENOTCONN => WSAENOTCONN,
        libc::ESHUTDOWN => WSAESHUTDOWN,
        libc::ETIMEDOUT => WSAETIMEDOUT,
        libc::ECONNREFUSED => WSAECONNREFUSED,
        libc::EHOSTUNREACH | libc::EHOSTDOWN => WSAEHOSTUNREACH,
        _ => WSAEINVAL,
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Sets the last error and returns SOCKET_ERROR.
pub(super) fn fail(code: u32) -> i32 {
    set_last_error(code);
    SOCKET_ERROR
}

fn fail_errno() -> i32 {
    fail(wsa_error(errno()))
}

/// Whether `WSAStartup` has been called; sets WSANOTINITIALISED if not.
pub(super) fn started() -> bool {
    let started = with_current(|p| p.winsock_starts > 0);
    if !started {
        set_last_error(WSANOTINITIALISED);
    }
    started
}

/// The socket behind a SOCKET, or WSAENOTSOCK.
pub(super) fn socket_of(s: u32) -> Result<Arc<SocketObject>, u32> {
    with_current(|p| match p.handles.get(s) {
        Some(Object::Socket(o)) => Ok(o.clone()),
        _ => Err(WSAENOTSOCK),
    })
}

/// Runs a host call until it is not interrupted by a signal.
fn retry(mut call: impl FnMut() -> isize) -> isize {
    loop {
        let r = call();
        if r >= 0 || errno() != libc::EINTR {
            return r;
        }
    }
}

/// A Winsock address as the host spells it.
fn to_host(addr: *const u8, len: i32) -> Result<(Vec<u8>, libc::socklen_t), u32> {
    if addr.is_null() || len < 2 {
        return Err(WSAEFAULT);
    }
    // SAFETY: `len` readable bytes (the API's contract).
    let bytes = unsafe { std::slice::from_raw_parts(addr, len as usize) };
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    let (size, host_family) = match family {
        2 => (SOCKADDR_IN, libc::AF_INET as u16),
        WIN_AF_INET6 => (SOCKADDR_IN6, libc::AF_INET6 as u16),
        other => {
            gap(&format!("address family {other}"));
            return Err(WSAEAFNOSUPPORT);
        }
    };
    if bytes.len() < size {
        return Err(WSAEFAULT);
    }
    let mut out = bytes[..size].to_vec();
    out[0..2].copy_from_slice(&host_family.to_ne_bytes());
    Ok((out, size as libc::socklen_t))
}

/// Writes a host address in Winsock's spelling to `addr`, whose size is
/// in `*len`. WSAEFAULT when it does not fit.
fn from_host(host: &libc::sockaddr_storage, addr: *mut u8, len: *mut i32) -> Result<(), u32> {
    if addr.is_null() || len.is_null() {
        return Ok(());
    }
    // SAFETY: sockaddr_storage is plain bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (host as *const libc::sockaddr_storage).cast::<u8>(),
            size_of::<libc::sockaddr_storage>(),
        )
    };
    let (size, family) = match i32::from(host.ss_family) {
        libc::AF_INET => (SOCKADDR_IN, 2u16),
        libc::AF_INET6 => (SOCKADDR_IN6, WIN_AF_INET6),
        _ => return Err(WSAEAFNOSUPPORT),
    };
    // SAFETY: readable and writable (the API's contract).
    let room = unsafe { *len };
    if room < size as i32 {
        return Err(WSAEFAULT);
    }
    let mut out = bytes[..size].to_vec();
    out[0..2].copy_from_slice(&family.to_le_bytes());
    // SAFETY: `room` >= size writable bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), addr, size);
        *len = size as i32;
    }
    Ok(())
}

fn insert(fd: i32) -> u32 {
    let object = SocketObject {
        fd,
        connecting: AtomicBool::new(false),
    };
    with_current(|p| p.handles.insert(Object::Socket(Arc::new(object))))
}

/// A new socket, or INVALID_SOCKET.
extern "stdcall" fn socket(family: i32, kind: i32, protocol: i32) -> u32 {
    if !started() {
        return INVALID_SOCKET;
    }
    let host_family = match family {
        2 => libc::AF_INET,
        23 => libc::AF_INET6,
        other => {
            gap(&format!("socket family {other}"));
            set_last_error(WSAEAFNOSUPPORT);
            return INVALID_SOCKET;
        }
    };
    if !(1..=3).contains(&kind) {
        gap(&format!("socket type {kind}"));
        set_last_error(WSAEPROTOTYPE);
        return INVALID_SOCKET;
    }
    // SAFETY: a plain socket call.
    let fd = unsafe { libc::socket(host_family, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        set_last_error(wsa_error(errno()));
        return INVALID_SOCKET;
    }
    insert(fd)
}

/// Runs `call` on the socket's descriptor after the usual checks.
fn with_socket(s: u32, call: impl FnOnce(&SocketObject) -> i32) -> i32 {
    if !started() {
        return SOCKET_ERROR;
    }
    match socket_of(s) {
        Ok(o) => call(&o),
        Err(code) => fail(code),
    }
}

extern "stdcall" fn bind(s: u32, addr: *const u8, len: i32) -> i32 {
    with_socket(s, |o| match to_host(addr, len) {
        // SAFETY: a host address of `n` bytes.
        Ok((a, n)) => match unsafe { libc::bind(o.fd, a.as_ptr().cast(), n) } {
            0 => 0,
            _ => fail_errno(),
        },
        Err(code) => fail(code),
    })
}

extern "stdcall" fn listen(s: u32, backlog: i32) -> i32 {
    // SAFETY: a plain listen call.
    with_socket(s, |o| match unsafe { libc::listen(o.fd, backlog) } {
        0 => 0,
        _ => fail_errno(),
    })
}

/// Accepts a connection. The new socket is non-blocking when the
/// listening one is, as on Windows.
extern "stdcall" fn accept(s: u32, addr: *mut u8, len: *mut i32) -> u32 {
    if !started() {
        return INVALID_SOCKET;
    }
    let o = match socket_of(s) {
        Ok(o) => o,
        Err(code) => {
            set_last_error(code);
            return INVALID_SOCKET;
        }
    };
    // SAFETY: plain descriptor calls; storage is large enough.
    let (fd, peer) = unsafe {
        let nonblocking = libc::fcntl(o.fd, libc::F_GETFL) & libc::O_NONBLOCK != 0;
        let flags = libc::SOCK_CLOEXEC | if nonblocking { libc::SOCK_NONBLOCK } else { 0 };
        let mut peer: libc::sockaddr_storage = std::mem::zeroed();
        let mut peer_len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let fd =
            retry(|| libc::accept4(o.fd, (&raw mut peer).cast(), &mut peer_len, flags) as isize)
                as i32;
        (fd, peer)
    };
    if fd < 0 {
        set_last_error(wsa_error(errno()));
        return INVALID_SOCKET;
    }
    if let Err(code) = from_host(&peer, addr, len) {
        // SAFETY: we own the new descriptor.
        unsafe { libc::close(fd) };
        set_last_error(code);
        return INVALID_SOCKET;
    }
    insert(fd)
}

extern "stdcall" fn connect(s: u32, addr: *const u8, len: i32) -> i32 {
    with_socket(s, |o| {
        let (a, n) = match to_host(addr, len) {
            Ok(a) => a,
            Err(code) => return fail(code),
        };
        // SAFETY: a host address of `n` bytes.
        let r = retry(|| unsafe { libc::connect(o.fd, a.as_ptr().cast(), n) } as isize);
        if r == 0 {
            o.connecting.store(false, Ordering::SeqCst);
            return 0;
        }
        let e = errno();
        if e == libc::EINPROGRESS {
            o.connecting.store(true, Ordering::SeqCst);
        }
        fail(wsa_error(e))
    })
}

/// `recv` flags in their host values.
fn recv_flags(flags: i32) -> Option<i32> {
    const MSG_WAITALL: i32 = 0x8;
    if flags & !(libc::MSG_OOB | libc::MSG_PEEK | MSG_WAITALL) != 0 {
        return None;
    }
    let mut host = flags & (libc::MSG_OOB | libc::MSG_PEEK);
    if flags & MSG_WAITALL != 0 {
        host |= libc::MSG_WAITALL;
    }
    Some(host)
}

extern "stdcall" fn recv(s: u32, buf: *mut u8, len: i32, flags: i32) -> i32 {
    with_socket(s, |o| {
        let Some(host_flags) = recv_flags(flags) else {
            gap(&format!("recv flags 0x{flags:x}"));
            return fail(WSAEOPNOTSUPP);
        };
        if len < 0 || (buf.is_null() && len > 0) {
            return fail(WSAEFAULT);
        }
        // SAFETY: `len` writable bytes (the API's contract).
        let r = retry(|| unsafe { libc::recv(o.fd, buf.cast(), len as usize, host_flags) });
        if r < 0 { fail_errno() } else { r as i32 }
    })
}

extern "stdcall" fn send(s: u32, buf: *const u8, len: i32, flags: i32) -> i32 {
    with_socket(s, |o| {
        if flags & !(libc::MSG_OOB | libc::MSG_DONTROUTE) != 0 {
            gap(&format!("send flags 0x{flags:x}"));
            return fail(WSAEOPNOTSUPP);
        }
        if len < 0 || (buf.is_null() && len > 0) {
            return fail(WSAEFAULT);
        }
        let host_flags = flags | libc::MSG_NOSIGNAL;
        // SAFETY: `len` readable bytes (the API's contract).
        let r = retry(|| unsafe { libc::send(o.fd, buf.cast(), len as usize, host_flags) });
        if r < 0 { fail_errno() } else { r as i32 }
    })
}

/// SD_RECEIVE (0), SD_SEND (1) and SD_BOTH (2) are the host's values.
extern "stdcall" fn shutdown(s: u32, how: i32) -> i32 {
    with_socket(s, |o| {
        if !(0..=2).contains(&how) {
            return fail(WSAEINVAL);
        }
        // SAFETY: a plain shutdown call.
        match unsafe { libc::shutdown(o.fd, how) } {
            0 => 0,
            _ => fail_errno(),
        }
    })
}

extern "stdcall" fn closesocket(s: u32) -> i32 {
    if !started() {
        return SOCKET_ERROR;
    }
    let removed = with_current(|p| match p.handles.get(s) {
        Some(Object::Socket(_)) => p.handles.remove(s).is_some(),
        _ => false,
    });
    if removed { 0 } else { fail(WSAENOTSOCK) }
}

type NameCall = unsafe extern "C" fn(i32, *mut libc::sockaddr, *mut libc::socklen_t) -> i32;

fn name_of(s: u32, addr: *mut u8, len: *mut i32, call: NameCall) -> i32 {
    with_socket(s, |o| {
        if addr.is_null() || len.is_null() {
            return fail(WSAEFAULT);
        }
        // SAFETY: storage is large enough for any address.
        let mut host: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut host_len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: as above.
        if unsafe { call(o.fd, (&raw mut host).cast(), &mut host_len) } != 0 {
            return fail_errno();
        }
        match from_host(&host, addr, len) {
            Ok(()) => 0,
            Err(code) => fail(code),
        }
    })
}

extern "stdcall" fn getsockname(s: u32, addr: *mut u8, len: *mut i32) -> i32 {
    name_of(s, addr, len, libc::getsockname)
}

extern "stdcall" fn getpeername(s: u32, addr: *mut u8, len: *mut i32) -> i32 {
    name_of(s, addr, len, libc::getpeername)
}

/// How an option's value is stored.
#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Int,
    /// `struct linger` with two u16 fields.
    Linger,
    /// SO_DONTLINGER: the inverse of `l_onoff`.
    DontLinger,
    /// A DWORD of milliseconds, a `timeval` on the host.
    Millis,
    /// SO_ERROR: an errno on the host, a WSAE code in Winsock.
    Error,
}

/// The host level, option and value shape for a Winsock option.
fn option(level: i32, name: i32) -> Option<(i32, i32, Shape)> {
    use Shape::*;
    Some(match (level, name as u32) {
        (WIN_SOL_SOCKET, 0x1) => (libc::SOL_SOCKET, libc::SO_DEBUG, Int),
        (WIN_SOL_SOCKET, 0x4) => (libc::SOL_SOCKET, libc::SO_REUSEADDR, Int),
        (WIN_SOL_SOCKET, 0x8) => (libc::SOL_SOCKET, libc::SO_KEEPALIVE, Int),
        (WIN_SOL_SOCKET, 0x10) => (libc::SOL_SOCKET, libc::SO_DONTROUTE, Int),
        (WIN_SOL_SOCKET, 0x20) => (libc::SOL_SOCKET, libc::SO_BROADCAST, Int),
        (WIN_SOL_SOCKET, 0x80) => (libc::SOL_SOCKET, libc::SO_LINGER, Linger),
        (WIN_SOL_SOCKET, 0xffff_ff7f) => (libc::SOL_SOCKET, libc::SO_LINGER, DontLinger),
        (WIN_SOL_SOCKET, 0x100) => (libc::SOL_SOCKET, libc::SO_OOBINLINE, Int),
        (WIN_SOL_SOCKET, 0x1001) => (libc::SOL_SOCKET, libc::SO_SNDBUF, Int),
        (WIN_SOL_SOCKET, 0x1002) => (libc::SOL_SOCKET, libc::SO_RCVBUF, Int),
        (WIN_SOL_SOCKET, 0x1005) => (libc::SOL_SOCKET, libc::SO_SNDTIMEO, Millis),
        (WIN_SOL_SOCKET, 0x1006) => (libc::SOL_SOCKET, libc::SO_RCVTIMEO, Millis),
        (WIN_SOL_SOCKET, 0x1007) => (libc::SOL_SOCKET, libc::SO_ERROR, Error),
        (WIN_SOL_SOCKET, 0x1008) => (libc::SOL_SOCKET, libc::SO_TYPE, Int),
        (IPPROTO_TCP, 0x1) => (libc::IPPROTO_TCP, libc::TCP_NODELAY, Int),
        _ => return None,
    })
}

fn read_u16(p: *const u8, at: usize) -> u16 {
    // SAFETY: inside the caller's option buffer.
    unsafe { p.add(at).cast::<u16>().read_unaligned() }
}

extern "stdcall" fn setsockopt(s: u32, level: i32, name: i32, value: *const u8, len: i32) -> i32 {
    with_socket(s, |o| {
        let Some((host_level, host_name, shape)) = option(level, name) else {
            gap(&format!("setsockopt level {level:#x} option {name:#x}"));
            return fail(WSAENOPROTOOPT);
        };
        if value.is_null() || len < 1 {
            return fail(WSAEFAULT);
        }
        // An int option may come as a single byte (a BOOL in a char).
        let int = || -> i32 {
            if len >= 4 {
                // SAFETY: four readable bytes.
                unsafe { value.cast::<i32>().read_unaligned() }
            } else {
                // SAFETY: one readable byte.
                i32::from(unsafe { *value })
            }
        };
        // SAFETY: plain setsockopt calls with values we built.
        let r = unsafe {
            match shape {
                Shape::Int => {
                    let v = int();
                    libc::setsockopt(o.fd, host_level, host_name, (&raw const v).cast(), 4)
                }
                Shape::Linger | Shape::DontLinger => {
                    if len < 4 && shape == Shape::Linger {
                        return fail(WSAEFAULT);
                    }
                    let l = if shape == Shape::Linger {
                        libc::linger {
                            l_onoff: i32::from(read_u16(value, 0)),
                            l_linger: i32::from(read_u16(value, 2)),
                        }
                    } else {
                        libc::linger {
                            l_onoff: i32::from(int() == 0),
                            l_linger: 0,
                        }
                    };
                    let size = size_of::<libc::linger>() as libc::socklen_t;
                    libc::setsockopt(o.fd, host_level, host_name, (&raw const l).cast(), size)
                }
                Shape::Millis => {
                    let ms = int() as u32;
                    let t = libc::timeval {
                        tv_sec: (ms / 1000) as libc::time_t,
                        tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
                    };
                    let size = size_of::<libc::timeval>() as libc::socklen_t;
                    libc::setsockopt(o.fd, host_level, host_name, (&raw const t).cast(), size)
                }
                Shape::Error => return fail(WSAENOPROTOOPT),
            }
        };
        if r == 0 { 0 } else { fail_errno() }
    })
}

extern "stdcall" fn getsockopt(
    s: u32,
    level: i32,
    name: i32,
    value: *mut u8,
    len: *mut i32,
) -> i32 {
    with_socket(s, |o| {
        let Some((host_level, host_name, shape)) = option(level, name) else {
            gap(&format!("getsockopt level {level:#x} option {name:#x}"));
            return fail(WSAENOPROTOOPT);
        };
        // SAFETY: readable when not NULL (the API's contract).
        if value.is_null() || len.is_null() || unsafe { *len } < 4 {
            return fail(WSAEFAULT);
        }
        // SAFETY: storage for any of the shapes.
        let mut buf = [0u8; 32];
        let mut buf_len = buf.len() as libc::socklen_t;
        // SAFETY: as above.
        if unsafe {
            libc::getsockopt(
                o.fd,
                host_level,
                host_name,
                buf.as_mut_ptr().cast(),
                &mut buf_len,
            )
        } != 0
        {
            return fail_errno();
        }
        let int = i32::from_ne_bytes(buf[0..4].try_into().unwrap());
        let out: u32 = match shape {
            Shape::Int => int as u32,
            Shape::Error => {
                if int == 0 {
                    0
                } else {
                    wsa_error(int)
                }
            }
            Shape::Linger | Shape::DontLinger => {
                let onoff = int;
                let secs = i32::from_ne_bytes(buf[4..8].try_into().unwrap());
                if shape == Shape::DontLinger {
                    u32::from(onoff == 0)
                } else {
                    (onoff as u32 & 0xffff) | ((secs as u32 & 0xffff) << 16)
                }
            }
            Shape::Millis => {
                // SAFETY: the host wrote a timeval.
                let t = unsafe { buf.as_ptr().cast::<libc::timeval>().read_unaligned() };
                (t.tv_sec as u32) * 1000 + (t.tv_usec as u32) / 1000
            }
        };
        // SAFETY: at least four writable bytes (checked above).
        unsafe {
            value.cast::<u32>().write_unaligned(out);
            *len = 4;
        }
        0
    })
}

const FIONBIO: u32 = 0x8004_667e;
const FIONREAD: u32 = 0x4004_667f;

extern "stdcall" fn ioctlsocket(s: u32, command: u32, arg: *mut u32) -> i32 {
    with_socket(s, |o| {
        if arg.is_null() {
            return fail(WSAEFAULT);
        }
        // SAFETY: plain descriptor calls; arg is readable and writable.
        unsafe {
            match command {
                FIONBIO => {
                    let flags = libc::fcntl(o.fd, libc::F_GETFL);
                    let flags = if *arg != 0 {
                        flags | libc::O_NONBLOCK
                    } else {
                        flags & !libc::O_NONBLOCK
                    };
                    if libc::fcntl(o.fd, libc::F_SETFL, flags) != 0 {
                        return fail_errno();
                    }
                }
                FIONREAD => {
                    let mut n: i32 = 0;
                    if libc::ioctl(o.fd, libc::FIONREAD, &mut n) != 0 {
                        return fail_errno();
                    }
                    *arg = n as u32;
                }
                other => {
                    gap(&format!("ioctlsocket command {other:#x}"));
                    return fail(WSAEINVAL);
                }
            }
        }
        0
    })
}

/// The calling thread's last error, as Winsock sets it.
#[allow(non_snake_case)]
extern "stdcall" fn WSAGetLastError() -> u32 {
    GetLastError()
}

#[allow(non_snake_case)]
extern "stdcall" fn WSASetLastError(code: u32) {
    set_last_error(code);
}

/// Pending connects are done once `select` sees the socket writable.
pub(super) fn connected(o: &SocketObject) {
    o.connecting.store(false, Ordering::SeqCst);
}

#[cfg(test)]
pub(super) mod tests;
