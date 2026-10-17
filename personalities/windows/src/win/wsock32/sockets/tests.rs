use super::*;
use crate::process::Process;
use crate::runtime::Runtime;

fn started_host() -> (Runtime, crate::runtime::Attached) {
    let runtime = Runtime::new(Process::new(Vec::new()));
    let thread = runtime.attach().unwrap();
    runtime.lock().winsock_starts = 1;
    (runtime, thread)
}

/// A Winsock `sockaddr_in` for 127.0.0.1 and `port` (host order).
fn loopback(port: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0..2].copy_from_slice(&2u16.to_le_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&[127, 0, 0, 1]);
    a
}

fn port_of(s: u32) -> u16 {
    let mut a = [0u8; 16];
    let mut len = 16;
    assert_eq!(getsockname(s, a.as_mut_ptr(), &mut len), 0);
    assert_eq!((u16::from_le_bytes([a[0], a[1]]), len), (2, 16));
    u16::from_be_bytes([a[2], a[3]])
}

/// An `fd_set` holding `sockets`.
fn fd_set(sockets: &[u32]) -> Vec<u32> {
    let mut set = vec![0u32; 65];
    set[0] = sockets.len() as u32;
    set[1..=sockets.len()].copy_from_slice(sockets);
    set
}

#[test]
fn tcp_over_loopback() {
    let (_runtime, _thread) = started_host();
    let server = socket(2, 1, 6);
    assert_ne!(server, INVALID_SOCKET);
    let one = 1i32;
    assert_eq!(
        setsockopt(server, WIN_SOL_SOCKET, 4, (&raw const one).cast(), 4),
        0
    );
    let any = loopback(0);
    assert_eq!(bind(server, any.as_ptr(), 16), 0);
    assert_eq!(listen(server, 4), 0);
    let port = port_of(server);

    // A non-blocking connect reports WSAEWOULDBLOCK, then becomes
    // writable.
    let client = socket(2, 1, 0);
    let mut on = 1u32;
    assert_eq!(ioctlsocket(client, FIONBIO, &mut on), 0);
    let to = loopback(port);
    let rc = connect(client, to.as_ptr(), 16);
    assert!(
        rc == 0 || GetLastError() == WSAEWOULDBLOCK,
        "{}",
        GetLastError()
    );
    let mut write = fd_set(&[client]);
    let wait = [5i32, 0];
    assert_eq!(
        super::super::select::tests_select(std::ptr::null_mut(), write.as_mut_ptr(), wait.as_ptr()),
        1
    );
    assert_eq!(write[..2], [1, client]);
    let mut error = 7u32;
    let mut len = 4;
    assert_eq!(
        getsockopt(
            client,
            WIN_SOL_SOCKET,
            0x1007,
            (&raw mut error).cast(),
            &mut len
        ),
        0
    );
    assert_eq!(error, 0, "SO_ERROR: connected");

    let mut peer = [0u8; 16];
    let mut peer_len = 16;
    let accepted = accept(server, peer.as_mut_ptr(), &mut peer_len);
    assert_ne!(accepted, INVALID_SOCKET);
    assert_eq!((peer_len, &peer[4..8]), (16, &[127, 0, 0, 1][..]));
    assert_eq!(port_of(client), u16::from_be_bytes([peer[2], peer[3]]));

    // Nothing to read yet: WSAEWOULDBLOCK on the non-blocking side.
    let mut buf = [0u8; 16];
    assert_eq!(recv(client, buf.as_mut_ptr(), 16, 0), SOCKET_ERROR);
    assert_eq!(GetLastError(), WSAEWOULDBLOCK);

    assert_eq!(send(accepted, b"hello".as_ptr(), 5, 0), 5);
    let mut read = fd_set(&[client, accepted]);
    assert_eq!(
        super::super::select::tests_select(read.as_mut_ptr(), std::ptr::null_mut(), wait.as_ptr()),
        1
    );
    assert_eq!(read[..2], [1, client]);
    let mut waiting = 0u32;
    assert_eq!(ioctlsocket(client, FIONREAD, &mut waiting), 0);
    assert_eq!(waiting, 5);
    assert_eq!(recv(client, buf.as_mut_ptr(), 16, 2), 5, "MSG_PEEK");
    assert_eq!(recv(client, buf.as_mut_ptr(), 16, 0), 5);
    assert_eq!(&buf[..5], b"hello");

    // Timeouts are milliseconds; lingering is two u16 values.
    let ms = 1500u32;
    assert_eq!(
        setsockopt(accepted, WIN_SOL_SOCKET, 0x1006, (&raw const ms).cast(), 4),
        0
    );
    let mut back = 0u32;
    len = 4;
    assert_eq!(
        getsockopt(
            accepted,
            WIN_SOL_SOCKET,
            0x1006,
            (&raw mut back).cast(),
            &mut len
        ),
        0
    );
    assert_eq!(back, 1500);
    let linger: [u16; 2] = [1, 3];
    assert_eq!(
        setsockopt(accepted, WIN_SOL_SOCKET, 0x80, linger.as_ptr().cast(), 4),
        0
    );
    assert_eq!(
        setsockopt(accepted, IPPROTO_TCP, 1, (&raw const one).cast(), 4),
        0
    );
    assert_eq!(
        setsockopt(accepted, 0, 99, (&raw const one).cast(), 4),
        SOCKET_ERROR
    );
    assert_eq!(GetLastError(), WSAENOPROTOOPT);

    // The peer closes: end of stream, then a send never raises SIGPIPE.
    assert_eq!(shutdown(accepted, 1), 0);
    assert_eq!(closesocket(accepted), 0);
    let mut off = 0u32;
    assert_eq!(ioctlsocket(client, FIONBIO, &mut off), 0);
    assert_eq!(recv(client, buf.as_mut_ptr(), 16, 0), 0);
    let mut failed = false;
    for _ in 0..50 {
        if send(client, b"x".as_ptr(), 1, 0) == SOCKET_ERROR {
            assert_eq!(GetLastError(), WSAECONNRESET);
            failed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(failed);
    assert_eq!(closesocket(client), 0);
    assert_eq!(closesocket(client), SOCKET_ERROR);
    assert_eq!(GetLastError(), WSAENOTSOCK);
    assert_eq!(closesocket(server), 0);
}

#[test]
fn refused_connections_and_errors() {
    let (runtime, _thread) = started_host();
    // A port nothing listens on: find one by binding and closing.
    let probe = socket(2, 1, 6);
    let any = loopback(0);
    assert_eq!(bind(probe, any.as_ptr(), 16), 0);
    let port = port_of(probe);
    closesocket(probe);
    let s = socket(2, 1, 6);
    let to = loopback(port);
    assert_eq!(connect(s, to.as_ptr(), 16), SOCKET_ERROR);
    assert_eq!(WSAGetLastError(), WSAECONNREFUSED);
    WSASetLastError(5);
    assert_eq!(WSAGetLastError(), 5);
    assert_eq!(socket(16, 1, 0), INVALID_SOCKET);
    assert_eq!(GetLastError(), WSAEAFNOSUPPORT);
    assert_eq!(recv(0x1234, std::ptr::null_mut(), 0, 0), SOCKET_ERROR);
    assert_eq!(GetLastError(), WSAENOTSOCK);
    closesocket(s);
    runtime.lock().winsock_starts = 0;
    assert_eq!(socket(2, 1, 6), INVALID_SOCKET);
    assert_eq!(GetLastError(), WSANOTINITIALISED);
}
