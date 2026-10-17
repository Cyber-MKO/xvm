//! Name resolution: `getaddrinfo`, `freeaddrinfo`.
//!
//! Following the getaddrinfo page on Microsoft Learn, and Kasim's decision
//! on where names come from (docs/BRIEF.md):
//!
//! | Name | Answer |
//! | --- | --- |
//! | NULL | Loopback, or the wildcard address with `AI_PASSIVE` |
//! | A numeric IPv4 or IPv6 address | That address |
//! | Listed in the host's `hosts` file | The file's addresses, in file order |
//! | Anything else | The real machine's resolver |
//!
//! The `hosts` file is `%SystemRoot%\System32\drivers\etc\hosts` on the
//! host's drives. Each result keeps the hints' socket type and protocol.
//! Service names (other than port numbers) and flags beyond
//! `AI_PASSIVE`, `AI_CANONNAME` and `AI_NUMERICHOST` are logged gaps.
//!
//! `ADDRINFOA` (32-bit): ai_flags, ai_family, ai_socktype, ai_protocol,
//! ai_addrlen, ai_canonname, ai_addr, ai_next; 32 bytes. One result list
//! is one allocation, kept in the process until `freeaddrinfo`.

use std::ffi::{CStr, CString, c_char};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use crate::gap::GapKind;
use crate::paths::DriveMap;
use crate::runtime::with_current;
use crate::win::kernel32::env::lookup;
use crate::win::kernel32::error::set_last_error;

const AF_UNSPEC: i32 = 0;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;
const AI_PASSIVE: i32 = 0x1;
const AI_CANONNAME: i32 = 0x2;
const AI_NUMERICHOST: i32 = 0x4;

// From "Windows Sockets Error Codes" on Microsoft Learn; getaddrinfo's
// EAI_* values are these.
const WSA_NOT_ENOUGH_MEMORY: i32 = 8;
const WSAEINVAL: i32 = 10022;
const WSAEAFNOSUPPORT: i32 = 10047;
const WSANOTINITIALISED: i32 = 10093;
const WSATYPE_NOT_FOUND: i32 = 10109;
const WSAHOST_NOT_FOUND: i32 = 11001;
const WSATRY_AGAIN: i32 = 11002;
const WSANO_RECOVERY: i32 = 11003;
const WSANO_DATA: i32 = 11004;

const NODE_WORDS: usize = 8;
const SOCKADDR_WORDS: usize = 7;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("getaddrinfo", getaddrinfo as *const () as u32),
        ("freeaddrinfo", freeaddrinfo as *const () as u32),
    ]
}

fn gap(what: String) {
    with_current(|p| p.record_runtime_gap(GapKind::Feature, "ws2_32.dll", &what));
}

#[derive(Debug, Clone, Copy, Default)]
struct Hints {
    flags: i32,
    family: i32,
    socktype: i32,
    protocol: i32,
}

fn wanted(ip: &IpAddr, family: i32) -> bool {
    match family {
        AF_INET => ip.is_ipv4(),
        AF_INET6 => ip.is_ipv6(),
        _ => true,
    }
}

/// The `hosts` file on the host's drives, if `SystemRoot` is set.
fn hosts_file() -> Option<PathBuf> {
    let root = lookup("SystemRoot")?;
    let path = format!(
        "{}\\System32\\drivers\\etc\\hosts",
        root.trim_end_matches('\\')
    );
    with_current(|p| {
        let params = &p.params;
        let full = DriveMap::full_path(&path, &params.current_directory).ok()?;
        params.drives.to_host(&full, &params.current_directory).ok()
    })
}

/// Addresses the `hosts` text lists for `name`: lines of an address and
/// names, `#` to the end of a line is a comment, names ignore case.
fn from_hosts(text: &str, name: &str, family: i32) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let Some(Ok(ip)) = fields.next().map(str::parse::<IpAddr>) else {
            continue;
        };
        if fields.any(|n| n.eq_ignore_ascii_case(name))
            && wanted(&ip, family)
            && !found.contains(&ip)
        {
            found.push(ip);
        }
    }
    found
}

/// Ask the real machine's resolver. Returns the addresses and the
/// canonical name, or a Winsock error.
fn from_resolver(name: &str, family: i32) -> Result<(Vec<IpAddr>, Option<String>), i32> {
    let node = CString::new(name).map_err(|_| WSAHOST_NOT_FOUND)?;
    // SAFETY: a zeroed addrinfo is valid hints.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = match family {
        AF_INET => libc::AF_INET,
        AF_INET6 => libc::AF_INET6,
        _ => libc::AF_UNSPEC,
    };
    // One entry per address.
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = libc::AI_CANONNAME;
    let mut list = std::ptr::null_mut();
    // SAFETY: valid strings and hints; list is freed below.
    let rc = unsafe { libc::getaddrinfo(node.as_ptr(), std::ptr::null(), &hints, &mut list) };
    if rc != 0 {
        return Err(match rc {
            libc::EAI_NONAME => WSAHOST_NOT_FOUND,
            libc::EAI_AGAIN => WSATRY_AGAIN,
            libc::EAI_NODATA => WSANO_DATA,
            libc::EAI_MEMORY => WSA_NOT_ENOUGH_MEMORY,
            _ => WSANO_RECOVERY,
        });
    }
    let mut addresses = Vec::new();
    let mut canonical = None;
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: entries of the list getaddrinfo returned.
        let e = unsafe { &*entry };
        if canonical.is_none() && !e.ai_canonname.is_null() {
            // SAFETY: a NUL-terminated string in the list.
            let text = unsafe { CStr::from_ptr(e.ai_canonname) };
            canonical = Some(text.to_string_lossy().into_owned());
        }
        // SAFETY: ai_addr matches ai_family.
        let ip = unsafe {
            match e.ai_family {
                libc::AF_INET => {
                    let a = &*e.ai_addr.cast::<libc::sockaddr_in>();
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))))
                }
                libc::AF_INET6 => {
                    let a = &*e.ai_addr.cast::<libc::sockaddr_in6>();
                    Some(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
                }
                _ => None,
            }
        };
        if let Some(ip) = ip.filter(|ip| !addresses.contains(ip)) {
            addresses.push(ip);
        }
        entry = e.ai_next;
    }
    // SAFETY: the list getaddrinfo returned, freed once.
    unsafe { libc::freeaddrinfo(list) };
    Ok((addresses, canonical))
}

/// The addresses and canonical name for `node`, or a Winsock error.
fn resolve(node: Option<&str>, hints: Hints) -> Result<(Vec<IpAddr>, Option<String>), i32> {
    let Some(name) = node else {
        let passive = hints.flags & AI_PASSIVE != 0;
        let v4 = IpAddr::V4(if passive {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::LOCALHOST
        });
        let v6 = IpAddr::V6(if passive {
            Ipv6Addr::UNSPECIFIED
        } else {
            Ipv6Addr::LOCALHOST
        });
        let all = [v6, v4].into_iter().filter(|ip| wanted(ip, hints.family));
        return Ok((all.collect(), None));
    };
    if let Ok(ip) = name.parse::<IpAddr>() {
        if !wanted(&ip, hints.family) {
            return Err(WSAHOST_NOT_FOUND);
        }
        return Ok((vec![ip], Some(name.to_string())));
    }
    if hints.flags & AI_NUMERICHOST != 0 {
        return Err(WSAHOST_NOT_FOUND);
    }
    if let Some(text) = hosts_file().and_then(|path| std::fs::read(path).ok()) {
        let found = from_hosts(&String::from_utf8_lossy(&text), name, hints.family);
        if !found.is_empty() {
            return Ok((found, Some(name.to_string())));
        }
    }
    from_resolver(name, hints.family)
}

/// The result list as one block: the nodes, then the socket addresses,
/// then the canonical name.
fn build(addresses: &[IpAddr], canonical: Option<&str>, hints: Hints, port: u16) -> Box<[u32]> {
    let n = addresses.len();
    let name = canonical.map(|c| {
        let mut bytes = c.as_bytes().to_vec();
        bytes.push(0);
        bytes
    });
    let name_words = name.as_ref().map_or(0, |b| b.len().div_ceil(4));
    let mut block = vec![0u32; n * (NODE_WORDS + SOCKADDR_WORDS) + name_words].into_boxed_slice();
    let base = block.as_ptr() as u32;
    let sockaddr_at = |i: usize| (n * NODE_WORDS + i * SOCKADDR_WORDS) * 4;
    let name_at = n * (NODE_WORDS + SOCKADDR_WORDS) * 4;
    // SAFETY: the block is sized for every write below.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(block.as_mut_ptr().cast::<u8>(), block.len() * 4) };
    for (i, ip) in addresses.iter().enumerate() {
        let (family, len) = match ip {
            IpAddr::V4(_) => (AF_INET, 16u32),
            IpAddr::V6(_) => (AF_INET6, 28u32),
        };
        let addr = sockaddr_at(i);
        bytes[addr..addr + 2].copy_from_slice(&(family as u16).to_le_bytes());
        bytes[addr + 2..addr + 4].copy_from_slice(&port.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => bytes[addr + 4..addr + 8].copy_from_slice(&v4.octets()),
            // sin6_flowinfo at +4 stays 0; sin6_scope_id at +24 stays 0.
            IpAddr::V6(v6) => bytes[addr + 8..addr + 24].copy_from_slice(&v6.octets()),
        }
        let node = [
            0,
            family as u32,
            hints.socktype as u32,
            hints.protocol as u32,
            len,
            if i == 0 && name.is_some() {
                base + name_at as u32
            } else {
                0
            },
            base + addr as u32,
            if i + 1 < n {
                base + ((i + 1) * NODE_WORDS * 4) as u32
            } else {
                0
            },
        ];
        block[i * NODE_WORDS..(i + 1) * NODE_WORDS].copy_from_slice(&node);
    }
    if let Some(name) = name {
        // SAFETY: as above.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(block.as_mut_ptr().cast::<u8>(), block.len() * 4)
        };
        bytes[name_at..name_at + name.len()].copy_from_slice(&name);
    }
    block
}

/// Returns 0 with the list in `*result`, or a Winsock error code, which
/// is also the thread's last error.
extern "stdcall" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const i32,
    result: *mut u32,
) -> i32 {
    let fail = |code: i32| {
        set_last_error(code as u32);
        code
    };
    if result.is_null() {
        return fail(WSAEINVAL);
    }
    // SAFETY: writable (the API's contract).
    unsafe { *result = 0 };
    if with_current(|p| p.winsock_starts) == 0 {
        return fail(WSANOTINITIALISED);
    }
    let hints = if hints.is_null() {
        Hints::default()
    } else {
        // SAFETY: an ADDRINFOA whose first four fields are read here.
        unsafe {
            Hints {
                flags: *hints,
                family: *hints.add(1),
                socktype: *hints.add(2),
                protocol: *hints.add(3),
            }
        }
    };
    // SAFETY: NUL-terminated strings or NULL (the API's contract).
    let text = |p: *const c_char| {
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    };
    let (node, service) = (text(node), text(service));
    if node.is_none() && service.is_none() {
        return fail(WSAHOST_NOT_FOUND);
    }
    if ![AF_UNSPEC, AF_INET, AF_INET6].contains(&hints.family) {
        return fail(WSAEAFNOSUPPORT);
    }
    if node.is_none() && hints.flags & AI_CANONNAME != 0 {
        return fail(WSAEINVAL);
    }
    let known = AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST;
    if hints.flags & !known != 0 {
        gap(format!("getaddrinfo flags {:#x}", hints.flags & !known));
    }
    let port = match service.as_deref() {
        None => 0,
        Some(s) => match s.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                gap(format!("getaddrinfo service name {s:?}"));
                return fail(WSATYPE_NOT_FOUND);
            }
        },
    };
    let (addresses, canonical) = match resolve(node.as_deref(), hints) {
        Ok((a, _)) if a.is_empty() => return fail(WSAHOST_NOT_FOUND),
        Ok(found) => found,
        Err(code) => return fail(code),
    };
    let canonical = canonical.filter(|_| hints.flags & AI_CANONNAME != 0);
    let block = build(&addresses, canonical.as_deref(), hints, port);
    let head = block.as_ptr() as u32;
    with_current(|p| p.addrinfo.insert(head, block));
    // SAFETY: as above.
    unsafe { *result = head };
    0
}

/// Frees a list `getaddrinfo` returned.
extern "stdcall" fn freeaddrinfo(list: u32) {
    if list == 0 {
        return;
    }
    let known = with_current(|p| p.addrinfo.remove(&list).is_some());
    if !known {
        gap(format!(
            "freeaddrinfo of {list:#x}, not a getaddrinfo result"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    struct Entry {
        family: u32,
        socktype: u32,
        canonical: Option<String>,
        ip: IpAddr,
        port: u16,
    }

    fn entries(head: u32) -> Vec<Entry> {
        let mut out = Vec::new();
        let mut node = head;
        while node != 0 {
            // SAFETY: nodes of a list getaddrinfo built.
            let w = unsafe { std::slice::from_raw_parts(node as *const u32, 8) };
            // SAFETY: as above.
            let addr = unsafe { std::slice::from_raw_parts(w[6] as *const u8, w[4] as usize) };
            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = if w[1] == AF_INET as u32 {
                IpAddr::V4(Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]))
            } else {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&addr[8..24]).unwrap()))
            };
            // SAFETY: a NUL-terminated name in the block.
            let canonical = (w[5] != 0).then(|| {
                unsafe { CStr::from_ptr(w[5] as *const c_char) }
                    .to_string_lossy()
                    .into_owned()
            });
            out.push(Entry {
                family: w[1],
                socktype: w[2],
                canonical,
                ip,
                port,
            });
            node = w[7];
        }
        out
    }

    fn call(node: Option<&CStr>, service: Option<&CStr>, hints: [i32; 8]) -> Result<u32, i32> {
        let mut head = 0;
        let rc = getaddrinfo(
            node.map_or(std::ptr::null(), CStr::as_ptr),
            service.map_or(std::ptr::null(), CStr::as_ptr),
            hints.as_ptr(),
            &mut head,
        );
        if rc == 0 { Ok(head) } else { Err(rc) }
    }

    fn host(tag: &str) -> (Runtime, crate::runtime::Attached, PathBuf) {
        let root = std::env::temp_dir().join(format!("xvm-addrinfo-{tag}-{}", std::process::id()));
        let etc = root.join("c/Windows/System32/drivers/etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("hosts"),
            "# comment\r\n10.1.2.3  wazuh-manager  alias # trailing\r\n\
             fd00::7 WAZUH-MANAGER\r\nbad line\r\n",
        )
        .unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), root.join("c"))]));
        process.params.current_directory = r"C:\".into();
        process.params.environment = vec![r"SystemRoot=C:\Windows".into()];
        process.winsock_starts = 1;
        let runtime = Runtime::new(process);
        let thread = runtime.attach().unwrap();
        (runtime, thread, root)
    }

    #[test]
    fn hosts_file_comes_first_and_keeps_its_order() {
        let (runtime, _t, root) = host("hosts");
        let head = call(
            Some(c"Wazuh-Manager"),
            Some(c"1514"),
            [AI_CANONNAME, 0, 1, 6, 0, 0, 0, 0],
        )
        .unwrap();
        let list = entries(head);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].ip, "10.1.2.3".parse::<IpAddr>().unwrap());
        assert_eq!(
            (list[0].family, list[0].socktype, list[0].port),
            (2, 1, 1514)
        );
        assert_eq!(list[0].canonical.as_deref(), Some("Wazuh-Manager"));
        assert_eq!(list[1].ip, "fd00::7".parse::<IpAddr>().unwrap());
        assert_eq!((list[1].family, list[1].canonical.as_deref()), (23, None));
        let v4 = call(Some(c"alias"), None, [0, AF_INET, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(entries(v4).len(), 1);
        freeaddrinfo(head);
        freeaddrinfo(v4);
        assert!(runtime.lock().addrinfo.is_empty());
        assert!(runtime.lock().gaps().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn numbers_null_names_and_the_real_resolver() {
        let (runtime, _t, root) = host("numeric");
        let list = entries(call(Some(c"192.0.2.9"), None, [0; 8]).unwrap());
        assert_eq!(list[0].ip, "192.0.2.9".parse::<IpAddr>().unwrap());
        let passive =
            entries(call(None, Some(c"80"), [AI_PASSIVE, AF_INET, 0, 0, 0, 0, 0, 0]).unwrap());
        assert_eq!(
            (passive[0].ip, passive[0].port),
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80)
        );
        let local = entries(call(None, Some(c"80"), [0, AF_INET6, 0, 0, 0, 0, 0, 0]).unwrap());
        assert_eq!(local[0].ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        // Not in the hosts file: the real machine's resolver answers.
        let real = entries(call(Some(c"localhost"), None, [0, AF_INET, 0, 0, 0, 0, 0, 0]).unwrap());
        assert_eq!(real[0].ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            call(
                Some(c"wazuh-manager"),
                None,
                [AI_NUMERICHOST, 0, 0, 0, 0, 0, 0, 0]
            ),
            Err(WSAHOST_NOT_FOUND)
        );
        assert_eq!(
            call(Some(c"no-such-host.invalid"), None, [0; 8]),
            Err(WSAHOST_NOT_FOUND)
        );
        drop(runtime);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn errors_and_gaps() {
        let (runtime, _t, root) = host("errors");
        assert_eq!(call(None, None, [0; 8]), Err(WSAHOST_NOT_FOUND));
        assert_eq!(
            call(Some(c"a"), None, [0, 17, 0, 0, 0, 0, 0, 0]),
            Err(WSAEAFNOSUPPORT)
        );
        assert_eq!(
            call(None, Some(c"1"), [AI_CANONNAME, 0, 0, 0, 0, 0, 0, 0]),
            Err(WSAEINVAL)
        );
        assert_eq!(
            call(Some(c"a"), Some(c"http"), [0; 8]),
            Err(WSATYPE_NOT_FOUND)
        );
        freeaddrinfo(0x1234);
        let gaps: Vec<String> = runtime
            .lock()
            .gaps()
            .iter()
            .map(|g| g.symbol.clone())
            .collect();
        assert_eq!(
            gaps,
            [
                "getaddrinfo service name \"http\"",
                "freeaddrinfo of 0x1234, not a getaddrinfo result"
            ]
        );
        runtime.lock().winsock_starts = 0;
        assert_eq!(call(Some(c"1.2.3.4"), None, [0; 8]), Err(WSANOTINITIALISED));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
