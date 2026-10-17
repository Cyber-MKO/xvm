use serde_json::json;

use super::*;
use crate::process::Process;
use crate::runtime::Runtime;

fn host() -> (Runtime, crate::runtime::Attached) {
    let base = json!({
        "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
        "source": {"golden_capture": "synthetic"},
        "network": {"dns_suffix": "corp.example",
                    "interfaces": [{"name": "Ethernet0", "description": "Example NIC", "dhcp": true}]},
    });
    let host = json!({
        "schema": 1, "kind": "host-profile", "name": "h", "base": "b", "os": "windows",
        "identity": {"hostname": "H"},
        "network": {"interfaces": [
            {"name": "Ethernet0", "mac": "02:00:00:00:01:01", "ipv4": ["192.0.2.11/24", "198.51.100.7/16"],
             "gateway": "192.0.2.1", "dns": ["192.0.2.53", "192.0.2.54"], "dhcp": false},
            {"name": "Backup", "ipv4": []},
        ]},
    });
    let mut process = Process::new(Vec::new());
    process.engine = Some(facts::test_engine(base, host));
    let runtime = Runtime::new(process);
    let thread = runtime.attach().unwrap();
    (runtime, thread)
}

fn u32_at(p: u32, offset: u32) -> u32 {
    // SAFETY: inside the test's buffer.
    unsafe { ((p + offset) as *const u32).read_unaligned() }
}

fn wide_at(p: u32) -> String {
    // SAFETY: a NUL-terminated UTF-16 string inside the buffer.
    unsafe { crate::win::text::wide(p as *const u16) }.unwrap()
}

/// The IPv4 address of the SOCKET_ADDRESS at `p`.
fn sockaddr_at(p: u32) -> Ipv4Addr {
    assert_eq!(u32_at(p, 4), 16);
    let sa = u32_at(p, 0);
    assert_eq!(u32_at(sa, 0) & 0xffff, AF_INET);
    Ipv4Addr::from(u32_at(sa, 4).to_le_bytes())
}

fn list(mut p: u32) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    while p != 0 {
        out.push(sockaddr_at(p + 12));
        p = u32_at(p, 8);
    }
    out
}

#[test]
fn adapters_follow_the_profile() {
    let (runtime, _thread) = host();
    let mut size = 0;
    let flags = GAA_FLAG_INCLUDE_GATEWAYS;
    assert_eq!(
        GetAdaptersAddresses(AF_UNSPEC, flags, 0, std::ptr::null_mut(), &mut size),
        ERROR_BUFFER_OVERFLOW
    );
    assert!(size as usize > 2 * ADAPTER_SIZE);
    let mut buf = vec![0u64; size as usize / 8];
    let base = buf.as_mut_ptr() as u32;
    assert_eq!(
        GetAdaptersAddresses(AF_INET, flags, 0, buf.as_mut_ptr().cast(), &mut size),
        0
    );

    let a = base;
    assert_eq!((u32_at(a, 0), u32_at(a, 4)), (ADAPTER_SIZE as u32, 1));
    assert_eq!(wide_at(u32_at(a, 40)), "Ethernet0");
    assert_eq!(wide_at(u32_at(a, 36)), "Example NIC");
    assert_eq!(wide_at(u32_at(a, 32)), "corp.example");
    // SAFETY: inside the buffer.
    let mac = unsafe { std::slice::from_raw_parts((a + 44) as *const u8, 6) };
    assert_eq!((mac, u32_at(a, 52)), (&[2, 0, 0, 0, 1, 1][..], 6));
    assert_eq!(
        u32_at(a, 56),
        IP_ADAPTER_IPV4_ENABLED,
        "static: no DHCP flag"
    );
    assert_eq!(
        (u32_at(a, 64), u32_at(a, 68)),
        (IF_TYPE_OTHER, IF_OPER_STATUS_UNKNOWN)
    );

    let u = u32_at(a, 16);
    assert_eq!(u32_at(u, 0), UNICAST_SIZE as u32);
    assert_eq!(sockaddr_at(u + 12), Ipv4Addr::new(192, 0, 2, 11));
    assert_eq!(u32_at(u, 20), IP_PREFIX_ORIGIN_MANUAL);
    assert_eq!(u32_at(u, 44) & 0xff, 24);
    let second = u32_at(u, 8);
    assert_eq!(sockaddr_at(second + 12), Ipv4Addr::new(198, 51, 100, 7));
    assert_eq!((u32_at(second, 44) & 0xff, u32_at(second, 8)), (16, 0));

    assert_eq!(
        list(u32_at(a, 28)),
        [Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)]
    );
    assert_eq!(list(u32_at(a, 164)), [Ipv4Addr::new(192, 0, 2, 1)]);

    // The second adapter: no addresses, and the end of the list.
    let b = u32_at(a, 8);
    assert_eq!(wide_at(u32_at(b, 40)), "Backup");
    assert_eq!(
        (u32_at(b, 4), u32_at(b, 8), u32_at(b, 16), u32_at(b, 52)),
        (2, 0, 0, 0)
    );
    assert!(b >= base && b + ADAPTER_SIZE as u32 <= base + size);

    // Skipping lists, and IPv6.
    assert_eq!(
        GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_DNS_SERVER,
            0,
            buf.as_mut_ptr().cast(),
            &mut size
        ),
        0
    );
    assert_eq!((u32_at(a, 16), u32_at(a, 28), u32_at(a, 164)), (0, 0, 0));
    assert_eq!(
        GetAdaptersAddresses(AF_INET6, 0, 0, buf.as_mut_ptr().cast(), &mut size),
        ERROR_NO_DATA
    );
    assert_eq!(
        GetAdaptersAddresses(7, 0, 0, buf.as_mut_ptr().cast(), &mut size),
        ERROR_INVALID_PARAMETER
    );
    let gaps: Vec<String> = runtime
        .lock()
        .gaps()
        .iter()
        .map(|g| g.symbol.clone())
        .collect();
    assert_eq!(gaps.len(), 2, "{gaps:?}");
}

#[test]
fn malformed_interfaces_are_rejected() {
    assert!(parse_interface(&json!({"name": "x", "mac": "zz:00"})).is_none());
    assert!(parse_interface(&json!({"name": "x", "ipv4": ["10.0.0.1/40"]})).is_none());
    assert_eq!(
        parse_interface(&json!({"name": "x"})),
        Some(Interface {
            name: "x".into(),
            ..Interface::default()
        })
    );
}
