//! `iphlpapi.dll`: the IP Helper API. `GetAdaptersAddresses`.
//!
//! Adapters come from the engine's `network` section: one per entry in
//! `network.interfaces`, in profile order. Structures follow
//! IP_ADAPTER_ADDRESSES_LH and its lists on Microsoft Learn, in their
//! 32-bit layout, all inside the caller's buffer.
//!
//! | Field | Source |
//! | --- | --- |
//! | `FriendlyName`, `Description` | `name`, `description` |
//! | `PhysicalAddress` | `mac` |
//! | Unicast addresses, `OnLinkPrefixLength` | `ipv4` (address/prefix); origin manual, or DHCP with `dhcp` |
//! | Gateways (`GAA_FLAG_INCLUDE_GATEWAYS`) | `gateway` |
//! | DNS servers | `dns` |
//! | `DnsSuffix` | `network.dns_suffix` |
//! | `Flags` | DHCP enabled with `dhcp`; IPv4 enabled |
//!
//! The profile has no adapter GUID (`AdapterName`), interface index,
//! interface type, MTU, link speed, operational status or metric. Until
//! it does, they are a logged gap and report nothing: an empty name,
//! the profile position as the index, type "other", status "unknown"
//! and zero for the numbers. The profile has no IPv6 addresses either:
//! asking for `AF_INET6` is a logged gap and finds no adapters. Prefix
//! and WINS lists are logged gaps; anycast and multicast lists are empty.

use std::net::Ipv4Addr;

use serde_json::Value;

use crate::gap::GapKind;
use crate::runtime::with_current;
use crate::win::facts::{self, Caller};

const CALLER: Caller = ("iphlpapi.dll", "GetAdaptersAddresses");

const AF_UNSPEC: u32 = 0;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

const GAA_FLAG_SKIP_UNICAST: u32 = 0x1;
const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x8;
const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x10;
const GAA_FLAG_SKIP_FRIENDLY_NAME: u32 = 0x20;
const GAA_FLAG_INCLUDE_WINS_INFO: u32 = 0x40;
const GAA_FLAG_INCLUDE_GATEWAYS: u32 = 0x80;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_NO_DATA: u32 = 232;
const ERROR_NOT_SUPPORTED: u32 = 50;

/// sizeof(IP_ADAPTER_ADDRESSES_LH) on 32-bit Windows.
const ADAPTER_SIZE: usize = 376;
/// sizeof(IP_ADAPTER_UNICAST_ADDRESS_LH).
const UNICAST_SIZE: usize = 48;
/// sizeof(IP_ADAPTER_DNS_SERVER_ADDRESS_XP) and of
/// IP_ADAPTER_GATEWAY_ADDRESS_LH.
const LIST_SIZE: usize = 24;
const SOCKADDR_IN_SIZE: usize = 16;

const IP_ADAPTER_DHCP_ENABLED: u32 = 0x4;
const IP_ADAPTER_IPV4_ENABLED: u32 = 0x80;
const IF_TYPE_OTHER: u32 = 1;
const IF_OPER_STATUS_UNKNOWN: u32 = 4;
const IP_PREFIX_ORIGIN_MANUAL: u32 = 1;
const IP_PREFIX_ORIGIN_DHCP: u32 = 3;
const IP_SUFFIX_ORIGIN_MANUAL: u32 = 1;
const IP_SUFFIX_ORIGIN_DHCP: u32 = 3;
const IP_DAD_STATE_PREFERRED: u32 = 4;
const INFINITE_LIFETIME: u32 = 0xffff_ffff;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![(
        "GetAdaptersAddresses",
        GetAdaptersAddresses as *const () as u32,
    )]
}

fn gap(what: &str) {
    with_current(|p| {
        p.record_runtime_gap(GapKind::Feature, CALLER.0, &format!("{}: {what}", CALLER.1))
    });
}

/// One interface from the profile.
#[derive(Debug, Default, PartialEq)]
struct Interface {
    name: String,
    description: String,
    mac: Vec<u8>,
    ipv4: Vec<(Ipv4Addr, u8)>,
    gateway: Option<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
    dhcp: bool,
}

fn parse_interface(v: &Value) -> Option<Interface> {
    let text = |k: &str| v.get(k).and_then(Value::as_str);
    let mac = match text("mac") {
        Some(m) => m
            .split(':')
            .map(|b| u8::from_str_radix(b, 16).ok())
            .collect::<Option<Vec<u8>>>()?,
        None => Vec::new(),
    };
    let ipv4 = v
        .get("ipv4")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|a| {
            let (addr, prefix) = a.as_str()?.split_once('/')?;
            Some((
                addr.parse().ok()?,
                prefix.parse().ok().filter(|&p| p <= 32)?,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let dns = v
        .get("dns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|a| a.as_str()?.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    Some(Interface {
        name: text("name")?.to_string(),
        description: text("description").unwrap_or_default().to_string(),
        mac,
        ipv4,
        gateway: match text("gateway") {
            Some(g) => Some(g.parse().ok()?),
            None => None,
        },
        dns,
        dhcp: v.get("dhcp").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// A buffer laid out at offset 0, with the offsets of the pointers in it,
/// which become addresses once its real base is known.
#[derive(Default)]
struct Layout {
    data: Vec<u8>,
    pointers: Vec<usize>,
}

impl Layout {
    fn alloc(&mut self, size: usize, align: usize) -> usize {
        let at = self.data.len().next_multiple_of(align);
        self.data.resize(at + size, 0);
        at
    }

    fn u32(&mut self, at: usize, v: u32) {
        self.data[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Stores at `at` a pointer to offset `target`.
    fn pointer(&mut self, at: usize, target: usize) {
        self.u32(at, target as u32);
        self.pointers.push(at);
    }

    fn wide(&mut self, s: &str) -> usize {
        let units: Vec<u16> = s.encode_utf16().chain([0]).collect();
        let at = self.alloc(units.len() * 2, 2);
        for (i, u) in units.iter().enumerate() {
            self.data[at + 2 * i..at + 2 * i + 2].copy_from_slice(&u.to_le_bytes());
        }
        at
    }

    fn ansi(&mut self, s: &str) -> usize {
        let at = self.alloc(s.len() + 1, 1);
        self.data[at..at + s.len()].copy_from_slice(s.as_bytes());
        at
    }

    fn sockaddr(&mut self, addr: Ipv4Addr) -> usize {
        let at = self.alloc(SOCKADDR_IN_SIZE, 4);
        self.data[at..at + 2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        self.data[at + 4..at + 8].copy_from_slice(&addr.octets());
        at
    }

    /// A list of SOCKET_ADDRESS entries of `size` bytes each, linked by
    /// `Next` at +8, the address at +12. Returns the first, if any.
    fn address_list(&mut self, addrs: &[Ipv4Addr], size: usize) -> Option<usize> {
        let entries: Vec<usize> = addrs.iter().map(|_| self.alloc(size, 8)).collect();
        for (i, (&at, &addr)) in entries.iter().zip(addrs).enumerate() {
            self.u32(at, size as u32);
            if let Some(&next) = entries.get(i + 1) {
                self.pointer(at + 8, next);
            }
            let sa = self.sockaddr(addr);
            self.pointer(at + 12, sa);
            self.u32(at + 16, SOCKADDR_IN_SIZE as u32);
        }
        entries.first().copied()
    }

    /// The bytes with every pointer moved to `base`.
    fn at(mut self, base: u32) -> Vec<u8> {
        for at in std::mem::take(&mut self.pointers) {
            let offset = u32::from_le_bytes(self.data[at..at + 4].try_into().unwrap());
            self.u32(at, base + offset);
        }
        self.data
    }
}

fn layout(interfaces: &[Interface], suffix: &str, flags: u32) -> Layout {
    let mut l = Layout::default();
    let adapters: Vec<usize> = interfaces
        .iter()
        .map(|_| l.alloc(ADAPTER_SIZE, 8))
        .collect();
    for (i, (&a, ifc)) in adapters.iter().zip(interfaces).enumerate() {
        l.u32(a, ADAPTER_SIZE as u32);
        l.u32(a + 4, i as u32 + 1);
        if let Some(&next) = adapters.get(i + 1) {
            l.pointer(a + 8, next);
        }
        let name = l.ansi("");
        l.pointer(a + 12, name);
        if flags & GAA_FLAG_SKIP_UNICAST == 0 && !ifc.ipv4.is_empty() {
            let entries: Vec<usize> = ifc.ipv4.iter().map(|_| l.alloc(UNICAST_SIZE, 8)).collect();
            for (j, (&u, &(addr, prefix))) in entries.iter().zip(&ifc.ipv4).enumerate() {
                l.u32(u, UNICAST_SIZE as u32);
                if let Some(&next) = entries.get(j + 1) {
                    l.pointer(u + 8, next);
                }
                let sa = l.sockaddr(addr);
                l.pointer(u + 12, sa);
                l.u32(u + 16, SOCKADDR_IN_SIZE as u32);
                let (prefix_origin, suffix_origin) = if ifc.dhcp {
                    (IP_PREFIX_ORIGIN_DHCP, IP_SUFFIX_ORIGIN_DHCP)
                } else {
                    (IP_PREFIX_ORIGIN_MANUAL, IP_SUFFIX_ORIGIN_MANUAL)
                };
                l.u32(u + 20, prefix_origin);
                l.u32(u + 24, suffix_origin);
                l.u32(u + 28, IP_DAD_STATE_PREFERRED);
                l.u32(u + 32, INFINITE_LIFETIME);
                l.u32(u + 36, INFINITE_LIFETIME);
                l.u32(u + 40, INFINITE_LIFETIME);
                l.data[u + 44] = prefix;
            }
            l.pointer(a + 16, entries[0]);
        }
        if flags & GAA_FLAG_SKIP_DNS_SERVER == 0
            && let Some(first) = l.address_list(&ifc.dns, LIST_SIZE)
        {
            l.pointer(a + 28, first);
        }
        let s = l.wide(suffix);
        l.pointer(a + 32, s);
        let s = l.wide(&ifc.description);
        l.pointer(a + 36, s);
        let friendly = if flags & GAA_FLAG_SKIP_FRIENDLY_NAME == 0 {
            ifc.name.as_str()
        } else {
            ""
        };
        let s = l.wide(friendly);
        l.pointer(a + 40, s);
        let mac_len = ifc.mac.len().min(8);
        l.data[a + 44..a + 44 + mac_len].copy_from_slice(&ifc.mac[..mac_len]);
        l.u32(a + 52, mac_len as u32);
        let mut adapter_flags = IP_ADAPTER_IPV4_ENABLED;
        if ifc.dhcp {
            adapter_flags |= IP_ADAPTER_DHCP_ENABLED;
        }
        l.u32(a + 56, adapter_flags);
        l.u32(a + 64, IF_TYPE_OTHER);
        l.u32(a + 68, IF_OPER_STATUS_UNKNOWN);
        if flags & GAA_FLAG_INCLUDE_GATEWAYS != 0
            && let Some(first) = l.address_list(ifc.gateway.as_slice(), LIST_SIZE)
        {
            l.pointer(a + 164, first);
        }
    }
    l.data.resize(l.data.len().next_multiple_of(8), 0);
    l
}

/// Fills the caller's buffer with the host's adapters. Returns 0,
/// ERROR_BUFFER_OVERFLOW with the size needed in `*size`, ERROR_NO_DATA
/// when there are none, or ERROR_INVALID_PARAMETER.
#[allow(non_snake_case)]
extern "stdcall" fn GetAdaptersAddresses(
    family: u32,
    flags: u32,
    _reserved: u32,
    buffer: *mut u8,
    size: *mut u32,
) -> u32 {
    if size.is_null() || !matches!(family, AF_UNSPEC | AF_INET | AF_INET6) {
        return ERROR_INVALID_PARAMETER;
    }
    if family == AF_INET6 {
        gap("IPv6 addresses are not in the host profile");
        return ERROR_NO_DATA;
    }
    if flags & GAA_FLAG_INCLUDE_PREFIX != 0 {
        gap("GAA_FLAG_INCLUDE_PREFIX");
    }
    if flags & GAA_FLAG_INCLUDE_WINS_INFO != 0 {
        gap("GAA_FLAG_INCLUDE_WINS_INFO");
    }
    let Some(network) = facts::section(CALLER, "network") else {
        return ERROR_NOT_SUPPORTED;
    };
    let entries = network.get("interfaces").and_then(Value::as_array);
    let Some(interfaces) = entries
        .into_iter()
        .flatten()
        .map(parse_interface)
        .collect::<Option<Vec<_>>>()
    else {
        gap("an interface in the network section is malformed");
        return ERROR_NOT_SUPPORTED;
    };
    if interfaces.is_empty() {
        return ERROR_NO_DATA;
    }
    gap("adapter GUID, index, type, MTU, speed, status and metric are not in the host profile");
    let suffix = network
        .get("dns_suffix")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let layout = layout(&interfaces, suffix, flags);
    let needed = layout.data.len() as u32;
    // SAFETY: readable and writable (the API's contract).
    let available = unsafe { *size };
    if buffer.is_null() || available < needed {
        // SAFETY: as above.
        unsafe { *size = needed };
        return ERROR_BUFFER_OVERFLOW;
    }
    let bytes = layout.at(buffer as u32);
    // SAFETY: the buffer holds `available` >= `needed` bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) };
    0
}

#[cfg(test)]
mod tests;
