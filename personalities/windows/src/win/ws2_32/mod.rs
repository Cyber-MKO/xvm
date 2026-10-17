//! `ws2_32.dll`, one submodule per API area.

mod addrinfo;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    addrinfo::exports()
}
