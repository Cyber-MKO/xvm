//! `ws2_32.dll`, one submodule per API area. Functions it shares with
//! `wsock32.dll` come from there.

mod addrinfo;

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    let mut all = addrinfo::exports();
    all.extend(super::wsock32::convert::shared(&[
        "inet_addr",
        "inet_ntoa",
        "ntohs",
    ]));
    all
}
