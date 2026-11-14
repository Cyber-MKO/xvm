use super::*;
use crate::process::Process;
use crate::runtime::Runtime;
use crate::win::kernel32::error::GetLastError;

fn host() -> (Runtime, crate::runtime::Attached) {
    let base = json!({
        "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
        "source": {"golden_capture": "synthetic"},
        "users": [{"name": "Administrator", "sid": "S-1-5-21-1-2-3-500", "enabled": true}],
        "groups": [
            {"name": "Administrators", "sid": "S-1-5-32-544"},
            {"name": "Web Operators", "sid": "S-1-5-21-1-2-3-1009"},
        ],
    });
    let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                      "os": "windows", "identity": {"hostname": "xvm-win-01-long-hostname"}});
    let mut process = Process::new(Vec::new());
    process.engine = Some(facts::test_engine(base, host));
    let runtime = Runtime::new(process);
    let thread = runtime.attach().unwrap();
    (runtime, thread)
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

#[test]
fn sids_convert_both_ways() {
    let (_runtime, _thread) = host();
    let mut sid: *mut u8 = std::ptr::null_mut();
    assert_eq!(
        ConvertStringSidToSidA(c"S-1-5-21-1-2-3-500".as_ptr(), &mut sid),
        1
    );
    assert_eq!(IsValidSid(sid), 1);
    assert_eq!(GetLengthSid(sid), 28);
    // SAFETY: a SID with five sub-authorities.
    unsafe {
        assert_eq!(*GetSidSubAuthorityCount(sid), 5);
        assert_eq!(*GetSidSubAuthority(sid, 4), 500);
    }
    assert_eq!(EqualSid(sid, sid), 1);
    let mut text: *mut u8 = std::ptr::null_mut();
    assert_eq!(ConvertSidToStringSidW(sid, &mut text), 1);
    // SAFETY: a NUL-terminated UTF-16 string.
    let back = unsafe { wide(text.cast()) }.unwrap();
    assert_eq!(back, "S-1-5-21-1-2-3-500");
    assert_eq!(ConvertStringSidToSidA(c"S-9".as_ptr(), &mut sid), 0);
    assert_eq!(GetLastError(), ERROR_INVALID_SID);
    assert_eq!(IsValidSid(std::ptr::null()), 0);
}

#[test]
fn accounts_from_the_profile() {
    let (runtime, _thread) = host();
    let none = std::ptr::null();
    // Sizes first, then the lookup.
    let (mut sid_len, mut dom_len, mut kind) = (0u32, 0u32, 0u32);
    let name = w("Administrators");
    assert_eq!(
        LookupAccountNameW(
            none,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut dom_len,
            &mut kind
        ),
        0
    );
    assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    assert_eq!((sid_len, dom_len), (16, 8), "BUILTIN and its NUL");
    let mut sid = vec![0u8; sid_len as usize];
    let mut dom = vec![0u16; dom_len as usize];
    assert_eq!(
        LookupAccountNameW(
            none,
            name.as_ptr(),
            sid.as_mut_ptr(),
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut kind
        ),
        1
    );
    assert_eq!(sid::to_text(&sid).as_deref(), Some("S-1-5-32-544"));
    assert_eq!(
        (String::from_utf16(&dom[..dom_len as usize]).unwrap(), kind),
        ("BUILTIN".into(), SID_TYPE_ALIAS)
    );

    // Back from the SID: a user in the computer's NetBIOS domain.
    let user = sid::to_bytes("S-1-5-21-1-2-3-500").unwrap();
    let (mut n, mut d) = ([0u8; 32], [0u8; 32]);
    let (mut n_len, mut d_len) = (32u32, 32u32);
    assert_eq!(
        LookupAccountSidA(
            std::ptr::null(),
            user.as_ptr(),
            n.as_mut_ptr(),
            &mut n_len,
            d.as_mut_ptr(),
            &mut d_len,
            &mut kind
        ),
        1
    );
    assert_eq!(&n[..n_len as usize], b"Administrator");
    assert_eq!(
        &d[..d_len as usize],
        b"XVM-WIN-01-LONG",
        "upper case, 15 characters"
    );
    assert_eq!(kind, SID_TYPE_USER);

    let qualified = w("XVM-WIN-01-LONG\\Web Operators");
    sid_len = 64;
    dom_len = 32;
    let mut sid = [0u8; 64];
    let mut dom = [0u16; 32];
    assert_eq!(
        LookupAccountNameW(
            none,
            qualified.as_ptr(),
            sid.as_mut_ptr(),
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut kind
        ),
        1
    );
    // Well-known accounts, from Learn.
    let ns = sid::to_bytes("S-1-5-20").unwrap();
    let (mut n, mut d) = ([0u16; 32], [0u16; 32]);
    let (mut n_len, mut d_len) = (32u32, 32u32);
    assert_eq!(
        LookupAccountSidW(
            none,
            ns.as_ptr(),
            n.as_mut_ptr(),
            &mut n_len,
            d.as_mut_ptr(),
            &mut d_len,
            &mut kind
        ),
        1
    );
    assert_eq!(
        String::from_utf16(&n[..n_len as usize]).unwrap(),
        "NETWORK SERVICE"
    );
    assert_eq!(
        String::from_utf16(&d[..d_len as usize]).unwrap(),
        "NT AUTHORITY"
    );
    assert_eq!(kind, SID_TYPE_WELL_KNOWN_GROUP);
    let unknown = w("Nobody");
    assert_eq!(
        LookupAccountNameW(
            none,
            unknown.as_ptr(),
            sid.as_mut_ptr(),
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut kind
        ),
        0
    );
    assert_eq!(GetLastError(), ERROR_NONE_MAPPED);
    assert_eq!(runtime.lock().gaps().len(), 1);
}
