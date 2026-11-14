use super::*;
use crate::process::Process;
use crate::runtime::Runtime;

fn host() -> (Runtime, crate::runtime::Attached) {
    let base = json!({
        "schema": 1, "kind": "base-image", "name": "b", "os": "windows",
        "source": {"golden_capture": "synthetic"},
        "users": [
            {"name": "Administrator", "sid": "S-1-5-21-1-2-3-500", "enabled": true, "groups": ["Administrators"]},
            {"name": "Guest", "sid": "S-1-5-21-1-2-3-501", "enabled": false, "groups": ["Guests", "Users"]},
        ],
        "groups": [
            {"name": "Administrators", "sid": "S-1-5-32-544"},
            {"name": "Guests", "sid": "S-1-5-32-546"},
        ],
    });
    let host = json!({"schema": 1, "kind": "host-profile", "name": "h", "base": "b",
                      "os": "windows", "identity": {"hostname": "H"}});
    let mut process = Process::new(Vec::new());
    process.engine = Some(facts::test_engine(base, host));
    let runtime = Runtime::new(process);
    let thread = runtime.attach().unwrap();
    (runtime, thread)
}

/// The strings at field `field` of each of `n` entries of `fields` pointers.
fn strings(buf: u32, n: u32, fields: usize, field: usize) -> Vec<String> {
    (0..n as usize)
        .map(|i| {
            // SAFETY: a block from the function under test.
            let p = unsafe { *((buf as usize + (i * fields + field) * 4) as *const u32) };
            // SAFETY: a NUL-terminated string inside the block.
            unsafe { wide(p as usize as *const u16) }.unwrap()
        })
        .collect()
}

#[test]
fn users_and_groups_from_the_profile() {
    let (runtime, _thread) = host();
    let none = std::ptr::null();
    let (mut buf, mut read, mut total, mut resume) = (0u32, 0u32, 0u32, 5u32);
    assert_eq!(
        NetLocalGroupEnum(
            none,
            1,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
            &mut resume
        ),
        0
    );
    assert_eq!((read, total, resume), (2, 2, 0));
    assert_eq!(strings(buf, read, 2, 0), ["Administrators", "Guests"]);
    assert_eq!(strings(buf, read, 2, 1), ["", ""]);
    assert_eq!(NetApiBufferFree(buf), 0);

    assert_eq!(
        NetUserEnum(
            none,
            0,
            0,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
            std::ptr::null_mut()
        ),
        0
    );
    assert_eq!(strings(buf, read, 1, 0), ["Administrator", "Guest"]);
    NetApiBufferFree(buf);

    let guest: Vec<u16> = "WIN\\guest\0".encode_utf16().collect();
    assert_eq!(
        NetUserGetLocalGroups(
            none,
            guest.as_ptr(),
            0,
            1,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total
        ),
        0
    );
    assert_eq!(strings(buf, read, 1, 0), ["Guests", "Users"]);
    NetApiBufferFree(buf);
    let nobody: Vec<u16> = "nobody\0".encode_utf16().collect();
    assert_eq!(
        NetUserGetLocalGroups(
            none,
            nobody.as_ptr(),
            0,
            1,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total
        ),
        NERR_USER_NOT_FOUND
    );

    assert_eq!(
        NetUserEnum(
            none,
            3,
            0,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
            std::ptr::null_mut()
        ),
        ERROR_INVALID_LEVEL
    );
    assert_eq!(
        NetUserGetInfo(none, guest.as_ptr(), 1, &mut buf),
        ERROR_INVALID_LEVEL
    );
    let remote: Vec<u16> = "\\\\DC01\0".encode_utf16().collect();
    assert_eq!(
        NetLocalGroupEnum(
            remote.as_ptr(),
            0,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
            std::ptr::null_mut()
        ),
        ERROR_NOT_SUPPORTED
    );
    assert_eq!(runtime.lock().gaps().len(), 4);
}
