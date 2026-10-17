//! Directory searches: `_findfirst`, `_findnext`, `_findclose`.
//!
//! The `_findfirst` page on Microsoft Learn: the pattern's last component
//! may hold `*` and `?`; names match without regard to case; a search
//! reports `.` and `..` for a directory other than a drive's root, as
//! Windows does. Names come back sorted without regard to case, the order
//! NTFS gives. `*.*` matches every name. Short (8.3) names are not
//! modelled.
//!
//! `struct _finddata_t` (32-bit `msvcrt`, 280 bytes): attrib, time_create,
//! time_access, time_write (32-bit `time_t`), size (32-bit), name[260].

use std::ffi::c_char;
use std::path::Path;

use super::errno::{self, EINVAL, ENOENT};
use super::stat::{resolve, status};
use crate::runtime::with_current;
use crate::win::text::ansi;

const A_RDONLY: u32 = 0x1;
const A_SUBDIR: u32 = 0x10;
const A_ARCH: u32 = 0x20;
const S_IWRITE: u16 = 0x80;
const S_IFDIR: u16 = 0x4000;

/// One entry, ready for `_finddata_t`.
#[derive(Debug, Clone)]
pub struct Entry {
    name: String,
    attrib: u32,
    times: [i64; 3],
    size: u64,
}

/// The entries a search has not reported yet.
#[derive(Debug, Default)]
pub struct Search {
    rest: std::collections::VecDeque<Entry>,
}

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("_findfirst", _findfirst as *const () as u32),
        ("_findnext", _findnext as *const () as u32),
        ("_findclose", _findclose as *const () as u32),
    ]
}

/// Whether `name` matches `pattern` (`*` and `?`), ignoring case.
fn matches(pattern: &str, name: &str) -> bool {
    if pattern == "*.*" {
        return true;
    }
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn entry(name: String, host: &Path, full: &str) -> Option<Entry> {
    let s = status(host, full).ok()?;
    let mut attrib = if s.mode & S_IFDIR != 0 {
        A_SUBDIR
    } else {
        A_ARCH
    };
    if s.mode & S_IWRITE == 0 {
        attrib |= A_RDONLY;
    }
    Some(Entry {
        name,
        attrib,
        times: [s.ctime, s.atime, s.mtime],
        size: s.size,
    })
}

/// The entries `pattern` (a Windows path) names, or an `errno` value.
fn search(pattern: &str) -> Result<Vec<Entry>, i32> {
    let (host, full) = resolve(pattern)?;
    let (dir_full, wanted) = full.rsplit_once('\\').ok_or(ENOENT)?;
    let dir_host = host.parent().ok_or(ENOENT)?;
    let dir_full = if dir_full.ends_with(':') {
        format!("{dir_full}\\")
    } else {
        dir_full.to_string()
    };
    let mut entries = Vec::new();
    for item in std::fs::read_dir(dir_host).map_err(|_| ENOENT)?.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        if matches(wanted, &name) {
            let full = format!("{}\\{name}", dir_full.trim_end_matches('\\'));
            entries.extend(entry(name, &item.path(), &full));
        }
    }
    entries.sort_by_key(|e| e.name.to_uppercase());
    let root = dir_full.len() == 3;
    if !root {
        let mut dots: Vec<Entry> = [".", ".."]
            .into_iter()
            .filter(|d| matches(wanted, d))
            .filter_map(|d| entry(d.to_string(), dir_host, &dir_full))
            .collect();
        dots.append(&mut entries);
        entries = dots;
    }
    if entries.is_empty() {
        return Err(ENOENT);
    }
    Ok(entries)
}

fn write(out: *mut u8, e: &Entry) {
    let mut buf = [0u8; 280];
    buf[0..4].copy_from_slice(&e.attrib.to_le_bytes());
    for (i, t) in e.times.iter().enumerate() {
        buf[4 + 4 * i..8 + 4 * i].copy_from_slice(&(*t as i32).to_le_bytes());
    }
    buf[16..20].copy_from_slice(&(e.size.min(u32::MAX as u64) as u32).to_le_bytes());
    let name = e.name.as_bytes();
    let len = name.len().min(259);
    buf[20..20 + len].copy_from_slice(&name[..len]);
    // SAFETY: out holds a struct _finddata_t (the function's contract).
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
}

/// Starts a search. Returns its handle, or -1 with ENOENT when nothing
/// matches.
extern "C" fn _findfirst(pattern: *const c_char, out: *mut u8) -> i32 {
    // SAFETY: a NUL-terminated string (the function's contract).
    let Some(pattern) = (unsafe { ansi(pattern) }) else {
        errno::set(EINVAL);
        return -1;
    };
    if out.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    let mut entries = match search(&pattern) {
        Ok(e) => std::collections::VecDeque::from(e),
        Err(code) => {
            errno::set(code);
            return -1;
        }
    };
    write(out, &entries.pop_front().expect("a match"));
    with_current(|p| {
        let handle = p.crt.finds.keys().next_back().map_or(0x10, |h| h + 1);
        p.crt.finds.insert(handle, Search { rest: entries });
        handle
    })
}

/// The next match: 0, or -1 with ENOENT when there are no more.
extern "C" fn _findnext(handle: i32, out: *mut u8) -> i32 {
    let next = with_current(|p| p.crt.finds.get_mut(&handle).map(|s| s.rest.pop_front()));
    match next {
        Some(Some(e)) if !out.is_null() => {
            write(out, &e);
            0
        }
        Some(None) => {
            errno::set(ENOENT);
            -1
        }
        _ => {
            errno::set(EINVAL);
            -1
        }
    }
}

extern "C" fn _findclose(handle: i32) -> i32 {
    if with_current(|p| p.crt.finds.remove(&handle)).is_some() {
        0
    } else {
        errno::set(ENOENT);
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::DriveMap;
    use crate::process::Process;
    use crate::runtime::Runtime;
    use std::collections::BTreeMap;

    #[test]
    fn wildcards_ignore_case() {
        assert!(matches("*.LOG", "ossec.log"));
        assert!(matches("os?ec.*", "OSSEC.conf"));
        assert!(matches("*.*", "README"));
        assert!(!matches("*.log", "ossec.conf"));
        assert!(matches("a*b*c", "aXXbYYc"));
    }

    #[test]
    fn lists_matches_in_name_order_with_dot_entries() {
        let root = std::env::temp_dir().join(format!("xvm-find-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("agent/queue")).unwrap();
        std::fs::write(c.join("agent/b.log"), b"12345").unwrap();
        std::fs::write(c.join("agent/A.log"), b"1").unwrap();
        std::fs::write(c.join("agent/x.conf"), b"").unwrap();
        let mut process = Process::new(Vec::new());
        process.params.drives = DriveMap::new(&BTreeMap::from([("C".to_string(), c.clone())]));
        process.params.current_directory = r"C:\agent".into();
        let runtime = Runtime::new(process);
        let _thread = runtime.attach().unwrap();

        let mut data = [0u8; 280];
        let name = |d: &[u8; 280]| {
            let end = d[20..].iter().position(|&b| b == 0).unwrap();
            String::from_utf8(d[20..20 + end].to_vec()).unwrap()
        };
        let h = _findfirst(c"C:\\agent\\*".as_ptr(), data.as_mut_ptr());
        assert!(h >= 0);
        let mut names = vec![name(&data)];
        while _findnext(h, data.as_mut_ptr()) == 0 {
            names.push(name(&data));
        }
        assert_eq!(names, [".", "..", "A.log", "b.log", "queue", "x.conf"]);
        assert_eq!(errno::get(), ENOENT);
        assert_eq!(_findclose(h), 0);
        assert_eq!(_findclose(h), -1);

        let h = _findfirst(c"*.LOG".as_ptr(), data.as_mut_ptr());
        assert_eq!(name(&data), "A.log");
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), A_ARCH);
        assert_eq!(_findnext(h, data.as_mut_ptr()), 0);
        assert_eq!(u32::from_le_bytes(data[16..20].try_into().unwrap()), 5);
        _findclose(h);
        let h = _findfirst(c"queue".as_ptr(), data.as_mut_ptr());
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), A_SUBDIR);
        _findclose(h);
        assert_eq!(_findfirst(c"*.none".as_ptr(), data.as_mut_ptr()), -1);
        assert_eq!(errno::get(), ENOENT);
        let h = _findfirst(c"C:\\*".as_ptr(), data.as_mut_ptr());
        assert_eq!(name(&data), "agent", "no dot entries at a drive root");
        _findclose(h);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
