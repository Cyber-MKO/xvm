//! Windows paths on the host file system.
//!
//! Each drive letter maps to a host directory (from the host profile).
//! Windows file names are case-insensitive and the host's are not, so each
//! component that exists is matched without regard to case. Components
//! that do not exist yet keep the spelling the agent used, so a file it
//! creates gets the name it asked for.
//!
//! Supported forms (the "File path formats" page on Microsoft Learn):
//! `C:\dir\file`, `\dir\file` (current drive) and `dir\file` (current
//! directory), with either separator, and the `\\?\` prefix on drive
//! paths. UNC paths and drive-relative paths (`C:file`) are refused.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// A form we do not map, such as a UNC path.
    Unsupported(String),
    /// The drive has no host directory in the profile.
    NoSuchDrive(char),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Unsupported(p) => write!(f, "unsupported path form: {p}"),
            PathError::NoSuchDrive(d) => write!(f, "no drive {d}:"),
        }
    }
}

impl std::error::Error for PathError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriveMap {
    drives: BTreeMap<char, PathBuf>,
}

impl DriveMap {
    /// `drives` maps upper-case drive letters ("C") to host directories.
    pub fn new(drives: &BTreeMap<String, PathBuf>) -> DriveMap {
        DriveMap {
            drives: drives
                .iter()
                .filter_map(|(k, v)| Some((k.chars().next()?.to_ascii_uppercase(), v.clone())))
                .collect(),
        }
    }

    /// Make `path` absolute and normal: `C:\dir\file`, with `.` and `..`
    /// resolved and separators unified. `cwd` must be absolute.
    pub fn full_path(path: &str, cwd: &str) -> Result<String, PathError> {
        let path = path.strip_prefix(r"\\?\").unwrap_or(path);
        let unsupported = || Err(PathError::Unsupported(path.to_string()));
        let bytes = path.as_bytes();
        let is_sep = |b: u8| b == b'\\' || b == b'/';
        let (drive, rest) =
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                if bytes.len() == 2 || !is_sep(bytes[2]) {
                    return unsupported();
                }
                (bytes[0].to_ascii_uppercase() as char, &path[2..])
            } else if bytes.len() >= 2 && is_sep(bytes[0]) && is_sep(bytes[1]) {
                return unsupported();
            } else {
                let cwd_full = Self::full_path(cwd, r"C:\")?;
                let drive = cwd_full.as_bytes()[0] as char;
                if bytes.first().copied().is_some_and(is_sep) {
                    (drive, path)
                } else {
                    return Self::full_path(&format!("{cwd_full}\\{path}"), &cwd_full);
                }
            };
        let mut parts: Vec<&str> = Vec::new();
        for part in rest.split(['\\', '/']) {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                _ => parts.push(part),
            }
        }
        Ok(format!("{drive}:\\{}", parts.join("\\")))
    }

    /// The host path for a Windows path, relative to `cwd` if needed.
    pub fn to_host(&self, path: &str, cwd: &str) -> Result<PathBuf, PathError> {
        let full = Self::full_path(path, cwd)?;
        let drive = full.as_bytes()[0] as char;
        let mut host = self
            .drives
            .get(&drive)
            .ok_or(PathError::NoSuchDrive(drive))?
            .clone();
        let mut exists = host.is_dir();
        for part in full[3..].split('\\').filter(|p| !p.is_empty()) {
            let found = exists.then(|| find_ignoring_case(&host, part)).flatten();
            exists = found.is_some();
            host.push(found.as_deref().unwrap_or(part));
        }
        Ok(host)
    }

    /// The Windows path of a host path inside one of the drives.
    pub fn to_windows(&self, host: &Path) -> Option<String> {
        self.drives.iter().find_map(|(drive, root)| {
            let rest = host.strip_prefix(root).ok()?;
            let parts: Vec<_> = rest.iter().map(|p| p.to_string_lossy()).collect();
            Some(format!("{drive}:\\{}", parts.join("\\")))
        })
    }
}

fn find_ignoring_case(dir: &Path, name: &str) -> Option<String> {
    if dir.join(name).exists() {
        return Some(name.to_string());
    }
    std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let file = entry.file_name().into_string().ok()?;
        file.eq_ignore_ascii_case(name).then_some(file)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_path_normalises_like_windows() {
        let cwd = r"C:\Windows\system32";
        let full = |p| DriveMap::full_path(p, cwd);
        assert_eq!(full(r"C:\a\.\b\..\c").unwrap(), r"C:\a\c");
        assert_eq!(full("c:/a//b/").unwrap(), r"C:\a\b");
        assert_eq!(full(r"\temp\x").unwrap(), r"C:\temp\x");
        assert_eq!(full(r"..\drivers\etc").unwrap(), r"C:\Windows\drivers\etc");
        assert_eq!(full(r"C:\..\..").unwrap(), r"C:\");
        assert_eq!(full(r"\\?\C:\x").unwrap(), r"C:\x");
        assert!(matches!(
            full(r"\\server\share\x"),
            Err(PathError::Unsupported(_))
        ));
        assert!(matches!(full("C:x"), Err(PathError::Unsupported(_))));
    }

    #[test]
    fn maps_to_host_ignoring_case_for_existing_parts() {
        let root = std::env::temp_dir().join(format!("xvm-paths-{}", std::process::id()));
        let c = root.join("c");
        std::fs::create_dir_all(c.join("Program Files (x86)/ossec-agent")).unwrap();
        let map = DriveMap::new(&BTreeMap::from([("C".to_string(), c.clone())]));
        let cwd = r"C:\";

        assert_eq!(
            map.to_host(r"c:\PROGRAM FILES (X86)\OSSEC-AGENT\New.Log", cwd)
                .unwrap(),
            c.join("Program Files (x86)/ossec-agent/New.Log")
        );
        assert_eq!(
            map.to_host(r"C:\Missing\Dir", cwd).unwrap(),
            c.join("Missing/Dir")
        );
        assert_eq!(map.to_host(r"D:\x", cwd), Err(PathError::NoSuchDrive('D')));
        assert_eq!(
            map.to_windows(&c.join("Program Files (x86)/ossec-agent"))
                .as_deref(),
            Some(r"C:\Program Files (x86)\ossec-agent")
        );
        assert_eq!(map.to_windows(Path::new("/etc")), None);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
