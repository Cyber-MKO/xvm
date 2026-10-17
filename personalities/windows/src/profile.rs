//! Host profiles: the declarative description of one emulated host.
//!
//! A profile is a TOML file (format in docs/host-profiles.md). The Windows
//! personality reads the host name, the drive table and the agent's
//! process parameters from it. Later the host-state engine serves the same
//! data (brief, Decisions). No host fact is hardcoded here (CLAUDE.md
//! rule 5).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::x509::Certificate;

pub const SCHEMA: u32 = 1;

#[derive(Debug)]
pub enum ProfileError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, toml::de::Error),
    Invalid(String),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::Io(p, e) => write!(f, "reading {}: {e}", p.display()),
            ProfileError::Parse(p, e) => write!(f, "{}: {e}", p.display()),
            ProfileError::Invalid(msg) => write!(f, "invalid profile: {msg}"),
        }
    }
}

impl std::error::Error for ProfileError {}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: u32,
    pub host: Host,
    pub windows: Option<Windows>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub name: String,
    pub os: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Windows {
    /// Drive letter to host directory. Relative directories are resolved
    /// against the profile file's directory when loaded.
    pub drives: BTreeMap<String, PathBuf>,
    pub agent: AgentProcess,
    /// The agent process's environment block.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// System certificate store name (`ROOT`, `CA`, `MY`) to DER
    /// certificate files. Relative files are resolved against the profile
    /// file's directory.
    #[serde(default)]
    pub cert_stores: BTreeMap<String, Vec<PathBuf>>,
    /// The directory emulated system DLLs report as their location, such
    /// as `C:\Windows\SysWOW64` for a 32-bit process on 64-bit Windows.
    #[serde(default)]
    pub system_module_directory: Option<String>,
    /// Windows path to the SHA-256 (hex) of a file whose signature is
    /// valid on this host.
    #[serde(default)]
    pub trusted_files: BTreeMap<String, String>,
    /// The certificates of `cert_stores`, read by `Profile::load`, keyed by
    /// upper-case store name.
    #[serde(skip)]
    pub certificates: BTreeMap<String, Vec<Certificate>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProcess {
    /// The full command line, as `GetCommandLine` returns it.
    pub command_line: String,
    pub current_directory: String,
    /// The agent's process ID: not 0 and a multiple of 4, as Windows
    /// process IDs are. The host-state engine's process list will include
    /// it.
    pub pid: u32,
    /// The service the Service Control Manager starts the agent as. Absent
    /// for an agent started from a console.
    #[serde(default)]
    pub service: Option<String>,
}

impl Profile {
    pub fn load(path: &Path) -> Result<Profile, ProfileError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ProfileError::Io(path.to_path_buf(), e))?;
        let mut profile = Profile::parse(&text).map_err(|e| match e {
            ProfileError::Parse(_, e) => ProfileError::Parse(path.to_path_buf(), e),
            other => other,
        })?;
        let base = path.parent().unwrap_or(Path::new("."));
        if let Some(windows) = &mut profile.windows {
            for dir in windows.drives.values_mut() {
                if dir.is_relative() {
                    *dir = base.join(&*dir);
                }
            }
            for (store, files) in &mut windows.cert_stores {
                let mut certs = Vec::new();
                for file in files {
                    if file.is_relative() {
                        *file = base.join(&*file);
                    }
                    let der =
                        std::fs::read(&*file).map_err(|e| ProfileError::Io(file.clone(), e))?;
                    let cert = Certificate::parse(&der)
                        .map_err(|e| ProfileError::Invalid(format!("{}: {e}", file.display())))?;
                    certs.push(cert);
                }
                windows
                    .certificates
                    .insert(store.to_ascii_uppercase(), certs);
            }
        }
        Ok(profile)
    }

    pub fn parse(text: &str) -> Result<Profile, ProfileError> {
        let profile: Profile =
            toml::from_str(text).map_err(|e| ProfileError::Parse(PathBuf::new(), e))?;
        profile.validate()?;
        Ok(profile)
    }

    /// The Windows section, required for a Windows host.
    pub fn windows(&self) -> Result<&Windows, ProfileError> {
        self.windows
            .as_ref()
            .ok_or_else(|| ProfileError::Invalid("no [windows] section".into()))
    }

    fn validate(&self) -> Result<(), ProfileError> {
        let invalid = |msg: String| Err(ProfileError::Invalid(msg));
        if self.schema != SCHEMA {
            return invalid(format!(
                "schema {} (this build reads {SCHEMA})",
                self.schema
            ));
        }
        let Some(windows) = &self.windows else {
            return Ok(());
        };
        if self.host.os != "windows" {
            return invalid(format!("[windows] section on a {} host", self.host.os));
        }
        for letter in windows.drives.keys() {
            let mut chars = letter.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if c.is_ascii_uppercase() => {}
                _ => return invalid(format!("drive {letter:?} is not one upper-case letter")),
            }
        }
        // Agents read these through the ANSI API. Code-page conversion
        // comes with GetACP; until then only ASCII is accepted.
        let strings = windows
            .environment
            .iter()
            .flat_map(|(k, v)| [k, v])
            .chain([
                &windows.agent.command_line,
                &windows.agent.current_directory,
            ])
            .chain(windows.agent.service.as_ref())
            .chain(windows.system_module_directory.as_ref())
            .chain(windows.trusted_files.keys());
        for s in strings {
            if !s.is_ascii() || s.contains('\0') {
                return invalid(format!("{s:?} is not plain ASCII"));
            }
        }
        if let Some((path, _)) = windows
            .trusted_files
            .iter()
            .find(|(_, hash)| crate::sha256::parse_hex(hash).is_none())
        {
            return invalid(format!("trusted file {path:?}: hash is not 64 hex digits"));
        }
        let mut stores: Vec<_> = windows
            .cert_stores
            .keys()
            .map(|k| k.to_ascii_uppercase())
            .collect();
        stores.sort();
        if stores.windows(2).any(|w| w[0] == w[1]) {
            return invalid("certificate store names must differ ignoring case".into());
        }
        if windows.agent.pid == 0 || windows.agent.pid % 4 != 0 {
            return invalid(format!(
                "agent pid {} is not a non-zero multiple of 4",
                windows.agent.pid
            ));
        }
        if stores.iter().any(|s| s.is_empty() || !s.is_ascii()) {
            return invalid("certificate store names must be non-empty ASCII".into());
        }
        if windows
            .environment
            .keys()
            .any(|k| k.is_empty() || k.contains('='))
        {
            return invalid("environment names must be non-empty and contain no '='".into());
        }
        Ok(())
    }
}

impl Windows {
    /// The environment as `NAME=value` strings, in the order Windows keeps
    /// its environment block: sorted by name, ignoring case.
    pub fn environment_block(&self) -> Vec<String> {
        let mut vars: Vec<_> = self.environment.iter().collect();
        vars.sort_by_key(|(k, _)| k.to_ascii_uppercase());
        vars.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"
        schema = 1

        [host]
        name = "TEST-HOST"
        os = "windows"

        [windows]
        drives = { C = "drives/c" }

        [windows.agent]
        command_line = '"C:\Program Files\app\app.exe" -f'
        current_directory = 'C:\Windows\system32'
        pid = 4812

        [windows.environment]
        windir = 'C:\Windows'
        ComSpec = 'C:\Windows\system32\cmd.exe'
        Path = 'C:\Windows\system32'
    "#;

    #[test]
    fn parses_and_sorts_the_environment_like_windows() {
        let p = Profile::parse(PROFILE).unwrap();
        assert_eq!(p.host.name, "TEST-HOST");
        let w = p.windows().unwrap();
        assert_eq!(w.agent.command_line, r#""C:\Program Files\app\app.exe" -f"#);
        assert_eq!(
            w.environment_block(),
            [
                r"ComSpec=C:\Windows\system32\cmd.exe",
                r"Path=C:\Windows\system32",
                r"windir=C:\Windows",
            ]
        );
    }

    #[test]
    fn rejects_bad_drives_unknown_keys_and_other_schemas() {
        let bad = |from: &str, to: &str| Profile::parse(&PROFILE.replace(from, to)).is_err();
        assert!(bad("{ C = ", "{ c = "));
        assert!(bad("{ C = ", "{ CD = "));
        assert!(bad("schema = 1", "schema = 2"));
        assert!(bad("pid = 4812", "pid = 4813"));
        assert!(bad("pid = 4812", "pid = 0"));
        assert!(bad("pid = 4812\n", ""));
        assert!(bad("[windows.agent]", "[windows.agent]\nextra = 1"));
        assert!(bad(
            "TEST-HOST\"\n        os = \"windows\"",
            "TEST-HOST\"\n        os = \"linux\""
        ));
        assert!(bad(r"windir = 'C:\Windows'", "windir = 'C:\\Wíndows'"));
        assert!(bad(
            "[windows.environment]",
            "[windows.trusted_files]\n'C:\\a.exe' = 'abc'\n[windows.environment]"
        ));
        assert!(bad(
            "[windows.environment]",
            "[windows.cert_stores]\nROOT = []\nroot = []\n[windows.environment]"
        ));
    }

    #[test]
    fn example_profile_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../control/profiles/example-windows.toml");
        let p = Profile::load(&path).unwrap();
        let w = p.windows().unwrap();
        assert!(w.agent.command_line.contains("wazuh-agent.exe"));
        assert!(w.drives["C"].ends_with("example-windows/c"));
        let root = &w.certificates["ROOT"];
        assert_eq!(
            root[0].subject.first(crate::x509::OID_COMMON_NAME),
            Some("DigiCert Assured ID Root CA")
        );
    }

    #[test]
    fn relative_drives_resolve_against_the_profile_file() {
        let dir = std::env::temp_dir().join(format!("xvm-profile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("host.toml");
        std::fs::write(&file, PROFILE).unwrap();
        let p = Profile::load(&file).unwrap();
        assert_eq!(p.windows().unwrap().drives["C"], dir.join("drives/c"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
