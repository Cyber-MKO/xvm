//! Fixture building shared by the integration tests.
//!
//! The fixtures need clang, lld-link and llvm-dlltool. Without them the tests
//! skip, unless XVM_REQUIRE_FIXTURES is set (CI sets it).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use xvm_windows::image::Image;

/// Build the fixtures once per test binary. Each binary uses its own
/// directory, so binaries running in parallel do not race.
pub fn fixtures() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let missing: Vec<_> = ["clang", "lld-link", "llvm-dlltool"]
            .into_iter()
            .filter(|tool| Command::new(tool).arg("--version").output().is_err())
            .collect();
        if !missing.is_empty() {
            assert!(
                std::env::var_os("XVM_REQUIRE_FIXTURES").is_none(),
                "missing fixture tools: {missing:?}"
            );
            eprintln!("skipping: missing fixture tools {missing:?}");
            return None;
        }
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let out = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(concat!("fixtures-", env!("CARGO_CRATE_NAME")));
        let status = Command::new("sh")
            .arg(src.join("build.sh"))
            .arg(&out)
            .status()
            .expect("run build.sh");
        assert!(status.success(), "fixture build failed");
        Some(out)
    })
    .as_deref()
}

pub fn load(name: &str) -> Option<Image> {
    let bytes = std::fs::read(fixtures()?.join(name)).unwrap();
    Some(Image::layout(name, &bytes).unwrap())
}
