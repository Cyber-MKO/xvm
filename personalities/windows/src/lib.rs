//! Windows personality.
//!
//! Phase 1: the PE32 loader. `pe` parses headers, `image` lays an image out
//! and binds it, `map` maps it into a 32-bit Linux process and `gap` records
//! every call we do not implement. `teb`, `tls` and `thread` give each thread
//! the TEB and implicit TLS that agent code reaches through `fs`. `emu`
//! builds the images of emulated system DLLs, `win` holds their functions,
//! `trap` reports calls to functions we lack, and `process` ties it all
//! into a module table. `runtime` runs start-up: TLS callbacks, `DllMain`
//! and the entry point.

pub mod cmdline;
pub mod emu;
pub mod gap;
pub mod handles;
pub mod image;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
pub mod map;
pub mod memory;
pub mod paths;
pub mod pe;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
pub mod process;
pub mod profile;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
pub mod runtime;
pub mod sha256;
pub mod sync;
pub mod teb;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
pub mod thread;
pub mod tls;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
pub mod trap;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
mod win;
pub mod x509;

/// Personality identifier used by the control plane.
pub const PERSONALITY: &str = "windows";

#[cfg(test)]
mod tests {
    #[test]
    fn identifier() {
        assert_eq!(super::PERSONALITY, "windows");
    }
}
