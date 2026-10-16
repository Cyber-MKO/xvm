//! Windows personality.
//!
//! Phase 1: the PE32 loader. `pe` parses headers, `image` lays an image out
//! and binds it, `map` maps it into a 32-bit Linux process and `gap` records
//! every call we do not implement. `teb`, `tls` and `thread` give each thread
//! the TEB and implicit TLS that agent code reaches through `fs`.

pub mod gap;
pub mod image;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
pub mod map;
pub mod pe;
pub mod teb;
#[cfg(all(target_arch = "x86", target_os = "linux"))]
pub mod thread;
pub mod tls;

/// Personality identifier used by the control plane.
pub const PERSONALITY: &str = "windows";

#[cfg(test)]
mod tests {
    #[test]
    fn identifier() {
        assert_eq!(super::PERSONALITY, "windows");
    }
}
