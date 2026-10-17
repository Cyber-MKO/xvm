//! Pseudorandom numbers: `srand`.
//!
//! The srand page on Microsoft Learn: the seed is per thread, and a
//! thread that never calls `srand` uses 1. The census shows no import of
//! `rand`, so the seed is only kept.

use std::cell::Cell;

thread_local! {
    static SEED: Cell<u32> = const { Cell::new(1) };
}

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![("srand", srand as *const () as u32)]
}

/// The calling thread's seed.
#[cfg(test)]
fn seed() -> u32 {
    SEED.with(Cell::get)
}

extern "C" fn srand(seed: u32) {
    SEED.with(|s| s.set(seed));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seed_is_per_thread() {
        assert_eq!(std::thread::spawn(seed).join().unwrap(), 1);
        srand(77);
        assert_eq!(seed(), 77);
        assert_eq!(std::thread::spawn(seed).join().unwrap(), 1);
    }
}
