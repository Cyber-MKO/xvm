//! Windows personality.
//!
//! Phase 1 work. Do not start the PE loader until the Wazuh census report in
//! `census/reports/` exists and has been reviewed (see CLAUDE.md).

/// Personality identifier used by the control plane.
pub const PERSONALITY: &str = "windows";

#[cfg(test)]
mod tests {
    #[test]
    fn identifier() {
        assert_eq!(super::PERSONALITY, "windows");
    }
}
