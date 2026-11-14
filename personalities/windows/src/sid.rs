//! Security identifiers: text (`S-1-5-32-544`) and the binary form of
//! the SID structure on Microsoft Learn: revision, sub-authority count,
//! the 48-bit identifier authority (big-endian), then each 32-bit
//! sub-authority (little-endian).

/// The binary SID for `text`, or None if it is not a SID string.
pub fn to_bytes(text: &str) -> Option<Vec<u8>> {
    let mut parts = text
        .strip_prefix("S-")
        .or_else(|| text.strip_prefix("s-"))?
        .split('-');
    let revision: u8 = parts.next()?.parse().ok()?;
    let authority: u64 = parts.next()?.parse().ok()?;
    if authority >= 1 << 48 {
        return None;
    }
    let subs: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<_>>()?;
    if revision != 1 || subs.len() > 15 {
        return None;
    }
    let mut out = vec![revision, subs.len() as u8];
    out.extend_from_slice(&authority.to_be_bytes()[2..]);
    for s in subs {
        out.extend_from_slice(&s.to_le_bytes());
    }
    Some(out)
}

/// The length of the SID at the start of `bytes`, if it is valid.
pub fn length(bytes: &[u8]) -> Option<usize> {
    let (&revision, &count) = (bytes.first()?, bytes.get(1)?);
    let len = 8 + 4 * count as usize;
    (revision == 1 && count <= 15 && bytes.len() >= len).then_some(len)
}

/// The text form of a binary SID. The authority is decimal below 2^32
/// and hex above, as ConvertSidToStringSid writes it.
pub fn to_text(bytes: &[u8]) -> Option<String> {
    let len = length(bytes)?;
    let mut authority = [0u8; 8];
    authority[2..].copy_from_slice(&bytes[2..8]);
    let authority = u64::from_be_bytes(authority);
    let mut text = if authority < 1 << 32 {
        format!("S-1-{authority}")
    } else {
        format!("S-1-0x{authority:012X}")
    };
    for chunk in bytes[8..len].chunks_exact(4) {
        text.push_str(&format!(
            "-{}",
            u32::from_le_bytes(chunk.try_into().unwrap())
        ));
    }
    Some(text)
}

/// The binary SID at `p`, copied, if it is valid.
///
/// # Safety
///
/// `p` must be NULL or point at a SID structure.
pub unsafe fn read(p: *const u8) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the header is two bytes; the caller's contract covers the rest.
    let count = unsafe { *p.add(1) } as usize;
    // SAFETY: as above.
    let bytes = unsafe { std::slice::from_raw_parts(p, 8 + 4 * count.min(15)) };
    length(bytes).map(|n| bytes[..n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let b = to_bytes("S-1-5-21-1-2-3-500").unwrap();
        assert_eq!(b[..8], [1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(b.len(), 28);
        assert_eq!(to_text(&b).as_deref(), Some("S-1-5-21-1-2-3-500"));
        assert_eq!(
            to_text(&to_bytes("S-1-1-0").unwrap()).as_deref(),
            Some("S-1-1-0")
        );
        assert_eq!(length(&b), Some(28));
        assert!(to_bytes("S-2-5-18").is_none());
        assert!(to_bytes("nonsense").is_none());
        assert!(length(&[1, 3, 0]).is_none());
    }
}
