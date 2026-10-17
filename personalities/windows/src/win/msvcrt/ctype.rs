//! Character classes in the "C" locale, the only one implemented: ASCII
//! rules, false for bytes above 127 and for EOF (-1).

pub(super) fn exports() -> Vec<(&'static str, u32)> {
    vec![
        ("isalnum", isalnum as *const () as u32),
        ("isalpha", isalpha as *const () as u32),
        ("iscntrl", iscntrl as *const () as u32),
        ("isgraph", isgraph as *const () as u32),
        ("islower", islower as *const () as u32),
        ("isprint", isprint as *const () as u32),
        ("ispunct", ispunct as *const () as u32),
        ("isspace", isspace as *const () as u32),
        ("isupper", isupper as *const () as u32),
        ("isxdigit", isxdigit as *const () as u32),
        ("tolower", tolower as *const () as u32),
        ("toupper", toupper as *const () as u32),
    ]
}

/// The byte for an `int` argument in 0..=127, else None.
fn ascii(c: i32) -> Option<u8> {
    u8::try_from(c).ok().filter(u8::is_ascii)
}

/// Nonzero for a match, as the C functions return.
fn class(c: i32, test: fn(&u8) -> bool) -> i32 {
    ascii(c).is_some_and(|b| test(&b)) as i32
}

extern "C" fn isalnum(c: i32) -> i32 {
    class(c, u8::is_ascii_alphanumeric)
}
extern "C" fn isalpha(c: i32) -> i32 {
    class(c, u8::is_ascii_alphabetic)
}
extern "C" fn iscntrl(c: i32) -> i32 {
    class(c, u8::is_ascii_control)
}
extern "C" fn isgraph(c: i32) -> i32 {
    class(c, u8::is_ascii_graphic)
}
extern "C" fn islower(c: i32) -> i32 {
    class(c, u8::is_ascii_lowercase)
}
/// Graphic characters and the space.
extern "C" fn isprint(c: i32) -> i32 {
    class(c, |b| b.is_ascii_graphic() || *b == b' ')
}
extern "C" fn ispunct(c: i32) -> i32 {
    class(c, u8::is_ascii_punctuation)
}
/// Space, tab, newline, vertical tab, form feed and carriage return.
extern "C" fn isspace(c: i32) -> i32 {
    class(c, |b| {
        matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
    })
}
extern "C" fn isupper(c: i32) -> i32 {
    class(c, u8::is_ascii_uppercase)
}
extern "C" fn isxdigit(c: i32) -> i32 {
    class(c, u8::is_ascii_hexdigit)
}
/// Other values come back unchanged.
extern "C" fn tolower(c: i32) -> i32 {
    ascii(c).map_or(c, |b| b.to_ascii_lowercase() as i32)
}
extern "C" fn toupper(c: i32) -> i32 {
    ascii(c).map_or(c, |b| b.to_ascii_uppercase() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_classes_in_the_c_locale() {
        assert_ne!(isspace(b'\x0b' as i32), 0);
        assert_eq!(isspace(0xa0), 0);
        assert_ne!(isalnum(b'z' as i32), 0);
        assert_eq!(isalpha(b'1' as i32), 0);
        assert_ne!(isxdigit(b'F' as i32), 0);
        assert_ne!(isprint(b' ' as i32), 0);
        assert_eq!(isgraph(b' ' as i32), 0);
        assert_ne!(ispunct(b'#' as i32), 0);
        assert_ne!(iscntrl(0x7f), 0);
        assert_eq!(islower(-1), 0, "EOF");
        assert_eq!(isupper(0xc9), 0);
        assert_eq!(toupper(b'q' as i32), b'Q' as i32);
        assert_eq!(tolower(b'Q' as i32), b'q' as i32);
        assert_eq!(tolower(-1), -1);
        assert_eq!(toupper(0xe9), 0xe9);
    }
}
