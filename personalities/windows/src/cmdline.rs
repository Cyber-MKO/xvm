//! Splitting a command line into `argv`, by the rules in "Parsing C
//! command-line arguments" on Microsoft Learn.
//!
//! - The program name runs to the next quote if it starts with one, else to
//!   the first space or tab. Backslashes in it are literal.
//! - Other arguments are separated by spaces and tabs. Quotes group text,
//!   and can start and stop inside an argument.
//! - Backslashes are literal unless a quote follows them. Then each pair
//!   gives one backslash, and an odd one out makes the quote literal.
//! - Inside a quoted block, `""` gives a literal quote and the block goes on.

pub fn split(command_line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = command_line.chars().peekable();

    let mut program = String::new();
    if chars.peek() == Some(&'"') {
        chars.next();
        for c in chars.by_ref() {
            if c == '"' {
                break;
            }
            program.push(c);
        }
    }
    while let Some(&c) = chars.peek() {
        if c == ' ' || c == '\t' {
            break;
        }
        program.push(c);
        chars.next();
    }
    args.push(program);

    loop {
        while chars.next_if(|&c| c == ' ' || c == '\t').is_some() {}
        if chars.peek().is_none() {
            return args;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            match c {
                '\\' => {
                    let mut slashes = 0;
                    while chars.next_if_eq(&'\\').is_some() {
                        slashes += 1;
                    }
                    if chars.peek() == Some(&'"') {
                        arg.extend(std::iter::repeat_n('\\', slashes / 2));
                        if slashes % 2 == 1 {
                            arg.push('"');
                            chars.next();
                        }
                    } else {
                        arg.extend(std::iter::repeat_n('\\', slashes));
                    }
                }
                '"' => {
                    chars.next();
                    if quoted && chars.peek() == Some(&'"') {
                        arg.push('"');
                        chars.next();
                    } else {
                        quoted = !quoted;
                    }
                }
                ' ' | '\t' if !quoted => break,
                _ => {
                    arg.push(c);
                    chars.next();
                }
            }
        }
        args.push(arg);
    }
}

#[cfg(test)]
mod tests {
    use super::split;

    /// The examples table from "Parsing C command-line arguments".
    #[test]
    fn matches_the_documented_examples() {
        let cases: [(&str, &[&str]); 5] = [
            (r#""abc" d e"#, &["abc", "d", "e"]),
            (r#"a\\b d"e f"g h"#, &[r"a\\b", "de fg", "h"]),
            (r#"a\\\"b c d"#, &[r#"a\"b"#, "c", "d"]),
            (r#"a\\\\"b c" d e"#, &[r"a\\b c", "d", "e"]),
            (r#"a"b"" c d"#, &[r#"ab" c d"#]),
        ];
        for (input, expected) in cases {
            let args = split(&format!("prog {input}"));
            assert_eq!(args[0], "prog");
            assert_eq!(&args[1..], expected, "{input}");
        }
    }

    #[test]
    fn program_name_keeps_backslashes_and_spaces_in_quotes() {
        assert_eq!(
            split(r#""C:\Program Files (x86)\ossec-agent\wazuh-agent.exe""#),
            [r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"]
        );
        assert_eq!(split(r"C:\a\b.exe  -x"), [r"C:\a\b.exe", "-x"]);
        assert_eq!(split(""), [""]);
        assert_eq!(split("prog \t "), ["prog"]);
    }
}
