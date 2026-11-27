//! A flat JSON object as Python's `json.dumps` writes it, which google-auth
//! signs: `", "` and `": "` between members, each character past ASCII
//! escaped. An assertion signed over other bytes is another assertion.

/// A member's value: text or a whole number.
pub(super) enum Member<'a> {
    Text(&'a str),
    Number(i64),
}

/// `members`, in order, as `json.dumps(dict(members))` writes them.
pub(super) fn dumps(members: &[(&str, Member<'_>)]) -> String {
    let mut written = String::from("{");
    for (at, (name, value)) in members.iter().enumerate() {
        if at > 0 {
            written.push_str(", ");
        }
        quoted(&mut written, name);
        written.push_str(": ");
        match value {
            Member::Text(text) => quoted(&mut written, text),
            Member::Number(number) => written.push_str(&number.to_string()),
        }
    }
    written.push('}');
    written
}

/// `text` as a JSON string, as Python escapes it with `ensure_ascii`.
fn quoted(written: &mut String, text: &str) {
    written.push('"');
    for character in text.chars() {
        match character {
            '"' => written.push_str("\\\""),
            '\\' => written.push_str("\\\\"),
            '\n' => written.push_str("\\n"),
            '\r' => written.push_str("\\r"),
            '\t' => written.push_str("\\t"),
            '\u{8}' => written.push_str("\\b"),
            '\u{c}' => written.push_str("\\f"),
            ' '..='~' => written.push(character),
            _ => {
                let mut units = [0; 2];
                for unit in character.encode_utf16(&mut units) {
                    written.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    written.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    // Python: json.dumps({"typ": "JWT", "n": 3, "t": "é\n\"😀"})
    #[test]
    fn an_object_is_written_as_python_writes_it() {
        let members = [
            ("typ", Member::Text("JWT")),
            ("n", Member::Number(3)),
            ("t", Member::Text("é\n\"😀")),
        ];
        assert_eq!(
            dumps(&members),
            r#"{"typ": "JWT", "n": 3, "t": "\u00e9\n\"\ud83d\ude00"}"#
        );
    }
}
