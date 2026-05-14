//! Parses TOML headers ([section], [[array]], [nested.section]) from raw text
//! for sidebar navigation.

/// A section header found in the TOML file, with its line number.
#[derive(Debug, Clone, PartialEq)]
pub struct TomlSection {
    /// Header text as it appears, e.g. "[pbs]", "[[relays]]",
    /// "[signer.local.loader]"
    pub name: String,
    /// 1-indexed line number in the file
    pub line: usize,
}

impl TomlSection {
    pub fn new(name: String, line: usize) -> Self {
        Self { name, line }
    }
}

/// Extract section/array headers from raw TOML text.
/// Returns headers in order of appearance, with 1-indexed line numbers.
///
/// Matches:
/// - `[section]`
/// - `[nested.section]`
/// - `[[array]]`
/// - `[nested[[weird]]]` (TOML allows brackets in keys)
///
/// Skips:
/// - Top-level key-value pairs (e.g. `chain = "Holesky"`)
/// - Comments
/// - Blank lines
pub fn parse_sections(raw: &str) -> Vec<TomlSection> {
    let mut sections = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        // TOML section headers match [something] or [[something]]
        if (trimmed.starts_with('[') && trimmed.ends_with(']')) && !trimmed.starts_with("[[") {
            sections.push(TomlSection::new(trimmed.to_string(), i + 1));
        } else if trimmed.starts_with("[") && trimmed.ends_with("]]") {
            // [[array]] — handle the double brackets
            sections.push(TomlSection::new(trimmed.to_string(), i + 1));
        }
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toml_section_holds_name_and_line() {
        let s = TomlSection::new("[pbs]".into(), 5);
        assert_eq!(s.name, "[pbs]");
        assert_eq!(s.line, 5);
    }

    #[test]
    fn test_parse_simple_section() {
        let toml = r#"
chain = "Holesky"

[pbs]
host = "127.0.0.1"
"#;
        let sections = parse_sections(toml);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].name, "[pbs]");
        assert_eq!(sections[0].line, 4);
    }

    #[test]
    fn test_parse_array_section() {
        let toml = r#"
[[relays]]
id = "relay-1"

[[relays]]
id = "relay-2"
"#;
        let sections = parse_sections(toml);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].name, "[[relays]]");
        assert_eq!(sections[0].line, 2);
        assert_eq!(sections[1].name, "[[relays]]");
        assert_eq!(sections[1].line, 5);
    }

    #[test]
    fn test_parse_nested_section() {
        let toml = r#"
[signer]
host = "127.0.0.1"

[signer.local]
key_path = "./keys"

[signer.local.loader]
format = "lighthouse"
"#;
        let sections = parse_sections(toml);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].name, "[signer]");
        assert_eq!(sections[1].name, "[signer.local]");
        assert_eq!(sections[2].name, "[signer.local.loader]");
    }

    #[test]
    fn test_skips_top_level_keys() {
        let toml = r#"chain = "Holesky"
# comment
"#;
        let sections = parse_sections(toml);
        assert!(sections.is_empty());
    }

    #[test]
    fn test_handles_empty_input() {
        assert!(parse_sections("").is_empty());
    }

    #[test]
    fn test_parse_mixed_sections() {
        let toml = r#"
[pbs]
timeout_ms = 950

[[relays]]
url = "http://example.com"

[metrics]
enabled = true

[logs.stdout]
level = "info"
"#;
        let sections = parse_sections(toml);
        assert_eq!(sections.len(), 4);
        assert_eq!(sections[0].name, "[pbs]");
        assert_eq!(sections[1].name, "[[relays]]");
        assert_eq!(sections[2].name, "[metrics]");
        assert_eq!(sections[3].name, "[logs.stdout]");
    }

    #[test]
    fn test_parse_sections_from_real_config_example() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("config.example.toml");
        let content = std::fs::read_to_string(&path)
            .expect("config.example.toml should exist at workspace root");
        let sections = parse_sections(&content);
        // config.example.toml should have these sections at minimum
        let names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"[pbs]"), "expected [pbs] in sections: {:?}", names);
        assert!(names.contains(&"[[relays]]"), "expected [[relays]] in sections: {:?}", names);
        assert!(names.contains(&"[metrics]"), "expected [metrics] in sections: {:?}", names);
    }
}
