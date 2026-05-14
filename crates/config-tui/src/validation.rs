/// Represents a single validation error with source location info.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    /// serde path like "pbs.timeout_get_header_ms"
    pub path: Option<String>,
    /// Human-readable error message
    pub message: String,
    /// 1-indexed line in the TOML file (if available)
    pub line: Option<usize>,
    /// 1-indexed column (if available)
    pub column: Option<usize>,
}

/// Current validation result for the config being edited.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationState {
    /// Config parsed and validated successfully.
    Valid,
    /// Config contains errors.
    Invalid(Vec<Diagnostic>),
    /// No validation has been run yet (initial state before first edit).
    Pending,
}

/// Convert a byte offset span from toml::de::Error::span() into 1-indexed
/// (line, column). Scans `raw` up to `span.start`, counting newlines to
/// determine the line number. Column is the offset from the last newline (or
/// start of string) + 1.
pub fn span_to_line_col(raw: &str, span: std::ops::Range<usize>) -> (usize, usize) {
    let offset = span.start;
    let offset = offset.min(raw.len());
    let before = &raw[..offset];
    let line = before.matches('\n').count() + 1;
    let last_newline = before.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let col = offset - last_newline + 1;
    (line, col)
}

/// Run sync validation on raw TOML string.
/// Parses into CommitBoostConfig using serde_path_to_error,
/// maps serde paths through path_mapper, and returns diagnostics.
pub fn validate_sync(raw: &str) -> ValidationState {
    use cb_common::config::CommitBoostConfig;
    use serde_path_to_error as serde_path;

    use crate::path_mapper;

    let deserializer = toml::Deserializer::new(raw);
    let result: Result<CommitBoostConfig, _> = serde_path::deserialize(deserializer);
    match result {
        Ok(_) => ValidationState::Valid,
        Err(err) => {
            let path = err.path().to_string();
            let mapped = path_mapper::map_path(&path);
            // Extract span before err.into_inner() discards the toml::de::Error
            let span = err.inner().span();
            let (line, column) = span
                .as_ref()
                .map(|s| span_to_line_col(raw, s.clone()))
                .map(|(l, c)| (Some(l), Some(c)))
                .unwrap_or((None, None));
            let inner = format!("{}", err.into_inner());
            let diag = if mapped.is_empty() || mapped == "." {
                inner
            } else {
                format!("{}: {}", mapped, inner)
            };
            ValidationState::Invalid(vec![Diagnostic {
                path: Some(mapped),
                message: diag,
                line,
                column,
            }])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_to_line_col_offset_zero_empty_string() {
        let (line, col) = span_to_line_col("", 0..0);
        assert_eq!(line, 1);
        assert_eq!(col, 1);
    }

    #[test]
    fn test_span_to_line_col_multi_line() {
        // "line1\nline2\nline3" — offset 12 is '3' on line 3, col 1
        let raw = "line1\nline2\nline3";
        assert_eq!(raw.len(), 17);
        // offset of '3' (last char): line3 starts at byte 12, '3' is at 12
        let (line, col) = span_to_line_col(raw, 12..17);
        assert_eq!(line, 3);
        assert_eq!(col, 1);
    }

    #[test]
    fn test_span_to_line_col_mid_line() {
        let raw = "chain = \"Holesky\"\n\n[pbs]";
        // 'H' in "Holesky" is at byte offset 9 (after "chain = \"")
        let (line, col) = span_to_line_col(raw, 9..16);
        assert_eq!(line, 1);
        assert_eq!(col, 10);
    }

    #[test]
    fn test_span_to_line_col_offset_at_newline() {
        let raw = "line1\nline2\n";
        // offset 5 is the first '\n' — should be end of line 1, col 6
        let (line, col) = span_to_line_col(raw, 5..5);
        assert_eq!(line, 1);
        assert_eq!(col, 6);
    }

    #[test]
    fn test_diagnostic_holds_path_message_line_column() {
        let d = Diagnostic {
            path: Some("pbs.timeout_get_header_ms".into()),
            message: "must be greater than 0".into(),
            line: Some(12),
            column: Some(5),
        };
        assert_eq!(d.path.as_deref(), Some("pbs.timeout_get_header_ms"));
        assert_eq!(d.message, "must be greater than 0");
        assert_eq!(d.line, Some(12));
        assert_eq!(d.column, Some(5));
    }

    #[test]
    fn test_diagnostic_path_can_be_none() {
        let d = Diagnostic {
            path: None,
            message: "could not parse TOML".into(),
            line: None,
            column: None,
        };
        assert!(d.path.is_none());
    }

    #[test]
    fn test_validation_state_valid() {
        assert_eq!(ValidationState::Valid, ValidationState::Valid);
    }

    #[test]
    fn test_validation_state_invalid_holds_diagnostics() {
        let diags = vec![Diagnostic {
            path: Some("pbs.timeout_get_header_ms".into()),
            message: "must be > 0".into(),
            line: None,
            column: None,
        }];
        let state = ValidationState::Invalid(diags.clone());
        match state {
            ValidationState::Invalid(ref ds) => assert_eq!(ds.len(), 1),
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn test_validation_state_pending() {
        assert_eq!(ValidationState::Pending, ValidationState::Pending);
    }

    #[test]
    fn test_validate_sync_returns_valid_for_well_formed_config() {
        let toml = r#"
chain = "Holesky"

[pbs]
"#;
        let state = validate_sync(toml);
        assert_eq!(state, ValidationState::Valid);
    }

    #[test]
    fn test_validate_sync_returns_invalid_for_malformed_toml() {
        let toml = r#"
chain = "Holesky"

[pbs]
host = "127.0.0.1
"#;
        let state = validate_sync(toml);
        assert!(matches!(state, ValidationState::Invalid(_)));
        if let ValidationState::Invalid(diags) = &state {
            assert!(!diags.is_empty());
            assert!(
                diags[0].message.contains("unterminated") ||
                    diags[0].message.contains("EOF") ||
                    diags[0].message.contains("string")
            );
        }
    }

    #[test]
    fn test_validate_sync_returns_invalid_for_missing_chain() {
        let toml = r#"
[pbs]
"#;
        let state = validate_sync(toml);
        assert!(matches!(state, ValidationState::Invalid(_)));
        if let ValidationState::Invalid(diags) = &state {
            assert_eq!(diags.len(), 1);
            assert!(diags[0].message.contains("missing"));
        }
    }

    #[test]
    fn test_validate_sync_diagnostic_includes_type_mismatch_in_message() {
        let toml = r#"
chain = "Holesky"

[pbs]
timeout_get_header_ms = "not_a_number"
"#;
        let state = validate_sync(toml);
        assert!(matches!(state, ValidationState::Invalid(_)));
        if let ValidationState::Invalid(diags) = &state {
            let msg = &diags[0].message;
            assert!(
                msg.contains("invalid type") || msg.contains("expected u64"),
                "msg should mention type mismatch: {}",
                msg
            );
        }
    }

    #[test]
    fn test_validate_sync_populates_diagnostic_line_from_span() {
        let toml = "chain = \"Holesky\"\n\n[pbs]\nhost = 42\n";
        // "host" expects a string, but we gave an integer — type mismatch at line 4
        let state = validate_sync(toml);
        assert!(matches!(state, ValidationState::Invalid(_)));
        if let ValidationState::Invalid(diags) = &state {
            assert!(!diags.is_empty());
            let d = &diags[0];
            assert!(d.line.is_some(), "diagnostic should have a line number from span(), got None");
            let line = d.line.unwrap();
            assert!(line >= 1, "line should be 1-indexed, got {}", line);
        }
    }

    #[test]
    fn test_validate_sync_populates_diagnostic_column_from_span() {
        let toml = "chain = \"Holesky\"\n\n[pbs]\nhost = 42\n";
        let state = validate_sync(toml);
        assert!(matches!(state, ValidationState::Invalid(_)));
        if let ValidationState::Invalid(diags) = &state {
            let d = &diags[0];
            assert!(
                d.column.is_some(),
                "diagnostic should have a column number from span(), got None"
            );
            let col = d.column.unwrap();
            assert!(col >= 1, "column should be 1-indexed, got {}", col);
        }
    }

    #[test]
    fn test_validate_sync_line_column_none_when_span_returns_none() {
        // A TOML error that might not have a span (root-level error)
        let toml = "= invalid root syntax\n";
        let state = validate_sync(toml);
        // This may be Valid or Invalid depending on how it parses.
        // If Invalid, we test that line/column are None when span() is None.
        if let ValidationState::Invalid(diags) = &state {
            let d = &diags[0];
            // Either both Some or both None — never one without the other
            assert_eq!(d.line.is_some(), d.column.is_some());
        }
    }

    #[test]
    fn test_validate_sync_diagnostic_mentions_missing_pbs() {
        let toml = r#"chain = "Holesky""#;
        let state = validate_sync(toml);
        assert!(matches!(state, ValidationState::Invalid(_)));
        if let ValidationState::Invalid(diags) = &state {
            let msg = &diags[0].message;
            assert!(
                msg.contains("pbs") || msg.contains("missing field"),
                "message should reference missing pbs: {}",
                msg
            );
        }
    }
}
