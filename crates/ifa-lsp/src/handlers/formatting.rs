use crate::document::Document;
use crate::protocol::{Position, Range, TextEdit};

pub fn handle_formatting(doc: &Document) -> Vec<TextEdit> {
    let formatted = format_ifa_source(&doc.text);
    if formatted == doc.text {
        return Vec::new();
    }

    let end_pos = doc.offset_to_position(doc.text.len());
    vec![TextEdit {
        range: Range::new(Position::new(0, 0), end_pos),
        new_text: formatted,
    }]
}

/// Canonical indentation and formatting algorithm for IFA source code.
pub fn format_ifa_source(src: &str) -> String {
    let mut formatted = String::with_capacity(src.len());
    let mut indent_level: usize = 0;

    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            formatted.push('\n');
            continue;
        }

        // Adjust indent for closing brace at the start of the line
        if trimmed.starts_with('}') || trimmed.starts_with(']') || trimmed.starts_with(')') {
            indent_level = indent_level.saturating_sub(1);
        }

        // Indent with 4 spaces per level
        for _ in 0..indent_level {
            formatted.push_str("    ");
        }
        formatted.push_str(trimmed);
        formatted.push('\n');

        // Increase indent if line ends with opening brace, bracket, or parenthesis
        let open_counts = trimmed
            .chars()
            .filter(|&c| c == '{' || c == '[' || c == '(')
            .count();
        let close_counts = trimmed
            .chars()
            .filter(|&c| c == '}' || c == ']' || c == ')')
            .count();

        if open_counts > close_counts {
            indent_level += open_counts - close_counts;
        } else if close_counts > open_counts
            && !trimmed.starts_with('}')
            && !trimmed.starts_with(']')
            && !trimmed.starts_with(')')
        {
            indent_level = indent_level.saturating_sub(close_counts - open_counts);
        }
    }

    formatted
}
