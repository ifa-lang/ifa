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

/// Count effective opening and closing delimiters outside strings and comments.
fn count_delimiters(line: &str) -> (usize, usize) {
    let mut opens = 0;
    let mut closes = 0;
    let mut in_str = false;
    let mut in_chr = false;
    let mut escaped = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if escaped {
            escaped = false;
            continue;
        }

        if c == '\\' && (in_str || in_chr) {
            escaped = true;
            continue;
        }

        if in_str {
            if c == '"' {
                in_str = false;
            }
            continue;
        }

        if in_chr {
            if c == '\'' {
                in_chr = false;
            }
            continue;
        }

        if c == '"' {
            in_str = true;
            continue;
        }

        if c == '\'' {
            in_chr = true;
            continue;
        }

        if c == '/' && chars.peek() == Some(&'/') {
            break;
        }

        match c {
            '{' | '(' | '[' => opens += 1,
            '}' | ')' | ']' => closes += 1,
            _ => {}
        }
    }

    (opens, closes)
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

        let (open_counts, close_counts) = count_delimiters(trimmed);

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

        // Increase or decrease indent based on delimiter delta
        if trimmed.starts_with('}') || trimmed.starts_with(']') || trimmed.starts_with(')') {
            if open_counts > close_counts.saturating_sub(1) {
                indent_level += open_counts - (close_counts.saturating_sub(1));
            } else if (close_counts.saturating_sub(1)) > open_counts {
                indent_level =
                    indent_level.saturating_sub((close_counts.saturating_sub(1)) - open_counts);
            }
        } else {
            if open_counts > close_counts {
                indent_level += open_counts - close_counts;
            } else if close_counts > open_counts {
                indent_level = indent_level.saturating_sub(close_counts - open_counts);
            }
        }
    }

    formatted
}
