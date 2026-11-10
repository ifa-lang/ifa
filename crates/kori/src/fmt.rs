//! Official Canonical Formatter for the IFA Programming Language.
//!
//! Provides deterministic, bit-for-bit reproducible source code formatting,
//! preserving strings, comments, and operator spacing with fixed-point idempotency:
//! `format(format(src)) == format(src)`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Configuration options for the canonical IFA formatter.
#[derive(Debug, Clone)]
pub struct FormatOptions {
    /// Indentation string (defaults to 4 spaces: `"    "`).
    pub indent_str: String,
    /// Maximum consecutive blank lines allowed (defaults to 1).
    pub max_consecutive_blank_lines: usize,
    /// Ensure a final trailing newline at EOF (defaults to true).
    pub trailing_newline: bool,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            indent_str: "    ".to_string(),
            max_consecutive_blank_lines: 1,
            trailing_newline: true,
        }
    }
}

/// Result summary of formatting operations across files or projects.
#[derive(Debug, Default, Clone)]
pub struct FormatReport {
    /// Total number of `.ifa` source files scanned.
    pub total_files: usize,
    /// Number of files that were already canonically formatted.
    pub formatted_files: usize,
    /// List of file paths that required modification or were unformatted.
    pub changed_files: Vec<PathBuf>,
}

impl FormatReport {
    /// Returns true if all examined files are canonically formatted.
    pub fn is_clean(&self) -> bool {
        self.changed_files.is_empty()
    }
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

        // Check for line comment `//`
        if c == '/' && chars.peek() == Some(&'/') {
            break; // Rest of line is comment
        }

        match c {
            '{' | '(' | '[' => opens += 1,
            '}' | ')' | ']' => closes += 1,
            _ => {}
        }
    }

    (opens, closes)
}

/// Checks if a trimmed line starts with a closing delimiter outside of quotes.
fn starts_with_closing_delimiter(trimmed: &str) -> bool {
    trimmed.starts_with('}') || trimmed.starts_with(']') || trimmed.starts_with(')')
}

/// Canonically format a single line of IFA code by normalizing whitespace and operators
/// while strictly preserving string literals and comments.
fn format_line_tokens(trimmed: &str) -> String {
    // If entire line is a comment, preserve comment content with standard spacing
    if let Some(stripped) = trimmed.strip_prefix("//") {
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            return trimmed.to_string();
        }
        let rest = stripped.trim_start();
        if rest.is_empty() {
            return "//".to_string();
        } else {
            return format!("// {}", rest);
        }
    }

    let mut out = String::with_capacity(trimmed.len() + 16);
    let mut in_str = false;
    let mut in_chr = false;
    let mut escaped = false;
    let mut chars = trimmed.chars().peekable();

    while let Some(c) = chars.next() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }

        if in_str {
            out.push(c);
            if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }

        if in_chr {
            out.push(c);
            if c == '\\' {
                escaped = true;
            } else if c == '\'' {
                in_chr = false;
            }
            continue;
        }

        if c == '"' {
            in_str = true;
            out.push(c);
            continue;
        }

        if c == '\'' {
            in_chr = true;
            out.push(c);
            continue;
        }

        // Line comment: append rest of line as is
        if c == '/' && chars.peek() == Some(&'/') {
            chars.next(); // consume second '/'
            let remainder: String = chars.collect();
            let comment_trimmed = remainder.trim_start();
            if comment_trimmed.starts_with('/') || comment_trimmed.starts_with('!') {
                // doc comment like /// or //!
                out.push_str("//");
                out.push_str(&remainder);
            } else if comment_trimmed.is_empty() {
                out.push_str("//");
            } else {
                // Ensure single space after //
                if !out.ends_with(' ') {
                    out.push(' ');
                }
                out.push_str("// ");
                out.push_str(comment_trimmed);
            }
            break;
        }

        // Punctuation and operator canonical spacing
        match c {
            ',' => {
                // Remove any space before comma
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(',');
                // Ensure space after comma if followed by non-space
                if let Some(&next_c) = chars.peek() {
                    if next_c != ' '
                        && next_c != '\n'
                        && next_c != ')'
                        && next_c != ']'
                        && next_c != '}'
                    {
                        out.push(' ');
                    }
                }
            }
            ';' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(';');
                if let Some(&next_c) = chars.peek() {
                    if next_c != ' ' && next_c != '\n' {
                        out.push(' ');
                    }
                }
            }
            ':' => {
                if chars.peek() == Some(&':') {
                    // Path separator `::`, preserve without spaces
                    chars.next();
                    while out.ends_with(' ') {
                        out.pop();
                    }
                    out.push_str("::");
                } else {
                    // Type or dictionary colon: no space before, space after
                    while out.ends_with(' ') {
                        out.pop();
                    }
                    out.push(':');
                    if let Some(&next_c) = chars.peek() {
                        if next_c != ' ' && next_c != '\n' {
                            out.push(' ');
                        }
                    }
                }
            }
            '(' | '[' => {
                out.push(c);
            }
            ')' | ']' => {
                // Remove space before closing parenthesis/bracket
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(c);
            }
            '{' => {
                // Ensure a space before `{` if preceded by an identifier, parenthesis, or keyword
                if !out.is_empty()
                    && !out.ends_with(' ')
                    && !out.ends_with('(')
                    && !out.ends_with('[')
                {
                    out.push(' ');
                }
                out.push('{');
            }
            '}' => {
                out.push('}');
            }
            '-' => {
                if chars.peek() == Some(&'>') {
                    chars.next();
                    while out.ends_with(' ') {
                        out.pop();
                    }
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str("->");
                    if let Some(&next_c) = chars.peek() {
                        if next_c != ' ' && next_c != '\n' {
                            out.push(' ');
                        }
                    }
                } else {
                    out.push('-');
                }
            }
            ' ' | '\t' => {
                // Collapse consecutive whitespace outside strings to a single space
                // Do not insert space immediately after `(` or `[`
                if !out.ends_with('(')
                    && !out.ends_with('[')
                    && !out.ends_with(' ')
                    && !out.is_empty()
                {
                    out.push(' ');
                }
            }
            _ => {
                out.push(c);
            }
        }
    }

    out.trim_end().to_string()
}

/// Canonically formats raw IFA source code string with default formatting options.
pub fn format_ifa_source(src: &str) -> String {
    format_ifa_source_with_options(src, &FormatOptions::default())
}

/// Canonically formats raw IFA source code string according to specified options.
pub fn format_ifa_source_with_options(src: &str, opts: &FormatOptions) -> String {
    let mut formatted = String::with_capacity(src.len() + 64);
    let mut indent_level: usize = 0;
    let mut consecutive_blank_lines = 0;

    for line in src.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            consecutive_blank_lines += 1;
            if consecutive_blank_lines <= opts.max_consecutive_blank_lines && !formatted.is_empty()
            {
                formatted.push('\n');
            }
            continue;
        }

        consecutive_blank_lines = 0;

        let (open_count, close_count) = count_delimiters(trimmed);

        // Dedent if line begins with closing delimiter
        if starts_with_closing_delimiter(trimmed) {
            indent_level = indent_level.saturating_sub(1);
        }

        // Apply indentation
        for _ in 0..indent_level {
            formatted.push_str(&opts.indent_str);
        }

        let formatted_line = format_line_tokens(trimmed);
        formatted.push_str(&formatted_line);
        formatted.push('\n');

        // Update indent level for following lines
        if starts_with_closing_delimiter(trimmed) {
            // Already subtracted 1 before emitting
            if open_count > close_count.saturating_sub(1) {
                indent_level += open_count - (close_count.saturating_sub(1));
            } else if (close_count.saturating_sub(1)) > open_count {
                indent_level =
                    indent_level.saturating_sub((close_count.saturating_sub(1)) - open_count);
            }
        } else {
            if open_count > close_count {
                indent_level += open_count - close_count;
            } else if close_count > open_count {
                indent_level = indent_level.saturating_sub(close_count - open_count);
            }
        }
    }

    // Ensure final newline
    if opts.trailing_newline && !formatted.ends_with('\n') {
        formatted.push('\n');
    }

    formatted
}

/// Recursively discovers all `.ifa` files in a directory, skipping hidden folders and build caches.
pub fn discover_ifa_files<P: AsRef<Path>>(dir: P) -> io::Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    discover_ifa_files_recursive(dir.as_ref(), &mut results)?;
    results.sort();
    Ok(results)
}

fn discover_ifa_files_recursive(dir: &Path, results: &mut Vec<PathBuf>) -> io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if name_str.starts_with('.') || name_str == "target" || name_str == "node_modules" {
            continue;
        }

        if path.is_dir() {
            discover_ifa_files_recursive(&path, results)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("ifa") {
            results.push(path);
        }
    }

    Ok(())
}

/// Formats a single IFA source file or all `.ifa` files in a project directory.
/// In `check_only` mode, files are never modified on disk.
pub fn format_project_or_file<P: AsRef<Path>>(
    target: P,
    check_only: bool,
    opts: &FormatOptions,
) -> Result<FormatReport, io::Error> {
    let target_path = target.as_ref();
    let files = if target_path.is_file() {
        vec![target_path.to_path_buf()]
    } else {
        discover_ifa_files(target_path)?
    };

    let mut report = FormatReport {
        total_files: files.len(),
        formatted_files: 0,
        changed_files: Vec::new(),
    };

    for file in &files {
        let content = fs::read_to_string(file)?;
        let formatted = format_ifa_source_with_options(&content, opts);

        if content == formatted {
            report.formatted_files += 1;
        } else {
            report.changed_files.push(file.clone());
            if !check_only {
                fs::write(file, formatted)?;
                report.formatted_files += 1;
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_empty_and_simple_function() {
        let raw = "fn   add( a:i64,b:i64 )->i64{\nreturn a+b;\n}\n";
        let formatted = format_ifa_source(raw);
        assert_eq!(
            formatted,
            "fn add(a: i64, b: i64) -> i64 {\n    return a+b;\n}\n"
        );
    }

    #[test]
    fn test_format_strings_preserved() {
        let raw = "let s = \"hello {world} // not a comment   \";\n";
        let formatted = format_ifa_source(raw);
        assert_eq!(
            formatted,
            "let s = \"hello {world} // not a comment   \";\n"
        );
    }

    #[test]
    fn test_format_comments_preserved() {
        let raw =
            "   //  Indented comment with { brackets }\nfn foo() {\n    // inner comment\n}\n";
        let formatted = format_ifa_source(raw);
        assert_eq!(
            formatted,
            "// Indented comment with { brackets }\nfn foo() {\n    // inner comment\n}\n"
        );
    }

    #[test]
    fn test_format_nested_blocks() {
        let raw = "fn test() {\nif cond {\nlet x = 1;\nif nested {\nlet y = 2;\n}\n}\n}\n";
        let formatted = format_ifa_source(raw);
        let expected = "fn test() {\n    if cond {\n        let x = 1;\n        if nested {\n            let y = 2;\n        }\n    }\n}\n";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_idempotency() {
        let sample = "pub fn calculate_sum(inout items: List<i64>, bias: i64) -> i64 {\n    mut total: i64 = 0;\n    mut i: i64 = 0;\n    while i < items.len() {\n        total = total + items[i];\n        i = i + 1;\n    }\n    return total + bias;\n}\n";
        let first_pass = format_ifa_source(sample);
        let second_pass = format_ifa_source(&first_pass);
        assert_eq!(first_pass, second_pass);
        assert_eq!(first_pass, sample);
    }

    #[test]
    fn test_format_type_annotations_and_colons() {
        let raw = "fn process(name:String, count:i64, inout cache:Map<String, i64>) {\nlet id:NodeId = 12;\n}\n";
        let formatted = format_ifa_source(raw);
        assert_eq!(
            formatted,
            "fn process(name: String, count: i64, inout cache: Map<String, i64>) {\n    let id: NodeId = 12;\n}\n"
        );
    }

    #[test]
    fn test_format_project_file_and_check_mode() {
        let tmp_dir = std::env::temp_dir().join(format!("ifa_fmt_test_{}", std::process::id()));
        fs::create_dir_all(tmp_dir.join("src")).expect("create test tmp dir");
        let file_path = tmp_dir.join("src").join("calc.ifa");
        let unformatted = "fn compute( x:i64 )->i64{\nreturn x*2;\n}\n";
        fs::write(&file_path, unformatted).expect("write unformatted file");

        let opts = FormatOptions::default();

        // 1. Check mode on unformatted file
        let report_check1 = format_project_or_file(&tmp_dir, true, &opts).expect("check format");
        assert_eq!(report_check1.total_files, 1);
        assert!(!report_check1.is_clean());
        assert_eq!(report_check1.changed_files.len(), 1);

        // 2. Format in place
        let report_fmt = format_project_or_file(&tmp_dir, false, &opts).expect("apply format");
        assert_eq!(report_fmt.total_files, 1);
        assert_eq!(report_fmt.formatted_files, 1);

        // 3. Verify file content on disk is now canonical
        let formatted_content = fs::read_to_string(&file_path).expect("read formatted file");
        assert_eq!(
            formatted_content,
            "fn compute(x: i64) -> i64 {\n    return x*2;\n}\n"
        );

        // 4. Re-check: must now be 100% clean
        let report_check2 = format_project_or_file(&tmp_dir, true, &opts).expect("re-check format");
        assert!(report_check2.is_clean());
        assert_eq!(report_check2.changed_files.len(), 0);

        let _ = fs::remove_dir_all(tmp_dir);
    }
}
