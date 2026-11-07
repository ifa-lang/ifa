use crate::protocol::{Diagnostic, DiagnosticSeverity, Position, Range};
use ifa_ast::Program;
use ifa_diagnostics::Severity;
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::{analyze, AnalysisResult};
use ifa_span::{SourceMap, Span};
use std::collections::HashMap;

/// In-memory representation of an open IFA source file.
#[derive(Debug, Clone)]
pub struct Document {
    pub uri: String,
    pub version: i64,
    pub text: String,
    pub line_starts: Vec<usize>,
    pub ast: Option<Program>,
    pub analysis: Option<AnalysisResult>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Document {
    pub fn new(uri: String, version: i64, text: String) -> Self {
        let mut doc = Self {
            uri,
            version,
            text: String::new(),
            line_starts: Vec::new(),
            ast: None,
            analysis: None,
            diagnostics: Vec::new(),
        };
        doc.update_text(text);
        doc
    }

    /// Update document text and recompute line offset indices.
    pub fn update_text(&mut self, text: String) {
        let mut line_starts = vec![0];
        for (idx, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(idx + 1);
            }
        }
        self.text = text;
        self.line_starts = line_starts;
        self.reparse_and_analyze();
    }

    /// Convert character offset into 0-based LSP position (line, character).
    pub fn offset_to_position(&self, offset: usize) -> Position {
        let offset = offset.min(self.text.len());
        let line_idx = match self.line_starts.binary_search(&offset) {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };
        let line_start = self.line_starts.get(line_idx).copied().unwrap_or(0);
        let character = (offset - line_start) as u32;
        Position::new(line_idx as u32, character)
    }

    /// Convert 0-based LSP position to character byte offset in text.
    pub fn position_to_offset(&self, pos: Position) -> usize {
        let line_idx = (pos.line as usize).min(self.line_starts.len().saturating_sub(1));
        let line_start = self.line_starts.get(line_idx).copied().unwrap_or(0);
        let next_line_start = self
            .line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(self.text.len());
        (line_start + pos.character as usize).min(next_line_start)
    }

    /// Convert an IFA compiler Span into an LSP Range.
    pub fn span_to_range(&self, span: Span) -> Range {
        let start = self.offset_to_position(span.start.0 as usize);
        let end = self.offset_to_position(span.end.0 as usize);
        Range::new(start, end)
    }

    /// Re-run lexing, Pratt parsing and bidirectional semantic analysis on the updated document.
    pub fn reparse_and_analyze(&mut self) {
        let mut source_map = SourceMap::new();
        let file_id = source_map.add_file(&self.uri, &self.text);

        let tokens = tokenize(file_id, &self.text);
        let (program, parse_diags) = parse(file_id, tokens);
        let analysis_res = analyze(&source_map, &program);

        let mut lsp_diags = Vec::new();

        // Convert parser diagnostics
        for diag in parse_diags {
            let range = if let Some(label) = diag.labels.first() {
                self.span_to_range(label.span)
            } else {
                Range::new(Position::new(0, 0), Position::new(0, 0))
            };
            let severity = match diag.severity {
                Severity::Error => DiagnosticSeverity::Error as u32,
                Severity::Warning => DiagnosticSeverity::Warning as u32,
                Severity::Note => DiagnosticSeverity::Information as u32,
                Severity::Help => DiagnosticSeverity::Hint as u32,
            };
            lsp_diags.push(Diagnostic {
                range,
                severity: Some(severity),
                code: diag.code,
                source: Some("ifa".to_string()),
                message: diag.message,
            });
        }

        // Convert semantic analyzer diagnostics
        for diag in &analysis_res.diagnostics {
            let range = if let Some(label) = diag.labels.first() {
                self.span_to_range(label.span)
            } else {
                Range::new(Position::new(0, 0), Position::new(0, 0))
            };
            let severity = match diag.severity {
                Severity::Error => DiagnosticSeverity::Error as u32,
                Severity::Warning => DiagnosticSeverity::Warning as u32,
                Severity::Note => DiagnosticSeverity::Information as u32,
                Severity::Help => DiagnosticSeverity::Hint as u32,
            };
            lsp_diags.push(Diagnostic {
                range,
                severity: Some(severity),
                code: diag.code.clone(),
                source: Some("ifa".to_string()),
                message: diag.message.clone(),
            });
        }

        self.ast = Some(program);
        self.analysis = Some(analysis_res);
        self.diagnostics = lsp_diags;
    }

    /// Extract identifier or keyword at given position.
    pub fn word_at_position(&self, pos: Position) -> Option<(&str, Range)> {
        let offset = self.position_to_offset(pos);
        let bytes = self.text.as_bytes();

        if bytes.is_empty() {
            return None;
        }

        let mut start = offset;
        while start > 0 && is_ident_char(bytes[start - 1]) {
            start -= 1;
        }

        let mut end = offset;
        while end < bytes.len() && is_ident_char(bytes[end]) {
            end += 1;
        }

        if start >= end {
            return None;
        }

        let word = std::str::from_utf8(&bytes[start..end]).ok()?;
        let range = Range::new(self.offset_to_position(start), self.offset_to_position(end));
        Some((word, range))
    }

    /// Check if cursor follows a dot access like `foo.`
    pub fn dot_access_receiver(&self, pos: Position) -> Option<String> {
        let offset = self.position_to_offset(pos);
        let bytes = self.text.as_bytes();

        let mut idx = offset;
        // Skip whitespace backwards
        while idx > 0 && (bytes[idx - 1] == b' ' || bytes[idx - 1] == b'\t') {
            idx -= 1;
        }

        if idx == 0 || bytes[idx - 1] != b'.' {
            return None;
        }

        idx -= 1; // skip '.'

        // Skip whitespace backwards before '.'
        while idx > 0 && (bytes[idx - 1] == b' ' || bytes[idx - 1] == b'\t') {
            idx -= 1;
        }

        let end_ident = idx;
        while idx > 0 && is_ident_char(bytes[idx - 1]) {
            idx -= 1;
        }

        if idx >= end_ident {
            return None;
        }

        std::str::from_utf8(&bytes[idx..end_ident])
            .ok()
            .map(|s| s.to_string())
    }
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// In-memory document collection mapped by URI.
#[derive(Debug, Default)]
pub struct DocumentStore {
    documents: HashMap<String, Document>,
}

impl DocumentStore {
    pub fn new() -> Self {
        Self {
            documents: HashMap::new(),
        }
    }

    pub fn open(&mut self, uri: String, version: i64, text: String) -> &Document {
        let doc = Document::new(uri.clone(), version, text);
        self.documents.insert(uri.clone(), doc);
        self.documents.get(&uri).unwrap()
    }

    pub fn update(&mut self, uri: &str, version: i64, text: String) -> Option<&Document> {
        if let Some(doc) = self.documents.get_mut(uri) {
            doc.version = version;
            doc.update_text(text);
            Some(doc)
        } else {
            None
        }
    }

    pub fn close(&mut self, uri: &str) -> Option<Document> {
        self.documents.remove(uri)
    }

    pub fn get(&self, uri: &str) -> Option<&Document> {
        self.documents.get(uri)
    }

    pub fn get_mut(&mut self, uri: &str) -> Option<&mut Document> {
        self.documents.get_mut(uri)
    }

    /// Iterate over all currently tracked documents in the store.
    pub fn iter(&self) -> impl Iterator<Item = &Document> {
        self.documents.values()
    }
}
