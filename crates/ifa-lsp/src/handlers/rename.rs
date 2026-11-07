//! Rename and Prepare Rename providers for IFA Language Server.

use crate::document::Document;
use crate::protocol::{Position, Range, RenameParams, TextEdit, WorkspaceEdit};
use ifa_lexer::tokenize;
use ifa_span::{sym, FileId};
use std::collections::HashMap;

/// Handle `textDocument/prepareRename` request.
pub fn handle_prepare_rename(doc: &Document, position: Position) -> Option<Range> {
    let (word, range) = doc.word_at_position(position)?;
    if is_keyword(word) {
        return None;
    }
    Some(range)
}

/// Handle `textDocument/rename` request.
pub fn handle_rename(doc: &Document, params: RenameParams) -> Option<WorkspaceEdit> {
    let (target_word, _) = doc.word_at_position(params.position)?;
    if is_keyword(target_word) {
        return None;
    }

    let new_name = params.new_name.trim();
    if !is_valid_ident(new_name) || is_keyword(new_name) {
        return None;
    }

    let target_symbol = sym(target_word);
    let file_id = FileId(0);
    let tokens = tokenize(file_id, &doc.text);

    let mut edits = Vec::new();
    for tok in tokens {
        if let ifa_lexer::TokenKind::Ident(s) = tok.kind {
            if s == target_symbol {
                let range = doc.span_to_range(tok.span);
                edits.push(TextEdit {
                    range,
                    new_text: new_name.to_string(),
                });
            }
        }
    }

    if edits.is_empty() {
        return None;
    }

    let mut changes = HashMap::new();
    changes.insert(doc.uri.clone(), edits);
    Some(WorkspaceEdit {
        changes: Some(changes),
    })
}

fn is_valid_ident(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_keyword(word: &str) -> bool {
    matches!(
        word,
        "fn" | "let"
            | "mut"
            | "struct"
            | "enum"
            | "import"
            | "as"
            | "pub"
            | "type"
            | "const"
            | "if"
            | "else"
            | "match"
            | "for"
            | "in"
            | "inout"
            | "sink"
            | "strict"
            | "comptime"
            | "extern"
            | "ref"
            | "while"
            | "loop"
            | "return"
            | "defer"
            | "break"
            | "continue"
            | "fail"
            | "try"
            | "catch"
            | "spawn"
            | "select"
            | "default"
            | "trait"
            | "interface"
            | "impl"
            | "true"
            | "false"
    )
}
