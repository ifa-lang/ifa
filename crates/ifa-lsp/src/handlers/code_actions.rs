//! Code Actions and Quick-Fixes provider (LSP 3.17) for IFA Language Server.

use crate::document::Document;
use crate::handlers::formatting::handle_formatting;
use crate::protocol::{CodeAction, CodeActionParams, TextEdit, WorkspaceEdit};
use std::collections::HashMap;

/// Handle `textDocument/codeAction` request.
pub fn handle_code_actions(doc: &Document, params: CodeActionParams) -> Vec<CodeAction> {
    let mut actions = Vec::new();

    // 1. Process compiler diagnostics in the requested range
    for diag in &params.context.diagnostics {
        let msg = diag.message.to_lowercase();

        // QuickFix: Mutability fix ("cannot mutate immutable variable `x`")
        if msg.contains("immutable") || msg.contains("cannot mutate") {
            if let Some((word, word_range)) = doc.word_at_position(diag.range.start) {
                // Find `let <word>` on that line
                let line_idx = word_range.start.line as usize;
                if let Some(line) = doc.text.lines().nth(line_idx) {
                    if let Some(let_offset) = line.find("let ") {
                        let let_range = crate::protocol::Range::new(
                            crate::protocol::Position::new(line_idx as u32, let_offset as u32),
                            crate::protocol::Position::new(
                                line_idx as u32,
                                (let_offset + 3) as u32,
                            ),
                        );
                        let mut changes = HashMap::new();
                        changes.insert(
                            doc.uri.clone(),
                            vec![TextEdit {
                                range: let_range,
                                new_text: "mut".to_string(),
                            }],
                        );
                        actions.push(CodeAction {
                            title: format!("Make `{}` mutable (`mut {}`)", word, word),
                            kind: Some("quickfix".to_string()),
                            diagnostics: Some(vec![diag.clone()]),
                            is_preferred: Some(true),
                            edit: Some(WorkspaceEdit {
                                changes: Some(changes),
                            }),
                        });
                    }
                }
            }
        }

        // QuickFix: Unused variable fix ("unused variable `x`")
        if msg.contains("unused variable") || msg.contains("never read") {
            if let Some((word, word_range)) = doc.word_at_position(diag.range.start) {
                if !word.starts_with('_') {
                    let mut changes = HashMap::new();
                    changes.insert(
                        doc.uri.clone(),
                        vec![TextEdit {
                            range: word_range,
                            new_text: format!("_{}", word),
                        }],
                    );
                    actions.push(CodeAction {
                        title: format!("Prefix unused variable with underscore (`_{}`)", word),
                        kind: Some("quickfix".to_string()),
                        diagnostics: Some(vec![diag.clone()]),
                        is_preferred: Some(true),
                        edit: Some(WorkspaceEdit {
                            changes: Some(changes),
                        }),
                    });
                }
            }
        }
    }

    // 2. Source Action: Format Document
    let fmt_edits = handle_formatting(doc);
    if !fmt_edits.is_empty() {
        let mut changes = HashMap::new();
        changes.insert(doc.uri.clone(), fmt_edits);
        actions.push(CodeAction {
            title: "Format Document (IFA Canonical)".to_string(),
            kind: Some("source.formatDocument".to_string()),
            diagnostics: None,
            is_preferred: Some(false),
            edit: Some(WorkspaceEdit {
                changes: Some(changes),
            }),
        });
    }

    actions
}
