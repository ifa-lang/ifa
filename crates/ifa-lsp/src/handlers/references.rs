//! Find All References provider for IFA Language Server.

use crate::document::Document;
use crate::protocol::{Location, ReferenceParams};
use ifa_lexer::tokenize;
use ifa_span::{sym, FileId};

/// Handle `textDocument/references` request.
pub fn handle_references(doc: &Document, params: ReferenceParams) -> Vec<Location> {
    let mut locations = Vec::new();
    let (target_word, target_range) = match doc.word_at_position(params.position) {
        Some(w) => w,
        None => return locations,
    };

    let target_symbol = sym(target_word);

    // Re-tokenize document to locate all identifier tokens matching target
    let file_id = FileId(0);
    let tokens = tokenize(file_id, &doc.text);

    for tok in tokens {
        if let ifa_lexer::TokenKind::Ident(s) = tok.kind {
            if s == target_symbol {
                let range = doc.span_to_range(tok.span);
                if !params.context.include_declaration && range == target_range {
                    continue;
                }
                locations.push(Location {
                    uri: doc.uri.clone(),
                    range,
                });
            }
        }
    }

    locations
}
