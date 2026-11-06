use crate::document::Document;
use crate::protocol::{Location, Position};
use ifa_span::sym;

pub fn handle_definition(doc: &Document, position: Position) -> Option<Location> {
    let (word, _) = doc.word_at_position(position)?;
    let analysis = doc.analysis.as_ref()?;
    let symbol = sym(word);

    // 1. Check functions
    if let Some(func) = analysis.symbols.functions.get(&symbol) {
        let range = doc.span_to_range(func.span);
        return Some(Location {
            uri: doc.uri.clone(),
            range,
        });
    }

    // 2. Check structs
    if let Some(str_sym) = analysis.symbols.structs.get(&symbol) {
        let range = doc.span_to_range(str_sym.span);
        return Some(Location {
            uri: doc.uri.clone(),
            range,
        });
    }

    // 3. Check enums
    if let Some(enum_sym) = analysis.symbols.enums.get(&symbol) {
        let range = doc.span_to_range(enum_sym.span);
        return Some(Location {
            uri: doc.uri.clone(),
            range,
        });
    }

    // 4. Check constants
    if let Some(const_sym) = analysis.symbols.consts.get(&symbol) {
        let range = doc.span_to_range(const_sym.span);
        return Some(Location {
            uri: doc.uri.clone(),
            range,
        });
    }

    // 5. Check local variables / parameters
    for scope in &analysis.symbols.scopes {
        if let Some(var) = scope.variables.get(&symbol) {
            let range = doc.span_to_range(var.span);
            return Some(Location {
                uri: doc.uri.clone(),
                range,
            });
        }
    }

    // 6. Check struct fields
    for str_sym in analysis.symbols.structs.values() {
        if let Some(field) = str_sym.get_field(&symbol) {
            let range = doc.span_to_range(field.span);
            return Some(Location {
                uri: doc.uri.clone(),
                range,
            });
        }
    }

    None
}
