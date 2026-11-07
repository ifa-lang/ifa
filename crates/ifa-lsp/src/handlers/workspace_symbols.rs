//! Workspace Symbols search provider (LSP 3.17) across all open documents.

use crate::document::DocumentStore;
use crate::protocol::{Location, SymbolInformation, SymbolKind};

/// Handle `workspace/symbol` request.
pub fn handle_workspace_symbols(store: &DocumentStore, query: &str) -> Vec<SymbolInformation> {
    let mut symbols = Vec::new();
    let query_lower = query.to_lowercase();

    for doc in store.iter() {
        let analysis = match &doc.analysis {
            Some(a) => a,
            None => continue,
        };

        // 1. Functions
        for (sym, func) in &analysis.symbols.functions {
            let name = sym.resolve();
            if query_lower.is_empty() || name.to_lowercase().contains(&query_lower) {
                let range = doc.span_to_range(func.span);
                symbols.push(SymbolInformation {
                    name,
                    kind: SymbolKind::Function as u32,
                    location: Location {
                        uri: doc.uri.clone(),
                        range,
                    },
                    container_name: None,
                });
            }
        }

        // 2. Structs & Fields
        for (sym, str_sym) in &analysis.symbols.structs {
            let struct_name = sym.resolve();
            if query_lower.is_empty() || struct_name.to_lowercase().contains(&query_lower) {
                let range = doc.span_to_range(str_sym.span);
                symbols.push(SymbolInformation {
                    name: struct_name.clone(),
                    kind: SymbolKind::Struct as u32,
                    location: Location {
                        uri: doc.uri.clone(),
                        range,
                    },
                    container_name: None,
                });
            }

            for field in &str_sym.fields {
                let f_name = field.name.resolve();
                if query_lower.is_empty() || f_name.to_lowercase().contains(&query_lower) {
                    let range = doc.span_to_range(field.span);
                    symbols.push(SymbolInformation {
                        name: f_name,
                        kind: SymbolKind::Field as u32,
                        location: Location {
                            uri: doc.uri.clone(),
                            range,
                        },
                        container_name: Some(struct_name.clone()),
                    });
                }
            }
        }

        // 3. Enums & Variants
        for (sym, enum_sym) in &analysis.symbols.enums {
            let enum_name = sym.resolve();
            if query_lower.is_empty() || enum_name.to_lowercase().contains(&query_lower) {
                let range = doc.span_to_range(enum_sym.span);
                symbols.push(SymbolInformation {
                    name: enum_name.clone(),
                    kind: SymbolKind::Enum as u32,
                    location: Location {
                        uri: doc.uri.clone(),
                        range,
                    },
                    container_name: None,
                });
            }

            for (v_name, _) in &enum_sym.variants {
                let v_str = v_name.resolve();
                if query_lower.is_empty() || v_str.to_lowercase().contains(&query_lower) {
                    let range = doc.span_to_range(enum_sym.span);
                    symbols.push(SymbolInformation {
                        name: v_str,
                        kind: SymbolKind::EnumMember as u32,
                        location: Location {
                            uri: doc.uri.clone(),
                            range,
                        },
                        container_name: Some(enum_name.clone()),
                    });
                }
            }
        }

        // 4. Constants
        for (sym, const_sym) in &analysis.symbols.consts {
            let const_name = sym.resolve();
            if query_lower.is_empty() || const_name.to_lowercase().contains(&query_lower) {
                let range = doc.span_to_range(const_sym.span);
                symbols.push(SymbolInformation {
                    name: const_name,
                    kind: SymbolKind::Constant as u32,
                    location: Location {
                        uri: doc.uri.clone(),
                        range,
                    },
                    container_name: None,
                });
            }
        }
    }

    symbols
}
