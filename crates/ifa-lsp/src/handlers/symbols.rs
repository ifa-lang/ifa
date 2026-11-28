use crate::document::Document;
use crate::protocol::{DocumentSymbol, SymbolKind};

pub fn handle_document_symbols(doc: &Document) -> Vec<DocumentSymbol> {
    let mut symbols = Vec::new();
    let analysis = match &doc.analysis {
        Some(a) => a,
        None => return symbols,
    };

    // 1. Functions
    for (sym, func) in &analysis.symbols.functions {
        let name = sym.resolve();
        let range = doc.span_to_range(func.span);
        let detail = format!("fn(...) -> {}", func.ret_ty);
        symbols.push(DocumentSymbol {
            name,
            detail: Some(detail),
            kind: SymbolKind::Function as u32,
            range,
            selection_range: range,
            children: None,
        });
    }

    // 2. Structs and their fields
    for (sym, str_sym) in &analysis.symbols.structs {
        let name = sym.resolve();
        if name.starts_with("__") {
            continue;
        }
        let range = doc.span_to_range(str_sym.span);

        let mut children = Vec::new();
        for field in &str_sym.fields {
            let f_name = field.name.resolve();
            let f_range = doc.span_to_range(field.span);
            children.push(DocumentSymbol {
                name: f_name,
                detail: Some(format!("{}", field.ty)),
                kind: SymbolKind::Field as u32,
                range: f_range,
                selection_range: f_range,
                children: None,
            });
        }

        symbols.push(DocumentSymbol {
            name,
            detail: Some(format!("struct ({} fields)", str_sym.fields.len())),
            kind: SymbolKind::Struct as u32,
            range,
            selection_range: range,
            children: Some(children),
        });
    }

    // 3. Enums and their variants
    for (sym, enum_sym) in &analysis.symbols.enums {
        let name = sym.resolve();
        let range = doc.span_to_range(enum_sym.span);

        let mut children = Vec::new();
        for (v_name, v_ty) in &enum_sym.variants {
            let v_str = v_name.resolve();
            let detail = v_ty.as_ref().map(|t| format!("{}", t));
            children.push(DocumentSymbol {
                name: v_str,
                detail,
                kind: SymbolKind::EnumMember as u32,
                range,
                selection_range: range,
                children: None,
            });
        }

        symbols.push(DocumentSymbol {
            name,
            detail: Some(format!("enum ({} variants)", enum_sym.variants.len())),
            kind: SymbolKind::Enum as u32,
            range,
            selection_range: range,
            children: Some(children),
        });
    }

    // 4. Constants
    for (sym, const_sym) in &analysis.symbols.consts {
        let name = sym.resolve();
        let range = doc.span_to_range(const_sym.span);
        symbols.push(DocumentSymbol {
            name,
            detail: Some(format!("const: {}", const_sym.ty)),
            kind: SymbolKind::Constant as u32,
            range,
            selection_range: range,
            children: None,
        });
    }

    // 5. Protocols and their channels / slices
    for (sym, proto_sym) in &analysis.symbols.protocols {
        let name = sym.resolve();
        let range = doc.span_to_range(proto_sym.span);

        let mut children = Vec::new();
        for ch in &proto_sym.channels {
            let ch_name = ch.name.resolve();
            let ch_range = doc.span_to_range(ch.span);
            let kind_label = if ch.is_slice { "slice" } else { "channel" };
            children.push(DocumentSymbol {
                name: ch_name,
                detail: Some(format!("{}: {}", kind_label, ch.ty)),
                kind: SymbolKind::Field as u32,
                range: ch_range,
                selection_range: ch_range,
                children: None,
            });
        }

        symbols.push(DocumentSymbol {
            name,
            detail: Some(format!(
                "protocol ({} channels/slices)",
                proto_sym.channels.len()
            )),
            kind: SymbolKind::Interface as u32,
            range,
            selection_range: range,
            children: Some(children),
        });
    }

    symbols
}
