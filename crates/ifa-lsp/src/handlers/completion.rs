use crate::document::Document;
use crate::protocol::{CompletionItem, CompletionItemKind, CompletionList, Position};
use ifa_span::sym;

pub fn handle_completion(doc: &Document, position: Position) -> CompletionList {
    let mut items = Vec::new();

    // Check for dot access: receiver.field
    if let Some(receiver) = doc.dot_access_receiver(position) {
        if let Some(analysis) = &doc.analysis {
            let receiver_sym = sym(&receiver);
            let mut struct_name = None;

            for scope in &analysis.symbols.scopes {
                if let Some(var) = scope.variables.get(&receiver_sym) {
                    if let ifa_sema::types::Type::Struct { name, .. } = &var.ty {
                        struct_name = Some(*name);
                        break;
                    }
                }
            }

            // If not found as variable, check if receiver is directly a struct name
            if struct_name.is_none() && analysis.symbols.structs.contains_key(&receiver_sym) {
                struct_name = Some(receiver_sym);
            }

            if let Some(s_sym) = struct_name {
                if let Some(str_sym) = analysis.symbols.structs.get(&s_sym) {
                    for field in &str_sym.fields {
                        let field_name = field.name.resolve();
                        let ty_str = format!("{}", field.ty);
                        items.push(
                            CompletionItem::new(&field_name, CompletionItemKind::Field)
                                .with_detail(format!("{}: {}", field_name, ty_str))
                                .with_doc(format!("Struct field of type `{}`", ty_str)),
                        );
                    }
                    return CompletionList {
                        is_incomplete: false,
                        items,
                    };
                }
            }
        }
    }

    // Default global & scoped completions
    // 1. IFA Language Keywords
    let keywords = [
        (
            "fn",
            "Function declaration",
            "fn <name>(<params>) -> <ret> { ... }",
        ),
        (
            "let",
            "Immutable value binding",
            "let <name>: <type> = <expr>",
        ),
        (
            "mut",
            "Mutable value binding",
            "mut <name>: <type> = <expr>",
        ),
        (
            "inout",
            "Exclusive mutable parameter passing",
            "inout <param>: <type>",
        ),
        (
            "struct",
            "Struct type declaration",
            "struct <Name> { <fields> }",
        ),
        (
            "enum",
            "Enumeration declaration",
            "enum <Name> { <variants> }",
        ),
        (
            "comptime",
            "Compile-time deterministic evaluation",
            "comptime fn <name>() -> <ret>",
        ),
        (
            "strict",
            "Deterministic zero-allocation strict mode",
            "strict fn <name>() -> <ret>",
        ),
        ("pub", "Public visibility specifier", "pub fn / pub struct"),
        (
            "match",
            "Pattern matching control-flow",
            "match <expr> { <pattern> => <expr> }",
        ),
        (
            "if",
            "Conditional branching",
            "if <cond> { ... } else { ... }",
        ),
        ("else", "Alternative conditional branch", "else { ... }"),
        ("while", "Looping construct", "while <cond> { ... }"),
        (
            "for",
            "Iteration construct",
            "for <ident> in <expr> { ... }",
        ),
        ("in", "Iterator keyword for loops", "for item in list"),
        ("return", "Return from function", "return <expr>;"),
        ("import", "Import module or package", "import std::io"),
        (
            "extern",
            "External C-ABI declaration",
            "extern \"C\" fn <name>()",
        ),
        (
            "catch",
            "Error handling expression",
            "expr catch err { ... }",
        ),
        ("defer", "Deferred cleanup statement", "defer { ... }"),
    ];

    for (kw, detail, doc_str) in keywords {
        items.push(
            CompletionItem::new(kw, CompletionItemKind::Keyword)
                .with_detail(detail)
                .with_doc(doc_str),
        );
    }

    // 2. Fundamental IFA Types
    let types = [
        ("int", "Default signed 64-bit integer type"),
        ("i8", "8-bit signed integer"),
        ("i16", "16-bit signed integer"),
        ("i32", "32-bit signed integer"),
        ("i64", "64-bit signed integer"),
        ("u8", "8-bit unsigned integer (byte)"),
        ("u16", "16-bit unsigned integer"),
        ("u32", "32-bit unsigned integer"),
        ("u64", "64-bit unsigned integer"),
        ("float", "Default 64-bit floating point type"),
        ("f32", "32-bit IEEE 754 floating point"),
        ("f64", "64-bit IEEE 754 floating point"),
        ("bool", "Boolean type (`true` or `false`)"),
        ("string", "UTF-8 immutable Copy-on-Write string"),
        ("char", "32-bit Unicode scalar character"),
        ("void", "Empty unit type ()"),
        ("ref", "Safe generational reference wrapper"),
    ];

    for (ty, detail) in types {
        items.push(
            CompletionItem::new(ty, CompletionItemKind::Class)
                .with_detail(format!("Primitive Type `{}`", ty))
                .with_doc(detail),
        );
    }

    // 3. User Symbols from Semantic Analysis
    if let Some(analysis) = &doc.analysis {
        // Functions
        for (f_sym, func) in &analysis.symbols.functions {
            let name = f_sym.resolve();
            let params_str = func
                .params
                .iter()
                .map(|p| format!("{}: {}", p.name.resolve(), p.ty))
                .collect::<Vec<_>>()
                .join(", ");
            let sig = format!("fn {}({}) -> {}", name, params_str, func.ret_ty);
            items.push(
                CompletionItem::new(&name, CompletionItemKind::Function)
                    .with_detail(sig.clone())
                    .with_doc(format!("```ifa\n{}\n```", sig)),
            );
        }

        // Structs
        for (s_sym, str_sym) in &analysis.symbols.structs {
            let name = s_sym.resolve();
            items.push(
                CompletionItem::new(&name, CompletionItemKind::Struct)
                    .with_detail(format!("struct {}", name))
                    .with_doc(format!(
                        "Struct definition `{}` ({} fields)",
                        name,
                        str_sym.fields.len()
                    )),
            );
        }

        // Enums
        for (e_sym, enum_sym) in &analysis.symbols.enums {
            let name = e_sym.resolve();
            items.push(
                CompletionItem::new(&name, CompletionItemKind::Enum)
                    .with_detail(format!("enum {}", name))
                    .with_doc(format!(
                        "Enum definition `{}` ({} variants)",
                        name,
                        enum_sym.variants.len()
                    )),
            );
        }

        // In-scope variables
        for (v_sym, var) in analysis.symbols.scopes.iter().flat_map(|s| &s.variables) {
            let name = v_sym.resolve();
            let mut_prefix = if var.is_mut { "mut" } else { "let" };
            items.push(
                CompletionItem::new(&name, CompletionItemKind::Variable)
                    .with_detail(format!("{} {}: {}", mut_prefix, name, var.ty))
                    .with_doc(format!("Local variable `{}` of type `{}`", name, var.ty)),
            );
        }
    }

    CompletionList {
        is_incomplete: false,
        items,
    }
}
