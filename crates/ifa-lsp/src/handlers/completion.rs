use crate::document::Document;
use crate::protocol::{CompletionItem, CompletionItemKind, CompletionList, Position};
use ifa_span::sym;

fn extract_struct_from_ast_type(ty: &ifa_ast::Type) -> Option<ifa_span::Symbol> {
    match &ty.kind {
        ifa_ast::TypeKind::Named(s) => Some(*s),
        ifa_ast::TypeKind::Generic(s, _) => Some(*s),
        ifa_ast::TypeKind::Path(p) => p.last().copied(),
        ifa_ast::TypeKind::Ref(inner)
        | ifa_ast::TypeKind::Optional(inner)
        | ifa_ast::TypeKind::Slice(inner)
        | ifa_ast::TypeKind::Array(inner, _) => extract_struct_from_ast_type(inner),
        _ => None,
    }
}

fn get_stdlib_completions_for_struct(name: &str) -> Option<Vec<CompletionItem>> {
    let mut items = Vec::new();
    match name {
        "RingBuffer" => {
            items.push(
                CompletionItem::new("capacity", CompletionItemKind::Field)
                    .with_detail("capacity: int")
                    .with_doc("Fixed capacity of circular ring buffer"),
            );
            items.push(
                CompletionItem::new("len", CompletionItemKind::Field)
                    .with_detail("len: int")
                    .with_doc("Current number of active items in ring buffer"),
            );
            items.push(
                CompletionItem::new("head", CompletionItemKind::Field)
                    .with_detail("head: int")
                    .with_doc("Current head read index"),
            );
            items.push(
                CompletionItem::new("tail", CompletionItemKind::Field)
                    .with_detail("tail: int")
                    .with_doc("Current tail write index"),
            );
            items.push(
                CompletionItem::new("is_full", CompletionItemKind::Field)
                    .with_detail("is_full: bool")
                    .with_doc("Whether buffer has reached maximum capacity"),
            );
            items.push(
                CompletionItem::new("push", CompletionItemKind::Method)
                    .with_detail("fn push(inout self, val: int) -> bool")
                    .with_doc("Push item into ring buffer, overwriting oldest if full"),
            );
            items.push(
                CompletionItem::new("pop", CompletionItemKind::Method)
                    .with_detail("fn pop(inout self) -> int")
                    .with_doc("Pop oldest item in FIFO order"),
            );
            items.push(
                CompletionItem::new("peek", CompletionItemKind::Method)
                    .with_detail("fn peek(self) -> int")
                    .with_doc("Inspect oldest item without removing"),
            );
            Some(items)
        }
        "BinaryHeap" => {
            items.push(
                CompletionItem::new("len", CompletionItemKind::Field)
                    .with_detail("len: int")
                    .with_doc("Number of elements in binary heap"),
            );
            items.push(
                CompletionItem::new("is_max", CompletionItemKind::Field)
                    .with_detail("is_max: bool")
                    .with_doc("True for Max-Heap, false for Min-Heap"),
            );
            items.push(
                CompletionItem::new("push", CompletionItemKind::Method)
                    .with_detail("fn push(inout self, val: int)")
                    .with_doc("Insert element maintaining logarithmic heap invariant"),
            );
            items.push(
                CompletionItem::new("pop", CompletionItemKind::Method)
                    .with_detail("fn pop(inout self) -> int")
                    .with_doc("Extract root element (maximum or minimum)"),
            );
            items.push(
                CompletionItem::new("peek", CompletionItemKind::Method)
                    .with_detail("fn peek(self) -> int")
                    .with_doc("View root element without removal"),
            );
            Some(items)
        }
        "Deque" | "IntDeque" => {
            items.push(
                CompletionItem::new("len", CompletionItemKind::Field)
                    .with_detail("len: int")
                    .with_doc("Number of elements in deque"),
            );
            items.push(
                CompletionItem::new("push_front", CompletionItemKind::Method)
                    .with_detail("fn push_front(inout self, val: int)")
                    .with_doc("Prepend element to front"),
            );
            items.push(
                CompletionItem::new("push_back", CompletionItemKind::Method)
                    .with_detail("fn push_back(inout self, val: int)")
                    .with_doc("Append element to back"),
            );
            items.push(
                CompletionItem::new("pop_front", CompletionItemKind::Method)
                    .with_detail("fn pop_front(inout self) -> int")
                    .with_doc("Remove and return element from front"),
            );
            items.push(
                CompletionItem::new("pop_back", CompletionItemKind::Method)
                    .with_detail("fn pop_back(inout self) -> int")
                    .with_doc("Remove and return element from back"),
            );
            Some(items)
        }
        "IntMap" => {
            items.push(
                CompletionItem::new("len", CompletionItemKind::Field)
                    .with_detail("len: int")
                    .with_doc("Number of key-value pairs in int map"),
            );
            items.push(
                CompletionItem::new("get", CompletionItemKind::Method)
                    .with_detail("fn get(self, key: int) -> int")
                    .with_doc("Lookup value by integer key"),
            );
            items.push(
                CompletionItem::new("set", CompletionItemKind::Method)
                    .with_detail("fn set(inout self, key: int, val: int) -> bool")
                    .with_doc("Insert or update key-value pair"),
            );
            items.push(
                CompletionItem::new("remove", CompletionItemKind::Method)
                    .with_detail("fn remove(inout self, key: int) -> bool")
                    .with_doc("Remove key-value pair"),
            );
            items.push(
                CompletionItem::new("has", CompletionItemKind::Method)
                    .with_detail("fn has(self, key: int) -> bool")
                    .with_doc("Check if key exists in map"),
            );
            Some(items)
        }
        "ByteBuffer" => {
            items.push(
                CompletionItem::new("len", CompletionItemKind::Field)
                    .with_detail("len: int")
                    .with_doc("Total written bytes in buffer"),
            );
            items.push(
                CompletionItem::new("capacity", CompletionItemKind::Field)
                    .with_detail("capacity: int")
                    .with_doc("Allocated capacity"),
            );
            items.push(
                CompletionItem::new("write_u8", CompletionItemKind::Method)
                    .with_detail("fn write_u8(inout self, val: int)")
                    .with_doc("Write single byte"),
            );
            items.push(
                CompletionItem::new("read_u8", CompletionItemKind::Method)
                    .with_detail("fn read_u8(self, offset: int) -> int")
                    .with_doc("Read single byte at offset"),
            );
            items.push(
                CompletionItem::new("write_u32_le", CompletionItemKind::Method)
                    .with_detail("fn write_u32_le(inout self, val: int)")
                    .with_doc("Write 32-bit little-endian integer"),
            );
            items.push(
                CompletionItem::new("read_u32_le", CompletionItemKind::Method)
                    .with_detail("fn read_u32_le(self, offset: int) -> int")
                    .with_doc("Read 32-bit little-endian integer"),
            );
            Some(items)
        }
        "TcpServer" => {
            items.push(
                CompletionItem::new("listener", CompletionItemKind::Field)
                    .with_detail("listener: TcpListener")
                    .with_doc("Bound non-blocking TCP socket listener"),
            );
            items.push(
                CompletionItem::new("clients", CompletionItemKind::Field)
                    .with_detail("clients: List<TcpStream>")
                    .with_doc("List of currently connected active client streams"),
            );
            items.push(
                CompletionItem::new("max_clients", CompletionItemKind::Field)
                    .with_detail("max_clients: int")
                    .with_doc("Maximum allowed concurrent client connections"),
            );
            items.push(
                CompletionItem::new("is_running", CompletionItemKind::Field)
                    .with_detail("is_running: bool")
                    .with_doc("Server running state"),
            );
            items.push(
                CompletionItem::new("total_accepted", CompletionItemKind::Field)
                    .with_detail("total_accepted: int")
                    .with_doc("Total connection count accepted since start"),
            );
            Some(items)
        }
        "TcpStream" => {
            items.push(
                CompletionItem::new("fd", CompletionItemKind::Field)
                    .with_detail("fd: int")
                    .with_doc("Operating system socket file descriptor"),
            );
            items.push(
                CompletionItem::new("is_open", CompletionItemKind::Field)
                    .with_detail("is_open: bool")
                    .with_doc("Whether the TCP stream is active and open"),
            );
            Some(items)
        }
        "TcpListener" => {
            items.push(
                CompletionItem::new("fd", CompletionItemKind::Field)
                    .with_detail("fd: int")
                    .with_doc("Listening socket file descriptor"),
            );
            items.push(
                CompletionItem::new("port", CompletionItemKind::Field)
                    .with_detail("port: int")
                    .with_doc("Bound local TCP port number"),
            );
            items.push(
                CompletionItem::new("is_open", CompletionItemKind::Field)
                    .with_detail("is_open: bool")
                    .with_doc("Whether the listener socket is actively accepting"),
            );
            Some(items)
        }
        "JsonValue" => {
            items.push(
                CompletionItem::new("kind", CompletionItemKind::Field)
                    .with_detail("kind: int")
                    .with_doc("0: Null, 1: Bool, 2: Number/Int, 3: String, 4: Array, 5: Object"),
            );
            items.push(
                CompletionItem::new("bool_val", CompletionItemKind::Field)
                    .with_detail("bool_val: bool")
                    .with_doc("Boolean payload"),
            );
            items.push(
                CompletionItem::new("int_val", CompletionItemKind::Field)
                    .with_detail("int_val: int")
                    .with_doc("64-bit signed integer payload"),
            );
            items.push(
                CompletionItem::new("str_val", CompletionItemKind::Field)
                    .with_detail("str_val: string")
                    .with_doc("String payload"),
            );
            items.push(
                CompletionItem::new("arr_val", CompletionItemKind::Field)
                    .with_detail("arr_val: List<JsonValue>")
                    .with_doc("Heterogeneous elements list"),
            );
            items.push(
                CompletionItem::new("obj_keys", CompletionItemKind::Field)
                    .with_detail("obj_keys: List<string>")
                    .with_doc("Ordered object keys"),
            );
            items.push(
                CompletionItem::new("obj_vals", CompletionItemKind::Field)
                    .with_detail("obj_vals: List<JsonValue>")
                    .with_doc("Ordered object values"),
            );
            Some(items)
        }
        _ => None,
    }
}

pub fn handle_completion(doc: &Document, position: Position) -> CompletionList {
    let mut items = Vec::new();

    // Check for dot access: receiver.field or receiver?.field
    if let Some(receiver) = doc.dot_access_receiver(position) {
        if let Some(analysis) = &doc.analysis {
            let receiver_sym = sym(&receiver);
            let mut struct_name = None;

            for scope in &analysis.symbols.scopes {
                if let Some(var) = scope.variables.get(&receiver_sym) {
                    let mut cur_ty = &var.ty;
                    while let ifa_sema::types::Type::Optional(inner)
                    | ifa_sema::types::Type::Ref(inner) = cur_ty
                    {
                        cur_ty = inner;
                    }
                    if let ifa_sema::types::Type::Struct { name, .. } = cur_ty {
                        struct_name = Some(*name);
                        break;
                    } else if let ifa_sema::types::Type::Generic { name, .. } = cur_ty {
                        struct_name = Some(*name);
                        break;
                    }
                }
            }

            // If not found in global scopes, inspect AST for local variables or parameters
            if struct_name.is_none() {
                if let Some(ast) = &doc.ast {
                    for item in &ast.items {
                        if let ifa_ast::Item::Function(f) = item {
                            for p in &f.params {
                                if p.name == receiver_sym {
                                    if let Some(sn) = extract_struct_from_ast_type(&p.ty) {
                                        struct_name = Some(sn);
                                        break;
                                    }
                                }
                            }
                            if struct_name.is_some() {
                                break;
                            }
                            if let Some(body) = &f.body {
                                for stmt in &body.stmts {
                                    if let ifa_ast::Stmt::Let {
                                        pattern:
                                            ifa_ast::Pattern::Ident(name, _)
                                            | ifa_ast::Pattern::Binding { name, .. },
                                        ty,
                                        ..
                                    } = stmt
                                    {
                                        if *name == receiver_sym {
                                            if let Some(t) = ty {
                                                if let Some(sn) = extract_struct_from_ast_type(t) {
                                                    struct_name = Some(sn);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if struct_name.is_some() {
                                break;
                            }
                        }
                    }
                }
            }

            // If not found as variable, check if receiver is directly a struct name
            if struct_name.is_none() && analysis.symbols.structs.contains_key(&receiver_sym) {
                struct_name = Some(receiver_sym);
            }

            if let Some(s_sym) = struct_name {
                let resolved_name = s_sym.resolve();
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
                } else if let Some(stdlib_items) = get_stdlib_completions_for_struct(&resolved_name)
                {
                    return CompletionList {
                        is_incomplete: false,
                        items: stdlib_items,
                    };
                }
            }

            if let Some(stdlib_items) = get_stdlib_completions_for_struct(&receiver) {
                return CompletionList {
                    is_incomplete: false,
                    items: stdlib_items,
                };
            }
        }
    }

    // Check for double-colon namespace resolution: module::member or Enum::Variant
    if let Some(receiver) = doc.colon_access_receiver(position) {
        if let Some(analysis) = &doc.analysis {
            let receiver_sym = sym(&receiver);

            // 1. Module namespace completions (functions, structs, enums, consts)
            if let Some(module) = analysis.symbols.lookup_module(&receiver_sym) {
                for (fn_name, func) in &module.functions {
                    if func.is_pub {
                        let name_str = fn_name.resolve();
                        let params_str: Vec<String> = func
                            .params
                            .iter()
                            .map(|p| format!("{}: {}", p.name.resolve(), p.ty))
                            .collect();
                        let detail = format!(
                            "fn {}({}) -> {}",
                            name_str,
                            params_str.join(", "),
                            func.ret_ty
                        );
                        items.push(
                            CompletionItem::new(&name_str, CompletionItemKind::Function)
                                .with_detail(detail)
                                .with_doc(format!(
                                    "Public function exported by module `{}`",
                                    receiver
                                )),
                        );
                    }
                }
                for (st_name, st) in &module.structs {
                    if st.is_pub {
                        let name_str = st_name.resolve();
                        items.push(
                            CompletionItem::new(&name_str, CompletionItemKind::Struct)
                                .with_detail(format!("struct {}", name_str))
                                .with_doc(format!(
                                    "Public struct exported by module `{}`",
                                    receiver
                                )),
                        );
                    }
                }
                for (en_name, en) in &module.enums {
                    if en.is_pub {
                        let name_str = en_name.resolve();
                        items.push(
                            CompletionItem::new(&name_str, CompletionItemKind::Enum)
                                .with_detail(format!("enum {}", name_str))
                                .with_doc(format!("Public enum exported by module `{}`", receiver)),
                        );
                    }
                }
                for (c_name, c) in &module.consts {
                    if c.is_pub {
                        let name_str = c_name.resolve();
                        items.push(
                            CompletionItem::new(&name_str, CompletionItemKind::Constant)
                                .with_detail(format!("const {}: {}", name_str, c.ty))
                                .with_doc(format!(
                                    "Public constant exported by module `{}`",
                                    receiver
                                )),
                        );
                    }
                }

                if !items.is_empty() {
                    return CompletionList {
                        is_incomplete: false,
                        items,
                    };
                }
            }

            // 2. Enum variant completions
            if let Some(enum_sym) = analysis.symbols.enums.get(&receiver_sym) {
                for (variant_name, var_ty) in &enum_sym.variants {
                    let v_str = variant_name.resolve();
                    let detail = if let Some(ty) = var_ty {
                        format!("Variant {}({})", v_str, ty)
                    } else {
                        format!("Variant {}", v_str)
                    };
                    items.push(
                        CompletionItem::new(&v_str, CompletionItemKind::EnumMember)
                            .with_detail(detail)
                            .with_doc(format!("Variant of enum `{}`", receiver)),
                    );
                }
                return CompletionList {
                    is_incomplete: false,
                    items,
                };
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

    // 3. Official IFA Standard Library Core Structures & Types
    let stdlib_structs = [
        (
            "RingBuffer",
            "Fixed-capacity circular FIFO ring buffer (`std/collections`)",
        ),
        (
            "BinaryHeap",
            "Deterministic binary heap priority queue (`std/collections`)",
        ),
        (
            "Deque",
            "Double-ended queue supporting O(1) front/back operations (`std/collections`)",
        ),
        (
            "IntMap",
            "Ordered integer key-value hash map (`std/collections`)",
        ),
        (
            "ByteBuffer",
            "Contiguous byte sequence buffer with endianness control (`std/collections`)",
        ),
        (
            "StringBuilder",
            "Deterministic mutable string builder (`std/collections`)",
        ),
        (
            "List",
            "Dynamic contiguous growable list (`std/collections`)",
        ),
        (
            "Map",
            "Ordered associative key-value map (`std/collections`)",
        ),
        ("Set", "Ordered unique elements set (`std/collections`)"),
        (
            "TcpServer",
            "Non-blocking multi-connection TCP server (`std/net`)",
        ),
        (
            "TcpStream",
            "Non-blocking TCP network stream socket (`std/net`)",
        ),
        (
            "TcpListener",
            "Non-blocking TCP socket listener (`std/net`)",
        ),
        ("TcpConnection", "Managed TCP client connection (`std/net`)"),
        ("UdpSocket", "UDP datagram network socket (`std/net`)"),
        (
            "HttpRequest",
            "Structured HTTP request representation (`std/net`)",
        ),
        (
            "HttpResponse",
            "Structured HTTP response representation (`std/net`)",
        ),
        (
            "HttpRouter",
            "Deterministic HTTP path and method router (`std/net`)",
        ),
        (
            "Url",
            "Structured URL parser and representation (`std/net`)",
        ),
        (
            "JsonValue",
            "Universal deterministic JSON AST representation (`std/json`)",
        ),
        (
            "JsonParseResult",
            "JSON parse outcome and error diagnostic (`std/json`)",
        ),
        (
            "Channel",
            "Colorless fiber typed message channel (`std/sync`)",
        ),
        (
            "Mutex",
            "Colorless fiber cooperative mutual exclusion lock (`std/sync`)",
        ),
        (
            "AtomicInt",
            "Atomic 64-bit integer with CAS synchronization (`std/sync`)",
        ),
        ("AtomicFlag", "Atomic boolean flag (`std/sync`)"),
        (
            "WaitGroup",
            "Deterministic fiber barrier synchronization counter (`std/sync`)",
        ),
    ];

    for (st, detail) in stdlib_structs {
        items.push(
            CompletionItem::new(st, CompletionItemKind::Struct)
                .with_detail(format!("Standard Library Struct `{}`", st))
                .with_doc(detail),
        );
    }

    // 4. User Symbols from Semantic Analysis
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
