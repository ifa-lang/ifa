use crate::document::Document;
use crate::protocol::{Hover, MarkupContent, Position};
use ifa_span::sym;

pub fn handle_hover(doc: &Document, position: Position) -> Option<Hover> {
    let (word, range) = doc.word_at_position(position)?;

    // 1. Language Keywords Hover Documentation
    let keyword_doc = match word {
        "fn" => Some("**`fn`** — Function declaration keyword in IFA."),
        "let" => Some("**`let`** — Immutable value binding. Enforces deterministic value semantics without GC overhead."),
        "mut" => Some("**`mut`** — Mutable local variable binding."),
        "inout" => Some("**`inout`** — Exclusive mutable reference parameter passing. Enforces static single-writer exclusivity without borrow-checker lifetimes."),
        "struct" => Some("**`struct`** — Declares a composite record type."),
        "enum" => Some("**`enum`** — Declares an algebraic data type (tagged union)."),
        "comptime" => Some("**`comptime`** — Executes deterministically during the compilation phase with zero runtime cost."),
        "strict" => Some("**`strict`** — Strict deterministic zero-allocation mode. Forbids implicit dynamic heap allocations."),
        "pub" => Some("**`pub`** — Visibility modifier making the item accessible outside its parent module."),
        "match" => Some("**`match`** — Pattern matching control flow with exhaustiveness verification."),
        "ref" => Some("**`ref`** — Safe 128-bit generational reference pointer (`GenRef`) guarded by GenHeader."),
        "defer" => Some("**`defer`** — Schedules an expression to be executed upon leaving the current lexical scope."),
        "catch" => Some("**`catch`** — Inline error-handling block capturing fallible expressions."),
        _ => None,
    };

    if let Some(doc_str) = keyword_doc {
        return Some(Hover {
            contents: MarkupContent::markdown(doc_str),
            range: Some(range),
        });
    }

    // 2. Fundamental Types Documentation
    let type_doc = match word {
        "int" => Some("`int`: Default signed 64-bit integer type."),
        "float" => Some("`float`: Default 64-bit IEEE 754 floating-point type."),
        "bool" => Some("`bool`: Boolean value (`true` or `false`)."),
        "string" => Some(
            "`string`: Native immutable Copy-on-Write string container with UTF-8 verification.",
        ),
        "char" => Some("`char`: 32-bit Unicode scalar character."),
        "void" => Some("`void`: Empty unit type `()`."),
        _ => None,
    };

    if let Some(doc_str) = type_doc {
        return Some(Hover {
            contents: MarkupContent::markdown(format!("```ifa\ntype {}\n```\n\n{}", word, doc_str)),
            range: Some(range),
        });
    }

    // 3. Standard Library Core Structures Documentation
    let stdlib_doc = match word {
        "RingBuffer" => Some(
            "**`RingBuffer`** — Fixed-capacity circular FIFO buffer (`std/collections`).\n\n\
             Guarantees constant-time $O(1)$ operations with zero dynamic heap allocations after initialization.\n\n\
             ```ifa\n\
             pub struct RingBuffer {\n\
                 capacity: int,\n\
                 len: int,\n\
                 head: int,\n\
                 tail: int,\n\
                 is_full: bool\n\
             }\n\
             ```",
        ),
        "BinaryHeap" => Some(
            "**`BinaryHeap`** — Deterministic priority queue binary heap (`std/collections`).\n\n\
             Supports configurable Max-Heap and Min-Heap modes with logarithmic $O(\\log N)$ insertions and root extractions.\n\n\
             ```ifa\n\
             pub struct BinaryHeap {\n\
                 len: int,\n\
                 is_max: bool\n\
             }\n\
             ```",
        ),
        "Deque" | "IntDeque" => Some(
            "**`Deque`** — Double-ended queue (`std/collections`).\n\n\
             Provides amortized $O(1)$ push/pop operations at both ends (`push_front`, `push_back`, `pop_front`, `pop_back`).\n\n\
             ```ifa\n\
             pub struct Deque {\n\
                 len: int\n\
             }\n\
             ```",
        ),
        "IntMap" => Some(
            "**`IntMap`** — High-performance 64-bit integer hash map with linear probing (`std/collections`).\n\n\
             Deterministic hashing without runtime boxing overhead.\n\n\
             ```ifa\n\
             pub struct IntMap {\n\
                 len: int\n\
             }\n\
             ```",
        ),
        "ByteBuffer" => Some(
            "**`ByteBuffer`** — Contiguous byte sequence buffer with endianness control (`std/collections`).\n\n\
             Optimized for low-level protocol encoders, network frame builders, and binary serializers.",
        ),
        "TcpServer" => Some(
            "**`TcpServer`** — Non-blocking multi-connection TCP server (`std/net`).\n\n\
             Orchestrates concurrent client streams without thread blocking, interfacable with colorless fibers reactor.\n\n\
             ```ifa\n\
             pub struct TcpServer {\n\
                 listener: TcpListener,\n\
                 clients: List<TcpStream>,\n\
                 max_clients: int,\n\
                 is_running: bool,\n\
                 total_accepted: int\n\
             }\n\
             ```",
        ),
        "TcpStream" => Some(
            "**`TcpStream`** — Non-blocking TCP network stream socket (`std/net`).\n\n\
             Supports cooperative read, write, and timeout handling over colorless fibers.",
        ),
        "TcpListener" => Some(
            "**`TcpListener`** — Non-blocking TCP socket listener (`std/net`).\n\n\
             Binds to a network port and cooperatively accepts client connections.",
        ),
        "WsServer" => Some(
            "**`WsServer`** — Multi-client WebSocket RFC 6455 server (`std/net`).\n\n\
             Multiplexes WebSocket client connections on top of non-blocking TCP sockets with automated HTTP Upgrade handshake and broadcast dispatch.",
        ),
        "WsClient" => Some(
            "**`WsClient`** — WebSocket client (RFC 6455) (`std/net`).\n\n\
             Handles client-side masking, handshake validation against `Sec-WebSocket-Accept`, and cooperative frame polling.",
        ),
        "WsSession" => Some(
            "**`WsSession`** — Active WebSocket connection session (`std/net`).\n\n\
             Maintains connection state, upgrade confirmation, and frame framing over a non-blocking stream.",
        ),
        "WsFrame" => Some(
            "**`WsFrame`** — RFC 6455 WebSocket frame representation (`std/net`).\n\n\
             Encapsulates opcode (Text, Binary, Ping, Pong, Close), masking keys, and payload data.",
        ),
        "JsonValue" => Some(
            "**`JsonValue`** — Universal deterministic JSON AST node (`std/json`).\n\n\
             Supports RFC 8785 canonical serialization, RFC 6901 pointer resolution, and deep recursive merging.\n\n\
             ```ifa\n\
             pub struct JsonValue {\n\
                 kind: int, // 0: Null, 1: Bool, 2: Number, 3: String, 4: Array, 5: Object\n\
                 bool_val: bool,\n\
                 int_val: int,\n\
                 str_val: string,\n\
                 arr_val: List<JsonValue>,\n\
                 obj_keys: List<string>,\n\
                 obj_vals: List<JsonValue>\n\
             }\n\
             ```",
        ),
        "Channel" => Some(
            "**`Channel`** — Typed fiber synchronization message channel (`std/sync`).\n\n\
             Supports bounded (backpressured) and unbounded cooperative rendezvous queues.",
        ),
        "Mutex" => Some(
            "**`Mutex`** — Colorless fiber mutual exclusion lock (`std/sync`).\n\n\
             Enforces critical section isolation without starving OS threads or consuming CPU spin cycles.",
        ),
        "AtomicInt" => Some(
            "**`AtomicInt`** — 64-bit atomic integer (`std/sync`).\n\n\
             Provides wait-free atomics including Compare-And-Swap (CAS), fetch-add, and sequential consistency.",
        ),
        _ => None,
    };

    if let Some(doc_str) = stdlib_doc {
        return Some(Hover {
            contents: MarkupContent::markdown(doc_str),
            range: Some(range),
        });
    }

    // 4. Semantic Analysis Lookup
    if let Some(analysis) = &doc.analysis {
        let symbol = sym(word);

        // Check functions
        if let Some(func) = analysis.symbols.functions.get(&symbol) {
            let params_str = func
                .params
                .iter()
                .map(|p| format!("{}: {}", p.name.resolve(), p.ty))
                .collect::<Vec<_>>()
                .join(", ");
            let mut modifiers = String::new();
            if func.is_pub {
                modifiers.push_str("pub ");
            }
            if func.is_strict {
                modifiers.push_str("strict ");
            }
            if func.is_comptime {
                modifiers.push_str("comptime ");
            }
            let sig = format!(
                "{}fn {}({}) -> {}",
                modifiers, word, params_str, func.ret_ty
            );
            return Some(Hover {
                contents: MarkupContent::markdown(format!("```ifa\n{}\n```", sig)),
                range: Some(range),
            });
        }

        // Check structs
        if let Some(str_sym) = analysis.symbols.structs.get(&symbol) {
            let mut fields_str = String::new();
            for field in &str_sym.fields {
                let f_name = field.name.resolve();
                fields_str.push_str(&format!("    {}: {},\n", f_name, field.ty));
            }
            let pub_prefix = if str_sym.is_pub { "pub " } else { "" };
            let body = format!("{}struct {} {{\n{}}}", pub_prefix, word, fields_str);
            return Some(Hover {
                contents: MarkupContent::markdown(format!("```ifa\n{}\n```", body)),
                range: Some(range),
            });
        }

        // Check enums
        if let Some(enum_sym) = analysis.symbols.enums.get(&symbol) {
            let mut variants_str = String::new();
            for (v_name, v_ty) in &enum_sym.variants {
                let v_str = v_name.resolve();
                if let Some(ty) = v_ty {
                    variants_str.push_str(&format!("    {}({}),\n", v_str, ty));
                } else {
                    variants_str.push_str(&format!("    {},\n", v_str));
                }
            }
            let pub_prefix = if enum_sym.is_pub { "pub " } else { "" };
            let body = format!("{}enum {} {{\n{}}}", pub_prefix, word, variants_str);
            return Some(Hover {
                contents: MarkupContent::markdown(format!("```ifa\n{}\n```", body)),
                range: Some(range),
            });
        }

        // Check variables in scopes
        for scope in &analysis.symbols.scopes {
            if let Some(var) = scope.variables.get(&symbol) {
                let binding = if var.is_mut { "mut" } else { "let" };
                let mut content = format!("```ifa\n{} {}: {}\n```", binding, word, var.ty);

                // Check for disjoint borrow details
                let offset = doc.position_to_offset(position);
                if let Some(enhanced) = &doc.enhanced {
                    if let Some(borrow) = enhanced.find_disjoint_borrow_at(offset) {
                        content.push_str(&format!(
                            "\n\n---\n### Exclusivité d'Accès Sensible au Chemin (IFA E0011)\n- **Chemin analysé** : `{}`\n- **Statut** : Emprunt mutable simultané garanti disjoint\n- **Chemins frères sans conflit** : `{}`\n- **Garantie** : Single-writer exclusif, zéro aliasing mutable illégal vérifié statiquement.",
                            borrow.path_display,
                            borrow.sibling_paths.join(", ")
                        ));
                    }
                    if let Some(barrier) = enhanced.find_gen_barrier_at(offset) {
                        let status_str = if barrier.eliminated {
                            "Éliminée statiquement (0 cycle CPU à l'exécution)"
                        } else {
                            "Contrôle dynamique actif (1 cycle CPU, comparaison génération)"
                        };
                        content.push_str(&format!(
                            "\n\n---\n### Sécurité Générationnelle (GenRef 128-bit)\n- **Barrière d'accès** : {}\n- **Optimisation** : Dominance lexicale & LICM (élimination statique >90%).",
                            status_str
                        ));
                    }
                }

                return Some(Hover {
                    contents: MarkupContent::markdown(content),
                    range: Some(range),
                });
            }
        }

        // Check struct fields
        for str_sym in analysis.symbols.structs.values() {
            if let Some(field) = str_sym.get_field(&symbol) {
                let struct_name = str_sym.name.resolve();
                let mut content = format!(
                    "```ifa\n(field) {}.{}: {}\n```",
                    struct_name, word, field.ty
                );

                let offset = doc.position_to_offset(position);
                if let Some(enhanced) = &doc.enhanced {
                    if let Some(borrow) = enhanced.find_disjoint_borrow_at(offset) {
                        content.push_str(&format!(
                            "\n\n---\n### Exclusivité d'Accès Sensible au Chemin (IFA E0011)\n- **Chemin analysé** : `{}`\n- **Statut** : Emprunt mutable simultané garanti disjoint\n- **Chemins frères sans conflit** : `{}`\n- **Garantie** : Single-writer exclusif, zéro aliasing mutable illégal.",
                            borrow.path_display,
                            borrow.sibling_paths.join(", ")
                        ));
                    }
                }

                return Some(Hover {
                    contents: MarkupContent::markdown(content),
                    range: Some(range),
                });
            }
        }
    }

    // Check if position directly points to a disjoint borrow or gen barrier even outside word lookup
    let offset = doc.position_to_offset(position);
    if let Some(enhanced) = &doc.enhanced {
        if let Some(borrow) = enhanced.find_disjoint_borrow_at(offset) {
            let doc_str = format!(
                "### Exclusivité d'Accès Sensible au Chemin (IFA E0011)\n- **Chemin analysé** : `{}`\n- **Statut** : Emprunt mutable simultané garanti disjoint\n- **Chemins frères sans conflit** : `{}`\n- **Garantie** : Single-writer exclusif, zéro aliasing mutable illégal.",
                borrow.path_display,
                borrow.sibling_paths.join(", ")
            );
            return Some(Hover {
                contents: MarkupContent::markdown(doc_str),
                range: Some(range),
            });
        }
        if let Some(barrier) = enhanced.find_gen_barrier_at(offset) {
            let status_str = if barrier.eliminated {
                "Éliminée statiquement (0 cycle CPU à l'exécution)"
            } else {
                "Contrôle dynamique actif (1 cycle CPU, comparaison génération)"
            };
            let doc_str = format!(
                "### Sécurité Générationnelle (GenRef 128-bit)\n- **Barrière d'accès** : {}\n- **Optimisation** : Dominance lexicale & LICM (élimination statique >90%).",
                status_str
            );
            return Some(Hover {
                contents: MarkupContent::markdown(doc_str),
                range: Some(range),
            });
        }
    }

    None
}
