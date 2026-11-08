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

    // 3. Semantic Analysis Lookup
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
