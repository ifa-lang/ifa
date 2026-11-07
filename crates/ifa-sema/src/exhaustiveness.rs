use crate::symbol_table::SymbolTable;
use crate::types::Type;
use ifa_ast::{Lit, MatchArm, Pattern};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

/// Helper to serialize a literal for uniqueness checks.
fn lit_to_string(lit: &Lit) -> String {
    match lit {
        Lit::Int(s) => format!("int:{}", s.as_str()),
        Lit::Float(s) => format!("float:{}", s.as_str()),
        Lit::Bool(b) => format!("bool:{}", b),
        Lit::Char(c) => format!("char:{}", c),
        Lit::String(s) => format!("str:{}", INTERNER.resolve(s)),
        Lit::Null => "null".to_string(),
    }
}

/// Helper to format a list of missing items into a readable comma-separated string.
fn format_missing_list(items: &[String]) -> String {
    items
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Helper returning whether a pattern unconditionally matches any value of its type.
fn is_irrefutable_pattern(pat: &Pattern) -> bool {
    match pat {
        Pattern::Wildcard(_) | Pattern::Ident(_, _) => true,
        Pattern::Tuple(elems, _) => elems.iter().all(is_irrefutable_pattern),
        Pattern::Struct { fields, .. } => fields.iter().all(|f| is_irrefutable_pattern(&f.pattern)),
        Pattern::Variant { .. } | Pattern::Lit(_, _) => false,
    }
}

/// Checks pattern exhaustiveness and dead arm / unreachable pattern usefulness in a `match` expression.
///
/// Emits:
/// - `E0043`: Non-exhaustive pattern matching (missing variants or catch-all branch).
/// - `E0044`: Unreachable pattern / dead branch (subsumed by previous unguarded branches).
pub fn check_match_exhaustiveness(
    symbols: &SymbolTable,
    arms: &[MatchArm],
    target_ty: &Type,
    match_span: Span,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if arms.is_empty() || *target_ty == Type::Unknown {
        return;
    }

    // Resolve enum variants if the target type is an enum
    let enum_variants_info: Option<Vec<(Symbol, Option<Type>)>> = match target_ty {
        Type::Enum { variants, .. } => Some(variants.clone()),
        Type::Generic { name, .. } => symbols.lookup_enum(name).map(|en| en.variants.clone()),
        _ => None,
    };

    let mut has_universal_catch_all = false;

    // Type-specific coverage tracking
    let mut fully_covered_variants: HashSet<Symbol> = HashSet::new();
    let mut variant_payload_literals: HashMap<Symbol, HashSet<String>> = HashMap::new();

    let mut covered_true = false;
    let mut covered_false = false;

    let mut covered_literals: HashSet<String> = HashSet::new();

    for arm in arms {
        let is_guarded = arm.guard.is_some();

        // 1. Check Usefulness (Unreachable / Dead Arm detection)
        if has_universal_catch_all {
            diagnostics.push(
                Diagnostic::error("motif inaccessible : cette branche ne sera jamais atteinte car un motif universel précédent couvre toutes les valeurs")
                    .with_code("E0044")
                    .with_primary_label(arm.span, "branche inaccessible"),
            );
            continue;
        }

        if let Some(ref all_variants) = enum_variants_info {
            match &arm.pattern {
                Pattern::Wildcard(_) | Pattern::Ident(_, _) => {
                    let all_covered = all_variants
                        .iter()
                        .all(|(v, _)| fully_covered_variants.contains(v));
                    if all_covered {
                        diagnostics.push(
                            Diagnostic::error("motif inaccessible : tous les variants de l'énumération ont déjà été couverts")
                                .with_code("E0044")
                                .with_primary_label(arm.span, "branche inaccessible"),
                        );
                        continue;
                    }
                }
                Pattern::Variant {
                    variant,
                    inner,
                    span,
                    ..
                } => {
                    if fully_covered_variants.contains(variant) {
                        diagnostics.push(
                            Diagnostic::error(format!(
                                "motif inaccessible : le variant '{}' a déjà été intégralement couvert par une branche précédente",
                                INTERNER.resolve(variant)
                            ))
                            .with_code("E0044")
                            .with_primary_label(*span, "branche inaccessible"),
                        );
                        continue;
                    }

                    if let Some(inner_pat) = inner {
                        if let Pattern::Lit(lit, lit_span) = inner_pat.as_ref() {
                            let lit_key = lit_to_string(lit);
                            if let Some(lits) = variant_payload_literals.get(variant) {
                                if lits.contains(&lit_key) {
                                    diagnostics.push(
                                        Diagnostic::error(format!(
                                            "motif inaccessible : la valeur pour le variant '{}' a déjà été couverte",
                                            INTERNER.resolve(variant)
                                        ))
                                        .with_code("E0044")
                                        .with_primary_label(*lit_span, "valeur déjà filtrée"),
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        } else if *target_ty == Type::Bool {
            match &arm.pattern {
                Pattern::Lit(Lit::Bool(b), b_span)
                    if (*b && covered_true) || (!*b && covered_false) =>
                {
                    diagnostics.push(
                        Diagnostic::error(format!(
                            "motif inaccessible : la valeur '{}' a déjà été couverte",
                            b
                        ))
                        .with_code("E0044")
                        .with_primary_label(*b_span, "valeur booléenne déjà filtrée"),
                    );
                    continue;
                }
                Pattern::Wildcard(_) | Pattern::Ident(_, _) if covered_true && covered_false => {
                    diagnostics.push(
                        Diagnostic::error("motif inaccessible : toutes les valeurs possibles ('true', 'false') ont déjà été couvertes")
                            .with_code("E0044")
                            .with_primary_label(arm.span, "branche inaccessible"),
                    );
                    continue;
                }
                _ => {}
            }
        } else {
            // Numeric, string, or open scalar types
            if let Pattern::Lit(lit, lit_span) = &arm.pattern {
                let key = lit_to_string(lit);
                if covered_literals.contains(&key) {
                    diagnostics.push(
                        Diagnostic::error(
                            "motif inaccessible : cette valeur a déjà été couverte par une branche précédente",
                        )
                        .with_code("E0044")
                        .with_primary_label(*lit_span, "valeur déjà filtrée"),
                    );
                    continue;
                }
            }
        }

        // 2. Accumulate Coverage (ONLY for unguarded arms)
        if !is_guarded {
            if is_irrefutable_pattern(&arm.pattern) {
                has_universal_catch_all = true;
                if let Some(ref all_variants) = enum_variants_info {
                    for (v, _) in all_variants {
                        fully_covered_variants.insert(*v);
                    }
                }
                if *target_ty == Type::Bool {
                    covered_true = true;
                    covered_false = true;
                }
            }

            match &arm.pattern {
                Pattern::Wildcard(_)
                | Pattern::Ident(_, _)
                | Pattern::Tuple(_, _)
                | Pattern::Struct { .. } => {}
                Pattern::Variant { variant, inner, .. } => {
                    match inner.as_deref() {
                        None | Some(Pattern::Wildcard(_)) | Some(Pattern::Ident(_, _)) => {
                            fully_covered_variants.insert(*variant);
                        }
                        Some(p) if is_irrefutable_pattern(p) => {
                            fully_covered_variants.insert(*variant);
                        }
                        Some(Pattern::Lit(lit, _)) => {
                            let lit_key = lit_to_string(lit);
                            variant_payload_literals
                                .entry(*variant)
                                .or_default()
                                .insert(lit_key);
                        }
                        Some(Pattern::Variant { .. })
                        | Some(Pattern::Tuple(_, _))
                        | Some(Pattern::Struct { .. }) => {
                            // Sub-pattern does not fully cover unless irrefutable
                        }
                    }
                }
                Pattern::Lit(lit, _) => {
                    if *target_ty == Type::Bool {
                        if let Lit::Bool(b) = lit {
                            if *b {
                                covered_true = true;
                            } else {
                                covered_false = true;
                            }
                        }
                    } else {
                        covered_literals.insert(lit_to_string(lit));
                    }
                }
            }
        }
    }

    // 3. Check Exhaustiveness
    if has_universal_catch_all {
        return;
    }

    if let Some(ref all_variants) = enum_variants_info {
        let missing: Vec<String> = all_variants
            .iter()
            .filter(|(v, _)| !fully_covered_variants.contains(v))
            .map(|(v, _)| INTERNER.resolve(v).to_string())
            .collect();

        if !missing.is_empty() {
            diagnostics.push(
                Diagnostic::error(format!(
                    "le filtrage par motif n'est pas exhaustif : variants non couverts : {}",
                    format_missing_list(&missing)
                ))
                .with_code("E0043")
                .with_primary_label(match_span, "motif non exhaustif"),
            );
        }
    } else if *target_ty == Type::Bool {
        let mut missing = Vec::new();
        if !covered_true {
            missing.push("true".to_string());
        }
        if !covered_false {
            missing.push("false".to_string());
        }
        if !missing.is_empty() {
            let label = if missing.len() == 1 {
                format!(
                    "le filtrage par motif n'est pas exhaustif : cas non couvert : '{}'",
                    missing[0]
                )
            } else {
                format!(
                    "le filtrage par motif n'est pas exhaustif : cas non couverts : {}",
                    format_missing_list(&missing)
                )
            };
            diagnostics.push(
                Diagnostic::error(label)
                    .with_code("E0043")
                    .with_primary_label(match_span, "motif non exhaustif"),
            );
        }
    } else {
        // Scalar types (int, float, string, char, etc.) and aggregates without universal catch-all
        diagnostics.push(
            Diagnostic::error(format!(
                "le filtrage par motif n'est pas exhaustif : un motif universel ou une variable de repli '_' est requis pour le type '{}'",
                target_ty
            ))
            .with_code("E0043")
            .with_primary_label(match_span, "motif non exhaustif"),
        );
    }
}
