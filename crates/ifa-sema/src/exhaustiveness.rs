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
        Pattern::Wildcard(_) | Pattern::Ident(_, _) | Pattern::Binding { .. } => true,
        Pattern::Tuple(elems, _) => elems.iter().all(is_irrefutable_pattern),
        Pattern::Struct { fields, .. } => fields.iter().all(|f| is_irrefutable_pattern(&f.pattern)),
        Pattern::Or(pats, _) => pats.iter().any(is_irrefutable_pattern),
        Pattern::Slice {
            prefix,
            rest,
            suffix,
            ..
        } => {
            let rest_ok = rest
                .as_ref()
                .is_none_or(|r| r.as_ref().is_none_or(|p| is_irrefutable_pattern(p)));
            prefix.is_empty() && suffix.is_empty() && rest.is_some() && rest_ok
        }
        Pattern::Variant { .. } | Pattern::Lit(_, _) | Pattern::Range { .. } => false,
    }
}

/// Helper returning whether a pattern unconditionally matches any value of the target type.
pub(crate) fn is_irrefutable_pattern_for_type(pat: &Pattern, target_ty: &Type) -> bool {
    match pat {
        Pattern::Wildcard(_) | Pattern::Ident(_, _) | Pattern::Binding { .. } => true,
        Pattern::Tuple(elems, _) => match target_ty {
            Type::Tuple(expected) if expected.len() == elems.len() => elems
                .iter()
                .zip(expected.iter())
                .all(|(p, t)| is_irrefutable_pattern_for_type(p, t)),
            _ => elems.iter().all(is_irrefutable_pattern),
        },
        Pattern::Struct { fields, .. } => fields.iter().all(|f| match target_ty {
            Type::Struct {
                fields: expected_fields,
                ..
            } => {
                if let Some((_, f_ty)) = expected_fields.iter().find(|(name, _)| *name == f.name) {
                    is_irrefutable_pattern_for_type(&f.pattern, f_ty)
                } else {
                    is_irrefutable_pattern(&f.pattern)
                }
            }
            _ => is_irrefutable_pattern(&f.pattern),
        }),
        Pattern::Or(pats, _) => pats
            .iter()
            .any(|p| is_irrefutable_pattern_for_type(p, target_ty)),
        Pattern::Slice {
            prefix,
            rest,
            suffix,
            ..
        } => match target_ty {
            Type::Array(elem_ty, len) => {
                let prefix_ok = prefix
                    .iter()
                    .all(|p| is_irrefutable_pattern_for_type(p, elem_ty));
                let suffix_ok = suffix
                    .iter()
                    .all(|s| is_irrefutable_pattern_for_type(s, elem_ty));
                let rest_ok = rest.as_ref().is_none_or(|r| {
                    r.as_ref().is_none_or(|p| {
                        is_irrefutable_pattern_for_type(p, &Type::Slice(elem_ty.clone()))
                    })
                });

                let total_min = (prefix.len() + suffix.len()) as u32;
                if rest.is_none() {
                    total_min == *len && prefix_ok && suffix_ok
                } else {
                    total_min <= *len && prefix_ok && suffix_ok && rest_ok
                }
            }
            Type::Slice(elem_ty) => {
                let rest_ok = rest.as_ref().is_none_or(|r| {
                    r.as_ref().is_none_or(|p| {
                        is_irrefutable_pattern_for_type(p, &Type::Slice(elem_ty.clone()))
                    })
                });
                prefix.is_empty() && suffix.is_empty() && rest.is_some() && rest_ok
            }
            _ => false,
        },
        Pattern::Variant { .. } | Pattern::Lit(_, _) | Pattern::Range { .. } => false,
    }
}

/// Helper holding the accumulated coverage state during exhaustiveness checking.
struct CoverageState<'a> {
    target_ty: &'a Type,
    enum_variants_info: &'a Option<Vec<(Symbol, Option<Type>)>>,
    fully_covered_variants: HashSet<Symbol>,
    variant_payload_literals: HashMap<Symbol, HashSet<String>>,
    covered_literals: HashSet<String>,
    covered_true: bool,
    covered_false: bool,
}

impl<'a> CoverageState<'a> {
    fn new(
        target_ty: &'a Type,
        enum_variants_info: &'a Option<Vec<(Symbol, Option<Type>)>>,
    ) -> Self {
        Self {
            target_ty,
            enum_variants_info,
            fully_covered_variants: HashSet::new(),
            variant_payload_literals: HashMap::new(),
            covered_literals: HashSet::new(),
            covered_true: false,
            covered_false: false,
        }
    }

    /// Helper determining if a pattern is already subsumed by earlier patterns.
    fn is_pattern_subsumed(&self, pat: &Pattern) -> bool {
        match pat {
            Pattern::Wildcard(_) | Pattern::Ident(_, _) | Pattern::Binding { .. } => {
                if let Some(ref all_variants) = self.enum_variants_info {
                    all_variants
                        .iter()
                        .all(|(v, _)| self.fully_covered_variants.contains(v))
                } else if *self.target_ty == Type::Bool {
                    self.covered_true && self.covered_false
                } else {
                    false
                }
            }
            Pattern::Variant { variant, inner, .. } => {
                if self.fully_covered_variants.contains(variant) {
                    return true;
                }
                if let Some(inner_pat) = inner {
                    if let Pattern::Lit(lit, _) = inner_pat.as_ref() {
                        let lit_key = lit_to_string(lit);
                        if let Some(lits) = self.variant_payload_literals.get(variant) {
                            return lits.contains(&lit_key);
                        }
                    }
                }
                false
            }
            Pattern::Lit(Lit::Bool(b), _) => {
                (*b && self.covered_true) || (!*b && self.covered_false)
            }
            Pattern::Lit(lit, _) => {
                let key = lit_to_string(lit);
                self.covered_literals.contains(&key)
            }
            Pattern::Range {
                start,
                end,
                inclusive,
                ..
            } => {
                if let (Some(s_pat), Some(e_pat)) = (start, end) {
                    if let (Pattern::Lit(Lit::Int(s1), _), Pattern::Lit(Lit::Int(s2), _)) =
                        (s_pat.as_ref(), e_pat.as_ref())
                    {
                        if let (Ok(v1), Ok(v2)) = (
                            s1.as_str().replace('_', "").parse::<i128>(),
                            s2.as_str().replace('_', "").parse::<i128>(),
                        ) {
                            let upper = if *inclusive { v2 } else { v2 - 1 };
                            if upper >= v1 && upper - v1 <= 10_000 {
                                return (v1..=upper).all(|v| {
                                    self.covered_literals.contains(&format!("int:{}", v))
                                });
                            }
                        }
                    }
                }
                false
            }
            Pattern::Or(pats, _) => pats.iter().all(|p| self.is_pattern_subsumed(p)),
            _ => false,
        }
    }

    /// Helper accumulating pattern coverage into tracked sets.
    fn accumulate_coverage(&mut self, pat: &Pattern) {
        match pat {
            Pattern::Wildcard(_)
            | Pattern::Ident(_, _)
            | Pattern::Binding { .. }
            | Pattern::Tuple(_, _)
            | Pattern::Struct { .. }
            | Pattern::Slice { .. } => {}
            Pattern::Variant { variant, inner, .. } => match inner.as_deref() {
                None
                | Some(Pattern::Wildcard(_))
                | Some(Pattern::Ident(_, _))
                | Some(Pattern::Binding { .. }) => {
                    self.fully_covered_variants.insert(*variant);
                }
                Some(p) if is_irrefutable_pattern(p) => {
                    self.fully_covered_variants.insert(*variant);
                }
                Some(Pattern::Lit(lit, _)) => {
                    let lit_key = lit_to_string(lit);
                    self.variant_payload_literals
                        .entry(*variant)
                        .or_default()
                        .insert(lit_key);
                }
                Some(Pattern::Variant { .. })
                | Some(Pattern::Tuple(_, _))
                | Some(Pattern::Struct { .. })
                | Some(Pattern::Or(_, _))
                | Some(Pattern::Range { .. })
                | Some(Pattern::Slice { .. }) => {}
            },
            Pattern::Lit(lit, _) => {
                if *self.target_ty == Type::Bool {
                    if let Lit::Bool(b) = lit {
                        if *b {
                            self.covered_true = true;
                        } else {
                            self.covered_false = true;
                        }
                    }
                } else {
                    self.covered_literals.insert(lit_to_string(lit));
                }
            }
            Pattern::Range {
                start,
                end,
                inclusive,
                ..
            } => {
                if let (Some(s_pat), Some(e_pat)) = (start, end) {
                    if let (Pattern::Lit(Lit::Int(s1), _), Pattern::Lit(Lit::Int(s2), _)) =
                        (s_pat.as_ref(), e_pat.as_ref())
                    {
                        if let (Ok(v1), Ok(v2)) = (
                            s1.as_str().replace('_', "").parse::<i128>(),
                            s2.as_str().replace('_', "").parse::<i128>(),
                        ) {
                            let upper = if *inclusive { v2 } else { v2 - 1 };
                            if upper >= v1 && upper - v1 <= 10_000 {
                                for v in v1..=upper {
                                    self.covered_literals.insert(format!("int:{}", v));
                                }
                            }
                        }
                    }
                }
            }
            Pattern::Or(pats, _) => {
                for p in pats {
                    self.accumulate_coverage(p);
                }
            }
        }
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
    let mut state = CoverageState::new(target_ty, &enum_variants_info);

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

        if let Pattern::Or(pats, _) = &arm.pattern {
            let mut any_useful = false;
            for p in pats {
                if state.is_pattern_subsumed(p) {
                    diagnostics.push(
                        Diagnostic::error("motif inaccessible : cette alternative a déjà été couverte par une branche ou alternative précédente")
                            .with_code("E0044")
                            .with_primary_label(p.span(), "alternative inaccessible"),
                    );
                } else {
                    any_useful = true;
                }
            }
            if !any_useful {
                continue;
            }
        } else if state.is_pattern_subsumed(&arm.pattern) {
            diagnostics.push(
                Diagnostic::error("motif inaccessible : cette branche ne sera jamais atteinte car les motifs précédents couvrent déjà ces valeurs")
                    .with_code("E0044")
                    .with_primary_label(arm.span, "branche inaccessible"),
            );
            continue;
        }

        // 2. Accumulate Coverage (ONLY for unguarded arms)
        if !is_guarded {
            if is_irrefutable_pattern_for_type(&arm.pattern, target_ty) {
                has_universal_catch_all = true;
                if let Some(ref all_variants) = enum_variants_info {
                    for (v, _) in all_variants {
                        state.fully_covered_variants.insert(*v);
                    }
                }
                if *target_ty == Type::Bool {
                    state.covered_true = true;
                    state.covered_false = true;
                }
            }

            state.accumulate_coverage(&arm.pattern);
        }
    }

    // 3. Check Exhaustiveness
    if has_universal_catch_all {
        return;
    }

    if let Some(ref all_variants) = enum_variants_info {
        let missing: Vec<String> = all_variants
            .iter()
            .filter(|(v, _)| !state.fully_covered_variants.contains(v))
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
        if !state.covered_true {
            missing.push("true".to_string());
        }
        if !state.covered_false {
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
