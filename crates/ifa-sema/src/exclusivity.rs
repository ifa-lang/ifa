use crate::symbol_table::SymbolTable;
use ifa_ast::{Arg, Expr, ExprKind, ParamMode, UnaryOp};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::HashMap;

/// Identifies the root variable of an lvalue expression.
/// For example, `x.y.z` or `x[0]` has root variable `x`.
pub fn extract_root_variable(expr: &Expr) -> Option<(Symbol, Span)> {
    match &expr.kind {
        ExprKind::Ident(sym) => Some((*sym, expr.span)),
        ExprKind::FieldAccess { receiver, .. } => extract_root_variable(receiver),
        ExprKind::Index { receiver, .. } => extract_root_variable(receiver),
        ExprKind::Unary {
            op: UnaryOp::InOut | UnaryOp::Sink,
            expr: inner,
        } => extract_root_variable(inner),
        _ => None,
    }
}

/// Checks whether an expression is a valid lvalue suitable for `inout` or `sink` mutation/move.
pub fn is_lvalue(expr: &Expr) -> bool {
    matches!(
        &expr.kind,
        ExprKind::Ident(_)
            | ExprKind::FieldAccess { .. }
            | ExprKind::Index { .. }
            | ExprKind::Unary {
                op: UnaryOp::InOut | UnaryOp::Sink,
                ..
            }
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorrowKind {
    In,
    InOut,
    Sink,
}

#[derive(Debug, Clone)]
pub struct BorrowRecord {
    pub var: Symbol,
    pub kind: BorrowKind,
    pub span: Span,
}

/// Verifies the Law of Exclusivity across arguments of a function or method call.
/// In IFA: "une même variable racine ne peut jamais être passée deux fois en inout
/// (ou en inout et in simultanément) dans le même appel de fonction."
/// De même, le transfert 'sink' exige l'exclusivité totale et ne peut coexister avec
/// aucun autre passage de la même variable racine dans le même appel.
pub fn check_call_exclusivity(
    args: &[Arg],
    param_modes: &[ParamMode],
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut borrows: HashMap<Symbol, BorrowRecord> = HashMap::new();

    for (idx, arg) in args.iter().enumerate() {
        let is_explicit_inout = matches!(
            &arg.value.kind,
            ExprKind::Unary {
                op: UnaryOp::InOut,
                ..
            }
        );
        let is_explicit_sink = matches!(
            &arg.value.kind,
            ExprKind::Unary {
                op: UnaryOp::Sink,
                ..
            }
        );

        let param_mode = param_modes.get(idx).copied().unwrap_or(ParamMode::In);
        let is_sink = is_explicit_sink || param_mode == ParamMode::Sink;
        let is_inout = is_explicit_inout || param_mode == ParamMode::InOut;

        if let Some((root_sym, _root_span)) = extract_root_variable(&arg.value) {
            let var_name = INTERNER.resolve(&root_sym);

            if is_sink {
                // 1. Verify variable exists
                let _ = symbols.lookup_variable(&root_sym);

                // 2. Exclusivity check against previous borrows in this call
                if let Some(existing) = borrows.get(&root_sym) {
                    match existing.kind {
                        BorrowKind::Sink => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' est transférée ('sink') plusieurs fois dans le même appel",
                                    var_name
                                ))
                                .with_code("E0016")
                                .with_primary_label(
                                    arg.value.span,
                                    "second transfert de propriété ('sink') interdit",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "premier transfert 'sink' ici",
                                )
                                .with_help("Une variable ne peut être déplacée/transférée qu'une seule fois."),
                            );
                        }
                        BorrowKind::InOut | BorrowKind::In => {
                            let other_mode = if existing.kind == BorrowKind::InOut {
                                "inout"
                            } else {
                                "in"
                            };
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être simultanément transférée ('sink') et passée en '{}'",
                                    var_name, other_mode
                                ))
                                .with_code("E0017")
                                .with_primary_label(
                                    arg.value.span,
                                    format!("conflit : transfert 'sink' sur une variable passée en '{}'", other_mode),
                                )
                                .with_secondary_label(
                                    existing.span,
                                    format!("passage en '{}' ici", other_mode),
                                ),
                            );
                        }
                    }
                } else {
                    borrows.insert(
                        root_sym,
                        BorrowRecord {
                            var: root_sym,
                            kind: BorrowKind::Sink,
                            span: arg.value.span,
                        },
                    );
                }
            } else if is_inout {
                // 1. Verify variable exists and is mutable
                if let Some(var) = symbols.lookup_variable(&root_sym) {
                    if !var.is_mut {
                        diagnostics.push(
                            Diagnostic::error(format!(
                                "impossible de passer la variable immuable '{}' en paramètre 'inout'",
                                var_name
                            ))
                            .with_code("E0010")
                            .with_primary_label(
                                arg.value.span,
                                format!("mutation exclusive 'inout' interdite sur '{}'", var_name),
                            )
                            .with_secondary_label(
                                var.span,
                                format!(
                                    "la variable '{}' a été déclarée immuable avec 'let' (utilisez 'mut')",
                                    var_name
                                ),
                            )
                            .with_help("Changez la déclaration en 'mut' pour autoriser la modification sur place."),
                        );
                    }
                }

                // 2. Exclusivity check against previous borrows in this call
                if let Some(existing) = borrows.get(&root_sym) {
                    match existing.kind {
                        BorrowKind::Sink => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être mutée ('inout') car elle est déjà transférée ('sink')",
                                    var_name
                                ))
                                .with_code("E0017")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : emprunt exclusif 'inout' sur une variable déjà transférée",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "transfert exclusif ('sink') ici",
                                ),
                            );
                        }
                        BorrowKind::InOut => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' est empruntée plusieurs fois en 'inout' dans le même appel",
                                    var_name
                                ))
                                .with_code("E0011")
                                .with_primary_label(
                                    arg.value.span,
                                    "second emprunt mutable exclusif ('inout') interdit",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "premier emprunt 'inout' ici",
                                )
                                .with_help("Une variable ne peut avoir qu'un seul accès 'inout' exclusif à la fois."),
                            );
                        }
                        BorrowKind::In => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être passée simultanément en lecture ('in') et en écriture ('inout')",
                                    var_name
                                ))
                                .with_code("E0012")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : emprunt exclusif 'inout' sur une variable déjà lue",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "emprunt en lecture ('in') ici",
                                ),
                            );
                        }
                    }
                } else {
                    borrows.insert(
                        root_sym,
                        BorrowRecord {
                            var: root_sym,
                            kind: BorrowKind::InOut,
                            span: arg.value.span,
                        },
                    );
                }
            } else {
                // Read-only borrow ('in')
                if let Some(existing) = borrows.get(&root_sym) {
                    match existing.kind {
                        BorrowKind::Sink => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être passée en lecture ('in') lorsqu'elle est déjà transférée ('sink')",
                                    var_name
                                ))
                                .with_code("E0017")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : lecture ('in') sur une variable déjà transférée ('sink')",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "transfert exclusif ('sink') ici",
                                ),
                            );
                        }
                        BorrowKind::InOut => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être passée en lecture ('in') lorsqu'elle est déjà empruntée en 'inout'",
                                    var_name
                                ))
                                .with_code("E0012")
                                .with_primary_label(
                                    arg.value.span,
                                    "conflit : lecture ('in') sur une variable déjà empruntée en écriture",
                                )
                                .with_secondary_label(
                                    existing.span,
                                    "emprunt exclusif ('inout') ici",
                                ),
                            );
                        }
                        BorrowKind::In => {}
                    }
                } else {
                    borrows.insert(
                        root_sym,
                        BorrowRecord {
                            var: root_sym,
                            kind: BorrowKind::In,
                            span: arg.value.span,
                        },
                    );
                }
            }
        } else if is_inout || is_sink {
            // Passing a literal or complex non-lvalue expression to inout or sink
            let kw = if is_inout { "inout" } else { "sink" };
            diagnostics.push(
                Diagnostic::error(format!(
                    "l'argument '{}' doit être une variable ou un champ modifiable (lvalue)",
                    kw
                ))
                .with_code("E0013")
                .with_primary_label(
                    arg.value.span,
                    "cette expression n'est pas modifiable ou transférable sur place",
                )
                .with_help("Passez une variable existante au lieu d'une valeur temporaire."),
            );
        }
    }
}

/// Checks that an assignment target is mutable and assignable.
pub fn check_assignment_target(
    target: &Expr,
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some((root_sym, _)) = extract_root_variable(target) {
        let var_name = INTERNER.resolve(&root_sym);
        if let Some(var) = symbols.lookup_variable(&root_sym) {
            if !var.is_mut && var.is_initialized {
                diagnostics.push(
                    Diagnostic::error(format!(
                        "impossible d'assigner à la variable immuable '{}'",
                        var_name
                    ))
                    .with_code("E0014")
                    .with_primary_label(
                        target.span,
                        format!("tentative de réassignation de '{}'", var_name),
                    )
                    .with_secondary_label(
                        var.span,
                        format!(
                            "variable '{}' déclarée immuable avec 'let' (utilisez 'mut')",
                            var_name
                        ),
                    )
                    .with_help("Déclarez la variable avec 'mut' si vous devez la réassigner."),
                );
            }
        }
    } else {
        diagnostics.push(
            Diagnostic::error(
                "cible d'assignation invalide (doit être une variable mutable ou un champ)",
            )
            .with_code("E0015")
            .with_primary_label(target.span, "cette expression n'est pas assignable"),
        );
    }
}
