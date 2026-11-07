use crate::symbol_table::SymbolTable;
use ifa_ast::{Arg, Expr, ExprKind, ParamMode, UnaryOp};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};

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

/// A segment in a structured memory access path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSegment {
    Field(Symbol),
    IndexConst(i64),
    IndexUnknown,
}

/// A path-sensitive access descriptor representing variable or field projections (e.g. `node.lhs.rhs` or `p.a`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPath {
    pub root: Symbol,
    pub segments: Vec<PathSegment>,
    pub display: String,
}

impl AccessPath {
    /// Determines whether two access paths overlap (alias).
    /// If both paths refer to the same root, and their prefix of field/index segments match
    /// without proven disjointness, they overlap.
    pub fn overlaps(&self, other: &AccessPath) -> bool {
        if self.root != other.root {
            return false;
        }
        let min_len = self.segments.len().min(other.segments.len());
        for i in 0..min_len {
            match (&self.segments[i], &other.segments[i]) {
                (PathSegment::Field(f1), PathSegment::Field(f2)) => {
                    if f1 != f2 {
                        return false; // distinct fields at the same depth are provably disjoint
                    }
                }
                (PathSegment::IndexConst(c1), PathSegment::IndexConst(c2)) => {
                    if c1 != c2 {
                        return false; // distinct constant indices are provably disjoint
                    }
                }
                _ => {
                    // Unknown index or matching segment -> potentially overlapping
                }
            }
        }
        true
    }
}

/// Extracts a path-sensitive access descriptor from an lvalue expression.
pub fn extract_access_path(expr: &Expr) -> Option<AccessPath> {
    match &expr.kind {
        ExprKind::Ident(sym) => {
            let name = INTERNER.resolve(sym).to_string();
            Some(AccessPath {
                root: *sym,
                segments: Vec::new(),
                display: name,
            })
        }
        ExprKind::FieldAccess { receiver, field, .. } => {
            let mut parent = extract_access_path(receiver)?;
            let field_name = INTERNER.resolve(field);
            parent.display.push('.');
            parent.display.push_str(&field_name);
            parent.segments.push(PathSegment::Field(*field));
            Some(parent)
        }
        ExprKind::Index { receiver, index } => {
            let mut parent = extract_access_path(receiver)?;
            match &index.kind {
                ExprKind::Lit(ifa_ast::Lit::Int(sym)) => {
                    let s = INTERNER.resolve(sym);
                    parent.display.push_str(&format!("[{}]", s));
                    let val: i64 = s.parse().unwrap_or(0);
                    parent.segments.push(PathSegment::IndexConst(val));
                }
                _ => {
                    parent.display.push_str("[*]");
                    parent.segments.push(PathSegment::IndexUnknown);
                }
            }
            Some(parent)
        }
        ExprKind::Unary {
            op: UnaryOp::InOut | UnaryOp::Sink,
            expr: inner,
        } => extract_access_path(inner),
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
    pub path: AccessPath,
    pub kind: BorrowKind,
    pub span: Span,
}

/// Verifies the Law of Exclusivity across arguments of a function or method call.
/// In IFA: "une même variable racine ne peut jamais être passée deux fois en inout
/// (ou en inout et in simultanément) dans le même appel de fonction."
/// Path-sensitive analysis permits concurrent inout borrows on provably disjoint fields
/// (e.g. `p.a` and `p.b`), while statically rejecting overlapping paths (e.g. `node.lhs` and `node.lhs.rhs`).
pub fn check_call_exclusivity(
    args: &[Arg],
    param_modes: &[ParamMode],
    symbols: &SymbolTable,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut borrows: Vec<BorrowRecord> = Vec::new();

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

        if let Some(path) = extract_access_path(&arg.value) {
            let root_sym = path.root;
            let var_name = INTERNER.resolve(&root_sym);

            if is_sink {
                // 1. Verify variable exists
                let _ = symbols.lookup_variable(&root_sym);

                // 2. Exclusivity check against previous borrows in this call
                if let Some(existing) = borrows.iter().find(|b| b.path.overlaps(&path)) {
                    match existing.kind {
                        BorrowKind::Sink => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' est transférée ('sink') plusieurs fois dans le même appel",
                                    path.display
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
                                    path.display, other_mode
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
                    borrows.push(
                        BorrowRecord {
                            path,
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
                if let Some(existing) = borrows.iter().find(|b| b.path.overlaps(&path)) {
                    match existing.kind {
                        BorrowKind::Sink => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être mutée ('inout') car elle est déjà transférée ('sink')",
                                    path.display
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
                            let msg = if path.display == existing.path.display {
                                format!(
                                    "loi d'exclusivité violée : la variable '{}' est empruntée plusieurs fois en 'inout' dans le même appel",
                                    path.display
                                )
                            } else {
                                format!(
                                    "loi d'exclusivité violée : l'emprunt 'inout' sur '{}' chevauche l'emprunt 'inout' sur '{}'",
                                    path.display, existing.path.display
                                )
                            };
                            diagnostics.push(
                                Diagnostic::error(msg)
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
                                    path.display
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
                    borrows.push(
                        BorrowRecord {
                            path,
                            kind: BorrowKind::InOut,
                            span: arg.value.span,
                        },
                    );
                }
            } else {
                // Read-only borrow ('in')
                if let Some(existing) = borrows.iter().find(|b| b.path.overlaps(&path) && b.kind != BorrowKind::In) {
                    match existing.kind {
                        BorrowKind::Sink => {
                            diagnostics.push(
                                Diagnostic::error(format!(
                                    "loi d'exclusivité violée : la variable '{}' ne peut pas être passée en lecture ('in') lorsqu'elle est déjà transférée ('sink')",
                                    path.display
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
                                    path.display
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
                    borrows.push(
                        BorrowRecord {
                            path,
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
