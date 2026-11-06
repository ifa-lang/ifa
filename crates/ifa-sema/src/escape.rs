use crate::exclusivity::extract_root_variable;
use crate::symbol_table::SymbolTable;
use ifa_ast::{Expr, ExprKind, Function, Stmt, UnaryOp};
use ifa_diagnostics::Diagnostic;
use ifa_span::{Span, Symbol, INTERNER};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocKind {
    Stack,
    HeapGenerational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeStatus {
    Local,
    EscapesFunction,
}

#[derive(Debug, Clone)]
pub struct VarEscapeInfo {
    pub var: Symbol,
    pub alloc_kind: AllocKind,
    pub escape_status: EscapeStatus,
    pub defined_span: Span,
}

pub struct EscapeAnalyzer<'a> {
    pub symbols: &'a SymbolTable,
    pub current_func_is_strict: bool,
    pub current_func_span: Span,
    pub var_info: HashMap<Symbol, VarEscapeInfo>,
    pub ref_dependencies: HashMap<Symbol, Vec<Symbol>>,
    pub spawn_depth: usize,
    pub diagnostics: Vec<Diagnostic>,
}

impl<'a> EscapeAnalyzer<'a> {
    pub fn new(symbols: &'a SymbolTable, is_strict: bool, func_span: Span) -> Self {
        Self {
            symbols,
            current_func_is_strict: is_strict,
            current_func_span: func_span,
            var_info: HashMap::new(),
            ref_dependencies: HashMap::new(),
            spawn_depth: 0,
            diagnostics: Vec::new(),
        }
    }

    pub fn record_local_var(&mut self, var: Symbol, span: Span) {
        self.var_info.insert(
            var,
            VarEscapeInfo {
                var,
                alloc_kind: AllocKind::Stack,
                escape_status: EscapeStatus::Local,
                defined_span: span,
            },
        );
    }

    pub fn check_function(&mut self, func: &Function) {
        if let Some(body) = &func.body {
            for stmt in &body.stmts {
                self.check_stmt(stmt);
            }
            if let Some(ret_expr) = &body.expr {
                self.check_return_expr(ret_expr);
            }
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let {
                name, init, span, ..
            } => {
                self.record_local_var(*name, *span);
                if let Some(expr) = init {
                    self.check_expr(expr);
                }
            }
            Stmt::Assign {
                target, val, span, ..
            } => {
                // Static detection of concurrent data race in spawn
                if self.spawn_depth > 0 {
                    if let Some((root_sym, root_span)) = extract_root_variable(target) {
                        if self.var_info.contains_key(&root_sym) {
                            let var_name = INTERNER.resolve(&root_sym);
                            self.diagnostics.push(
                                Diagnostic::error(format!(
                                    "mutation concurrente interdite : la variable locale '{}' ne peut pas être modifiée au sein d'une fibre 'spawn' sans synchronisation atomique",
                                    var_name
                                ))
                                .with_code("E0025")
                                .with_primary_label(
                                    *span,
                                    format!("mutation concurrente de '{}' dans spawn", var_name),
                                )
                                .with_secondary_label(
                                    root_span,
                                    format!("'{}' appartient au cadre de pile parent", var_name),
                                )
                                .with_note("Les fibres partagent la mémoire de manière non-bloquante et interdisent les courses aux données statiques.")
                                .with_help("Utilisez un canal 'Channel', un type atomique ou transférez la variable avec 'sink'."),
                            );
                        }
                    }
                }

                self.check_expr(target);
                self.check_expr(val);

                // Check if assigning a ref to a struct field (e.g. child.parent = ref parent)
                if let ExprKind::FieldAccess { receiver, .. } = &target.kind {
                    if let ExprKind::Unary {
                        op: UnaryOp::Ref,
                        expr: ref_target,
                    } = &val.kind
                    {
                        self.handle_ref_assignment(receiver, ref_target, val.span);
                    }
                }
            }
            Stmt::Expr(expr) => self.check_expr(expr),
            Stmt::Return(ret_expr, _) => {
                if let Some(expr) = ret_expr {
                    self.check_return_expr(expr);
                }
            }
            Stmt::Fail(expr, _) => self.check_expr(expr),
            Stmt::While { cond, body, .. } => {
                self.check_expr(cond);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            Stmt::For { iterable, body, .. } => {
                self.check_expr(iterable);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            Stmt::Loop(body, _) => {
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            Stmt::Defer(body, _) => {
                for s in &body.stmts {
                    self.check_stmt(s);
                }
            }
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }

    fn check_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Unary {
                op: UnaryOp::Ref,
                expr: inner,
            } => {
                self.handle_ref_creation(inner, expr.span);
            }
            ExprKind::Call { callee, args } => {
                self.check_expr(callee);
                for arg in args {
                    // Check for invalid inout passing into concurrent spawn
                    if self.spawn_depth > 0 {
                        if let ExprKind::Unary {
                            op: UnaryOp::InOut,
                            expr: inner,
                        } = &arg.value.kind
                        {
                            if let Some((root_sym, root_span)) = extract_root_variable(inner) {
                                if self.var_info.contains_key(&root_sym) {
                                    let var_name = INTERNER.resolve(&root_sym);
                                    self.diagnostics.push(
                                        Diagnostic::error(format!(
                                            "mutation concurrente interdite : l'argument 'inout {}' crée un accès mutable concurrent au sein d'une fibre 'spawn'",
                                            var_name
                                        ))
                                        .with_code("E0025")
                                        .with_primary_label(
                                            arg.value.span,
                                            "passage inout interdit dans une fibre concurrente",
                                        )
                                        .with_secondary_label(
                                            root_span,
                                            format!("'{}' appartient au thread parent", var_name),
                                        )
                                        .with_help("Transférez la propriété avec 'sink' ou envoyez un message via un canal."),
                                    );
                                }
                            }
                        }
                    }
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::MethodCall { receiver, args, .. } => {
                self.check_expr(receiver);
                for arg in args {
                    if self.spawn_depth > 0 {
                        if let ExprKind::Unary {
                            op: UnaryOp::InOut,
                            expr: inner,
                        } = &arg.value.kind
                        {
                            if let Some((root_sym, root_span)) = extract_root_variable(inner) {
                                if self.var_info.contains_key(&root_sym) {
                                    let var_name = INTERNER.resolve(&root_sym);
                                    self.diagnostics.push(
                                        Diagnostic::error(format!(
                                            "mutation concurrente interdite : l'argument 'inout {}' crée un accès mutable concurrent au sein d'une fibre 'spawn'",
                                            var_name
                                        ))
                                        .with_code("E0025")
                                        .with_primary_label(
                                            arg.value.span,
                                            "passage inout interdit dans une fibre concurrente",
                                        )
                                        .with_secondary_label(
                                            root_span,
                                            format!("'{}' appartient au thread parent", var_name),
                                        )
                                        .with_help("Transférez la propriété avec 'sink' ou envoyez un message via un canal."),
                                    );
                                }
                            }
                        }
                    }
                    self.check_expr(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.check_expr(left);
                self.check_expr(right);
            }
            ExprKind::FieldAccess { receiver, .. } => self.check_expr(receiver),
            ExprKind::Index { receiver, index } => {
                self.check_expr(receiver);
                self.check_expr(index);
            }
            ExprKind::Array(elems) => {
                for elem in elems {
                    self.check_expr(elem);
                }
            }
            ExprKind::ArrayRepeat(val, count) => {
                self.check_expr(val);
                self.check_expr(count);
            }
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.check_expr(cond);
                for s in &then_branch.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &then_branch.expr {
                    self.check_expr(e);
                }
                if let Some(el) = else_branch {
                    self.check_expr(el);
                }
            }
            ExprKind::Catch { expr, body, .. } => {
                self.check_expr(expr);
                for s in &body.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &body.expr {
                    self.check_expr(e);
                }
            }
            ExprKind::StructInit { fields, .. } => {
                for (_, val) in fields {
                    self.check_expr(val);
                }
            }
            ExprKind::Tuple(items) => {
                for item in items {
                    self.check_expr(item);
                }
            }
            ExprKind::Block(blk) => {
                for s in &blk.stmts {
                    self.check_stmt(s);
                }
                if let Some(e) = &blk.expr {
                    self.check_expr(e);
                }
            }
            ExprKind::Spawn(inner) => {
                let prev_depth = self.spawn_depth;
                self.spawn_depth += 1;
                self.check_expr(inner);
                self.spawn_depth = prev_depth;
            }
            ExprKind::Comptime(inner) => self.check_expr(inner),
            _ => {}
        }
    }

    fn handle_ref_creation(&mut self, target: &Expr, span: Span) {
        if self.current_func_is_strict {
            self.diagnostics.push(
                Diagnostic::error("violation du mode strict : les références générationnelles ('ref') sont interdites dans une fonction 'strict fn'")
                    .with_code("E0020")
                    .with_primary_label(span, "création de 'ref' interdite en mode strict")
                    .with_secondary_label(self.current_func_span, "cette fonction est annotée 'strict fn'")
                    .with_note("Le mode strict garantit l'absence totale d'allocation sur le tas et de références indirectes.")
                    .with_help("Utilisez des projections directes 'in' ou 'inout' sur la pile.")
            );
        }

        if let ExprKind::Ident(sym) = &target.kind {
            if let Some(info) = self.var_info.get_mut(sym) {
                // Mark variable as requiring generational slab header
                info.alloc_kind = AllocKind::HeapGenerational;
            }
        }
    }

    fn handle_ref_assignment(&mut self, receiver: &Expr, ref_target: &Expr, span: Span) {
        if self.current_func_is_strict {
            self.diagnostics.push(
                Diagnostic::error("violation du mode strict : assignation de référence 'ref' interdite en mode strict")
                    .with_code("E0020")
                    .with_primary_label(span, "assignation de 'ref' interdite")
            );
        }

        let recv_root = extract_root_variable(receiver).map(|(s, _)| s);
        let target_root = extract_root_variable(ref_target).map(|(s, _)| s);

        if let (Some(recv), Some(tgt)) = (recv_root, target_root) {
            self.ref_dependencies.entry(recv).or_default().push(tgt);
            self.detect_and_handle_cycles();
        }

        if let ExprKind::Ident(sym) = &ref_target.kind {
            if let Some(info) = self.var_info.get_mut(sym) {
                info.alloc_kind = AllocKind::HeapGenerational;
            }
        }
    }

    fn detect_and_handle_cycles(&mut self) {
        let nodes: Vec<Symbol> = self.ref_dependencies.keys().copied().collect();
        for start_node in nodes {
            let mut visited = Vec::new();
            if self.has_cycle(start_node, start_node, &mut visited) {
                // Promote all participating nodes in the cycle to HeapGenerational
                for sym in &visited {
                    if let Some(info) = self.var_info.get_mut(sym) {
                        info.alloc_kind = AllocKind::HeapGenerational;
                    }
                }

                if self.current_func_is_strict {
                    let names: Vec<String> = visited.iter().map(|s| INTERNER.resolve(s)).collect();
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "violation du mode strict : graphe d'objets cyclique ('{}') interdit en mode strict",
                            names.join(" -> ")
                        ))
                        .with_code("E0020")
                        .with_primary_label(
                            self.current_func_span,
                            "les graphes cycliques par référence 'ref' sont interdits dans une fonction 'strict fn'",
                        )
                        .with_note("Le mode strict impose une hiérarchie de pile stricte sans cycles de pointeurs.")
                        .with_help("Allouez les graphes cycliques dans une arène ou utilisez des indices entiers."),
                    );
                }
                break;
            }
        }
    }

    fn has_cycle(&self, current: Symbol, target: Symbol, visited: &mut Vec<Symbol>) -> bool {
        visited.push(current);
        if let Some(neighbors) = self.ref_dependencies.get(&current) {
            for &next in neighbors {
                if next == target && visited.len() >= 2 {
                    return true;
                }
                if !visited.contains(&next) && self.has_cycle(next, target, visited) {
                    return true;
                }
            }
        }
        visited.pop();
        false
    }

    fn check_return_expr(&mut self, expr: &Expr) {
        self.check_expr(expr);

        // Check if returning a ref to a local stack variable
        if let ExprKind::Unary {
            op: UnaryOp::Ref,
            expr: inner,
        } = &expr.kind
        {
            if let ExprKind::Ident(sym) = &inner.kind {
                let var_name = INTERNER.resolve(sym);
                if let Some(info) = self.var_info.get_mut(sym) {
                    info.escape_status = EscapeStatus::EscapesFunction;
                    self.diagnostics.push(
                        Diagnostic::error(format!(
                            "échappement illégal : la référence 'ref {}' pointe vers une variable locale de la pile",
                            var_name
                        ))
                        .with_code("E0021")
                        .with_primary_label(
                            expr.span,
                            format!("la référence vers '{}' s'échappe de la fonction", var_name),
                        )
                        .with_secondary_label(
                            info.defined_span,
                            format!("'{}' est allouée sur la pile locale de cette fonction", var_name),
                        )
                        .with_help("Ne retournez pas de référence vers une variable locale dont la durée de vie expire avec la pile."),
                    );
                }
            }
        }
    }
}
