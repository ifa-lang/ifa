//! Inlay Hints provider (LSP 3.17) for inferred variable types and call parameter names.

use crate::document::Document;
use crate::protocol::{InlayHint, InlayHintKind, Range};
use ifa_ast::{Expr, ExprKind, Stmt, Visitor};

struct InlayHintVisitor<'a> {
    doc: &'a Document,
    hints: Vec<InlayHint>,
}

impl<'a, 'ast> Visitor<'ast> for InlayHintVisitor<'a> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if let Stmt::Let {
            pattern: ifa_ast::Pattern::Ident(name, _),
            ty: None,
            span,
            ..
        } = stmt
        {
            if let Some(analysis) = &self.doc.analysis {
                // Find inferred type from semantic scopes
                for scope in &analysis.symbols.scopes {
                    if let Some(var) = scope.variables.get(name) {
                        let ty_str = format!("{}", var.ty);
                        if ty_str != "unknown" {
                            let name_str = name.resolve();
                            let start_offset = span.start.0 as usize;
                            let end_offset = (span.end.0 as usize).min(self.doc.text.len());
                            if let Some(rel_idx) =
                                self.doc.text[start_offset..end_offset].find(&name_str)
                            {
                                let hint_offset = start_offset + rel_idx + name_str.len();
                                let position = self.doc.offset_to_position(hint_offset);
                                self.hints.push(InlayHint {
                                    position,
                                    label: format!(": {}", ty_str),
                                    kind: Some(InlayHintKind::Type as u32),
                                    padding_left: Some(false),
                                    padding_right: Some(true),
                                });
                            }
                        }
                        break;
                    }
                }
            }
        }

        match stmt {
            Stmt::Let { init, .. } => {
                if let Some(e) = init {
                    self.visit_expr(e);
                }
            }
            Stmt::Assign { target, val, .. } => {
                self.visit_expr(target);
                self.visit_expr(val);
            }
            Stmt::AssignPattern { val, .. } => {
                self.visit_expr(val);
            }
            Stmt::Expr(e) => self.visit_expr(e),
            Stmt::Defer(b, _) => self.visit_block(b),
            Stmt::Return(e, _) => {
                if let Some(expr) = e {
                    self.visit_expr(expr);
                }
            }
            Stmt::Fail(e, _) => self.visit_expr(e),
            Stmt::While { cond, body, .. } => {
                self.visit_expr(cond);
                self.visit_block(body);
            }
            Stmt::WhileLet {
                expr, guard, body, ..
            } => {
                self.visit_expr(expr);
                if let Some(g) = guard {
                    self.visit_expr(g);
                }
                self.visit_block(body);
            }
            Stmt::For { iterable, body, .. } => {
                self.visit_expr(iterable);
                self.visit_block(body);
            }
            Stmt::Loop(b, _) => self.visit_block(b),
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let ExprKind::Call { callee, args } = &expr.kind {
            if let ExprKind::Ident(fn_sym) = callee.kind {
                if let Some(analysis) = &self.doc.analysis {
                    if let Some(func) = analysis.symbols.functions.get(&fn_sym) {
                        for (i, arg) in args.iter().enumerate() {
                            if arg.name.is_none() {
                                if let Some(param) = func.params.get(i) {
                                    let param_name = param.name.resolve();
                                    let pos = self
                                        .doc
                                        .offset_to_position(arg.value.span.start.0 as usize);
                                    self.hints.push(InlayHint {
                                        position: pos,
                                        label: format!("{}: ", param_name),
                                        kind: Some(InlayHintKind::Parameter as u32),
                                        padding_left: Some(false),
                                        padding_right: Some(true),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        match &expr.kind {
            ExprKind::Lit(_) | ExprKind::Ident(_) | ExprKind::Path(_) | ExprKind::Unit => {}
            ExprKind::Binary { left, right, .. } => {
                self.visit_expr(left);
                self.visit_expr(right);
            }
            ExprKind::Unary { expr, .. } => self.visit_expr(expr),
            ExprKind::Call { callee, args } => {
                self.visit_expr(callee);
                for arg in args {
                    self.visit_expr(&arg.value);
                }
            }
            ExprKind::MethodCall { receiver, args, .. } => {
                self.visit_expr(receiver);
                for arg in args {
                    self.visit_expr(&arg.value);
                }
            }
            ExprKind::FieldAccess { receiver, .. } => self.visit_expr(receiver),
            ExprKind::Index { receiver, index } => {
                self.visit_expr(receiver);
                self.visit_expr(index);
            }
            ExprKind::Array(elems) => {
                for elem in elems {
                    self.visit_expr(elem);
                }
            }
            ExprKind::ArrayRepeat(val, count) => {
                self.visit_expr(val);
                self.visit_expr(count);
            }
            ExprKind::Record(entries) => {
                for (_, val) in entries {
                    self.visit_expr(val);
                }
            }
            ExprKind::Block(b) => self.visit_block(b),
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.visit_expr(cond);
                self.visit_block(then_branch);
                if let Some(els) = else_branch {
                    self.visit_expr(els);
                }
            }
            ExprKind::IfLet {
                expr,
                guard,
                then_branch,
                else_branch,
                ..
            } => {
                self.visit_expr(expr);
                if let Some(g) = guard {
                    self.visit_expr(g);
                }
                self.visit_block(then_branch);
                if let Some(els) = else_branch {
                    self.visit_expr(els);
                }
            }
            ExprKind::Match { expr, arms } => {
                self.visit_expr(expr);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        self.visit_expr(guard);
                    }
                    self.visit_expr(&arm.body);
                }
            }
            ExprKind::Select { arms } => {
                for arm in arms {
                    if let Some(chan) = &arm.channel {
                        self.visit_expr(chan);
                    }
                    self.visit_expr(&arm.body);
                }
            }
            ExprKind::Spawn(e) => self.visit_expr(e),
            ExprKind::Catch { expr, body, .. } => {
                self.visit_expr(expr);
                self.visit_block(body);
            }
            ExprKind::StructInit { fields, .. } => {
                for (_, f_expr) in fields {
                    self.visit_expr(f_expr);
                }
            }
            ExprKind::Tuple(exprs) => {
                for expr in exprs {
                    self.visit_expr(expr);
                }
            }
            ExprKind::Lambda { body, .. } => {
                self.visit_block(body);
            }
            ExprKind::Comptime(e) => self.visit_expr(e),
        }
    }
}

pub fn handle_inlay_hints(doc: &Document, _range: Range) -> Vec<InlayHint> {
    let mut visitor = InlayHintVisitor {
        doc,
        hints: Vec::new(),
    };

    if let Some(ast) = &doc.ast {
        visitor.visit_program(ast);
    }

    visitor.hints
}
