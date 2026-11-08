use ifa_ast::{Expr, ExprKind, ParamMode, Program, UnaryOp, Visitor};
use ifa_fir::{compile_to_fir, GenerationalOptPass, ValueExpr};
use ifa_sema::exclusivity::extract_access_path;
use ifa_sema::symbol_table::SymbolTable;
use ifa_span::{Span, Symbol};

/// Represents a proven disjoint borrow pair/set occurring in simultaneous parameter evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisjointBorrow {
    pub span: Span,
    pub root: Symbol,
    pub path_display: String,
    pub sibling_paths: Vec<String>,
}

/// Represents a generational reference access barrier and its compile-time elimination status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenBarrier {
    pub span: Span,
    pub eliminated: bool,
    pub ref_id: u32,
}

/// Enhanced compile-time analysis results computed for interactive IDE / LSP feedback.
#[derive(Debug, Clone, Default)]
pub struct EnhancedAnalysis {
    pub disjoint_borrows: Vec<DisjointBorrow>,
    pub gen_barriers: Vec<GenBarrier>,
}

impl EnhancedAnalysis {
    /// Compute both disjoint path borrows and generational check barrier statuses.
    pub fn compute(program: &Program, symbols: &SymbolTable) -> Self {
        let mut disjoint_borrows = Vec::new();

        // 1. AST visitor detecting simultaneous calls with provably disjoint inout paths
        let mut visitor = DisjointBorrowVisitor {
            symbols,
            borrows: Vec::new(),
        };
        visitor.visit_program(program);
        disjoint_borrows.extend(visitor.borrows);

        // 2. FIR lowering and generational pass for static barrier elimination inspection
        let mut gen_barriers = Vec::new();
        if let Ok(mut fir) = compile_to_fir(program, symbols, true, true) {
            let mut opt = GenerationalOptPass::new();
            opt.run_on_module(&mut fir);

            for func in &fir.functions {
                for block in &func.blocks {
                    for inst in &block.instructions {
                        if let ValueExpr::GenCheck { ref_val, redundant } = inst.expr {
                            if inst.span != Span::DUMMY && !inst.span.is_empty() {
                                gen_barriers.push(GenBarrier {
                                    span: inst.span,
                                    eliminated: redundant,
                                    ref_id: ref_val.0,
                                });
                            }
                        }
                    }
                }
            }
        }

        Self {
            disjoint_borrows,
            gen_barriers,
        }
    }

    /// Query disjoint borrow at given byte offset.
    pub fn find_disjoint_borrow_at(&self, offset: usize) -> Option<&DisjointBorrow> {
        self.disjoint_borrows.iter().find(|b| {
            let start = b.span.start.0 as usize;
            let end = b.span.end.0 as usize;
            offset >= start && offset <= end
        })
    }

    /// Query generational reference barrier at given byte offset.
    pub fn find_gen_barrier_at(&self, offset: usize) -> Option<&GenBarrier> {
        self.gen_barriers.iter().find(|g| {
            let start = g.span.start.0 as usize;
            let end = g.span.end.0 as usize;
            offset >= start && offset <= end
        })
    }
}

struct DisjointBorrowVisitor<'a> {
    symbols: &'a SymbolTable,
    borrows: Vec<DisjointBorrow>,
}

impl<'a, 'ast> Visitor<'ast> for DisjointBorrowVisitor<'a> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match &expr.kind {
            ExprKind::Call { callee, args } => {
                let mut param_modes = Vec::new();
                if let ExprKind::Ident(fn_name) = callee.kind {
                    if let Some(func) = self.symbols.functions.get(&fn_name) {
                        for p in &func.params {
                            param_modes.push(p.mode);
                        }
                    }
                }

                self.analyze_call_args(args, &param_modes);
                self.visit_expr(callee);
                for arg in args {
                    self.visit_expr(&arg.value);
                }
            }
            ExprKind::MethodCall { receiver, args, .. } => {
                self.visit_expr(receiver);
                let param_modes = Vec::new();
                self.analyze_call_args(args, &param_modes);
                for arg in args {
                    self.visit_expr(&arg.value);
                }
            }
            ExprKind::Binary { left, right, .. } => {
                self.visit_expr(left);
                self.visit_expr(right);
            }
            ExprKind::Unary { expr: u, .. } => self.visit_expr(u),
            ExprKind::FieldAccess { receiver, .. } => self.visit_expr(receiver),
            ExprKind::Index { receiver, index } => {
                self.visit_expr(receiver);
                self.visit_expr(index);
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
            ExprKind::Match { expr: m, arms } => {
                self.visit_expr(m);
                for arm in arms {
                    if let Some(g) = &arm.guard {
                        self.visit_expr(g);
                    }
                    self.visit_expr(&arm.body);
                }
            }
            _ => {}
        }
    }
}

impl<'a> DisjointBorrowVisitor<'a> {
    fn analyze_call_args(&mut self, args: &[ifa_ast::Arg], param_modes: &[ParamMode]) {
        if args.len() < 2 {
            return;
        }

        struct ArgBorrow {
            span: Span,
            path: ifa_sema::exclusivity::AccessPath,
            is_mutable: bool,
        }

        let mut collected: Vec<ArgBorrow> = Vec::new();

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
            let is_mutable = is_explicit_inout
                || is_explicit_sink
                || matches!(param_mode, ParamMode::InOut | ParamMode::Sink);

            if let Some(path) = extract_access_path(&arg.value) {
                collected.push(ArgBorrow {
                    span: arg.value.span,
                    path,
                    is_mutable,
                });
            }
        }

        // Compare all pairs sharing the same root
        for i in 0..collected.len() {
            let mut siblings = Vec::new();
            for j in 0..collected.len() {
                if i == j {
                    continue;
                }
                let a = &collected[i];
                let b = &collected[j];

                if a.path.root == b.path.root
                    && (a.is_mutable || b.is_mutable)
                    && !a.path.overlaps(&b.path)
                {
                    siblings.push(b.path.display.clone());
                }
            }

            if !siblings.is_empty() {
                self.borrows.push(DisjointBorrow {
                    span: collected[i].span,
                    root: collected[i].path.root,
                    path_display: collected[i].path.display.clone(),
                    sibling_paths: siblings,
                });
            }
        }
    }
}
