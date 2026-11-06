use ifa_ast::{ExprKind, Item, Program, Stmt};
use ifa_fir::{compile_to_fir, FirInterpreter, FirValue};
use ifa_sema::SymbolTable;
use ifa_span::{SourceMap, INTERNER};
use std::fs;
use std::path::Path;
use std::time::Instant;

/// Initialize a new IFA package with kori.toml manifest and canonical src/main.ifa.
pub fn init_project(name: &str) -> std::io::Result<()> {
    let root = Path::new(name);
    fs::create_dir_all(root.join("src"))?;

    let kori_toml = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
edition = "2026"
description = "Deterministic systems application built with IFA"

[dependencies]

[build]
backend = "cranelift"
strict = false
"#
    );

    let main_ifa = r#"import std::io

pub fn main() -> () {
    let greeting = "Hello from IFA!"
    println(greeting)
}
"#;

    let gitignore = r#"/target/
*.lock
*.log
"#;

    fs::write(root.join("kori.toml"), kori_toml)?;
    fs::write(root.join("src").join("main.ifa"), main_ifa)?;
    fs::write(root.join(".gitignore"), gitignore)?;

    Ok(())
}

/// Canonically format IFA source code: normalize indentation, remove trailing whitespace.
pub fn format_source(src: &str) -> String {
    let mut formatted = String::with_capacity(src.len());
    let mut indent_level: usize = 0;

    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            formatted.push('\n');
            continue;
        }

        // Adjust indent for closing brace at the start of the line
        if trimmed.starts_with('}') || trimmed.starts_with(']') || trimmed.starts_with(')') {
            indent_level = indent_level.saturating_sub(1);
        }

        // Indent with 4 spaces per level
        for _ in 0..indent_level {
            formatted.push_str("    ");
        }
        formatted.push_str(trimmed);
        formatted.push('\n');

        // Increase indent if line ends with opening brace, bracket, or parenthesis
        let open_counts = trimmed
            .chars()
            .filter(|&c| c == '{' || c == '[' || c == '(')
            .count();
        let close_counts = trimmed
            .chars()
            .filter(|&c| c == '}' || c == ']' || c == ')')
            .count();
        if open_counts > close_counts {
            indent_level += open_counts - close_counts;
        }
    }

    formatted
}

/// Static linting on AST to enforce IFA canonical naming conventions and best practices.
pub fn lint_program(prog: &Program, _sm: &SourceMap) -> Vec<String> {
    let mut warnings = Vec::new();

    for item in &prog.items {
        match item {
            Item::Function(f) => {
                let name = INTERNER.resolve(&f.name);
                if !is_snake_case(&name) && !name.starts_with('_') {
                    warnings.push(format!(
                        "style warning: function name `{}` should follow snake_case convention",
                        name
                    ));
                }
                for param in &f.params {
                    let p_name = INTERNER.resolve(&param.name);
                    if !is_snake_case(&p_name) {
                        warnings.push(format!(
                            "style warning: parameter `{}` in function `{}` should follow snake_case convention",
                            p_name, name
                        ));
                    }
                }
                if let Some(body) = &f.body {
                    lint_statements(&body.stmts, &mut warnings);
                }
            }
            Item::Struct(s) => {
                let name = INTERNER.resolve(&s.name);
                if !is_pascal_case(&name) {
                    warnings.push(format!(
                        "style warning: struct name `{}` should follow PascalCase convention",
                        name
                    ));
                }
            }
            Item::Enum(e) => {
                let name = INTERNER.resolve(&e.name);
                if !is_pascal_case(&name) {
                    warnings.push(format!(
                        "style warning: enum name `{}` should follow PascalCase convention",
                        name
                    ));
                }
            }
            _ => {}
        }
    }

    warnings
}

fn lint_statements(stmts: &[Stmt], warnings: &mut Vec<String>) {
    for stmt in stmts {
        match stmt {
            Stmt::Let { name, .. } => {
                let var_name = INTERNER.resolve(name);
                if !is_snake_case(&var_name) && !var_name.starts_with('_') {
                    warnings.push(format!(
                        "style warning: variable `{}` should follow snake_case convention",
                        var_name
                    ));
                }
            }
            Stmt::Expr(expr) => match &expr.kind {
                ExprKind::Block(b) => lint_statements(&b.stmts, warnings),
                ExprKind::If {
                    then_branch,
                    else_branch,
                    ..
                } => {
                    lint_statements(&then_branch.stmts, warnings);
                    if let Some(e) = else_branch {
                        if let ExprKind::Block(b) = &e.kind {
                            lint_statements(&b.stmts, warnings);
                        }
                    }
                }
                ExprKind::Catch { body, .. } => lint_statements(&body.stmts, warnings),
                _ => {}
            },
            Stmt::While { body, .. } => lint_statements(&body.stmts, warnings),
            Stmt::For { var, body, .. } => {
                let var_name = INTERNER.resolve(var);
                if !is_snake_case(&var_name) && !var_name.starts_with('_') {
                    warnings.push(format!(
                        "style warning: loop variable `{}` should follow snake_case convention",
                        var_name
                    ));
                }
                lint_statements(&body.stmts, warnings);
            }
            _ => {}
        }
    }
}

fn is_snake_case(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_pascal_case(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => !s.contains('_'),
        _ => false,
    }
}

/// Discover and execute test functions in an IFA program.
pub fn run_tests(prog: &Program, symbols: &SymbolTable) -> (usize, usize, Vec<String>) {
    let mut passed = 0;
    let mut failed = 0;
    let mut logs = Vec::new();

    let fir_module = match compile_to_fir(prog, symbols, true, true) {
        Ok(m) => m,
        Err(diags) => {
            logs.push(format!(
                "FIR compilation failed with {} errors",
                diags.len()
            ));
            return (0, 1, logs);
        }
    };

    let test_functions: Vec<String> = fir_module
        .functions
        .iter()
        .map(|f| INTERNER.resolve(&f.name))
        .filter(|name| name.starts_with("test_"))
        .collect();

    if test_functions.is_empty() {
        logs.push("No test functions found (test functions must start with `test_`)".to_string());
        return (0, 0, logs);
    }

    for test_fn in &test_functions {
        let start = Instant::now();
        let mut interp = FirInterpreter::new(&fir_module);
        match interp.execute_function(test_fn, vec![]) {
            Ok(val) => {
                let duration = start.elapsed();
                if val == FirValue::Unit || val == FirValue::Bool(true) {
                    let status_msg = format!("test {} ... ok ({:.2?})", test_fn, duration);
                    logs.push(status_msg);
                    passed += 1;
                } else if val == FirValue::Bool(false) {
                    let status_msg = format!(
                        "test {} ... FAILED (returned false) ({:.2?})",
                        test_fn, duration
                    );
                    logs.push(status_msg);
                    failed += 1;
                } else {
                    let status_msg = format!(
                        "test {} ... ok (returned {}) ({:.2?})",
                        test_fn, val, duration
                    );
                    logs.push(status_msg);
                    passed += 1;
                }
            }
            Err(e) => {
                let duration = start.elapsed();
                logs.push(format!(
                    "test {} ... FAILED ({}) ({:.2?})",
                    test_fn, e, duration
                ));
                failed += 1;
            }
        }
    }

    (passed, failed, logs)
}
