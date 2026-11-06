#![allow(clippy::result_large_err)]

pub mod checker;
pub mod escape;
pub mod exclusivity;
pub mod symbol_table;
pub mod types;

pub use checker::SemanticAnalyzer;
pub use escape::{AllocKind, EscapeAnalyzer, EscapeStatus};
pub use exclusivity::check_call_exclusivity;
pub use symbol_table::{FunctionSymbol, StructSymbol, SymbolTable, VariableSymbol};
pub use types::{FloatType, IntType, Type};

use ifa_ast::Program;
use ifa_diagnostics::{Diagnostic, Severity};
use ifa_span::SourceMap;

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub symbols: SymbolTable,
    pub diagnostics: Vec<Diagnostic>,
}

impl AnalysisResult {
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count()
    }
}

/// Performs complete semantic analysis, type inference, exclusivity checks and escape analysis.
pub fn analyze(source_map: &SourceMap, program: &Program) -> AnalysisResult {
    let analyzer = SemanticAnalyzer::new(source_map);
    let (symbols, diagnostics) = analyzer.analyze(program);
    AnalysisResult {
        symbols,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ifa_lexer::tokenize;
    use ifa_parser::parse;
    use ifa_span::SourceMap;

    fn parse_and_analyze(src: &str) -> AnalysisResult {
        let mut source_map = SourceMap::new();
        let file_id = source_map.add_file("test.ifa", src);
        let tokens = tokenize(file_id, src);
        let (prog, parse_diags) = parse(file_id, tokens);
        assert!(
            parse_diags.is_empty(),
            "Parsing failed unexpectedly: {:?}",
            parse_diags
        );
        analyze(&source_map, &prog)
    }

    #[test]
    fn test_valid_types_and_inout() {
        let code = r#"
            fn add(a: u32, inout b: u32) -> u32 {
                mut res = a + b;
                return res;
            }

            pub fn main() {
                mut count: u32 = 40;
                let delta: u32 = 2;
                let total = add(delta, inout count);
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(
            !res.has_errors(),
            "Expected no errors, got: {:?}",
            res.diagnostics
        );
        assert!(res
            .symbols
            .lookup_function(&ifa_span::INTERNER.intern("add"))
            .is_some());
    }

    #[test]
    fn test_exclusivity_double_inout_rejected() {
        let code = r#"
            fn swap(inout a: u32, inout b: u32) {
                let tmp = a;
                a = b;
                b = tmp;
            }

            pub fn main() {
                mut x: u32 = 10;
                swap(inout x, inout x);
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(res.has_errors(), "Expected exclusivity violation error");
        let has_exclusivity_err = res
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0011"));
        assert!(has_exclusivity_err, "Expected E0011 diagnostic code");
    }

    #[test]
    fn test_exclusivity_in_and_inout_rejected() {
        let code = r#"
            fn inspect_and_modify(val: u32, inout target: u32) {
                target = target + val;
            }

            pub fn main() {
                mut x: u32 = 10;
                inspect_and_modify(x, inout x);
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(res.has_errors(), "Expected exclusivity violation error");
        let has_exclusivity_err = res
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0012"));
        assert!(has_exclusivity_err, "Expected E0012 diagnostic code");
    }

    #[test]
    fn test_inout_on_immutable_let_rejected() {
        let code = r#"
            fn inc(inout val: u32) {
                val += 1;
            }

            pub fn main() {
                let x: u32 = 10;
                inc(inout x);
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(res.has_errors(), "Expected immutable inout rejection");
        let has_immut_err = res
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0010"));
        assert!(has_immut_err, "Expected E0010 diagnostic code");
    }

    #[test]
    fn test_assign_to_immutable_let_rejected() {
        let code = r#"
            pub fn main() {
                let x: u32 = 10;
                x = 20;
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(res.has_errors(), "Expected immutable assignment rejection");
        let has_assign_err = res
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0014"));
        assert!(has_assign_err, "Expected E0014 diagnostic code");
    }

    #[test]
    fn test_error_union_fail_and_catch() {
        let code = r#"
            struct IoError {
                code: u32,
                message: String
            }

            fn read_file(path: String) -> IoError!String {
                if path == "" {
                    fail IoError(code: 1, message: "Chemin vide");
                }
                return "contenu";
            }

            pub fn main() {
                let data = read_file("test.ifa") catch err {
                    return;
                };
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(
            !res.has_errors(),
            "Expected valid error union handling, got: {:?}",
            res.diagnostics
        );
    }

    #[test]
    fn test_fail_without_error_union_rejected() {
        let code = r#"
            fn normal_fn() -> u32 {
                fail 42;
                return 0;
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(
            res.has_errors(),
            "Expected fail without error union rejection"
        );
        let has_fail_err = res
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0030"));
        assert!(has_fail_err, "Expected E0030 diagnostic code");
    }

    #[test]
    fn test_strict_fn_ref_forbidden() {
        let code = r#"
            strict fn compute(a: u32) -> u32 {
                let r = ref a;
                return a;
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(
            res.has_errors(),
            "Expected strict mode violation for ref creation"
        );
        let has_strict_err = res
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020"));
        assert!(has_strict_err, "Expected E0020 diagnostic code");
    }

    #[test]
    fn test_escape_stack_ref_return_rejected() {
        let code = r#"
            fn get_ref() -> ref u32 {
                let local: u32 = 100;
                return ref local;
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(
            res.has_errors(),
            "Expected escaping stack reference rejection"
        );
        let has_escape_err = res
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0021"));
        assert!(has_escape_err, "Expected E0021 diagnostic code");
    }

    #[test]
    fn test_generational_ref_in_struct() {
        let code = r#"
            struct WindowNode {
                id: String,
                title: String,
                parent: ?ref WindowNode,
                children: List<WindowNode>
            }

            fn attach_child(inout parent: WindowNode, mut child: WindowNode) {
                child.parent = ref parent;
                parent.children.push(child);
            }
        "#;
        let res = parse_and_analyze(code);
        assert!(
            !res.has_errors(),
            "Expected valid generational ref in struct, got: {:?}",
            res.diagnostics
        );
    }
}
