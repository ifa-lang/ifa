use ifa_comptime::{eval_expr, fold_expr, ComptimeErrorKind, ComptimeVM, Value};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_span::{sym, SourceMap};

fn parse_program_from_src(src: &str) -> (ifa_span::FileId, ifa_ast::Program) {
    let mut sm = SourceMap::new();
    let fid = sm.add_file("test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(
        diags.is_empty(),
        "Erreurs de parsing : {:?}",
        diags.iter().map(|d| d.message.clone()).collect::<Vec<_>>()
    );
    (fid, prog)
}

fn parse_first_expr(src: &str) -> ifa_ast::Expr {
    let (_, prog) = parse_program_from_src(&format!("fn main() {{ return {}; }}", src));
    if let ifa_ast::Item::Function(f) = &prog.items[0] {
        if let Some(body) = &f.body {
            if let ifa_ast::Stmt::Return(Some(expr), _) = &body.stmts[0] {
                return expr.clone();
            }
        }
    }
    panic!("Impossible d'extraire l'expression de test");
}

#[test]
fn test_comptime_basic_arithmetic() {
    let expr = parse_first_expr("10 + 20 * 3");
    let val = eval_expr(&expr).expect("Evaluation réussie");
    assert_eq!(val, Value::Int(70));

    let expr2 = parse_first_expr("100 / 4 - 5");
    let val2 = eval_expr(&expr2).expect("Evaluation réussie");
    assert_eq!(val2, Value::Int(20));

    let expr3 = parse_first_expr("17 % 5");
    let val3 = eval_expr(&expr3).expect("Evaluation réussie");
    assert_eq!(val3, Value::Int(2));
}

#[test]
fn test_comptime_bitwise_ops() {
    let expr = parse_first_expr("(0xFF00 >> 8) & 0xFF");
    let val = eval_expr(&expr).expect("Evaluation réussie");
    assert_eq!(val, Value::Int(0xFF));

    let expr2 = parse_first_expr("1 << 10");
    let val2 = eval_expr(&expr2).expect("Evaluation réussie");
    assert_eq!(val2, Value::Int(1024));

    let expr3 = parse_first_expr("0xAA ^ 0x55");
    let val3 = eval_expr(&expr3).expect("Evaluation réussie");
    assert_eq!(val3, Value::Int(0xFF));
}

#[test]
fn test_comptime_comparisons_and_short_circuit() {
    let expr = parse_first_expr("10 > 5 && 2 < 4");
    let val = eval_expr(&expr).expect("Evaluation réussie");
    assert_eq!(val, Value::Bool(true));

    let expr2 = parse_first_expr("10 == 20 || 3 != 4");
    let val2 = eval_expr(&expr2).expect("Evaluation réussie");
    assert_eq!(val2, Value::Bool(true));
}

#[test]
fn test_comptime_if_else() {
    let expr = parse_first_expr("if 10 > 5 { 42 } else { 99 }");
    let val = eval_expr(&expr).expect("Evaluation réussie");
    assert_eq!(val, Value::Int(42));
}

#[test]
fn test_comptime_function_execution() {
    let src = r#"
comptime fn factorial(n: i64) -> i64 {
    mut res = 1;
    mut i = 1;
    while i <= n {
        res = res * i;
        i = i + 1;
    }
    return res;
}
"#;
    let (_, prog) = parse_program_from_src(src);
    let mut vm = ComptimeVM::new();
    vm.load_program(&prog).expect("Chargement réussi");

    let fid = ifa_span::FileId(0);
    let span = ifa_span::Span::new(fid, ifa_span::BytePos(0), ifa_span::BytePos(0));
    let res = vm
        .call_function(sym("factorial"), vec![Value::Int(5)], span)
        .expect("Appel factorial(5) réussi");
    assert_eq!(res, Value::Int(120));
}

#[test]
fn test_comptime_generate_crc_table_specification() {
    // Tests the exact example from IFA SPECIFICATION.md section 4.4
    let src = r#"
comptime fn generate_crc_table() -> [u32; 256] {
    mut table = [0; 256];
    mut i = 0;
    while i < 256 {
        mut crc = i;
        mut j = 0;
        while j < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
            j = j + 1;
        }
        table[i] = crc;
        i = i + 1;
    }
    return table;
}
"#;
    let (_, prog) = parse_program_from_src(src);
    let mut vm = ComptimeVM::new();
    vm.load_program(&prog).expect("Chargement réussi");

    let fid = ifa_span::FileId(0);
    let span = ifa_span::Span::new(fid, ifa_span::BytePos(0), ifa_span::BytePos(0));
    let table_val = vm
        .call_function(sym("generate_crc_table"), vec![], span)
        .expect("Génération table CRC réussie");

    if let Value::Array(entries) = table_val {
        assert_eq!(entries.len(), 256);
        // Table entry 0 should be 0
        assert_eq!(entries[0], Value::Int(0));
        // Table entry 1: crc of 1 with polynomial 0xEDB88320
        assert_ne!(entries[1], Value::Int(0));
    } else {
        panic!("Table CRC n'est pas un tableau");
    }
}

#[test]
fn test_comptime_intrinsics() {
    let expr = parse_first_expr("crc32(\"hello\")");
    let val = eval_expr(&expr).expect("Appel intrinsèque crc32 réussi");
    assert!(matches!(val, Value::UInt(_)));

    let expr_len = parse_first_expr("len([10, 20, 30, 40])");
    let val_len = eval_expr(&expr_len).expect("len réussi");
    assert_eq!(val_len, Value::Int(4));

    let expr_type = parse_first_expr("type_of(42)");
    let val_type = eval_expr(&expr_type).expect("type_of réussi");
    assert_eq!(val_type, Value::String("int".to_string()));

    let expr_json = parse_first_expr("json_validate(\"{\\\"name\\\": \\\"ifa\\\"}\")");
    let val_json = eval_expr(&expr_json).expect("json_validate");
    assert_eq!(val_json, Value::Bool(true));
}

#[test]
fn test_comptime_division_by_zero_error() {
    let expr = parse_first_expr("42 / 0");
    let err = eval_expr(&expr).unwrap_err();
    assert_eq!(err.kind, ComptimeErrorKind::DivisionByZero);
}

#[test]
fn test_comptime_index_out_of_bounds_error() {
    let expr = parse_first_expr("[1, 2, 3][10]");
    let err = eval_expr(&expr).unwrap_err();
    assert!(matches!(
        err.kind,
        ComptimeErrorKind::IndexOutOfBounds { .. }
    ));
}

#[test]
fn test_comptime_gas_limit_prevents_infinite_loop() {
    let src = r#"
comptime fn loop_forever() {
    while true {
        let x = 1;
    }
}
"#;
    let (_, prog) = parse_program_from_src(src);
    let mut vm = ComptimeVM::new().with_gas_limit(500);
    vm.load_program(&prog).expect("Chargement réussi");

    let fid = ifa_span::FileId(0);
    let span = ifa_span::Span::new(fid, ifa_span::BytePos(0), ifa_span::BytePos(0));
    let err = vm
        .call_function(sym("loop_forever"), vec![], span)
        .unwrap_err();
    assert!(matches!(
        err.kind,
        ComptimeErrorKind::GasLimitExceeded { .. }
    ));
}

#[test]
fn test_comptime_assertion_failure() {
    let expr = parse_first_expr("assert(10 > 100, \"dépassement attendu\")");
    let err = eval_expr(&expr).unwrap_err();
    assert!(matches!(err.kind, ComptimeErrorKind::AssertionFailed(_)));
}

#[test]
fn test_comptime_constant_folding() {
    let expr = parse_first_expr("10 + 20 * 2");
    let folded = fold_expr(&expr).expect("Pliage de constantes réussi");
    if let ifa_ast::ExprKind::Lit(ifa_ast::Lit::Int(s)) = folded.kind {
        let text = ifa_span::INTERNER.resolve(&s);
        assert_eq!(text, "50");
    } else {
        panic!("Pliage n'a pas produit de littéral Int");
    }
}
