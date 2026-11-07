use ifa_comptime::{eval_expr, eval_function, ComptimeErrorKind, Value};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_span::SourceMap;

fn parse_first_expr(code: &str) -> ifa_ast::Expr {
    let mut source_map = SourceMap::new();
    let file_id = source_map.add_file("test.ifa", code);
    let tokens = tokenize(file_id, code);
    let (prog, diags) = parse(file_id, tokens);
    assert!(diags.is_empty(), "Parse error: {:?}", diags);
    match prog.items.into_iter().next().unwrap() {
        ifa_ast::Item::Const(c) => c.value,
        _ => panic!("Expected const item"),
    }
}

fn parse_first_fn(code: &str) -> ifa_ast::Function {
    let mut source_map = SourceMap::new();
    let file_id = source_map.add_file("test.ifa", code);
    let tokens = tokenize(file_id, code);
    let (prog, diags) = parse(file_id, tokens);
    assert!(diags.is_empty(), "Parse error: {:?}", diags);
    match prog.items.into_iter().next().unwrap() {
        ifa_ast::Item::Function(f) => f,
        _ => panic!("Expected function item"),
    }
}

#[test]
fn test_comptime_arithmetic_precedence() {
    let expr = parse_first_expr("const X = 2 + 3 * 4;");
    let res = eval_expr(&expr).expect("eval_expr failed");
    assert_eq!(res, Value::Int(14));
}

#[test]
fn test_comptime_bitwise_and_shifts() {
    let expr = parse_first_expr("const X = (1 << 4) | 0x05;");
    let res = eval_expr(&expr).expect("eval_expr failed");
    assert_eq!(res, Value::Int(21));
}

#[test]
fn test_comptime_array_repeat_and_index() {
    let expr = parse_first_expr("const X = [42; 5][2];");
    let res = eval_expr(&expr).expect("eval_expr failed");
    assert_eq!(res, Value::Int(42));
}

#[test]
fn test_comptime_intrinsic_crc32() {
    let expr = parse_first_expr("const X = crc32(\"IFA\");");
    let res = eval_expr(&expr).expect("eval_expr failed");
    match res {
        Value::UInt(h) => assert!(h > 0),
        Value::Int(h) => assert!(h != 0),
        other => panic!("Expected uint crc32, got {:?}", other),
    }
}

#[test]
fn test_comptime_intrinsic_hex_encode() {
    let expr = parse_first_expr("const X = hex_encode([0xCA, 0xFE]);");
    let res = eval_expr(&expr).expect("eval_expr failed");
    assert_eq!(res, Value::String("cafe".to_string()));
}

#[test]
fn test_comptime_intrinsic_assert_success() {
    let expr = parse_first_expr("const X = assert(10 > 5, \"ok\");");
    let res = eval_expr(&expr).expect("assert should pass");
    assert_eq!(res, Value::Unit);
}

#[test]
fn test_comptime_intrinsic_assert_failure() {
    let expr = parse_first_expr("const X = assert(2 + 2 == 5, \"math broken\");");
    let err = eval_expr(&expr).expect_err("assert must fail");
    assert!(matches!(err.kind, ComptimeErrorKind::AssertionFailed(_)));
}

#[test]
fn test_comptime_division_by_zero_rejected() {
    let expr = parse_first_expr("const X = 100 / 0;");
    let err = eval_expr(&expr).expect_err("division by zero must fail");
    assert_eq!(err.kind, ComptimeErrorKind::DivisionByZero);
}

#[test]
fn test_comptime_function_execution() {
    let func = parse_first_fn(
        r#"
        comptime fn factorial(n: i64) -> i64 {
            if n <= 1 {
                return 1;
            }
            return n * factorial(n - 1);
        }
    "#,
    );
    let res = eval_function(&func, vec![Value::Int(5)]).expect("comptime factorial failed");
    assert_eq!(res, Value::Int(120));
}

#[test]
fn test_comptime_infinite_loop_gas_limit() {
    let func = parse_first_fn(
        r#"
        comptime fn infinite() {
            while true {}
        }
    "#,
    );
    let err = eval_function(&func, vec![]).expect_err("gas limit must be reached");
    assert!(matches!(
        err.kind,
        ComptimeErrorKind::GasLimitExceeded { .. }
    ));
}

#[test]
fn test_comptime_memory_limit_exceeded_sandbox() {
    let mut vm = ifa_comptime::ComptimeVM::new().with_max_memory(1024);
    let expr = parse_first_expr("const X = [0; 500];");
    let err = vm
        .eval_expr(&expr)
        .expect_err("memory sandbox quota should abort massive allocation");
    assert!(matches!(
        err.kind,
        ComptimeErrorKind::MemoryLimitExceeded { .. }
    ));
}

#[test]
fn test_comptime_for_loop_destructuring() {
    let func = parse_first_fn(
        r#"
        comptime fn sum_pairs() -> i64 {
            let pairs = [(1, 10), (2, 20), (3, 30)];
            mut sum = 0;
            for (x, y) in pairs {
                sum = sum + x * y;
            }
            return sum;
        }
    "#,
    );
    let res = eval_function(&func, vec![]).expect("comptime sum_pairs failed");
    assert_eq!(res, Value::Int(140));
}
