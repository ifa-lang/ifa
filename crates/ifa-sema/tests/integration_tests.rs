use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::{analyze, AnalysisResult};
use ifa_span::SourceMap;

fn run_analysis(src: &str) -> AnalysisResult {
    let mut source_map = SourceMap::new();
    let file_id = source_map.add_file("integration_test.ifa", src);
    let tokens = tokenize(file_id, src);
    let (prog, parse_diags) = parse(file_id, tokens);
    assert!(
        parse_diags.is_empty(),
        "Code source non analysable syntaxiquement : {:?}",
        parse_diags
    );
    analyze(&source_map, &prog)
}

#[test]
fn test_lexical_scoping_and_shadowing() {
    let code = r#"
        pub fn main() {
            let x: u32 = 10;
            {
                let x: bool = true;
                if x {
                    let y: u64 = 100;
                }
            }
            let z: u32 = x + 5;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Scoping and shadowing should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_undefined_variable_reported() {
    let code = r#"
        pub fn main() {
            let a = 10;
            let b = unknown_var + 5;
        }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors());
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0001")));
}

#[test]
fn test_law_of_exclusivity_three_arguments_conflict() {
    let code = r#"
        fn transform(inout a: u32, b: u32, inout c: u32) {
            a += b;
            c += a;
        }

        pub fn main() {
            mut x: u32 = 5;
            mut y: u32 = 10;
            // x is passed as inout AND in (b)
            transform(inout x, x, inout y);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Should violate exclusivity due to in and inout conflict on x"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0012")));
}

#[test]
fn test_law_of_exclusivity_valid_distinct_inouts() {
    let code = r#"
        fn swap_and_add(inout a: u32, inout b: u32, c: u32) {
            let tmp = a;
            a = b + c;
            b = tmp;
        }

        pub fn main() {
            mut x: u32 = 1;
            mut y: u32 = 2;
            let z: u32 = 3;
            swap_and_add(inout x, inout y, z);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Distinct inout variables should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_inout_literal_rejected() {
    let code = r#"
        fn modify(inout target: u32) {
            target += 1;
        }

        pub fn main() {
            modify(inout 42);
        }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors(), "inout literal must be rejected");
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0013")));
}

#[test]
fn test_field_access_and_struct_mutation() {
    let code = r#"
        struct Account {
            balance: u64,
            owner: String
        }

        fn credit(inout acc: Account, amount: u64) {
            acc.balance += amount;
        }

        pub fn main() {
            mut a = Account(balance: 1000, owner: "Alice");
            credit(inout a, 500);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Struct field mutation inout should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_unknown_struct_field_reported() {
    let code = r#"
        struct User {
            name: String
        }

        pub fn main() {
            let u = User(name: "Bob");
            let x = u.age;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Accessing non-existent field should report error"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0007")));
}

#[test]
fn test_try_operator_propagation() {
    let code = r#"
        struct CustomError {
            code: u32
        }

        fn step_one() -> CustomError!u32 {
            return 42;
        }

        fn step_two() -> CustomError!u64 {
            let val = try step_one();
            return 100;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "try operator should succeed when error union matches: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_try_in_non_error_union_function_rejected() {
    let code = r#"
        struct CustomError {
            code: u32
        }

        fn fallible() -> CustomError!u32 {
            return 1;
        }

        fn normal_fn() -> u32 {
            let v = try fallible();
            return v;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "try in non-error function must be rejected"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0036")));
}

#[test]
fn test_while_non_bool_condition_rejected() {
    let code = r#"
        pub fn main() {
            mut x = 10;
            while x {
                x -= 1;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors(), "while loop condition must be bool");
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0001")));
}

#[test]
fn test_break_outside_loop_rejected() {
    let code = r#"
        pub fn main() {
            break;
        }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors(), "break outside loop must be rejected");
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0033")));
}

#[test]
fn test_strict_fn_valid_execution() {
    let code = r#"
        strict fn hash_block(data: Slice<u8>) -> [u8; 16] {
            mut state = [0u8; 16];
            for byte in data {
                state[0] ^= byte;
            }
            return state;
        }

        pub fn main() {
            let input = [10u8, 20u8, 30u8];
            let out = hash_block(input);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Strict fn without heap allocations should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_law_of_exclusivity_sink_conflict() {
    let code = r#"
        fn consume_pair(sink a: u32, sink b: u32) {}

        pub fn main() {
            mut x: u32 = 42;
            consume_pair(sink x, sink x);
        }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors(), "Duplicate sink must violate exclusivity");
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0016")));
}

#[test]
fn test_law_of_exclusivity_sink_and_inout_conflict() {
    let code = r#"
        fn take_and_mutate(sink a: u32, inout b: u32) {}

        pub fn main() {
            mut x: u32 = 100;
            take_and_mutate(sink x, inout x);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "sink and inout on same variable must violate exclusivity"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0017")));
}

#[test]
fn test_law_of_exclusivity_sink_and_in_conflict() {
    let code = r#"
        fn inspect_and_move(a: u32, sink b: u32) {}

        pub fn main() {
            let x: u32 = 50;
            inspect_and_move(x, sink x);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "in and sink on same variable must violate exclusivity"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0017")));
}

#[test]
fn test_use_after_move_rejected() {
    let code = r#"
        fn consume(sink val: u32) {}

        pub fn main() {
            mut x: u32 = 10;
            consume(sink x);
            let y = x + 1;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Reading variable after sink must be rejected"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0018")));
}

#[test]
fn test_use_after_move_reassigned_succeeds() {
    let code = r#"
        fn consume(sink val: u32) {}

        pub fn main() {
            mut x: u32 = 10;
            consume(sink x);
            x = 20;
            let y = x + 1;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Reassigning variable after sink must make it usable again: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_uninitialized_variable_read_rejected() {
    let code = r#"
        pub fn main() {
            let x: u32;
            let y = x + 5;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Reading uninitialized variable must be rejected"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0019")));
}

#[test]
fn test_delayed_initialization_immutable_let_succeeds() {
    let code = r#"
        pub fn main() {
            let x: u32;
            x = 10;
            let y = x + 5;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "First assignment to uninitialized let must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_reassign_initialized_immutable_let_rejected() {
    let code = r#"
        pub fn main() {
            let x: u32 = 10;
            x = 20;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Reassigning initialized immutable let must be rejected"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0014")));
}

#[test]
fn test_duplicate_variable_same_scope_rejected() {
    let code = r#"
        pub fn main() {
            let a = 1;
            let a = 2;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Duplicate variable definition in same scope must fail"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0002")));
}

#[test]
fn test_duplicate_function_rejected() {
    let code = r#"
        fn calculate() -> u32 { return 1; }
        fn calculate() -> u32 { return 2; }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors(), "Duplicate function definition must fail");
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0003")));
}

#[test]
fn test_duplicate_struct_rejected() {
    let code = r#"
        struct Point { x: i32 }
        struct Point { y: i32 }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors(), "Duplicate struct definition must fail");
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0004")));
}

#[test]
fn test_duplicate_enum_rejected() {
    let code = r#"
        enum Color { Red, Green }
        enum Color { Blue }
    "#;
    let res = run_analysis(code);
    assert!(res.has_errors(), "Duplicate enum definition must fail");
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0005")));
}

#[test]
fn test_bidirectional_integer_inference_widths() {
    let code = r#"
        pub fn main() {
            let a: u8 = 10;
            let b: u16 = 200;
            let c: u32 = 50000;
            let d: u64 = 1000000;
            let e: i8 = -10;
            let f: i16 = -500;
            let g: i32 = -30000;
            let h: i64 = -999999999;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Bidirectional integer literal inference should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_float_types_inference() {
    let code = r#"
        pub fn main() {
            let f1: f32 = 3.14;
            let f2: f64 = 2.71828;
            let sum: f64 = f2 + 1.0;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Float literal inference should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_array_to_slice_coercion() {
    let code = r#"
        fn sum_slice(s: Slice<u32>) -> u32 {
            return 0;
        }

        pub fn main() {
            let arr = [1u32, 2u32, 3u32];
            let res = sum_slice(arr);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Passing array [T; N] to Slice<T> parameter should coerce cleanly: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_optional_coalesce_operator() {
    let code = r#"
        pub fn main() {
            let maybe_val: ?u32 = 42;
            let val: u32 = maybe_val ?? 0;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Optional coalesce operator '??' should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_lambda_type_checking() {
    let code = r#"
        pub fn main() {
            let square = fn(x: u32) { return x * x; };
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Lambda expression should typecheck: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_comptime_expression_inference() {
    let code = r#"
        pub fn main() {
            let val = comptime (10 + 32);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Comptime expression should typecheck cleanly: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_struct_box_inference_and_field_access() {
    let code = r#"
        struct Box<T> {
            val: T,
        }

        pub fn main() {
            let b = Box(val: 42);
            let extracted: i64 = b.val;
            let str_box = Box(val: "hello");
            let str_val: str = str_box.val;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Generic struct Box<T> inference should typecheck cleanly: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_struct_multi_param_pair() {
    let code = r#"
        struct Pair<T, U> {
            first: T,
            second: U,
        }

        pub fn main() {
            let p = Pair(first: 100, second: true);
            let a: i64 = p.first;
            let b: bool = p.second;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Generic struct Pair<T, U> should infer both parameters cleanly: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_struct_with_generational_ref() {
    let code = r#"
        struct Box<T> {
            val: T,
        }

        pub fn read_box(inout b: Box<i64>) -> i64 {
            let r: ref Box<i64> = ref b;
            return r.val;
        }

        pub fn main() {
            mut my_box = Box(val: 99);
            let res = read_box(inout my_box);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Generational ref to generic struct Box<T> should typecheck cleanly: {:?}",
        res.diagnostics
    );
}
