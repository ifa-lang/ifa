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
            let val2 = step_one()?;
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
fn test_optional_safe_navigation_operator() {
    let code = r#"
        struct Node {
            val: i64,
            next: ?ref Node,
        }

        pub fn get_val(n: ref Node) -> i64 {
            return n.val;
        }

        pub fn main() {
            let opt_node: ?ref Node = null;
            let v: ?i64 = opt_node?.val;
            let next_v: ?i64 = opt_node?.next?.val;
            let method_res: ?i64 = opt_node?.get_val();
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Safe navigation operator '?.' should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_optional_direct_access_rejected() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            let opt_node: ?ref Node = null;
            let v: i64 = opt_node.val;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Direct member access '.' on optional reference should fail"
    );
}

#[test]
fn test_lambda_type_checking() {
    let code = r#"
        pub fn main() {
            let square = fn(x: u32) -> u32 { return x * x; };
            let res = square(5);
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
fn test_closure_bidirectional_type_inference() {
    let code = r#"
        pub fn main() {
            let transform: fn(i32) -> i32 = fn(x) { return x * 2; };
            let result: i32 = transform(21);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Bidirectional type inference on closure should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_closure_environment_capture_ref() {
    let code = r#"
        pub fn main() {
            let factor = 10;
            let multiplier = fn(x: i32) -> i32 {
                return x * factor;
            };
            let result = multiplier(5);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Closure capturing environment by ref should succeed: {:?}",
        res.diagnostics
    );
    // Verify that 'factor' was captured
    let has_capture = res.symbols.lambda_captures.values().any(|caps| {
        caps.iter()
            .any(|c| ifa_span::INTERNER.resolve(&c.name) == "factor" && c.is_ref)
    });
    assert!(
        has_capture,
        "Lambda should have registered 'factor' as a captured variable"
    );
}

#[test]
fn test_closure_capturing_sink_moved_var_fails() {
    let code = r#"
        pub fn consume(sink x: i32) {}

        pub fn main() {
            let val = 42;
            consume(sink val);
            let bad_closure = fn() -> i32 {
                return val;
            };
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Capturing a moved/sinked variable in a closure should fail with E0020"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 error diagnostic: {:?}",
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

#[test]
fn test_generic_function_free_and_method_call() {
    let code = r#"
        struct Box<T> {
            val: T,
        }

        fn unbox<T>(b: Box<T>) -> T {
            return b.val;
        }

        pub fn main() {
            let b1 = Box(val: 42);
            let v1: i64 = unbox(b1);
            let v2: i64 = b1.unbox();

            let b2 = Box(val: "hello");
            let s1: str = unbox(b2);
            let s2: str = b2.unbox();
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Generic function unbox<T> and method call b.unbox() should typecheck cleanly: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_function_multi_param_swap() {
    let code = r#"
        struct Pair<T, U> {
            first: T,
            second: U,
        }

        fn make_pair<T, U>(first: T, second: U) -> Pair<T, U> {
            return Pair(first: first, second: second);
        }

        fn swap<T, U>(p: Pair<T, U>) -> Pair<U, T> {
            return Pair(first: p.second, second: p.first);
        }

        pub fn main() {
            let p = make_pair(123, true);
            let swapped = p.swap();
            let first_val: bool = swapped.first;
            let second_val: i64 = swapped.second;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Generic swap<T, U> and method syntax p.swap() should typecheck cleanly: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_function_arg_mismatch_rejected() {
    let code = r#"
        fn compare_same<T>(a: T, b: T) -> bool {
            return true;
        }

        pub fn main() {
            let res = compare_same(42, "not an integer");
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Generic function with conflicting type arguments must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0001")),
        "Expected E0001 diagnostic for argument type mismatch"
    );
}

#[test]
fn test_unknown_method_call_rejected() {
    let code = r#"
        struct Simple {
            val: i64,
        }

        pub fn main() {
            let s = Simple(val: 10);
            s.non_existent_method();
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Calling unknown method must produce semantic diagnostic"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0008")),
        "Expected E0008 diagnostic for unknown method"
    );
}

#[test]
fn test_generic_trait_bound_satisfied() {
    let code = r#"
        trait Serializable {
            fn serialize(self) -> String;
        }

        struct Book {
            title: String,
        }

        fn serialize(b: Book) -> String {
            return b.title;
        }

        struct Container<T: Serializable> {
            item: T,
        }

        pub fn main() {
            let b = Book(title: "The Rust & IFA Bible");
            let c = Container(item: b);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Generic struct with satisfied trait bound must succeed, diagnostics: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_trait_bound_violation_rejected() {
    let code = r#"
        trait Serializable {
            fn serialize(self) -> String;
        }

        struct SecretKey {
            key_id: i64,
        }

        struct Container<T: Serializable> {
            item: T,
        }

        pub fn main() {
            let k = SecretKey(key_id: 12345);
            let c = Container(item: k);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Generic struct with unfulfilled trait bound must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0030")),
        "Expected E0030 diagnostic for trait bound violation, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_function_trait_bound_satisfied() {
    let code = r#"
        interface Printable {
            fn print_repr(self) -> String;
        }

        struct User {
            name: String,
        }

        fn print_repr(u: User) -> String {
            return u.name;
        }

        fn display_item<T: Printable>(item: T) -> String {
            return item.print_repr();
        }

        pub fn main() {
            let u = User(name: "Dieudonne");
            let s = display_item(u);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Generic function with satisfied trait bound must succeed, diagnostics: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_generic_function_trait_bound_violation_rejected() {
    let code = r#"
        trait Printable {
            fn print_repr(self) -> String;
        }

        struct RawBytes {
            len: i64,
        }

        fn display_item<T: Printable>(item: T) -> String {
            return "ok";
        }

        pub fn main() {
            let b = RawBytes(len: 16);
            let s = display_item(b);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Calling generic function with type violating trait bound must fail"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0030")),
        "Expected E0030 diagnostic for trait bound violation, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_impl_trait_for_type_satisfaction() {
    let code = r#"
        trait Renderable {
            fn render(self) -> String;
        }

        struct Widget {
            id: i64,
        }

        impl Renderable for Widget {
            fn render(w: Widget) -> String {
                return "widget";
            }
        }

        struct View<T: Renderable> {
            root: T,
        }

        pub fn main() {
            let w = Widget(id: 1);
            let v = View(root: w);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Explicit impl Trait for Type must satisfy generic trait bound, diagnostics: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_import_builtin_modules_and_qualified_access() {
    let code = r#"
        import std::io;
        import math;
        import encoding::json as j;

        pub fn main() {
            let s = math::sqrt(16.0);
            let pi = math::PI;
            io::println("Computed square root and PI");
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Valid imports of built-in std::io, math and encoding::json must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_import_nonexistent_module_rejected() {
    let code = r#"
        import non::existent::network::adapter;

        pub fn main() {
            let x = 42;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Importing an unknown/non-existent module must trigger a semantic error"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0010")),
        "Expected E0010 diagnostic for missing module, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_module_private_member_access_rejected() {
    use ifa_lexer::tokenize;
    use ifa_parser::parse;
    use ifa_sema::symbol_table::{FunctionSymbol, ModuleSymbol, ParamSymbol};
    use ifa_span::{sym, BytePos, FileId, SourceMap, Span};

    let mut sm = SourceMap::new();
    let fid = sm.add_file(
        "test_mod.ifa",
        r#"
        import custom::auth as auth;

        pub fn main() {
            let pub_ok = auth::login("admin");
            let priv_fail = auth::internal_hash("secret");
        }
    "#,
    );
    let tokens = tokenize(fid, sm.get_file(fid).unwrap().src.as_str());
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty());

    let mut analyzer = ifa_sema::SemanticAnalyzer::new(&sm);

    // Pre-register a custom module with 1 public and 1 private function
    let dummy = Span::new(FileId(0), BytePos(0), BytePos(0));
    let mut custom_mod = ModuleSymbol::new(
        sym("custom::auth"),
        vec![sym("custom"), sym("auth")],
        true,
        dummy,
    );
    custom_mod.add_function(FunctionSymbol {
        name: sym("login"),
        is_pub: true,
        is_strict: false,
        is_comptime: false,
        is_extern: None,
        generics: Vec::new(),
        params: vec![ParamSymbol {
            mode: ifa_ast::ParamMode::In,
            name: sym("user"),
            ty: ifa_sema::Type::String,
            span: dummy,
        }],
        ret_ty: ifa_sema::Type::Bool,
        span: dummy,
    });
    custom_mod.add_function(FunctionSymbol {
        name: sym("internal_hash"),
        is_pub: false, // Private!
        is_strict: false,
        is_comptime: false,
        is_extern: None,
        generics: Vec::new(),
        params: vec![ParamSymbol {
            mode: ifa_ast::ParamMode::In,
            name: sym("key"),
            ty: ifa_sema::Type::String,
            span: dummy,
        }],
        ret_ty: ifa_sema::Type::String,
        span: dummy,
    });
    analyzer.symbols.define_module(custom_mod).unwrap();

    let (_, diagnostics) = analyzer.analyze(&prog);
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0011")),
        "Expected E0011 diagnostic for accessing private module function, got: {:?}",
        diagnostics
    );
}

#[test]
fn test_flow_sensitive_narrowing_if_not_null() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            let opt_node: ?ref Node = null;
            if opt_node != null {
                let v: i64 = opt_node.val;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Direct member access inside 'if x != null' should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_flow_sensitive_narrowing_outside_scope_fails() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            let opt_node: ?ref Node = null;
            if opt_node != null {
                let v: i64 = opt_node.val;
            }
            let v_after: i64 = opt_node.val;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Direct member access outside guarded scope must fail"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0007")),
        "Expected E0007 on unguarded access after 'if'"
    );
}

#[test]
fn test_flow_sensitive_narrowing_if_else() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            let opt_node: ?ref Node = null;
            if opt_node == null {
                let fallback = 0;
            } else {
                let v: i64 = opt_node.val;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Direct member access inside 'else' of 'if x == null' should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_flow_sensitive_narrowing_early_return() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn get_value(opt_node: ?ref Node) -> i64 {
            if opt_node == null {
                return 0;
            }
            let v: i64 = opt_node.val;
            return v;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Direct member access following early return guard should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_flow_sensitive_narrowing_while() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            mut opt_node: ?ref Node = null;
            while opt_node != null {
                let v: i64 = opt_node.val;
                opt_node = null;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Direct member access inside 'while x != null' should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_flow_sensitive_narrowing_short_circuit_and() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            let opt_node: ?ref Node = null;
            if opt_node != null && opt_node.val > 0 {
                let v: i64 = opt_node.val;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Short-circuit 'x != null && x.val > 0' should narrow in right operand and then-branch: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_flow_sensitive_narrowing_not_equal_null() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            let opt_node: ?ref Node = null;
            if !(opt_node == null) {
                let v: i64 = opt_node.val;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Inverted condition '!(x == null)' should narrow in then-branch: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_flow_sensitive_narrowing_reassigned_null_invalidated() {
    let code = r#"
        struct Node {
            val: i64,
        }

        pub fn main() {
            mut opt_node: ?ref Node = null;
            if opt_node != null {
                let v1: i64 = opt_node.val;
                opt_node = null;
                let v2: i64 = opt_node.val;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Direct member access after reassigning null inside guarded scope must fail"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0007")),
        "Expected E0007 on access after reassigning null"
    );
}

#[test]
fn test_multiple_structs_implementing_same_trait_monomorphic_resolution() {
    let code = r#"
        trait Describable {
            fn describe(self) -> String;
        }

        struct Book {
            title: String,
        }

        impl Describable for Book {
            fn describe(b: Book) -> String {
                return b.title;
            }
        }

        struct Person {
            name: String,
        }

        impl Describable for Person {
            fn describe(p: Person) -> String {
                return p.name;
            }
        }

        fn print_item<T: Describable>(item: T) -> String {
            return item.describe();
        }

        pub fn main() {
            let b = Book(title: "The IFA Architecture");
            let p = Person(name: "Dieudonne");

            // Direct devirtualized method calls
            let desc_b = b.describe();
            let desc_p = p.describe();

            // Monomorphized generic calls
            let s1 = print_item(b);
            let s2 = print_item(p);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Multiple structs implementing same trait without method collision must succeed, diagnostics: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_match_exhaustiveness_missing_enum_variants_rejected() {
    let code = r#"
        enum Light {
            Red,
            Yellow,
            Green,
        }

        fn action(l: Light) -> i64 {
            return match l {
                Light::Red => 1,
                Light::Yellow => 2,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Non-exhaustive enum match must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0043")),
        "Expected E0043 diagnostic for non-exhaustive enum match: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_match_exhaustiveness_missing_bool_branch_rejected() {
    let code = r#"
        fn test_bool(b: bool) -> i64 {
            return match b {
                true => 10,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Non-exhaustive bool match must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0043")),
        "Expected E0043 diagnostic for non-exhaustive bool match: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_match_exhaustiveness_missing_scalar_catch_all_rejected() {
    let code = r#"
        fn classify_int(n: i64) -> i64 {
            return match n {
                0 => 100,
                1 => 200,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Match on infinite scalar domain without wildcard must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0043")),
        "Expected E0043 diagnostic for missing catch-all: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_match_unreachable_pattern_after_catch_all_rejected() {
    let code = r#"
        enum State {
            On,
            Off,
        }

        fn handle(s: State) -> i64 {
            return match s {
                _ => 1,
                State::On => 2,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Unreachable branch after wildcard must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0044")),
        "Expected E0044 diagnostic for unreachable pattern: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_match_unreachable_pattern_redundant_variant_rejected() {
    let code = r#"
        enum Color {
            Red,
            Blue,
        }

        fn inspect_color(c: Color) -> i64 {
            return match c {
                Color::Red => 1,
                Color::Red => 2,
                Color::Blue => 3,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Redundant variant pattern must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0044")),
        "Expected E0044 diagnostic for duplicate variant: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_match_exhaustive_enum_and_bool_succeeds() {
    let code = r#"
        enum OptionI64 {
            Some(i64),
            None,
        }

        fn unwrap_or_zero(opt: OptionI64) -> i64 {
            return match opt {
                OptionI64::Some(v) => v,
                OptionI64::None => 0,
            }
        }

        fn negate_bool(b: bool) -> bool {
            return match b {
                true => false,
                false => true,
            }
        }

        fn classify_with_fallback(x: i64) -> i64 {
            return match x {
                1 => 10,
                2 => 20,
                _ => 0,
            }
        }

        pub fn main() {
            let res = unwrap_or_zero(OptionI64::Some(42));
            let b = negate_bool(true);
            let c = classify_with_fallback(5);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Exhaustive pattern matches must succeed without semantic errors: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_tuple_pattern_matching_valid() {
    let code = r#"
        fn classify_pair(pair: (i64, i64)) -> i64 {
            return match pair {
                (0, 0) => 0,
                (0, y) => y,
                (x, 0) => x,
                (x, y) => x + y,
            }
        }

        pub fn main() {
            let res = classify_pair((10, 20));
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Tuple pattern matching must succeed without semantic errors: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_tuple_pattern_arite_mismatch_reported() {
    let code = r#"
        fn bad_tuple_match(pair: (i64, i64)) -> i64 {
            return match pair {
                (x, y, z) => x + y + z,
                _ => 0,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Mismatched tuple pattern arity must emit diagnostic"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0036")));
}

#[test]
fn test_struct_pattern_matching_valid() {
    let code = r#"
        struct Point {
            x: i64,
            y: i64
        }

        fn check_origin(p: Point) -> i64 {
            return match p {
                Point { x: 0, y: 0 } => 0,
                Point { x: 0, y } => y,
                Point { x, y } => x + y,
            }
        }

        pub fn main() {
            let p = Point(x: 10, y: 20);
            let c = check_origin(p);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Struct pattern matching must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_struct_pattern_with_rest_pattern_valid() {
    let code = r#"
        struct User {
            id: i64,
            name: String,
            active: bool
        }

        fn get_id(u: User) -> i64 {
            return match u {
                User { id, .. } => id,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Struct pattern with '..' rest pattern must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_struct_pattern_missing_field_without_rest_reported() {
    let code = r#"
        struct Point {
            x: i64,
            y: i64
        }

        fn partial(p: Point) -> i64 {
            return match p {
                Point { x } => x,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Omitted fields without '..' must report non-exhaustive / incomplete pattern"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0043")));
}

#[test]
fn test_nested_recursive_tuple_and_struct_patterns() {
    let code = r#"
        struct Vector {
            coords: (i64, i64),
            scale: i64
        }

        fn process_vec(v: Vector) -> i64 {
            return match v {
                Vector { coords: (0, 0), scale } => scale,
                Vector { coords: (x, y), scale } => (x + y) * scale,
            }
        }

        pub fn main() {
            let v = Vector(coords: (3, 4), scale: 2);
            let res = process_vec(v);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Nested recursive tuple and struct patterns must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_or_patterns_semantic_valid() {
    let code = r#"
        enum Coin {
            Heads,
            Tails,
            Edge
        }

        fn is_valid_flip(c: Coin) -> bool {
            return match c {
                Coin::Heads | Coin::Tails => true,
                Coin::Edge => false,
            }
        }

        fn classify_digit(d: i64) -> i64 {
            return match d {
                1 | 3 | 5 | 7 | 9 => 1,
                0 | 2 | 4 | 6 | 8 => 2,
                _ => 0,
            }
        }

        pub fn main() {
            let f = is_valid_flip(Coin::Heads);
            let d = classify_digit(3);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Or-patterns without bindings must be accepted: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_or_patterns_with_shared_bindings_valid() {
    let code = r#"
        enum ResultVal {
            Success(i64),
            Cached(i64),
            Failure
        }

        fn extract_or_default(res: ResultVal) -> i64 {
            return match res {
                ResultVal::Success(v) | ResultVal::Cached(v) => v,
                ResultVal::Failure => -1,
            }
        }

        pub fn main() {
            let val = extract_or_default(ResultVal::Cached(100));
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Or-patterns with consistent bindings must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_or_patterns_divergent_bindings_rejected() {
    let code = r#"
        enum ResultVal {
            Success(i64),
            Cached(i64),
            Failure
        }

        fn bad_or(res: ResultVal) -> i64 {
            return match res {
                ResultVal::Success(v) | ResultVal::Failure => 0,
                _ => -1,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Or-patterns with missing variable bindings in alternative must fail"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0045")));
}

#[test]
fn test_range_patterns_semantic_valid() {
    let code = r#"
        fn classify_age(age: i64) -> i64 {
            return match age {
                0..=12 => 1,
                13..=17 => 2,
                18..=64 => 3,
                _ => 4,
            }
        }

        fn combined_ranges_and_or(val: i64) -> i64 {
            return match val {
                1..=5 | 10..=15 => 100,
                _ => 0,
            }
        }

        pub fn main() {
            let a = classify_age(15);
            let c = combined_ranges_and_or(12);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Range patterns and combinations with or-patterns must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_range_pattern_non_scalar_rejected() {
    let code = r#"
        struct Point {
            x: i64
        }

        fn bad_range(p: Point) -> i64 {
            return match p {
                Point { x: 1 }..=Point { x: 2 } => 0,
                _ => 1,
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Range pattern on non-scalar struct must fail with E0036"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0036")));
}

#[test]
fn test_slice_pattern_matching_fixed_array_success() {
    let code = r#"
        fn classify_trio(arr: [i64; 3]) -> i64 {
            return match arr {
                [0, 0, 0] => 0,
                [first, 2, third] => first + third,
                [x, y, z] => x + y + z,
            };
        }

        fn classify_with_rest(arr: [i64; 4]) -> i64 {
            return match arr {
                [0, ..mid, 0] => 100,
                [first, ..mid, last] => first + last,
            };
        }

        fn test_rest_wildcards(arr: [i64; 4]) -> i64 {
            return match arr {
                [1, ..] => 1,
                [.., 9] => 9,
                [..] => 0,
            };
        }

        pub fn main() {
            let a = classify_trio([1, 2, 3]);
            let b = classify_with_rest([10, 20, 30, 40]);
            let c = test_rest_wildcards([1, 2, 3, 4]);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Slice pattern matching on fixed arrays must pass type checking: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_slice_pattern_arity_mismatch_rejected() {
    let code = r#"
        fn bad_arity(arr: [i64; 3]) -> i64 {
            return match arr {
                [a, b] => a + b,
                _ => 0,
            };
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Slice pattern with incorrect fixed arity must fail with E0036"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0036")));
}

#[test]
fn test_slice_pattern_insufficient_elements_rejected() {
    let code = r#"
        fn too_many_elements(arr: [i64; 2]) -> i64 {
            return match arr {
                [a, b, c, ..rest] => a + b + c,
                _ => 0,
            };
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Slice pattern with more elements than fixed array must fail with E0036"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0036")));
}

#[test]
fn test_slice_pattern_multiple_rest_rejected() {
    let code = r#"
        fn double_rest(arr: [i64; 4]) -> i64 {
            return match arr {
                [a, ..mid1, ..mid2, z] => a + z,
                _ => 0,
            };
        }
    "#;
    let mut source_map = SourceMap::new();
    let file_id = source_map.add_file("test_double_rest.ifa", code);
    let tokens = tokenize(file_id, code);
    let (_, diags) = parse(file_id, tokens);
    assert!(
        !diags.is_empty(),
        "Multiple rest patterns in a slice pattern must be rejected with E0046"
    );
    assert!(diags.iter().any(|d| d.code.as_deref() == Some("E0046")));
}

#[test]
fn test_slice_pattern_non_indexable_rejected() {
    let code = r#"
        fn slice_on_scalar(n: i64) -> i64 {
            return match n {
                [a, b] => a + b,
                _ => 0,
            };
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Slice pattern on non-indexable scalar must fail with E0036"
    );
    assert!(res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0036")));
}

#[test]
fn test_destructuring_let_tuple_valid() {
    let code = r#"
        fn test_tuple() -> i64 {
            let (a, b) = (10, 20);
            return a + b;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Valid tuple destructuring in let must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_mut_tuple_and_immutability() {
    let code_mut = r#"
        fn test_mut() -> i64 {
            mut (a, b) = (10, 20);
            a += 5;
            b += 10;
            return a + b;
        }
    "#;
    let res_mut = run_analysis(code_mut);
    assert!(
        !res_mut.has_errors(),
        "Mut tuple destructuring allows reassignment: {:?}",
        res_mut.diagnostics
    );

    let code_immutable = r#"
        fn test_immut() -> i64 {
            let (a, b) = (10, 20);
            a = 99;
            return a + b;
        }
    "#;
    let res_immut = run_analysis(code_immutable);
    assert!(
        res_immut.has_errors(),
        "Immutable tuple let must reject reassignment"
    );
}

#[test]
fn test_destructuring_let_struct_valid() {
    let code = r#"
        struct Vector2 {
            x: i64,
            y: i64,
        }

        fn get_sum(v: Vector2) -> i64 {
            let Vector2 { x, y } = v;
            return x + y;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Valid struct destructuring in let must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_let_slice_array_valid() {
    let code = r#"
        fn first_and_tail(arr: [i64; 4]) -> i64 {
            let [first, ..rest] = arr;
            return first;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Valid array slice destructuring in let must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_let_refutable_rejected() {
    let code_variant = r#"
        enum Status {
            Active(i64),
            Inactive,
        }

        fn test_refutable(s: Status) -> i64 {
            let Status::Active(val) = s;
            return val;
        }
    "#;
    let res_variant = run_analysis(code_variant);
    assert!(
        res_variant.has_errors(),
        "Refutable enum variant pattern in let must be rejected"
    );
    assert!(
        res_variant
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0047")),
        "Expected E0047 for refutable pattern in let"
    );

    let code_lit = r#"
        fn test_lit(x: i64) -> i64 {
            let 42 = x;
            return x;
        }
    "#;
    let res_lit = run_analysis(code_lit);
    assert!(
        res_lit.has_errors(),
        "Literal pattern in let must be rejected with E0047"
    );
    assert!(
        res_lit
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0047")),
        "Expected E0047 for literal pattern in let"
    );

    let code_dynamic_slice = r#"
        fn test_dyn_slice(s: [i64]) -> i64 {
            let [a, b] = s;
            return a + b;
        }
    "#;
    let res_dyn = run_analysis(code_dynamic_slice);
    assert!(
        res_dyn.has_errors(),
        "Dynamic slice pattern without catch-all in let must be rejected with E0047"
    );
    assert!(
        res_dyn
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0047")),
        "Expected E0047 for dynamic slice pattern in let"
    );
}

#[test]
fn test_destructuring_let_without_init_rejected() {
    let code = r#"
        fn test_no_init() {
            let (a, b);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Destructuring let without init must be rejected with E0047"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0047")),
        "Expected E0047 for destructuring let without initializer"
    );
}

#[test]
fn test_if_let_refutable_pattern_valid() {
    let code = r#"
        enum Status {
            Active(i64),
            Inactive,
        }

        fn check_status(s: Status) -> i64 {
            if let Status::Active(val) = s {
                return val;
            } else {
                return 0;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Valid refutable if let must succeed without errors: {:?}",
        res.diagnostics
    );
    assert_eq!(
        res.warning_count(),
        0,
        "No warnings expected for refutable pattern"
    );
}

#[test]
fn test_if_let_scoping_isolation() {
    let code_leak_else = r#"
        enum OptionI64 {
            Some(i64),
            None,
        }

        fn leak_in_else(opt: OptionI64) -> i64 {
            if let OptionI64::Some(x) = opt {
                return x;
            } else {
                return x;
            }
        }
    "#;
    let res_else = run_analysis(code_leak_else);
    assert!(
        res_else.has_errors(),
        "Variable bound in if let must not leak to else branch"
    );
    assert!(
        res_else
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0001") && d.message.contains("inconnu")),
        "Expected unknown variable error in else branch: {:?}",
        res_else.diagnostics
    );

    let code_leak_after = r#"
        enum OptionI64 {
            Some(i64),
            None,
        }

        fn leak_after(opt: OptionI64) -> i64 {
            if let OptionI64::Some(x) = opt {
                let _ = x;
            }
            return x;
        }
    "#;
    let res_after = run_analysis(code_leak_after);
    assert!(
        res_after.has_errors(),
        "Variable bound in if let must not leak after if let block"
    );
    assert!(
        res_after
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0001") && d.message.contains("inconnu")),
        "Expected unknown variable error after if let: {:?}",
        res_after.diagnostics
    );
}

#[test]
fn test_if_let_irrefutable_warning() {
    let code = r#"
        fn test_irrefutable(x: i64) -> i64 {
            if let val = x {
                return val;
            } else {
                return 0;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Irrefutable pattern in if let is a warning, not an error: {:?}",
        res.diagnostics
    );
    assert!(
        res.warning_count() > 0,
        "Expected warning for irrefutable pattern in if let"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("W0001")),
        "Expected W0001 warning for irrefutable pattern in if let"
    );
}

#[test]
fn test_while_let_refutable_valid_and_scoping() {
    let code = r#"
        enum Step {
            More(i64),
            Done,
        }

        fn process_all() -> i64 {
            mut total = 0;
            mut step = Step::More(5);
            while let Step::More(val) = step {
                total = total + val;
                step = Step::Done;
            }
            return total;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Valid while let must succeed without errors: {:?}",
        res.diagnostics
    );
    assert_eq!(res.warning_count(), 0);

    let code_leak_after = r#"
        enum Step {
            More(i64),
            Done,
        }

        fn leak_while(step: Step) -> i64 {
            while let Step::More(val) = step {
                let _ = val;
            }
            return val;
        }
    "#;
    let res_leak = run_analysis(code_leak_after);
    assert!(
        res_leak.has_errors(),
        "Pattern variable from while let must not leak outside loop"
    );
    assert!(
        res_leak
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0001") && d.message.contains("inconnu")),
        "Expected unknown variable error after while let: {:?}",
        res_leak.diagnostics
    );
}

#[test]
fn test_while_let_irrefutable_warning() {
    let code = r#"
        fn test_irrefutable_loop(n: i64) {
            while let x = n {
                let _ = x;
                break;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Irrefutable pattern in while let should produce warning, not error"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("W0001")),
        "Expected W0001 warning for irrefutable pattern in while let"
    );
}

#[test]
fn test_if_let_and_while_let_with_guard_valid() {
    let code = r#"
        enum ResultVal {
            Ok(i64),
            Err(i64),
        }

        fn process_positive(res: ResultVal) -> i64 {
            if let ResultVal::Ok(val) = res if val > 0 {
                return val * 10;
            } else if let ResultVal::Ok(zero) = res if zero == 0 {
                return 0;
            } else {
                return -1;
            }
        }

        fn drain_positive() -> i64 {
            mut current = ResultVal::Ok(5);
            mut sum = 0;
            while let ResultVal::Ok(v) = current if v > 0 {
                sum = sum + v;
                current = ResultVal::Ok(v - 1);
            }
            return sum;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Guarded if let and while let must validate successfully: {:?}",
        res.diagnostics
    );
    assert_eq!(res.warning_count(), 0);
}

#[test]
fn test_if_let_irrefutable_with_guard_no_warning() {
    let code = r#"
        fn test_guarded_irrefutable(x: i64) -> i64 {
            if let val = x if val > 100 {
                return val;
            } else {
                return 0;
            }
        }

        fn test_guarded_while_irrefutable(n: i64) {
            while let val = n if val < 10 {
                break;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Guarded irrefutable pattern must pass semantic analysis: {:?}",
        res.diagnostics
    );
    assert_eq!(
        res.warning_count(),
        0,
        "No W0001 warning must be emitted when an irrefutable pattern has a conditional guard"
    );
}

#[test]
fn test_if_let_guard_non_bool_error() {
    let code = r#"
        enum Opt {
            Some(i64),
            None,
        }

        fn bad_guard(o: Opt) -> i64 {
            if let Opt::Some(x) = o if x + 1 {
                return x;
            } else {
                return 0;
            }
        }

        fn bad_while_guard(o: Opt) {
            while let Opt::Some(y) = o if y * 2 {
                break;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Non-boolean guard expressions must produce semantic errors"
    );
    let guard_errors: Vec<_> = res
        .diagnostics
        .iter()
        .filter(|d| d.code.as_deref() == Some("E0034"))
        .collect();
    assert_eq!(
        guard_errors.len(),
        2,
        "Expected 2 E0034 guard errors, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_if_let_nested_patterns_with_guard() {
    let code = r#"
        struct Point {
            x: i64,
            y: i64,
        }

        enum Shape {
            Circle((Point, i64)),
            None,
        }

        fn test_nested(s: Shape) -> i64 {
            if let Shape::Circle((Point { x, y }, radius)) = s if x > 0 && y > 0 && radius > 10 {
                return x + y + radius;
            } else {
                return 0;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Nested pattern destructuring with guard in if let must validate successfully: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_assignment_tuple_and_swap() {
    let code = r#"
        pub fn main() -> i64 {
            mut a = 10;
            mut b = 20;
            (a, b) = (b, a);
            (a, _) = (100, 200);
            _ = (1, 2);
            return a + b;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Tuple destructuring assignment and swap should validate successfully: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_assignment_struct_and_slice() {
    let code = r#"
        struct Coordinate {
            lat: i64,
            lon: i64,
        }

        pub fn main() -> i64 {
            mut x = 0;
            mut y = 0;
            Coordinate { lat: x, lon: y } = Coordinate(lat: 48, lon: 2);

            mut first = 0;
            mut last = 0;
            let arr: [i64; 3] = [10, 20, 30];
            [first, .., last] = arr;

            return x + y + first + last;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Struct and slice destructuring assignment should validate successfully: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_assignment_slice_with_rest_var() {
    let code = r#"
        pub fn main() -> i64 {
            mut first = 0;
            mut middle: Slice<i64> = [];
            mut last = 0;
            let arr: [i64; 4] = [10, 20, 30, 40];
            [first, ..middle, last] = arr;
            return first + last;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Slice destructuring assignment with rest variable should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_assignment_immutable_error() {
    let code = r#"
        pub fn main() {
            let a = 10;
            mut b = 20;
            (a, b) = (1, 2);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Reassigning immutable variable 'a' in tuple destructuring must produce E0014"
    );
    let has_e0014 = res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0014"));
    assert!(
        has_e0014,
        "Expected E0014 error, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_destructuring_assignment_unknown_var_error() {
    let code = r#"
        pub fn main() {
            mut a = 10;
            (a, unknown_target) = (1, 2);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Assigning to unknown variable in pattern destructuring must fail"
    );
}

#[test]
fn test_destructuring_assignment_refutable_error() {
    let code = r#"
        enum Maybe {
            Val(i64),
            None,
        }

        pub fn main() {
            mut a = 10;
            let opt = Maybe::Val(42);
            Maybe::Val(a) = opt;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Refutable pattern in unconditional destructuring assignment must emit E0047"
    );
    let has_e0047 = res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0047"));
    assert!(
        has_e0047,
        "Expected E0047 error, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_duplicate_pattern_binding_error() {
    let code = r#"
        pub fn main() {
            let (x, x) = (10, 20);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Duplicate pattern binding 'x' must produce error E0048"
    );
    let has_e0048 = res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0048"));
    assert!(has_e0048, "Expected E0048, got: {:?}", res.diagnostics);
}

#[test]
fn test_inout_binding_on_immutable_source_error() {
    let code = r#"
        struct Point {
            x: i64,
            y: i64,
        }

        pub fn main() {
            let p = Point(x: 1, y: 2);
            let Point { inout x, y } = p;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Inout binding on immutable variable 'p' must produce error E0010"
    );
    let has_e0010 = res
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0010"));
    assert!(has_e0010, "Expected E0010, got: {:?}", res.diagnostics);
}

#[test]
fn test_inout_and_mut_binding_patterns_valid() {
    let code = r#"
        struct Point {
            x: i64,
            y: i64,
        }

        pub fn main() {
            mut p = Point(x: 10, y: 20);
            let Point { inout x, mut y } = p;
            x = x + 5;
            y = y + 10;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Valid inout and mut pattern bindings should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_ref_binding_destructuring_on_generational_ref() {
    let code = r#"
        struct Node {
            id: i64,
            value: i64,
        }

        pub fn main() {
            let n = Node(id: 1, value: 42);
            let ref node_ref = n;
            let Node { ref id, value } = node_ref;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Destructuring on generational ref should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_inout_binding_on_generational_ref_rejected() {
    let code = r#"
        struct Node {
            id: i64,
            value: i64,
        }

        pub fn main() {
            let n = Node(id: 1, value: 42);
            let ref node_ref = n;
            let Node { inout id, .. } = node_ref;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "inout binding on generational ref must be rejected"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0010")),
        "Expected E0010 for inout on ref target: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_nested_graph_struct_ref_bindings_valid() {
    let code = r#"
        struct TargetNode {
            key: i64,
        }

        struct Edge {
            weight: i64,
            target: ref TargetNode,
        }

        struct GraphNode {
            id: i64,
            edge: Edge,
        }

        pub fn main() {
            let t = TargetNode(key: 99);
            let ref target_ref = t;
            let g = GraphNode(id: 7, edge: Edge(weight: 100, target: target_ref));
            let GraphNode { id, edge: Edge { weight, ref target } } = g;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Nested graph struct with ref binding should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_tuple_ref_destructuring_valid() {
    let code = r#"
        pub fn main() {
            let pair = (10, 20);
            let ref pair_ref = pair;
            let (ref a, b) = pair_ref;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Tuple ref destructuring should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_for_loop_pattern_destructuring_semantic_success() {
    let code = r#"
        struct Point {
            x: i64,
            y: i64,
        }

        pub fn main() {
            let points = [Point(x: 1, y: 2), Point(x: 3, y: 4)];
            for Point { x, y } in points {
                let _ = x + y;
            }

            let pairs = [(10, 100), (20, 200)];
            for (idx, msg) in pairs {
                let _ = idx + msg;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "For loop pattern destructuring should succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_for_loop_pattern_duplicate_binding_semantic_error() {
    let code = r#"
        pub fn main() {
            let pairs = [(10, 20)];
            for (a, a) in pairs {
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Duplicate binding in for loop pattern must produce an error"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0048")),
        "Expected E0048 for duplicate binding, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_refutable_let_with_diverging_else_clause_valid() {
    let code = r#"
        enum OptionI64 {
            Some(i64),
            None,
        }

        pub fn unwrap_or_zero(opt: OptionI64) -> i64 {
            let OptionI64::Some(val) = opt else {
                return 0;
            };
            return val + 1;
        }

        pub fn fail_on_none(opt: OptionI64) -> String!i64 {
            let OptionI64::Some(val) = opt else {
                fail "missing value";
            };
            return val * 2;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Refutable let with diverging else must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_refutable_let_else_non_divergent_rejected() {
    let code = r#"
        enum Status {
            Active(i64),
            Inactive,
        }

        pub fn test(s: Status) -> i64 {
            let Status::Active(code) = s else {
                let _ = 123;
            };
            return code;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Non-diverging else block in let ... else must produce an error"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0049")),
        "Expected E0049 for non-divergent else block, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_irrefutable_let_else_warning() {
    let code = r#"
        pub fn test(pair: (i64, i64)) -> i64 {
            let (a, b) = pair else {
                return 0;
            };
            return a + b;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Irrefutable let with else should not error: {:?}",
        res.diagnostics
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("W0001")),
        "Expected W0001 warning for irrefutable pattern in let ... else, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_refutable_destructuring_assignment_with_else_valid() {
    let code = r#"
        enum Token {
            Number(i64),
            Identifier,
        }

        pub fn parse_num(t: Token) -> i64 {
            mut val = 0;
            Token::Number(val) = t else {
                return -1;
            };
            return val;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Refutable destructuring assignment with diverging else must succeed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_refutable_destructuring_assignment_non_divergent_rejected() {
    let code = r#"
        enum Token {
            Number(i64),
            Identifier,
        }

        pub fn parse_num(t: Token) -> i64 {
            mut val = 0;
            Token::Number(val) = t else {
                val = 42;
            };
            return val;
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Non-diverging else block in destructuring assignment must produce an error"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0049")),
        "Expected E0049 for non-divergent assignment else, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_law_of_exclusivity_for_loop_mutation_rejected() {
    let code = r#"
        pub fn main() {
            mut items: [i64; 3] = [1, 2, 3];
            for x in items {
                items[0] = 99;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Mutating iterable array inside for loop must violate exclusivity"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0012")),
        "Expected E0012 diagnostic code for loop mutation, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_law_of_exclusivity_for_loop_disjoint_field_allowed() {
    let code = r#"
        struct State {
            items: [i64; 3],
            counter: i64,
        }

        pub fn main() {
            mut s = State { items: [10, 20, 30], counter: 0 };
            for x in s.items {
                s.counter = s.counter + 1;
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Mutating provably disjoint struct field during for-loop must be allowed: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_law_of_exclusivity_for_loop_inout_call_rejected() {
    let code = r#"
        fn modify_slice(inout target: [i64; 3]) {
            target[0] = 42;
        }

        pub fn main() {
            mut items: [i64; 3] = [1, 2, 3];
            for x in items {
                modify_slice(inout items);
            }
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Passing iterable inout during for-loop must violate exclusivity"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0012")),
        "Expected E0012 for inout call on active iterable borrow, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_law_of_exclusivity_ref_and_inout_conflict() {
    let code = r#"
        fn compare_and_mutate(r: ref i64, inout target: i64) {
            target = target + 1;
        }

        pub fn main() {
            mut x: i64 = 10;
            compare_and_mutate(ref x, inout x);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Concurrent ref and inout on same variable must violate exclusivity"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0012")),
        "Expected E0012 for ref and inout conflict, got: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_law_of_exclusivity_ref_disjoint_fields_allowed() {
    let code = r#"
        struct Pair {
            a: i64,
            b: i64,
        }

        fn update_with_ref(r: ref i64, inout target: i64) {
            target = target + 1;
        }

        pub fn main() {
            mut p = Pair { a: 10, b: 20 };
            update_with_ref(ref p.a, inout p.b);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        !res.has_errors(),
        "Concurrent ref and inout on provably disjoint fields must be permitted: {:?}",
        res.diagnostics
    );
}

#[test]
fn test_law_of_exclusivity_ref_overlapping_fields_rejected() {
    let code = r#"
        struct Sub {
            val: i64,
        }
        struct Wrapper {
            child: Sub,
        }

        fn inspect_and_mod(r: ref Wrapper, inout target: i64) {
            target = target + 1;
        }

        pub fn main() {
            mut w = Wrapper { child: Sub { val: 42 } };
            inspect_and_mod(ref w, inout w.child.val);
        }
    "#;
    let res = run_analysis(code);
    assert!(
        res.has_errors(),
        "Overlapping ref and inout paths must violate exclusivity"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0012")),
        "Expected E0012 for overlapping ref and child inout, got: {:?}",
        res.diagnostics
    );
}
