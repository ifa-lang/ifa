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
