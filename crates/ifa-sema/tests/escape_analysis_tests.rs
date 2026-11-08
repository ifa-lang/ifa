use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_stack_ref_escape_detection() {
    let src = r#"
pub fn escape_local() -> ref i64 {
    let x = 42
    return ref x
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("escape.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0021")));
}

#[test]
fn test_strict_fn_ref_disallowed() {
    let src = r#"
pub strict fn compute(x: i64) -> () {
    let r = ref x
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_ref.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0020")));
}

#[test]
fn test_cyclic_object_graph_in_strict_disallowed() {
    let src = r#"
struct Node {
    id: i64,
    next: ?ref Node,
    prev: ?ref Node,
}

pub strict fn make_cycle() -> () {
    mut a = Node { id: 1, next: nil, prev: nil }
    mut b = Node { id: 2, next: nil, prev: nil }
    a.next = ref b
    b.prev = ref a
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("cycle_strict.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0020")));
}

#[test]
fn test_concurrent_mutation_in_spawn_detected() {
    let src = r#"
pub fn spawn_race() -> () {
    mut counter = 0
    spawn {
        counter = counter + 1
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("spawn_race.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0025")));
}

#[test]
fn test_concurrent_inout_in_spawn_detected() {
    let src = r#"
fn increment(inout val: i64) -> () {
    val = val + 1
}

pub fn spawn_inout() -> () {
    mut counter = 10
    spawn {
        increment(inout counter)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("spawn_inout.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0025")));
}

#[test]
fn test_concurrent_read_only_copy_in_spawn_allowed() {
    let src = r#"
fn process(val: i64) -> () {
    let _ = val
}

pub fn spawn_read() -> () {
    let counter = 10
    spawn {
        let local_val = counter
        process(local_val)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("spawn_read.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());
}

#[test]
fn test_transitive_cyclic_graph_promotion() {
    let src = r#"
struct Node {
    id: i64,
    link: ?ref Node,
}

pub fn make_transitive_cycle() -> () {
    mut a = Node { id: 1, link: nil }
    mut b = Node { id: 2, link: nil }
    mut c = Node { id: 3, link: nil }
    a.link = ref b
    b.link = ref c
    c.link = ref a
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("transitive_cycle.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());
}

#[test]
fn test_generic_container_scalar_projection_ref_escape() {
    let src = r#"
struct Container<T> {
    item: T,
    id: i64,
}

pub fn leak_field() -> ref i64 {
    let c = Container(item: 42, id: 1)
    return ref c.item
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("leak_field.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0021")));
}

#[test]
fn test_generic_container_holding_local_ref_escapes() {
    let src = r#"
struct Container<T> {
    item: T,
    id: i64,
}

pub fn leak_container() -> Container<ref i64> {
    let x = 42
    let c = Container(item: ref x, id: 1)
    return c
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("leak_container.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0021")));
}

#[test]
fn test_generic_container_projection_resolving_to_local_ref_escapes() {
    let src = r#"
struct Container<T> {
    item: T,
    id: i64,
}

pub fn leak_projection_val() -> ref i64 {
    let x = 42
    let c = Container(item: ref x, id: 1)
    return c.item
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("leak_proj_val.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0021")));
}

#[test]
fn test_stack_array_scalar_projection_ref_escape() {
    let src = r#"
pub fn leak_array_elem() -> ref i64 {
    let arr = [10, 20, 30]
    return ref arr[1]
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("leak_arr.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0021")));
}

#[test]
fn test_strict_fn_generic_container_ref_disallowed() {
    let src = r#"
struct Box<T> {
    val: T,
}

pub strict fn strict_container() -> () {
    let b = Box(val: 42)
    let r = ref b.val
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_box.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0020")));
}

#[test]
fn test_strict_fn_generic_container_stack_projection_allowed() {
    let src = r#"
struct Box<T> {
    val: T,
}

pub strict fn compute_box() -> i64 {
    let b = Box(val: 42)
    return b.val
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("compute_box.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());
}

#[test]
fn test_spawn_concurrent_scalar_projection_mutation() {
    let src = r#"
struct Container<T> {
    item: T,
    id: i64,
}

pub fn spawn_field_race() -> () {
    mut c = Container(item: 10, id: 1)
    spawn {
        c.item = 20
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("spawn_field_race.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0025")));
}

#[test]
fn test_spawn_concurrent_array_index_mutation() {
    let src = r#"
pub fn spawn_arr_race() -> () {
    mut arr = [1, 2, 3]
    spawn {
        arr[0] = 99
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("spawn_arr_race.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0025")));
}

#[test]
fn test_in_param_generic_container_ref_escape_disallowed() {
    let src = r#"
struct Container<T> {
    item: T,
}

pub fn return_param_ref(in c: Container<i64>) -> ref i64 {
    return ref c.item
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("return_param_ref.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0021")));
}

#[test]
fn test_nested_generic_container_ref_propagation() {
    let src = r#"
struct Box<T> {
    val: T,
}

struct Pair<A, B> {
    first: A,
    second: B,
}

pub fn leak_nested() -> Pair<Box<ref i64>, i64> {
    let x = 100
    let b = Box(val: ref x)
    let p = Pair(first: b, second: 200)
    return p
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("leak_nested.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0021")));
}

#[test]
fn test_generic_container_cyclic_graph_strict_disallowed() {
    let src = r#"
struct Node<T> {
    data: T,
    link: ?ref Node<T>,
}

pub strict fn make_generic_cycle() -> () {
    mut a = Node(data: 1, link: nil)
    mut b = Node(data: 2, link: nil)
    a.link = ref b
    b.link = ref a
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("generic_cycle_strict.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0020")));
}

#[test]
fn test_strict_fn_ref_in_pattern_rejected() {
    let src = r#"
struct Point {
    x: i64,
    y: i64,
}

pub strict fn process_strict() -> () {
    let p = Point(x: 10, y: 20)
    let Point { ref x, y } = p
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_pattern_ref.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for ref in pattern under strict mode: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_return_ref_bound_from_local_stack_rejected() {
    let src = r#"
struct Point {
    x: i64,
    y: i64,
}

pub fn leak_pattern_ref() -> ref i64 {
    let p = Point(x: 10, y: 20)
    let Point { ref x, y } = p
    return x
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("leak_pattern_ref.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0021")),
        "Expected E0021 for returning ref bound from local stack: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_spawn_ref_bound_from_parent_local_stack_rejected() {
    let src = r#"
struct Point {
    x: i64,
    y: i64,
}

pub fn spawn_pattern_ref() -> () {
    let p = Point(x: 10, y: 20)
    spawn {
        let Point { ref x, y } = p
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("spawn_pattern_ref.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0025")),
        "Expected E0025 for borrowing parent stack in spawn pattern: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_string_interp_rejected() {
    let src = r#"
pub strict fn format_error_code(code: i64) -> () {
    let msg = "Erreur: {code}"
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_interp.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for heap-allocated string interpolation in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_string_concat_rejected() {
    let src = r#"
pub strict fn concat_strings() -> () {
    let s = "cle_" + "valeur"
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_concat.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for heap-allocated string concatenation in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_spawn_rejected() {
    let src = r#"
pub strict fn run_concurrent_task() -> () {
    spawn {
        let x = 100
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_spawn.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for spawn in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_list_allocation_rejected() {
    let src = r#"
pub strict fn run_dynamic_list() -> () {
    let l = List::new()
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_list.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for List::new in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_string_return_rejected() {
    let src = r#"
pub strict fn get_dynamic_name() -> String {
    return "alpha"
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_ret_string.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for String return type in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_disjoint_slice_spawns_allowed() {
    let src = r#"
fn worker(inout s: Slice<i64>) -> () {
    s[0] = 42
}

pub fn spawn_disjoint_slices() -> () {
    mut buf = [1, 2, 3, 4, 5, 6, 7, 8]
    spawn {
        worker(inout buf[0..4])
    }
    spawn {
        worker(inout buf[4..8])
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("disjoint_spawns.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Concurrent spawns with provably disjoint slice projections must be allowed: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_overlapping_slice_spawns_rejected() {
    let src = r#"
fn worker(inout s: Slice<i64>) -> () {
    s[0] = 42
}

pub fn spawn_overlapping_slices() -> () {
    mut buf = [1, 2, 3, 4, 5, 6, 7, 8]
    spawn {
        worker(inout buf[0..5])
    }
    spawn {
        worker(inout buf[4..8])
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("overlapping_spawns.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Concurrent spawns with overlapping slice projections must trigger E0025"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0025")),
        "Expected E0025 for overlapping slice spawns: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_disjoint_field_spawns_allowed() {
    let src = r#"
struct Node {
    lhs: i64,
    rhs: i64,
}

fn mutate_field(inout f: i64) -> () {
    f = f + 1
}

pub fn spawn_disjoint_fields() -> () {
    mut node = Node(lhs: 10, rhs: 20)
    spawn {
        mutate_field(inout node.lhs)
    }
    spawn {
        mutate_field(inout node.rhs)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("disjoint_field_spawns.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Concurrent spawns on provably disjoint struct fields must be allowed: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_overlapping_field_spawns_rejected() {
    let src = r#"
struct Node {
    lhs: i64,
    rhs: i64,
}

fn mutate_field(inout f: i64) -> () {
    f = f + 1
}

pub fn spawn_overlapping_fields() -> () {
    mut node = Node(lhs: 10, rhs: 20)
    spawn {
        mutate_field(inout node.lhs)
    }
    spawn {
        mutate_field(inout node.lhs)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("overlapping_field_spawns.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Concurrent spawns on same struct field must trigger E0025"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0025")),
        "Expected E0025 for overlapping field spawns: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_read_write_field_spawns_conflict() {
    let src = r#"
struct Node {
    lhs: i64,
    rhs: i64,
}

fn mutate_field(inout f: i64) -> () {
    f = f + 1
}

fn inspect_field(f: ref i64) -> i64 {
    let _ = f
    42
}

pub fn spawn_rw_conflict() -> () {
    mut node = Node(lhs: 10, rhs: 20)
    spawn {
        mutate_field(inout node.lhs)
    }
    spawn {
        let _ = inspect_field(ref node.lhs)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("rw_conflict.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Concurrent read-write on same struct field must trigger E0025"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0025")),
        "Expected E0025 for read-write conflict on same field: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_disjoint_field_read_write_spawns_allowed() {
    let src = r#"
struct Node {
    lhs: i64,
    rhs: i64,
}

fn mutate_field(inout f: i64) -> () {
    f = f + 1
}

fn inspect_field(f: ref i64) -> i64 {
    let _ = f
    42
}

pub fn spawn_rw_disjoint() -> () {
    mut node = Node(lhs: 10, rhs: 20)
    spawn {
        mutate_field(inout node.lhs)
    }
    spawn {
        let _ = inspect_field(ref node.rhs)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("rw_disjoint.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Concurrent read and write on provably disjoint struct fields must be allowed: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_multi_reader_field_spawns_allowed() {
    let src = r#"
struct Node {
    lhs: i64,
    rhs: i64,
}

fn inspect_field(f: ref i64) -> i64 {
    let _ = f
    42
}

pub fn spawn_multi_readers() -> () {
    let node = Node(lhs: 10, rhs: 20)
    spawn {
        let _ = inspect_field(ref node.lhs)
    }
    spawn {
        let _ = inspect_field(ref node.lhs)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("multi_readers.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Concurrent multiple readers on the same field must be allowed without race: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_sink_conflict_spawns_rejected() {
    let src = r#"
struct Node {
    lhs: i64,
    rhs: i64,
}

fn consume_field(sink f: i64) -> () {
    let _ = f
}

fn mutate_field(inout f: i64) -> () {
    f = f + 1
}

pub fn spawn_sink_conflict() -> () {
    mut node = Node(lhs: 10, rhs: 20)
    spawn {
        consume_field(sink node.lhs)
    }
    spawn {
        mutate_field(inout node.lhs)
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("sink_conflict.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Concurrent sink and write on same struct field must trigger E0025"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0025")),
        "Expected E0025 for sink conflict: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_slice_read_write_disjoint_allowed() {
    let src = r#"
fn mutate_slice(inout s: Slice<i64>) -> () {
    s[0] = 42
}

fn inspect_slice(s: Slice<i64>) -> () {
    let _ = s[0]
}

pub fn spawn_slice_disjoint() -> () {
    mut buf = [1, 2, 3, 4, 5, 6, 7, 8]
    spawn {
        inspect_slice(ref buf[0..4])
    }
    spawn {
        mutate_slice(inout buf[4..8])
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("slice_disjoint.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Disjoint slice read-write across concurrent spawns must be allowed: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_concurrent_slice_read_write_overlapping_rejected() {
    let src = r#"
fn mutate_slice(inout s: Slice<i64>) -> () {
    s[0] = 42
}

fn inspect_slice(s: Slice<i64>) -> () {
    let _ = s[0]
}

pub fn spawn_slice_overlapping() -> () {
    mut buf = [1, 2, 3, 4, 5, 6, 7, 8]
    spawn {
        inspect_slice(ref buf[2..6])
    }
    spawn {
        mutate_slice(inout buf[4..8])
    }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("slice_overlapping.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Overlapping slice read-write across concurrent spawns must trigger E0025"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0025")),
        "Expected E0025 for overlapping slice read-write conflict: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_hidden_cow_mutation_rejected() {
    let src = r#"
pub strict fn process_array() -> () {
    mut a = [1, 2, 3, 4]
    let b = a
    a[0] = 99
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_cow.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Hidden Copy-on-Write mutation on shared array in strict fn must be rejected"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for hidden CoW mutation in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_sink_transfer_avoids_cow_allowed() {
    let src = r#"
pub strict fn process_unique_transfer() -> () {
    mut a = [1, 2, 3, 4]
    mut b = sink a
    b[0] = 99
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_sink_unique.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Exclusive sink transfer avoids CoW and must succeed in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_closure_capture_heap_promotion_rejected() {
    let src = r#"
pub strict fn compute_with_closure() -> () {
    let factor = 10
    let mul = fn(x: i64) -> i64 { x * factor }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_closure_capture.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Closure capturing local stack variable in strict fn must be rejected (implicit heap promotion)"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for closure capture heap promotion in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_closure_pure_no_capture_allowed() {
    let src = r#"
pub strict fn compute_pure_closure() -> () {
    let double = fn(x: i64) -> i64 { x * 2 }
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_closure_pure.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Pure non-capturing closure without heap allocation must succeed in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_stack_array_slice_return_heap_promotion_rejected() {
    let src = r#"
pub strict fn leak_stack_array() -> Slice<i64> {
    let buf = [1, 2, 3, 4]
    return buf[0..2]
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_slice_ret.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Returning a slice pointing to local stack array in strict fn must be rejected"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for returning stack array slice in strict fn: {:?}",
        analysis.diagnostics
    );
}

#[test]
fn test_strict_fn_shared_struct_field_mutation_cow_rejected() {
    let src = r#"
struct Point {
    x: i64,
    y: i64,
}

pub strict fn process_struct() -> () {
    mut p = Point(x: 10, y: 20)
    let q = p
    p.x = 42
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_struct_cow.ifa".to_string(), src);
    let (prog, parse_diags) = parse(fid, tokenize(fid, src));
    assert!(parse_diags.is_empty(), "parse_diags: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        analysis.has_errors(),
        "Mutating shared struct field requiring CoW in strict fn must be rejected"
    );
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E0020")),
        "Expected E0020 for mutating shared struct field in strict fn: {:?}",
        analysis.diagnostics
    );
}
