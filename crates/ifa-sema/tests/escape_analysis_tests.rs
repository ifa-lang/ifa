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
    assert!(parse_diags.is_empty());

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
    assert!(parse_diags.is_empty());

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
    assert!(parse_diags.is_empty());

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
    assert!(parse_diags.is_empty());

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
    assert!(parse_diags.is_empty());

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
    assert!(parse_diags.is_empty());

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
    assert!(parse_diags.is_empty());

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());
}
