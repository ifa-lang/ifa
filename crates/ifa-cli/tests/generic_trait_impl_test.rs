use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_ifa_binary() -> PathBuf {
    if let Some(bin) = option_env!("CARGO_BIN_EXE_ifa") {
        let p = PathBuf::from(bin);
        if p.exists() {
            return p;
        }
    }
    let mut path = std::env::current_exe().expect("current exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push(if cfg!(windows) { "ifa.exe" } else { "ifa" });
    path
}

#[test]
fn test_generic_trait_impl_and_devirtualization_end_to_end() {
    let ifa_bin = get_ifa_binary();
    let temp_file = std::env::temp_dir().join(format!(
        "test_generic_trait_impl_{}.ifa",
        std::process::id()
    ));

    let source = r#"
trait Display {
    fn display(self) -> String;
}

struct Book {
    title: String,
}

impl Display for Book {
    fn display(b: Book) -> String {
        return b.title;
    }
}

trait Printable {
    fn print(self) -> String;
}

struct Container<T> {
    item: T,
}

impl<T: Display> Printable for Container<T> {
    fn print(c: Container<T>) -> String {
        return c.item.display();
    }
}

fn render_item<U: Printable>(x: U) -> String {
    return x.print();
}

pub fn main() {
    let b = Book(title: "The Deterministic IFA Architecture");
    let c = Container(item: b);

    // Direct devirtualized method call
    let direct_res = c.print();
    println("Direct print:", direct_res);

    // Monomorphized generic function dispatch
    let generic_res = render_item(c);
    println("Rendered item:", generic_res);
}
"#;

    fs::write(&temp_file, source).expect("Failed to write test file");

    // 1. Static check
    let check_status = Command::new(&ifa_bin)
        .arg("check")
        .arg(&temp_file)
        .status()
        .expect("Failed to execute `ifa check`");
    assert!(
        check_status.success(),
        "ifa check failed on generic trait impl for generic struct"
    );

    // 2. Execution via interpreter
    let run_output = Command::new(&ifa_bin)
        .arg("run")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute `ifa run`");

    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(
        run_output.status.success(),
        "ifa run failed with code {:?}\nstdout: {}\nstderr: {}",
        run_output.status.code(),
        run_stdout,
        String::from_utf8_lossy(&run_output.stderr)
    );

    assert!(
        run_stdout.contains("Direct print: The Deterministic IFA Architecture"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Rendered item: The Deterministic IFA Architecture"),
        "stdout was: {}",
        run_stdout
    );

    let _ = fs::remove_file(temp_file);
}

#[test]
fn test_generic_trait_impl_bound_violation_rejected_statically() {
    let ifa_bin = get_ifa_binary();
    let temp_file = std::env::temp_dir().join(format!(
        "test_generic_trait_impl_fail_{}.ifa",
        std::process::id()
    ));

    let invalid_source = r#"
trait Display {
    fn display(self) -> String;
}

struct RawPacket {
    size: i64,
}

trait Printable {
    fn print(self) -> String;
}

struct Container<T> {
    item: T,
}

impl<T: Display> Printable for Container<T> {
    fn print(c: Container<T>) -> String {
        return c.item.display();
    }
}

fn render_item<U: Printable>(x: U) -> String {
    return x.print();
}

pub fn main() {
    let raw = RawPacket(size: 256);
    let c = Container(item: raw);

    // Must be rejected with E0030: RawPacket does not implement Display,
    // so Container<RawPacket> does not implement Printable!
    let res = render_item(c);
}
"#;

    fs::write(&temp_file, invalid_source).expect("Failed to write test file");

    let check_output = Command::new(&ifa_bin)
        .arg("check")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute `ifa check`");

    assert!(
        !check_output.status.success(),
        "ifa check should have rejected trait bound violation on generic trait implementation"
    );

    let stderr = String::from_utf8_lossy(&check_output.stderr);
    let stdout = String::from_utf8_lossy(&check_output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("E0030") || combined.contains("ne satisfait pas la contrainte"),
        "Expected E0030 diagnostic, got:\n{}",
        combined
    );

    let _ = fs::remove_file(temp_file);
}

#[test]
fn test_nested_generic_struct_path_sensitive_exclusivity() {
    let ifa_bin = get_ifa_binary();
    let temp_ok = std::env::temp_dir().join(format!(
        "test_nested_exclusivity_ok_{}.ifa",
        std::process::id()
    ));
    let temp_overlap = std::env::temp_dir().join(format!(
        "test_nested_exclusivity_err_{}.ifa",
        std::process::id()
    ));

    let valid_source = r#"
struct Inner<T> {
    val: T,
}

struct Pair<T> {
    first: Inner<T>,
    second: Inner<T>,
}

fn mutate_both(inout a: i64, inout b: i64) {
    a = a + 1;
    b = b + 2;
}

pub fn main() {
    let mut p = Pair(
        first: Inner(val: 10),
        second: Inner(val: 20),
    );

    // Distinct nested fields: proven disjoint paths p.first.val and p.second.val!
    mutate_both(inout p.first.val, inout p.second.val);
    println("First updated:", p.first.val);
    println("Second updated:", p.second.val);
}
"#;

    fs::write(&temp_ok, valid_source).expect("Failed to write test file");

    let check_status = Command::new(&ifa_bin)
        .arg("check")
        .arg(&temp_ok)
        .status()
        .expect("Failed to execute `ifa check`");
    assert!(
        check_status.success(),
        "Path-sensitive disjoint nested fields should pass exclusivity checks"
    );

    let run_output = Command::new(&ifa_bin)
        .arg("run")
        .arg(&temp_ok)
        .output()
        .expect("Failed to execute `ifa run`");
    assert!(run_output.status.success());
    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(run_stdout.contains("First updated: 11"));
    assert!(run_stdout.contains("Second updated: 22"));

    // Now test overlapping nested path rejection
    let overlapping_source = r#"
struct Inner<T> {
    val: T,
}

struct Pair<T> {
    first: Inner<T>,
    second: Inner<T>,
}

fn mutate_both(inout a: i64, inout b: i64) {
    a = a + 1;
    b = b + 2;
}

pub fn main() {
    let mut p = Pair(
        first: Inner(val: 10),
        second: Inner(val: 20),
    );

    // Overlapping paths: same nested field p.first.val twice!
    mutate_both(inout p.first.val, inout p.first.val);
}
"#;

    fs::write(&temp_overlap, overlapping_source).expect("Failed to write test file");

    let check_err = Command::new(&ifa_bin)
        .arg("check")
        .arg(&temp_overlap)
        .output()
        .expect("Failed to execute `ifa check`");

    assert!(
        !check_err.status.success(),
        "Overlapping nested field inout borrowing must be statically rejected"
    );

    let stderr = String::from_utf8_lossy(&check_err.stderr);
    let stdout = String::from_utf8_lossy(&check_err.stdout);
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("E0011") || combined.contains("loi d'exclusivité violée"),
        "Expected E0011 diagnostic for overlapping nested inout borrow, got:\n{}",
        combined
    );

    let _ = fs::remove_file(temp_ok);
    let _ = fs::remove_file(temp_overlap);
}

#[test]
fn test_multi_parameter_where_clauses_execution_end_to_end() {
    let ifa_bin = get_ifa_binary();
    let temp_file =
        std::env::temp_dir().join(format!("test_multi_param_where_{}.ifa", std::process::id()));

    let source = r#"
trait Display {
    fn display(self) -> String;
}

trait Serializable {
    fn serialize(self) -> String;
}

trait Summarize {
    fn summary(self) -> String;
}

struct Article {
    title: String,
}

impl Display for Article {
    fn display(a: Article) -> String {
        return a.title;
    }
}

impl Serializable for Article {
    fn serialize(a: Article) -> String {
        return a.title;
    }
}

struct Tag {
    label: String,
}

impl Summarize for Tag {
    fn summary(t: Tag) -> String {
        return t.label;
    }
}

struct Envelope<T, U>
where T: Display + Serializable, U: Summarize {
    content: T,
    meta: U,
}

impl<T, U> Envelope<T, U>
where T: Display + Serializable, U: Summarize {
    fn format_both(env: Envelope<T, U>) -> String {
        let c_str = env.content.display();
        let m_str = env.meta.summary();
        return c_str;
    }
}

fn render_envelope<A, B>(env: Envelope<A, B>) -> String
where A: Display + Serializable, B: Summarize {
    return env.format_both();
}

pub fn main() {
    let art = Article(title: "Deterministic Compilation with Where Clauses");
    let tg = Tag(label: "IFA-v0.1");

    let env = Envelope(content: art, meta: tg);

    // Direct devirtualized method call on struct with where clause
    let d = env.format_both();
    println("Direct formatted:", d);

    // Monomorphized function call with multi-parameter where clause
    let r = render_envelope(env);
    println("Rendered envelope:", r);
}
"#;

    fs::write(&temp_file, source).expect("Failed to write test file");

    let check_status = Command::new(&ifa_bin)
        .arg("check")
        .arg(&temp_file)
        .status()
        .expect("Failed to execute `ifa check`");
    assert!(
        check_status.success(),
        "ifa check failed on multi-parameter where clause"
    );

    let run_output = Command::new(&ifa_bin)
        .arg("run")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute `ifa run`");

    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(
        run_output.status.success(),
        "ifa run failed with code {:?}\nstdout: {}\nstderr: {}",
        run_output.status.code(),
        run_stdout,
        String::from_utf8_lossy(&run_output.stderr)
    );

    assert!(
        run_stdout.contains("Direct formatted: Deterministic Compilation with Where Clauses"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Rendered envelope: Deterministic Compilation with Where Clauses"),
        "stdout was: {}",
        run_stdout
    );

    let _ = fs::remove_file(temp_file);
}
