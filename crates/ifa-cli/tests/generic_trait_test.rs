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
fn test_generic_trait_bound_end_to_end() {
    let ifa_bin = get_ifa_binary();
    let temp_file =
        std::env::temp_dir().join(format!("test_generic_trait_{}.ifa", std::process::id()));

    let source = r#"
trait Serializable {
    fn serialize(self) -> String;
}

struct Article {
    title: String,
    reads: i64,
}

fn serialize(a: Article) -> String {
    return a.title;
}

struct Container<T: Serializable> {
    item: T,
}

fn dump_item<T: Serializable>(c: Container<T>) -> String {
    return c.item.serialize();
}

pub fn main() {
    let art = Article(title: "Architecture IFA Moderne", reads: 1250);
    let ser_str = art.serialize();
    println("Article serialized:", ser_str);

    let cont = Container(item: art);
    let dumped = dump_item(cont);
    println("Container dumped:", dumped);
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
        "ifa check failed on generic trait bounds"
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
        run_stdout.contains("Article serialized: Architecture IFA Moderne"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Container dumped: Architecture IFA Moderne"),
        "stdout was: {}",
        run_stdout
    );

    let _ = fs::remove_file(temp_file);
}

#[test]
fn test_generic_trait_bound_violation_rejected_cli() {
    let ifa_bin = get_ifa_binary();
    let temp_file = std::env::temp_dir().join(format!(
        "test_generic_trait_fail_{}.ifa",
        std::process::id()
    ));

    let invalid_source = r#"
trait Serializable {
    fn serialize(self) -> String;
}

struct UnserializableRawBuffer {
    capacity: i64,
}

struct Container<T: Serializable> {
    item: T,
}

pub fn main() {
    let raw = UnserializableRawBuffer(capacity: 1024);
    // Must be rejected: UnserializableRawBuffer does not implement Serializable
    let c = Container(item: raw);
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
        "ifa check should have rejected trait bound violation"
    );

    let stderr = String::from_utf8_lossy(&check_output.stderr);
    let stdout = String::from_utf8_lossy(&check_output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("E0030") || combined.contains("ne satisfait pas la contrainte"),
        "Output did not contain expected diagnostic. Got:\n{}",
        combined
    );

    let _ = fs::remove_file(temp_file);
}
