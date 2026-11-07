use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_ifa_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("current exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("ifa");
    path
}

#[test]
fn test_generic_struct_end_to_end() {
    let ifa_bin = get_ifa_binary();
    let temp_file = std::env::temp_dir().join(format!("test_generic_{}.ifa", std::process::id()));

    let source = r#"
struct Box<T> {
    val: T,
}

struct Pair<T, U> {
    first: T,
    second: U,
}

fn unbox_i64(b: Box<i64>) -> i64 {
    return b.val;
}

pub fn main() {
    let b = Box(val: 42);
    let v = unbox_i64(b);
    println("Boxed value:", v);

    let p = Pair(first: 100, second: "hello");
    println("Pair first:", p.first);
    println("Pair second:", p.second);
}
"#;

    fs::write(&temp_file, source).expect("Failed to write test file");

    // 1. Static check
    let check_status = Command::new(&ifa_bin)
        .arg("check")
        .arg(&temp_file)
        .status()
        .expect("Failed to execute `ifa check`");
    assert!(check_status.success(), "ifa check failed on generic struct");

    // 2. Execution
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
        run_stdout.contains("Boxed value: 42"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Pair first: 100"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Pair second: hello"),
        "stdout was: {}",
        run_stdout
    );

    let _ = fs::remove_file(&temp_file);
}
