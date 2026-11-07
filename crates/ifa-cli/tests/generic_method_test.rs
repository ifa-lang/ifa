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
fn test_generic_function_and_polymorphic_method_end_to_end() {
    let ifa_bin = get_ifa_binary();
    let temp_file =
        std::env::temp_dir().join(format!("test_generic_method_{}.ifa", std::process::id()));

    let source = r#"
struct Box<T> {
    val: T,
}

struct Pair<T, U> {
    first: T,
    second: U,
}

fn unbox<T>(b: Box<T>) -> T {
    return b.val;
}

fn duplicate<T>(b: Box<T>) -> Pair<T, T> {
    return Pair(first: b.val, second: b.val);
}

fn swap<T, U>(p: Pair<T, U>) -> Pair<U, T> {
    return Pair(first: p.second, second: p.first);
}

pub fn main() {
    let b = Box(val: 99);
    let v1 = unbox(b);
    let v2 = b.unbox();
    println("Free unbox:", v1);
    println("Method unbox:", v2);

    let d = b.duplicate();
    println("Duplicated first:", d.first);
    println("Duplicated second:", d.second);

    let p = Pair(first: 777, second: "golden");
    let sw = p.swap();
    println("Swapped first:", sw.first);
    println("Swapped second:", sw.second);
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
        "ifa check failed on generic function and method calls"
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
        run_stdout.contains("Free unbox: 99"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Method unbox: 99"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Duplicated first: 99"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Duplicated second: 99"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Swapped first: golden"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Swapped second: 777"),
        "stdout was: {}",
        run_stdout
    );

    let _ = fs::remove_file(&temp_file);
}
