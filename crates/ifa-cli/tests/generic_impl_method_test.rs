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
fn test_generic_struct_impl_methods_end_to_end() {
    let ifa_bin = get_ifa_binary();
    let temp_file =
        std::env::temp_dir().join(format!("test_generic_impl_{}.ifa", std::process::id()));

    let source = r#"
struct Container<T> {
    value: T,
}

impl<T> Container<T> {
    fn get_value(self) -> T {
        return self.value;
    }

    fn update(inout self, new_val: T) -> T {
        let old = self.value;
        self.value = new_val;
        return old;
    }
}

pub fn main() {
    let mut c_int = Container(value: 42);
    let v1 = c_int.get_value();
    println("Initial int value:", v1);

    let old_int = c_int.update(99);
    println("Replaced int value:", old_int);
    println("Updated int value:", c_int.get_value());

    let mut c_bool = Container(value: true);
    println("Initial bool value:", c_bool.get_value());
    let old_bool = c_bool.update(false);
    println("Replaced bool value:", old_bool);
    println("Updated bool value:", c_bool.get_value());
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
        "ifa check failed on generic struct impl methods"
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
        run_stdout.contains("Initial int value: 42"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Replaced int value: 42"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Updated int value: 99"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Initial bool value: true"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Replaced bool value: true"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Updated bool value: false"),
        "stdout was: {}",
        run_stdout
    );

    let _ = fs::remove_file(&temp_file);
}
