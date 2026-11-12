use kori::test_runner::{TestRunner, TestSummaryReport};
use std::fs;

#[test]
fn test_runner_single_file_passing_assertions() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_test_runner_pass_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_math.ifa");

    let src = r#"
        pub fn add(a: i64, b: i64) -> i64 {
            return a + b;
        }

        pub fn test_basic_addition() -> () {
            let res = add(20, 22);
            assert_eq(res, 42, "sum should be 42");
        }

        pub fn test_assertions_variety() -> () {
            assert(true);
            assert_ne(10, 20);
            assert_eq(100, 100);
        }
    "#;
    fs::write(&file_path, src).unwrap();

    let runner = TestRunner::new(&file_path).with_quiet(true);
    let summary = runner.run().unwrap();

    assert!(summary.is_success());
    assert_eq!(summary.total_passed, 2);
    assert_eq!(summary.total_failed, 0);
    assert_eq!(summary.suites.len(), 1);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runner_single_file_failing_assertion() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_test_runner_fail_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_fail.ifa");

    let src = r#"
        pub fn test_passing() -> () {
            assert_eq(5, 5);
        }

        pub fn test_failing_assertion() -> () {
            assert_eq(42, 99, "financial calculation mismatch");
        }
    "#;
    fs::write(&file_path, src).unwrap();

    let runner = TestRunner::new(&file_path).with_quiet(true);
    let summary = runner.run().unwrap();

    assert!(!summary.is_success());
    assert_eq!(summary.total_passed, 1);
    assert_eq!(summary.total_failed, 1);
    assert_eq!(summary.failure_details.len(), 1);

    let (test_id, msg) = &summary.failure_details[0];
    assert!(test_id.contains("test_failing_assertion"));
    assert!(msg.contains("financial calculation mismatch"));

    let report = summary.render_report();
    assert!(report.contains("FAILED"));
    assert!(report.contains("financial calculation mismatch"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runner_package_discovery_multiple_suites() {
    let temp_dir = std::env::temp_dir().join(format!("ifa_test_runner_pkg_{}", std::process::id()));
    let src_dir = temp_dir.join("src");
    let tests_dir = temp_dir.join("tests");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&tests_dir).unwrap();

    let kori_toml = r#"
[package]
name = "sample_test_pkg"
version = "0.1.0"
authors = ["Test <test@example.com>"]
"#;
    fs::write(temp_dir.join("kori.toml"), kori_toml).unwrap();

    let main_src = r#"
        pub fn multiply(a: i64, b: i64) -> i64 {
            return a * b;
        }

        pub fn test_in_src_main() -> () {
            assert_eq(multiply(6, 7), 42);
        }
    "#;
    fs::write(src_dir.join("main.ifa"), main_src).unwrap();

    let test_src = r#"
        pub fn test_integration_flow() -> () {
            let x = 100;
            assert(x > 50);
            assert_ne(x, 0);
        }
    "#;
    fs::write(tests_dir.join("integration_test.ifa"), test_src).unwrap();

    let runner = TestRunner::new(&temp_dir).with_quiet(true);
    let summary = runner.run().unwrap();

    assert!(summary.is_success());
    assert_eq!(summary.total_passed, 2);
    assert_eq!(summary.total_failed, 0);
    assert_eq!(summary.suites.len(), 2);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runner_name_filtering() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_test_runner_filt_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_filter.ifa");

    let src = r#"
        pub fn test_network_connect() -> () {
            assert(true);
        }

        pub fn test_network_disconnect() -> () {
            assert(true);
        }

        pub fn test_crypto_hash() -> () {
            assert(true);
        }
    "#;
    fs::write(&file_path, src).unwrap();

    let runner = TestRunner::new(&file_path)
        .with_filter(Some("network".to_string()))
        .with_quiet(true);
    let summary = runner.run().unwrap();

    assert!(summary.is_success());
    assert_eq!(summary.total_passed, 2);
    assert_eq!(summary.total_failed, 0);
    assert_eq!(summary.total_filtered_out, 1);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runner_resource_telemetry_audit() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_test_runner_telem_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_telemetry.ifa");

    let src = r#"
        pub fn test_simple_compute() -> () {
            let mut sum: i64 = 0;
            let mut i: i64 = 0;
            while i < 100 {
                sum = sum + i;
                i = i + 1;
            }
            assert_eq(sum, 4950);
        }
    "#;
    fs::write(&file_path, src).unwrap();

    let runner = TestRunner::new(&file_path).with_quiet(true);
    let summary = runner.run().unwrap();

    assert!(summary.is_success());
    assert_eq!(summary.total_passed, 1);
    assert_eq!(summary.total_failed, 0);

    // Verify summary telemetry
    assert!(summary.resource_usage.wall_time_ns > 0);
    assert!(summary.resource_usage.max_rss_bytes > 0);
    assert!(summary.resource_usage.cpu_count >= 1);

    // Verify suite-level telemetry
    assert_eq!(summary.suites.len(), 1);
    let suite = &summary.suites[0];
    assert!(suite.resource_usage.wall_time_ns > 0);
    assert!(suite.resource_usage.max_rss_bytes > 0);
    assert!(suite.resource_usage.cpu_count >= 1);

    // Verify rendered report contains telemetry summary
    let report = summary.render_report();
    assert!(report.contains("wall:"));
    assert!(report.contains("cpu:"));
    assert!(report.contains("peak rss:"));
    assert!(report.contains("cores:"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runner_json_reporting_success() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_test_runner_json_ok_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_json_ok.ifa");

    let src = r#"
        pub fn test_alpha() -> () {
            assert_eq(10 + 20, 30);
        }

        pub fn test_beta() -> () {
            assert(true);
        }
    "#;
    fs::write(&file_path, src).unwrap();

    let runner = TestRunner::new(&file_path).with_quiet(true);
    let summary = runner.run().unwrap();

    let json_compact = summary.to_json().unwrap();
    let json_pretty = summary.to_json_pretty().unwrap();

    assert!(json_compact.contains("\"success\":true"));
    assert!(json_compact.contains("\"total_passed\":2"));
    assert!(json_compact.contains("\"total_failed\":0"));

    let report: TestSummaryReport = serde_json::from_str(&json_pretty).unwrap();
    assert!(report.success);
    assert_eq!(report.total_passed, 2);
    assert_eq!(report.total_failed, 0);
    assert_eq!(report.total_filtered_out, 0);
    assert_eq!(report.suites.len(), 1);
    assert_eq!(report.suites[0].cases.len(), 2);
    assert_eq!(report.suites[0].cases[0].status, "passed");
    assert_eq!(report.suites[0].cases[1].status, "passed");
    assert!(report.resource_usage.wall_time_ns > 0);
    assert!(report.resource_usage.cpu_count >= 1);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runner_json_reporting_failure() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_test_runner_json_fail_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_json_fail.ifa");

    let src = r#"
        pub fn test_pass() -> () {
            assert(true);
        }

        pub fn test_fail() -> () {
            assert_eq(1, 2, "mismatch detected in json test");
        }
    "#;
    fs::write(&file_path, src).unwrap();

    let runner = TestRunner::new(&file_path).with_quiet(true);
    let summary = runner.run().unwrap();

    let json_str = summary.to_json_pretty().unwrap();
    let report: TestSummaryReport = serde_json::from_str(&json_str).unwrap();

    assert!(!report.success);
    assert_eq!(report.total_passed, 1);
    assert_eq!(report.total_failed, 1);
    assert_eq!(report.failures.len(), 1);
    assert!(report.failures[0]
        .1
        .contains("mismatch detected in json test"));

    let failed_case = report.suites[0]
        .cases
        .iter()
        .find(|c| c.name == "test_fail")
        .expect("test_fail must exist in report");
    assert_eq!(failed_case.status, "failed");
    assert!(failed_case
        .failure_reason
        .as_ref()
        .unwrap()
        .contains("mismatch detected in json test"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runner_with_telemetry_configuration() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_test_runner_telem_cfg_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_telem_cfg.ifa");

    let src = r#"
        pub fn test_light() -> () {
            assert(true);
        }
    "#;
    fs::write(&file_path, src).unwrap();

    let runner = TestRunner::new(&file_path)
        .with_telemetry(true)
        .with_quiet(true);
    let summary = runner.run().unwrap();

    assert!(summary.is_success());
    assert_eq!(summary.suites.len(), 1);
    assert!(summary.suites[0].resource_usage.max_rss_bytes > 0);
    assert!(summary.suites[0].resource_usage.cpu_count >= 1);

    let _ = fs::remove_dir_all(&temp_dir);
}
