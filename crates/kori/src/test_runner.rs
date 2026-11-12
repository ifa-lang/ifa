//! Package-wide unit and integration test runner for IFA programs and packages.
//!
//! Provides automated discovery, filtering, and isolated execution of `test_*` functions
//! with assertion diagnostics across package sources (`src/`) and test directories (`tests/`).

use crate::builder::BuildOrchestrator;
use crate::error::KoriError;
use ifa_codegen_cranelift::JitEngine;
use ifa_fir::{compile_to_fir, FirInterpreter, FirModule, FirType, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_runtime::{ResourceAuditScope, ResourceUsage};
use ifa_span::{SourceMap, INTERNER};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Status of an individual test case execution.
#[derive(Debug, Clone, PartialEq)]
pub enum TestStatus {
    /// Test passed successfully.
    Passed,
    /// Test failed with a reason / diagnostic message.
    Failed(String),
    /// Test was skipped / ignored.
    Ignored,
}

/// Result of a single executed test case.
#[derive(Debug, Clone)]
pub struct TestCaseResult {
    /// Name of the test function.
    pub name: String,
    /// Execution status.
    pub status: TestStatus,
    /// Time taken to execute the test.
    pub duration: Duration,
}

/// Results for a specific IFA test file or suite.
#[derive(Debug, Clone)]
pub struct TestSuiteResult {
    /// Source file path of the test suite.
    pub file_path: PathBuf,
    /// Individual test cases executed in this suite.
    pub cases: Vec<TestCaseResult>,
    /// Number of tests passed in this suite.
    pub passed: usize,
    /// Number of tests failed in this suite.
    pub failed: usize,
    /// Number of tests filtered out / ignored.
    pub filtered_out: usize,
    /// Total duration for this suite.
    pub duration: Duration,
    /// Resource usage telemetry for this test suite.
    pub resource_usage: ResourceUsage,
}

/// Aggregated summary of all executed test suites across the package.
#[derive(Debug, Clone)]
pub struct TestSummary {
    /// List of suite results.
    pub suites: Vec<TestSuiteResult>,
    /// Total number of passing tests across all suites.
    pub total_passed: usize,
    /// Total number of failing tests across all suites.
    pub total_failed: usize,
    /// Total number of filtered out tests.
    pub total_filtered_out: usize,
    /// Total elapsed wall-clock duration.
    pub total_duration: Duration,
    /// Aggregated resource usage telemetry across all executed suites.
    pub resource_usage: ResourceUsage,
    /// Detailed list of all failures: (test_identifier, failure_message).
    pub failure_details: Vec<(String, String)>,
}

impl TestSummary {
    /// Returns true if all executed tests passed (0 failures).
    pub fn is_success(&self) -> bool {
        self.total_failed == 0
    }

    /// Format summary report into a human-readable string.
    pub fn render_report(&self) -> String {
        let mut out = String::new();

        if !self.failure_details.is_empty() {
            out.push_str("\nfailures:\n\n");
            for (test_id, msg) in &self.failure_details {
                out.push_str(&format!("---- {} ----\n", test_id));
                out.push_str(msg);
                out.push('\n');
                out.push('\n');
            }

            out.push_str("failures:\n");
            for (test_id, _) in &self.failure_details {
                out.push_str(&format!("    {}\n", test_id));
            }
            out.push('\n');
        }

        let status_str = if self.is_success() { "ok" } else { "FAILED" };
        out.push_str(&format!(
            "test result: {}. {} passed; {} failed; {} filtered out; finished in {:.2?} ({})\nTest result: {} passed; {} failed\n",
            status_str,
            self.total_passed,
            self.total_failed,
            self.total_filtered_out,
            self.total_duration,
            self.resource_usage.format_summary(),
            self.total_passed,
            self.total_failed
        ));

        out
    }

    /// Converts aggregated test summary into a serializable report representation.
    pub fn to_report(&self) -> TestSummaryReport {
        let suites = self
            .suites
            .iter()
            .map(|s| TestSuiteReport {
                file: s.file_path.to_string_lossy().to_string(),
                passed: s.passed,
                failed: s.failed,
                filtered_out: s.filtered_out,
                duration_ms: (s.duration.as_nanos() as f64) / 1_000_000.0,
                resource_usage: ResourceUsageReport::from(&s.resource_usage),
                cases: s
                    .cases
                    .iter()
                    .map(|c| TestCaseReport {
                        name: c.name.clone(),
                        status: match &c.status {
                            TestStatus::Passed => "passed".to_string(),
                            TestStatus::Failed(_) => "failed".to_string(),
                            TestStatus::Ignored => "ignored".to_string(),
                        },
                        duration_ms: (c.duration.as_nanos() as f64) / 1_000_000.0,
                        failure_reason: match &c.status {
                            TestStatus::Failed(reason) => Some(reason.clone()),
                            _ => None,
                        },
                    })
                    .collect(),
            })
            .collect();

        TestSummaryReport {
            success: self.is_success(),
            total_passed: self.total_passed,
            total_failed: self.total_failed,
            total_filtered_out: self.total_filtered_out,
            total_duration_ms: (self.total_duration.as_nanos() as f64) / 1_000_000.0,
            resource_usage: ResourceUsageReport::from(&self.resource_usage),
            suites,
            failures: self.failure_details.clone(),
        }
    }

    /// Serialize test results to a compact JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.to_report())
    }

    /// Serialize test results to a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.to_report())
    }
}

/// Machine-readable telemetry metrics for test execution and resource consumption audits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsageReport {
    pub wall_time_ns: u64,
    pub wall_time_ms: f64,
    pub cpu_time_ns: u64,
    pub cpu_time_ms: f64,
    pub max_rss_bytes: u64,
    pub max_rss_mb: f64,
    pub resident_bytes: u64,
    pub virtual_bytes: u64,
    pub cpu_count: i64,
}

impl From<&ResourceUsage> for ResourceUsageReport {
    fn from(r: &ResourceUsage) -> Self {
        Self {
            wall_time_ns: r.wall_time_ns,
            wall_time_ms: (r.wall_time_ns as f64) / 1_000_000.0,
            cpu_time_ns: r.cpu_time_ns,
            cpu_time_ms: (r.cpu_time_ns as f64) / 1_000_000.0,
            max_rss_bytes: r.max_rss_bytes,
            max_rss_mb: (r.max_rss_bytes as f64) / (1024.0 * 1024.0),
            resident_bytes: r.resident_bytes,
            virtual_bytes: r.virtual_bytes,
            cpu_count: r.cpu_count,
        }
    }
}

/// Machine-readable report of an individual test case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestCaseReport {
    pub name: String,
    pub status: String,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Machine-readable report of an individual test suite / source file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestSuiteReport {
    pub file: String,
    pub passed: usize,
    pub failed: usize,
    pub filtered_out: usize,
    pub duration_ms: f64,
    pub resource_usage: ResourceUsageReport,
    pub cases: Vec<TestCaseReport>,
}

/// Machine-readable report summarizing complete test execution across a package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestSummaryReport {
    pub success: bool,
    pub total_passed: usize,
    pub total_failed: usize,
    pub total_filtered_out: usize,
    pub total_duration_ms: f64,
    pub resource_usage: ResourceUsageReport,
    pub suites: Vec<TestSuiteReport>,
    pub failures: Vec<(String, String)>,
}

/// Universal test runner orchestrating discovery, compilation, and execution of IFA tests.
pub struct TestRunner {
    /// Package root directory or single file path.
    target_path: PathBuf,
    /// Optional filter pattern matching test names.
    filter: Option<String>,
    /// Whether to execute tests natively via Cranelift JIT instead of FIR interpreter.
    native: bool,
    /// Silent mode suppressing stdout printing during programmatic runs.
    quiet: bool,
    /// Granular resource telemetry reporting per test suite.
    telemetry: bool,
}

impl TestRunner {
    /// Create a new test runner targeting a package directory or file.
    pub fn new(target_path: impl AsRef<Path>) -> Self {
        Self {
            target_path: target_path.as_ref().to_path_buf(),
            filter: None,
            native: false,
            quiet: false,
            telemetry: false,
        }
    }

    /// Set an optional substring filter on test function names.
    pub fn with_filter(mut self, filter: Option<String>) -> Self {
        self.filter = filter;
        self
    }

    /// Configure whether to execute tests natively via Cranelift JIT.
    pub fn with_native(mut self, native: bool) -> Self {
        self.native = native;
        self
    }

    /// Configure quiet mode (suppress terminal output).
    pub fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Configure whether to report granular per-suite resource consumption telemetry.
    pub fn with_telemetry(mut self, telemetry: bool) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Discover all `.ifa` test files within the target package or path.
    pub fn discover_test_files(&self) -> Result<Vec<PathBuf>, KoriError> {
        let mut files = Vec::new();

        if self.target_path.is_file() {
            if self.target_path.extension().is_some_and(|ext| ext == "ifa") {
                files.push(self.target_path.clone());
            }
            return Ok(files);
        }

        // If target_path is a directory, search in tests/ first, then src/
        let tests_dir = self.target_path.join("tests");
        if tests_dir.is_dir() {
            Self::collect_ifa_files(&tests_dir, &mut files)?;
        }

        let src_dir = self.target_path.join("src");
        if src_dir.is_dir() {
            Self::collect_ifa_files(&src_dir, &mut files)?;
        }

        // If neither exists, check current directory for any *.ifa files
        if files.is_empty() && self.target_path.is_dir() {
            Self::collect_ifa_files(&self.target_path, &mut files)?;
        }

        files.sort();
        Ok(files)
    }

    fn collect_ifa_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), KoriError> {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if !dir_name.starts_with('.') && dir_name != "target" && dir_name != "dist" {
                        Self::collect_ifa_files(&path, files)?;
                    }
                } else if path.extension().is_some_and(|ext| ext == "ifa") {
                    files.push(path);
                }
            }
        }
        Ok(())
    }

    /// Execute all discovered tests across the target and return an aggregated `TestSummary`.
    pub fn run(&self) -> Result<TestSummary, KoriError> {
        let audit_scope = ResourceAuditScope::start();
        let test_files = self.discover_test_files()?;
        let overall_start = Instant::now();

        let mut suites = Vec::new();
        let mut total_passed = 0;
        let mut total_failed = 0;
        let mut total_filtered_out = 0;
        let mut failure_details = Vec::new();

        if test_files.is_empty() {
            if !self.quiet {
                println!(
                    "No IFA test files found in `{}`",
                    self.target_path.display()
                );
            }
            return Ok(TestSummary {
                suites,
                total_passed: 0,
                total_failed: 0,
                total_filtered_out: 0,
                total_duration: overall_start.elapsed(),
                resource_usage: audit_scope.finish(),
                failure_details,
            });
        }

        for file in &test_files {
            let suite_result = self.run_test_file(file)?;
            if !suite_result.cases.is_empty() || suite_result.failed > 0 {
                total_passed += suite_result.passed;
                total_failed += suite_result.failed;
                total_filtered_out += suite_result.filtered_out;

                for case in &suite_result.cases {
                    if let TestStatus::Failed(ref msg) = case.status {
                        let id = format!("{} :: {}", file.display(), case.name);
                        failure_details.push((id, msg.clone()));
                    }
                }

                if self.telemetry && !self.quiet {
                    println!(
                        "   telemetry [{}]: {}",
                        file.display(),
                        suite_result.resource_usage.format_summary()
                    );
                }

                suites.push(suite_result);
            }
        }

        let summary = TestSummary {
            suites,
            total_passed,
            total_failed,
            total_filtered_out,
            total_duration: overall_start.elapsed(),
            resource_usage: audit_scope.finish(),
            failure_details,
        };

        if !self.quiet {
            println!("{}", summary.render_report());
        }

        Ok(summary)
    }

    fn run_test_file(&self, file: &Path) -> Result<TestSuiteResult, KoriError> {
        let suite_start = Instant::now();
        let audit_scope = ResourceAuditScope::start();
        let src = fs::read_to_string(file).map_err(KoriError::Io)?;

        let mut source_map = SourceMap::new();
        let fid = source_map.add_file(file.to_string_lossy(), &src);
        let tokens = tokenize(fid, &src);
        let (prog, parse_diags) = parse(fid, tokens);

        if !parse_diags.is_empty() {
            let mut err_msg = String::new();
            for d in parse_diags {
                err_msg.push_str(&d.render_to_string(&source_map));
            }
            if !self.quiet {
                eprintln!("{}", err_msg);
            }
            return Ok(TestSuiteResult {
                file_path: file.to_path_buf(),
                cases: vec![TestCaseResult {
                    name: "syntax_validation".to_string(),
                    status: TestStatus::Failed(err_msg),
                    duration: suite_start.elapsed(),
                }],
                passed: 0,
                failed: 1,
                filtered_out: 0,
                duration: suite_start.elapsed(),
                resource_usage: audit_scope.finish(),
            });
        }

        // Determine base directory for module resolution
        let base_dir = if let Some(parent) = file.parent() {
            if parent.join("kori.toml").exists() {
                parent.to_path_buf()
            } else if let Some(grandparent) = parent.parent() {
                if grandparent.join("kori.toml").exists() {
                    grandparent.join("src")
                } else {
                    parent.to_path_buf()
                }
            } else {
                parent.to_path_buf()
            }
        } else {
            PathBuf::from(".")
        };

        let (analysis, sub_firs) =
            BuildOrchestrator::analyze_with_local_modules(&mut source_map, &base_dir, &prog);
        if analysis.has_errors() {
            let mut err_msg = String::new();
            for d in analysis.diagnostics {
                err_msg.push_str(&d.render_to_string(&source_map));
            }
            if !self.quiet {
                eprintln!("{}", err_msg);
            }
            return Ok(TestSuiteResult {
                file_path: file.to_path_buf(),
                cases: vec![TestCaseResult {
                    name: "type_and_semantic_validation".to_string(),
                    status: TestStatus::Failed(err_msg),
                    duration: suite_start.elapsed(),
                }],
                passed: 0,
                failed: 1,
                filtered_out: 0,
                duration: suite_start.elapsed(),
                resource_usage: audit_scope.finish(),
            });
        }

        let mut fir_module = match compile_to_fir(&prog, &analysis.symbols, true, true) {
            Ok(m) => m,
            Err(errors) => {
                let mut err_msg = String::new();
                for e in errors {
                    err_msg.push_str(&e.render_to_string(&source_map));
                }
                return Ok(TestSuiteResult {
                    file_path: file.to_path_buf(),
                    cases: vec![TestCaseResult {
                        name: "fir_lowering".to_string(),
                        status: TestStatus::Failed(err_msg),
                        duration: suite_start.elapsed(),
                    }],
                    passed: 0,
                    failed: 1,
                    filtered_out: 0,
                    duration: suite_start.elapsed(),
                    resource_usage: audit_scope.finish(),
                });
            }
        };

        for sub_fir in sub_firs {
            fir_module.merge(sub_fir);
        }

        let mut test_fn_names: Vec<String> = fir_module
            .functions
            .iter()
            .map(|f| INTERNER.resolve(&f.name))
            .filter(|name| name.starts_with("test_"))
            .collect();
        test_fn_names.sort();

        let total_discovered = test_fn_names.len();
        if total_discovered == 0 {
            return Ok(TestSuiteResult {
                file_path: file.to_path_buf(),
                cases: Vec::new(),
                passed: 0,
                failed: 0,
                filtered_out: 0,
                duration: suite_start.elapsed(),
                resource_usage: audit_scope.finish(),
            });
        }

        let filtered_names: Vec<String> = if let Some(ref pattern) = self.filter {
            test_fn_names
                .into_iter()
                .filter(|name| name.contains(pattern))
                .collect()
        } else {
            test_fn_names
        };

        let filtered_out = total_discovered - filtered_names.len();

        if !self.quiet {
            println!(
                "\nrunning {} test{} in {}",
                filtered_names.len(),
                if filtered_names.len() == 1 { "" } else { "s" },
                file.display()
            );
        }

        let mut cases = Vec::new();
        let mut passed = 0;
        let mut failed = 0;

        for test_name in &filtered_names {
            let case_start = Instant::now();
            let status = self.execute_single_test(&fir_module, test_name);
            let case_duration = case_start.elapsed();

            match &status {
                TestStatus::Passed => {
                    passed += 1;
                    if !self.quiet {
                        println!("test {} ... ok ({:.2?})", test_name, case_duration);
                    }
                }
                TestStatus::Failed(reason) => {
                    failed += 1;
                    if !self.quiet {
                        println!("test {} ... FAILED ({:.2?})", test_name, case_duration);
                        let first_line = reason.lines().next().unwrap_or(reason);
                        println!("     {}", first_line);
                    }
                }
                TestStatus::Ignored => {}
            }

            cases.push(TestCaseResult {
                name: test_name.clone(),
                status,
                duration: case_duration,
            });
        }

        Ok(TestSuiteResult {
            file_path: file.to_path_buf(),
            cases,
            passed,
            failed,
            filtered_out,
            duration: suite_start.elapsed(),
            resource_usage: audit_scope.finish(),
        })
    }

    fn execute_single_test(&self, module: &FirModule, test_name: &str) -> TestStatus {
        if self.native {
            let is_bool_ret = module
                .functions
                .iter()
                .find(|f| INTERNER.resolve(&f.name) == test_name)
                .map(|f| matches!(f.ret_ty, FirType::Bool))
                .unwrap_or(false);

            match JitEngine::new() {
                Ok(mut jit) => {
                    if let Err(e) = jit.compile_module(module) {
                        return TestStatus::Failed(format!("JIT compilation failed: {}", e));
                    }
                    match jit.run_function(test_name) {
                        Ok(code) => {
                            if is_bool_ret {
                                if code == 1 {
                                    TestStatus::Passed
                                } else {
                                    TestStatus::Failed(
                                        "Native test returned false (assertion failure)"
                                            .to_string(),
                                    )
                                }
                            } else if code == 0 {
                                TestStatus::Passed
                            } else {
                                TestStatus::Failed(format!("Native test exited with code {}", code))
                            }
                        }
                        Err(e) => TestStatus::Failed(format!("JIT execution error: {}", e)),
                    }
                }
                Err(e) => {
                    TestStatus::Failed(format!("Failed to initialize Cranelift JIT engine: {}", e))
                }
            }
        } else {
            let mut interp = FirInterpreter::new(module);
            match interp.execute_function(test_name, vec![]) {
                Ok(val) => {
                    if val == FirValue::Unit || val == FirValue::Bool(true) {
                        TestStatus::Passed
                    } else if val == FirValue::Bool(false) {
                        TestStatus::Failed("Test returned false (assertion failure)".to_string())
                    } else {
                        TestStatus::Passed
                    }
                }
                Err(e) => TestStatus::Failed(format!("{}", e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_usage_report_conversion() {
        let usage = ResourceUsage {
            wall_time_ns: 25_000_000,
            cpu_time_ns: 18_000_000,
            max_rss_bytes: 10 * 1024 * 1024,
            resident_bytes: 8 * 1024 * 1024,
            virtual_bytes: 32 * 1024 * 1024,
            cpu_count: 4,
        };

        let report = ResourceUsageReport::from(&usage);
        assert_eq!(report.wall_time_ns, 25_000_000);
        assert!((report.wall_time_ms - 25.0).abs() < 1e-6);
        assert_eq!(report.cpu_time_ns, 18_000_000);
        assert!((report.cpu_time_ms - 18.0).abs() < 1e-6);
        assert_eq!(report.max_rss_bytes, 10 * 1024 * 1024);
        assert!((report.max_rss_mb - 10.0).abs() < 1e-6);
        assert_eq!(report.cpu_count, 4);
    }

    #[test]
    fn test_summary_to_json_serialization() {
        let summary = TestSummary {
            suites: vec![TestSuiteResult {
                file_path: PathBuf::from("tests/demo.ifa"),
                cases: vec![
                    TestCaseResult {
                        name: "test_addition".to_string(),
                        status: TestStatus::Passed,
                        duration: Duration::from_millis(5),
                    },
                    TestCaseResult {
                        name: "test_failing".to_string(),
                        status: TestStatus::Failed("assertion failed: 1 == 2".to_string()),
                        duration: Duration::from_millis(3),
                    },
                ],
                passed: 1,
                failed: 1,
                filtered_out: 0,
                duration: Duration::from_millis(8),
                resource_usage: ResourceUsage {
                    wall_time_ns: 8_000_000,
                    cpu_time_ns: 6_000_000,
                    max_rss_bytes: 4 * 1024 * 1024,
                    resident_bytes: 3 * 1024 * 1024,
                    virtual_bytes: 12 * 1024 * 1024,
                    cpu_count: 2,
                },
            }],
            total_passed: 1,
            total_failed: 1,
            total_filtered_out: 0,
            total_duration: Duration::from_millis(10),
            resource_usage: ResourceUsage {
                wall_time_ns: 10_000_000,
                cpu_time_ns: 8_000_000,
                max_rss_bytes: 5 * 1024 * 1024,
                resident_bytes: 4 * 1024 * 1024,
                virtual_bytes: 16 * 1024 * 1024,
                cpu_count: 2,
            },
            failure_details: vec![(
                "tests/demo.ifa :: test_failing".to_string(),
                "assertion failed: 1 == 2".to_string(),
            )],
        };

        let json_pretty = summary
            .to_json_pretty()
            .expect("json serialization must succeed");
        assert!(json_pretty.contains("\"success\": false"));
        assert!(json_pretty.contains("\"total_passed\": 1"));
        assert!(json_pretty.contains("\"total_failed\": 1"));
        assert!(json_pretty.contains("\"file\": \"tests/demo.ifa\""));
        assert!(json_pretty.contains("assertion failed: 1 == 2"));

        let deserialized: TestSummaryReport =
            serde_json::from_str(&json_pretty).expect("deserialization must succeed");
        assert!(!deserialized.success);
        assert_eq!(deserialized.total_passed, 1);
        assert_eq!(deserialized.total_failed, 1);
        assert_eq!(deserialized.suites.len(), 1);
        assert_eq!(deserialized.suites[0].cases.len(), 2);
        assert_eq!(deserialized.suites[0].cases[0].status, "passed");
        assert_eq!(deserialized.suites[0].cases[1].status, "failed");
        assert_eq!(
            deserialized.suites[0].cases[1].failure_reason.as_deref(),
            Some("assertion failed: 1 == 2")
        );
    }
}
