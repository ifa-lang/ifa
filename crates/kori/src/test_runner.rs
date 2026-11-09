//! Package-wide unit and integration test runner for IFA programs and packages.
//!
//! Provides automated discovery, filtering, and isolated execution of `test_*` functions
//! with assertion diagnostics across package sources (`src/`) and test directories (`tests/`).

use crate::builder::BuildOrchestrator;
use crate::error::KoriError;
use ifa_codegen_cranelift::JitEngine;
use ifa_fir::{compile_to_fir, FirInterpreter, FirModule, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::{analyze, analyze_with_symbols, ModuleSymbol, SymbolTable};
use ifa_span::{SourceMap, INTERNER};
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
            "test result: {}. {} passed; {} failed; {} filtered out; finished in {:.2?}\nTest result: {} passed; {} failed\n",
            status_str,
            self.total_passed,
            self.total_failed,
            self.total_filtered_out,
            self.total_duration,
            self.total_passed,
            self.total_failed
        ));

        out
    }
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
}

impl TestRunner {
    /// Create a new test runner targeting a package directory or file.
    pub fn new(target_path: impl AsRef<Path>) -> Self {
        Self {
            target_path: target_path.as_ref().to_path_buf(),
            filter: None,
            native: false,
            quiet: false,
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
                suites.push(suite_result);
            }
        }

        let summary = TestSummary {
            suites,
            total_passed,
            total_failed,
            total_filtered_out,
            total_duration: overall_start.elapsed(),
            failure_details,
        };

        if !self.quiet {
            println!("{}", summary.render_report());
        }

        Ok(summary)
    }

    fn run_test_file(&self, file: &Path) -> Result<TestSuiteResult, KoriError> {
        let suite_start = Instant::now();
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
            });
        }

        let mut symbols = SymbolTable::new();
        let mut sub_firs = Vec::new();

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

        for item in &prog.items {
            if let ifa_ast::Item::Import(im) = item {
                if let Some(sub_path) = BuildOrchestrator::resolve_module_file(&base_dir, &im.path)
                {
                    if let Ok(sub_src) = fs::read_to_string(&sub_path) {
                        let sub_fid = source_map.add_file(sub_path.to_string_lossy(), &sub_src);
                        let sub_toks = tokenize(sub_fid, &sub_src);
                        let (sub_prog, sub_diags) = parse(sub_fid, sub_toks);
                        if sub_diags.is_empty() {
                            let sub_res = analyze(&source_map, &sub_prog);
                            if !sub_res.has_errors() {
                                if let Ok(sub_fir) =
                                    compile_to_fir(&sub_prog, &sub_res.symbols, true, true)
                                {
                                    sub_firs.push(sub_fir);
                                }
                                let local_alias =
                                    im.alias.unwrap_or_else(|| *im.path.last().unwrap());
                                let path_str = im
                                    .path
                                    .iter()
                                    .map(|s| INTERNER.resolve(s))
                                    .collect::<Vec<_>>()
                                    .join("::");
                                let path_sym = INTERNER.intern(&path_str);
                                let mut mod_sym =
                                    ModuleSymbol::new(local_alias, im.path.clone(), true, im.span);
                                for f in sub_res.symbols.functions.values() {
                                    mod_sym.add_function(f.clone());
                                }
                                for s in sub_res.symbols.structs.values() {
                                    mod_sym.add_struct(s.clone());
                                }
                                for e in sub_res.symbols.enums.values() {
                                    mod_sym.add_enum(e.clone());
                                }
                                for c in sub_res.symbols.consts.values() {
                                    mod_sym.add_const(c.clone());
                                }
                                symbols.modules.insert(local_alias, mod_sym.clone());
                                symbols.modules.insert(path_sym, mod_sym.clone());
                                if let Some(last) = im.path.last() {
                                    symbols.modules.insert(*last, mod_sym);
                                }
                            }
                        }
                    }
                }
            }
        }

        let analysis = analyze_with_symbols(&source_map, &prog, symbols);
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
        })
    }

    fn execute_single_test(&self, module: &FirModule, test_name: &str) -> TestStatus {
        if self.native {
            match JitEngine::new() {
                Ok(mut jit) => {
                    if let Err(e) = jit.compile_module(module) {
                        return TestStatus::Failed(format!("JIT compilation failed: {}", e));
                    }
                    match jit.run_function(test_name) {
                        Ok(code) => {
                            if code == 0 {
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
