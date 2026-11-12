use clap::{Parser, Subcommand};
use kori::builder::BuildOrchestrator;
use kori::manifest::{
    BackendKind, BinTarget, CrateType, DependencySpec, DetailedDependency, LibTarget, Manifest,
    PackageMetadata,
};
use kori::packager::Packager;
use kori::resolver::DependencyResolver;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

#[derive(Parser)]
#[command(name = "kori")]
#[command(version = "0.1.0")]
#[command(
    about = "Kori: Deterministic package manager and build orchestrator for IFA",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new IFA project with kori.toml manifest
    New {
        /// Project directory name
        name: String,
        /// Initialize as library package instead of binary
        #[arg(long)]
        lib: bool,
    },
    /// Compile the current package and its dependencies
    Build {
        /// Build artifacts in release mode with aggressive optimizations
        #[arg(short, long)]
        release: bool,
        /// Select compilation backend (cranelift or llvm)
        #[arg(long)]
        backend: Option<String>,
        /// Target architecture or filter (e.g. wasm32-wasi, native, all)
        #[arg(short, long)]
        target: Option<String>,
        /// Force rebuilding all artifacts ignoring cache
        #[arg(short, long)]
        force: bool,
        /// Path to kori.toml manifest file or project directory
        #[arg(long)]
        manifest_path: Option<PathBuf>,
    },
    /// Build and run the project binary
    Run {
        /// Build and execute in release mode
        #[arg(short, long)]
        release: bool,
        /// Path to kori.toml manifest file or project directory
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Pass trailing arguments directly to the program
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Run automated unit and integration tests across the package
    Test {
        /// Optional test name filter pattern
        #[arg(short, long)]
        filter: Option<String>,
        /// Path to kori.toml manifest file or project directory
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Execute tests natively via Cranelift JIT
        #[arg(long)]
        native: bool,
        /// Display granular resource consumption telemetry per test suite
        #[arg(long, visible_alias = "audit")]
        telemetry: bool,
        /// Output test results as deterministic JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a dependency to kori.toml
    Add {
        /// Dependency package name
        name: String,
        /// Optional path to local package directory
        #[arg(long)]
        path: Option<PathBuf>,
        /// SemVer version requirement
        #[arg(short, long)]
        version: Option<String>,
    },
    /// Remove a dependency from kori.toml
    Remove {
        /// Dependency package name
        name: String,
    },
    /// Display topological dependency tree of the workspace
    Tree,
    /// Resolve and pin dependencies into deterministic kori.lock
    Lock,
    /// Check syntax and semantics for the current package and its modules without code generation
    Check {
        /// Path to kori.toml manifest file or project directory
        #[arg(long)]
        manifest_path: Option<PathBuf>,
    },
    /// Canonically format IFA source files in the project or a specific file
    Fmt {
        /// Optional path to source file (.ifa) or directory (defaults to current project)
        path: Option<PathBuf>,
        /// Check if files are canonically formatted without writing changes to disk
        #[arg(long)]
        check: bool,
    },
    /// Package the project into a deterministic redistributable archive
    Package {
        /// Optional custom output directory
        #[arg(short, long)]
        out_dir: Option<PathBuf>,
        /// Path to kori.toml manifest file or project directory
        #[arg(long)]
        manifest_path: Option<PathBuf>,
    },
    /// Publish the package to a registry
    Publish {
        /// Perform all checks and packaging without publishing to registry
        #[arg(long)]
        dry_run: bool,
        /// Custom registry path
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Path to kori.toml manifest file or project directory
        #[arg(long)]
        manifest_path: Option<PathBuf>,
    },
    /// Search for packages in the registry
    Search {
        /// Search query (package name, description, or keyword)
        query: String,
        /// Custom registry path
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Display information about a package in the registry
    Info {
        /// Package name
        name: String,
        /// Custom registry path
        #[arg(long)]
        registry: Option<PathBuf>,
    },
}

fn resolve_project_dir(manifest_path: Option<PathBuf>, fallback: &Path) -> PathBuf {
    if let Some(p) = manifest_path {
        if p.is_dir() {
            p
        } else if p.file_name().and_then(|s| s.to_str()) == Some("kori.toml") {
            p.parent().unwrap_or(fallback).to_path_buf()
        } else {
            p
        }
    } else {
        fallback.to_path_buf()
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match cli.command {
        Commands::New { name, lib } => handle_new(&name, lib),
        Commands::Build {
            release,
            backend,
            target,
            force,
            manifest_path,
        } => {
            let target_dir = resolve_project_dir(manifest_path, &current_dir);
            handle_build(&target_dir, release, backend, target, force)
        }
        Commands::Run {
            release,
            manifest_path,
            args,
        } => {
            let target_dir = resolve_project_dir(manifest_path, &current_dir);
            handle_run(&target_dir, release, args)
        }
        Commands::Test {
            filter,
            manifest_path,
            native,
            telemetry,
            json,
        } => handle_test(&current_dir, filter, manifest_path, native, telemetry, json),
        Commands::Add {
            name,
            path,
            version,
        } => handle_add(&current_dir, &name, path, version),
        Commands::Remove { name } => handle_remove(&current_dir, &name),
        Commands::Tree => handle_tree(&current_dir),
        Commands::Lock => handle_lock(&current_dir),
        Commands::Check { manifest_path } => {
            let target_dir = resolve_project_dir(manifest_path, &current_dir);
            handle_check(&target_dir)
        }
        Commands::Fmt { path, check } => handle_fmt(&current_dir, path, check),
        Commands::Package {
            out_dir,
            manifest_path,
        } => {
            let target_dir = resolve_project_dir(manifest_path, &current_dir);
            handle_package(&target_dir, out_dir.as_deref())
        }
        Commands::Publish {
            dry_run,
            registry,
            manifest_path,
        } => {
            let target_dir = resolve_project_dir(manifest_path, &current_dir);
            handle_publish(&target_dir, registry.as_deref(), dry_run)
        }
        Commands::Search { query, registry } => handle_search(&query, registry.as_deref()),
        Commands::Info { name, registry } => handle_info(&name, registry.as_deref()),
    }
}

fn handle_new(name: &str, lib: bool) -> ExitCode {
    let root = Path::new(name);
    if root.exists() {
        eprintln!("error: target directory `{}` already exists", name);
        return ExitCode::FAILURE;
    }

    if let Err(e) = fs::create_dir_all(root.join("src")) {
        eprintln!("error: failed to create directories: {}", e);
        return ExitCode::FAILURE;
    }

    let manifest = Manifest {
        package: PackageMetadata {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            edition: "2026".to_string(),
            authors: vec!["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>".to_string()],
            license: Some("MIT OR Apache-2.0".to_string()),
            description: Some(format!("Deterministic IFA systems package `{}`", name)),
            repository: None,
            homepage: None,
            keywords: vec!["ifa".to_string(), "systems".to_string()],
        },
        targets: if lib {
            kori::manifest::TargetsConfig {
                bin: Vec::new(),
                lib: Some(LibTarget {
                    name: name.to_string(),
                    path: PathBuf::from("src/lib.ifa"),
                    crate_types: vec![CrateType::IfaLib, CrateType::Cdylib],
                }),
            }
        } else {
            kori::manifest::TargetsConfig {
                bin: vec![BinTarget {
                    name: name.to_string(),
                    path: PathBuf::from("src/main.ifa"),
                    target: None,
                }],
                lib: None,
            }
        },
        dependencies: BTreeMap::new(),
        dev_dependencies: BTreeMap::new(),
        registries: BTreeMap::new(),
        profiles: Default::default(),
        ffi: if lib { Some(Default::default()) } else { None },
    };

    if let Err(e) = manifest.save(&root.join("kori.toml")) {
        eprintln!("error: failed to save kori.toml: {}", e);
        return ExitCode::FAILURE;
    }

    let code_stub = if lib {
        r#"// Canonical IFA library module
pub extern "C" strict fn add(a: i64, b: i64) -> i64 {
    return a + b
}
"#
    } else {
        r#"pub fn main() -> () {
    println("Hello, deterministic world from IFA!")
}
"#
    };

    let target_file = if lib { "src/lib.ifa" } else { "src/main.ifa" };
    if let Err(e) = fs::write(root.join(target_file), code_stub) {
        eprintln!("error: failed to create source file: {}", e);
        return ExitCode::FAILURE;
    }

    let gitignore = "/target/\n.kori-cache/\n*.lock\n";
    let _ = fs::write(root.join(".gitignore"), gitignore);

    println!(
        "Created new IFA {} package `{}` ({})",
        if lib { "library" } else { "binary" },
        name,
        target_file
    );
    ExitCode::SUCCESS
}

fn handle_build(
    current_dir: &Path,
    release: bool,
    backend_str: Option<String>,
    target_str: Option<String>,
    force: bool,
) -> ExitCode {
    let orchestrator = match BuildOrchestrator::new(current_dir.to_path_buf()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let backend_override = match backend_str.as_deref() {
        Some("cranelift") => Some(BackendKind::Cranelift),
        Some("llvm") => Some(BackendKind::Llvm),
        Some(other) => {
            eprintln!(
                "error: unrecognized backend `{}` (expected cranelift or llvm)",
                other
            );
            return ExitCode::FAILURE;
        }
        None => None,
    };

    match orchestrator.build_with_target(release, backend_override, target_str.as_deref(), force) {
        Ok(report) => {
            println!(
                "Finished {} build in {:.2?} ({})",
                if release { "release" } else { "dev" },
                report.duration,
                report.resource_usage.format_summary()
            );
            for art in report.artifacts {
                println!(
                    "  {} {:?} => {}",
                    if art.cached { "[cached]" } else { "[built]" },
                    art.kind,
                    art.path.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: build failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_run(current_dir: &Path, release: bool, args: Vec<String>) -> ExitCode {
    let orchestrator = match BuildOrchestrator::new(current_dir.to_path_buf()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let report = match orchestrator.build(release, None, false) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: build failed: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let exe = report
        .artifacts
        .iter()
        .find(|a| a.kind == kori::ArtifactKind::Executable);

    if let Some(exe_art) = exe {
        let mut cmd = Command::new(&exe_art.path);
        cmd.args(&args);
        let status = kori::supervise_command(&mut cmd);
        match status {
            Ok((s, _telemetry)) => {
                if s.success() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(s.code().unwrap_or(1) as u8)
                }
            }
            Err(e) => {
                eprintln!(
                    "error: failed to execute `{}`: {}",
                    exe_art.path.display(),
                    e
                );
                ExitCode::FAILURE
            }
        }
    } else {
        eprintln!("error: no executable target found in package");
        ExitCode::FAILURE
    }
}

fn handle_test(
    current_dir: &Path,
    filter: Option<String>,
    manifest_path: Option<PathBuf>,
    native: bool,
    telemetry: bool,
    json: bool,
) -> ExitCode {
    let target_dir = resolve_project_dir(manifest_path, current_dir);
    let runner = kori::test_runner::TestRunner::new(&target_dir)
        .with_filter(filter)
        .with_native(native)
        .with_telemetry(telemetry)
        .with_quiet(json);

    match runner.run() {
        Ok(summary) => {
            if json {
                match summary.to_json_pretty() {
                    Ok(json_output) => println!("{}", json_output),
                    Err(e) => {
                        eprintln!("error: failed to serialize test results to JSON: {}", e);
                        return ExitCode::FAILURE;
                    }
                }
            }
            if summary.is_success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_add(
    current_dir: &Path,
    name: &str,
    path: Option<PathBuf>,
    version: Option<String>,
) -> ExitCode {
    let manifest_path = current_dir.join("kori.toml");
    let mut manifest = match Manifest::from_file(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let spec = if let Some(p) = path {
        DependencySpec::Detailed(DetailedDependency {
            version,
            path: Some(p),
            ..Default::default()
        })
    } else if let Some(v) = version {
        DependencySpec::Simple(v)
    } else {
        DependencySpec::Simple("0.1.0".to_string())
    };

    manifest.dependencies.insert(name.to_string(), spec);

    if let Err(e) = manifest.save(&manifest_path) {
        eprintln!("error: failed to update kori.toml: {}", e);
        return ExitCode::FAILURE;
    }

    println!("Added dependency `{}` to kori.toml", name);
    handle_lock(current_dir)
}

fn handle_remove(current_dir: &Path, name: &str) -> ExitCode {
    let manifest_path = current_dir.join("kori.toml");
    let mut manifest = match Manifest::from_file(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    if manifest.dependencies.remove(name).is_some() {
        if let Err(e) = manifest.save(&manifest_path) {
            eprintln!("error: failed to update kori.toml: {}", e);
            return ExitCode::FAILURE;
        }
        println!("Removed dependency `{}` from kori.toml", name);
        handle_lock(current_dir)
    } else {
        eprintln!("warning: dependency `{}` not found in kori.toml", name);
        ExitCode::SUCCESS
    }
}

fn handle_tree(current_dir: &Path) -> ExitCode {
    let manifest_path = current_dir.join("kori.toml");
    let manifest = match Manifest::from_file(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let resolver = DependencyResolver::new(current_dir.to_path_buf());
    match resolver.resolve(&manifest, None) {
        Ok((order, _)) => {
            println!("Package Dependency Order (topological):");
            for (idx, pkg) in order.iter().enumerate() {
                println!(
                    "  [{}] {} v{} ({})",
                    idx + 1,
                    pkg.name,
                    pkg.version,
                    pkg.source
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: dependency resolution failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_lock(current_dir: &Path) -> ExitCode {
    let manifest_path = current_dir.join("kori.toml");
    let manifest = match Manifest::from_file(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let resolver = DependencyResolver::new(current_dir.to_path_buf());
    match resolver.resolve(&manifest, None) {
        Ok((_, mut lock)) => {
            let lock_path = current_dir.join("kori.lock");
            if let Err(e) = lock.save(&lock_path) {
                eprintln!("error: failed to save kori.lock: {}", e);
                return ExitCode::FAILURE;
            }
            println!("Synchronized deterministic `kori.lock` successfully");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to resolve dependencies: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_check(current_dir: &Path) -> ExitCode {
    let orchestrator = match BuildOrchestrator::new(current_dir.to_path_buf()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: failed to load package: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match orchestrator.check() {
        Ok(report) => {
            println!(
                "Checked package `{}` ({} target(s)) in {:.2?}: syntax and semantics valid with zero errors.",
                report.package, report.targets_checked, report.duration
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: check failed:\n{}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_fmt(current_dir: &Path, target_path: Option<PathBuf>, check: bool) -> ExitCode {
    let target = target_path.unwrap_or_else(|| current_dir.to_path_buf());
    let opts = kori::fmt::FormatOptions::default();

    match kori::fmt::format_project_or_file(&target, check, &opts) {
        Ok(report) => {
            if report.total_files == 0 {
                println!("No .ifa files found in {:?}", target);
                return ExitCode::SUCCESS;
            }

            if check {
                if report.is_clean() {
                    println!(
                        "Checked {} file(s): all canonically formatted.",
                        report.total_files
                    );
                    ExitCode::SUCCESS
                } else {
                    eprintln!(
                        "error: {} of {} file(s) are not canonically formatted:",
                        report.changed_files.len(),
                        report.total_files
                    );
                    for file in &report.changed_files {
                        eprintln!("    {}", file.display());
                    }
                    ExitCode::FAILURE
                }
            } else {
                if report.changed_files.is_empty() {
                    println!(
                        "Checked {} file(s): already canonically formatted.",
                        report.total_files
                    );
                } else {
                    println!(
                        "Formatted {} of {} file(s):",
                        report.changed_files.len(),
                        report.total_files
                    );
                    for file in &report.changed_files {
                        println!("    {}", file.display());
                    }
                }
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("error formatting {:?}: {}", target, e);
            ExitCode::FAILURE
        }
    }
}

fn handle_package(project_dir: &Path, out_dir: Option<&Path>) -> ExitCode {
    match Packager::pack(project_dir, out_dir) {
        Ok(report) => {
            println!(
                "Packaged `{}` v{} ({} files, {} bytes)",
                report.name, report.version, report.file_count, report.total_bytes
            );
            println!("  Archive:  {}", report.package_path.display());
            println!("  Checksum: {}", report.checksum);
            println!("  SHA-256:  {}", report.checksum_path.display());
            println!("  Audit:    {}", report.resource_usage.format_summary());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: packaging failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_publish(project_dir: &Path, registry_path: Option<&Path>, dry_run: bool) -> ExitCode {
    match Packager::publish(project_dir, registry_path, dry_run) {
        Ok(report) => {
            if report.dry_run {
                println!(
                    "[dry-run] Validated package `{}` v{} for publishing",
                    report.name, report.version
                );
                println!("  Checksum: {}", report.checksum);
                println!("  Registry: {}", report.registry_path.display());
            } else {
                println!(
                    "Published `{}` v{} to registry `{}`",
                    report.name,
                    report.version,
                    report.registry_path.display()
                );
                println!("  Checksum: {}", report.checksum);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: publishing failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_search(query: &str, registry_path: Option<&Path>) -> ExitCode {
    match Packager::search(query, registry_path) {
        Ok(results) => {
            if results.is_empty() {
                println!("No packages found matching `{}`", query);
            } else {
                println!("Found {} package(s) matching `{}`:", results.len(), query);
                for pkg in results {
                    println!(
                        "  {} = \"{}\" - {}",
                        pkg.name,
                        pkg.version,
                        pkg.description.as_deref().unwrap_or("No description")
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: search failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_info(name: &str, registry_path: Option<&Path>) -> ExitCode {
    match Packager::info(name, registry_path) {
        Ok(entries) => {
            println!("Package `{}`:", name);
            for entry in entries {
                println!("  Version:     {}", entry.version);
                println!("  Checksum:    {}", entry.checksum);
                println!(
                    "  Description: {}",
                    entry.description.as_deref().unwrap_or("N/A")
                );
                println!("  Authors:     {}", entry.authors.join(", "));
                if let Some(lic) = &entry.license {
                    println!("  License:     {}", lic);
                }
                if !entry.dependencies.is_empty() {
                    println!("  Dependencies:");
                    for (dep, spec) in &entry.dependencies {
                        println!("    - {}: {:?}", dep, spec);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to inspect package `{}`: {}", name, e);
            ExitCode::FAILURE
        }
    }
}
