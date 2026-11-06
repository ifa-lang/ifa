use clap::{Parser as ClapParser, Subcommand};
use ifa_codegen_cranelift::{AotCompiler, JitEngine};
use ifa_comptime::ComptimeVM;
use ifa_fir::{compile_to_fir, format_module, FirInterpreter};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::{sym, SourceMap, Span, INTERNER};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

mod tooling;
use tooling::{format_source, init_project, lint_program, run_tests};

#[derive(ClapParser)]
#[command(name = "ifa")]
#[command(version = "0.1.0")]
#[command(about = "IFA Programming Language Compiler & Toolchain", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new IFA package with kori.toml manifest and canonical src/main.ifa
    New {
        /// Project directory name
        name: String,
    },
    /// Format IFA source file canonically
    Fmt {
        /// Source file path (.ifa)
        file: PathBuf,
        /// Check if file is formatted without modifying
        #[arg(long)]
        check: bool,
    },
    /// Run static analysis and linting checks on an IFA program
    Lint {
        /// Source file path (.ifa)
        file: PathBuf,
    },
    /// Run unit tests defined in an IFA file
    Test {
        /// Source file path (.ifa)
        file: PathBuf,
    },
    /// Tokenize and inspect tokens of a source file
    Lex {
        /// Source file path (.ifa)
        file: PathBuf,
    },
    /// Parse and output the AST of a source file
    Parse {
        /// Source file path (.ifa)
        file: PathBuf,
    },
    /// Check syntax, semantics and report diagnostics on a source file
    Check {
        /// Source file path (.ifa)
        file: PathBuf,
    },
    /// Execute compile-time (comptime) evaluation and inspect constants
    Comptime {
        /// Source file path (.ifa)
        file: PathBuf,
        /// Optional comptime function name to evaluate
        #[arg(short, long)]
        function: Option<String>,
    },
    /// Generate and inspect FIR SSA (IFA Intermediate Representation)
    Fir {
        /// Source file path (.ifa)
        file: PathBuf,
        /// Disable implicit Copy-on-Write transformation pass
        #[arg(long)]
        no_cow: bool,
        /// Disable generational check elimination pass
        #[arg(long)]
        no_gen_opt: bool,
    },
    /// Compile and run an IFA program
    Run {
        /// Source file path (.ifa)
        file: PathBuf,
        /// Execute directly as machine code via Cranelift JIT
        #[arg(long)]
        native: bool,
    },
    /// Compile an IFA program to native object file or binary using Cranelift
    Build {
        /// Source file path (.ifa)
        file: PathBuf,
        /// Output path for binary or object
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Emit native object file (.o) without linking
        #[arg(long)]
        emit_obj: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut source_map = SourceMap::new();

    match cli.command {
        Commands::New { name } => match init_project(&name) {
            Ok(()) => {
                println!(
                    "Created new IFA package `{}` (kori.toml + src/main.ifa)",
                    name
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: failed to create package `{}`: {}", name, e);
                ExitCode::FAILURE
            }
        },

        Commands::Fmt { file, check } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };

            let formatted = format_source(&src);
            if check {
                if formatted != src {
                    eprintln!("error: {:?} is not canonically formatted", file);
                    return ExitCode::FAILURE;
                }
                println!("{:?} is properly formatted", file);
            } else {
                if let Err(e) = fs::write(&file, formatted) {
                    eprintln!("error: failed to write formatted file {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
                println!("Formatted {:?}", file);
            }
            ExitCode::SUCCESS
        }

        Commands::Lint { file } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            for diag in &parse_diags {
                eprint!("{}", diag.render_to_string(&source_map));
            }
            if !parse_diags.is_empty() {
                return ExitCode::FAILURE;
            }

            let warnings = lint_program(&prog, &source_map);
            if warnings.is_empty() {
                println!("Lint passed: zero style warnings for {:?}", file);
                ExitCode::SUCCESS
            } else {
                for w in &warnings {
                    println!("{}", w);
                }
                ExitCode::SUCCESS
            }
        }

        Commands::Test { file } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            for diag in &parse_diags {
                eprint!("{}", diag.render_to_string(&source_map));
            }
            if !parse_diags.is_empty() {
                return ExitCode::FAILURE;
            }

            let analysis = analyze(&source_map, &prog);
            for diag in &analysis.diagnostics {
                eprint!("{}", diag.render_to_string(&source_map));
            }
            if analysis.has_errors() {
                return ExitCode::FAILURE;
            }

            println!("\nRunning tests in {:?}:", file);
            let (passed, failed, logs) = run_tests(&prog, &analysis.symbols);
            for log in logs {
                println!("  {}", log);
            }

            println!("\nTest result: {} passed; {} failed\n", passed, failed);

            if failed > 0 {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }

        Commands::Lex { file } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);

            println!("Tokens pour {:?}:", file);
            for tok in tokens {
                println!(
                    "  [{:>4}..{:<4}] {}",
                    tok.span.start.0, tok.span.end.0, tok.kind
                );
            }
            ExitCode::SUCCESS
        }

        Commands::Parse { file } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, diags) = parse(fid, tokens);

            for diag in &diags {
                eprint!("{}", diag.render_to_string(&source_map));
            }

            if diags.is_empty() {
                println!("AST pour {:?} ({} items):", file, prog.items.len());
                for item in &prog.items {
                    println!("  {:#?}", item);
                }
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }

        Commands::Check { file } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            let mut has_errors = false;
            for diag in &parse_diags {
                eprint!("{}", diag.render_to_string(&source_map));
                has_errors = true;
            }

            if has_errors {
                return ExitCode::FAILURE;
            }

            let analysis = analyze(&source_map, &prog);
            for diag in &analysis.diagnostics {
                eprint!("{}", diag.render_to_string(&source_map));
            }

            if analysis.has_errors() {
                ExitCode::FAILURE
            } else {
                println!(
                    "Analyse sémantique réussie pour {:?}. Aucune erreur détectée.",
                    file
                );
                ExitCode::SUCCESS
            }
        }

        Commands::Comptime { file, function } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            if !parse_diags.is_empty() {
                for diag in &parse_diags {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
                return ExitCode::FAILURE;
            }

            let analysis = analyze(&source_map, &prog);
            if !analysis.diagnostics.is_empty() {
                for diag in &analysis.diagnostics {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
            }

            if analysis.has_errors() {
                return ExitCode::FAILURE;
            }

            let mut vm = ComptimeVM::new();
            if let Err(err) = vm.load_program(&prog) {
                eprint!("{}", err.to_diagnostic().render_to_string(&source_map));
                return ExitCode::FAILURE;
            }

            if let Some(fn_name) = function {
                let sym_fn = sym(&fn_name);
                let span = Span::new(fid, ifa_span::BytePos(0), ifa_span::BytePos(0));
                match vm.call_function(sym_fn, vec![], span) {
                    Ok(val) => {
                        println!("Résultat comptime pour '{}' : {}", fn_name, val);
                        ExitCode::SUCCESS
                    }
                    Err(err) => {
                        eprint!("{}", err.to_diagnostic().render_to_string(&source_map));
                        ExitCode::FAILURE
                    }
                }
            } else {
                println!(
                    "Évaluation comptime validée pour {:?} ({} constantes, {} fonctions)",
                    file,
                    vm.constants.len(),
                    vm.functions.len()
                );
                for (name, val) in &vm.constants {
                    println!("  const {} = {}", INTERNER.resolve(name), val);
                }
                ExitCode::SUCCESS
            }
        }

        Commands::Fir {
            file,
            no_cow,
            no_gen_opt,
        } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            if !parse_diags.is_empty() {
                for diag in &parse_diags {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
                return ExitCode::FAILURE;
            }

            let analysis = analyze(&source_map, &prog);
            if !analysis.diagnostics.is_empty() {
                for diag in &analysis.diagnostics {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
            }

            if analysis.has_errors() {
                return ExitCode::FAILURE;
            }

            match compile_to_fir(&prog, &analysis.symbols, !no_cow, !no_gen_opt) {
                Ok(fir_module) => {
                    let formatted = format_module(&fir_module);
                    print!("{}", formatted);
                    ExitCode::SUCCESS
                }
                Err(errors) => {
                    for err in errors {
                        eprint!("{}", err.render_to_string(&source_map));
                    }
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Run { file, native } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            if !parse_diags.is_empty() {
                for diag in &parse_diags {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
                return ExitCode::FAILURE;
            }

            let analysis = analyze(&source_map, &prog);
            if !analysis.diagnostics.is_empty() {
                for diag in &analysis.diagnostics {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
            }

            if analysis.has_errors() {
                return ExitCode::FAILURE;
            }

            let fir_module = match compile_to_fir(&prog, &analysis.symbols, true, true) {
                Ok(m) => m,
                Err(errors) => {
                    for err in errors {
                        eprint!("{}", err.render_to_string(&source_map));
                    }
                    return ExitCode::FAILURE;
                }
            };

            if native {
                match JitEngine::new() {
                    Ok(mut jit) => {
                        if let Err(e) = jit.compile_module(&fir_module) {
                            eprintln!("JIT compilation error: {}", e);
                            return ExitCode::FAILURE;
                        }
                        match jit.run_main() {
                            Ok(code) => {
                                println!("Program finished with native exit code: {}", code);
                                ExitCode::SUCCESS
                            }
                            Err(e) => {
                                eprintln!("JIT execution error: {}", e);
                                ExitCode::FAILURE
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to initialize Cranelift JIT engine: {}", e);
                        ExitCode::FAILURE
                    }
                }
            } else {
                let mut interp = FirInterpreter::new(&fir_module);
                match interp.execute_function("main", vec![]) {
                    Ok(val) => {
                        if val != ifa_fir::FirValue::Unit {
                            println!("Program finished with result: {}", val);
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("runtime error: {}", e);
                        ExitCode::FAILURE
                    }
                }
            }
        }

        Commands::Build {
            file,
            output,
            emit_obj,
        } => {
            let src = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier {:?}: {}", file, e);
                    return ExitCode::FAILURE;
                }
            };
            let fid = source_map.add_file(file.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            if !parse_diags.is_empty() {
                for diag in &parse_diags {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
                return ExitCode::FAILURE;
            }

            let analysis = analyze(&source_map, &prog);
            if !analysis.diagnostics.is_empty() {
                for diag in &analysis.diagnostics {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
            }

            if analysis.has_errors() {
                return ExitCode::FAILURE;
            }

            let fir_module = match compile_to_fir(&prog, &analysis.symbols, true, true) {
                Ok(m) => m,
                Err(errors) => {
                    for err in errors {
                        eprint!("{}", err.render_to_string(&source_map));
                    }
                    return ExitCode::FAILURE;
                }
            };

            let default_stem = file
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "out".into());

            let target_out = output.unwrap_or_else(|| {
                if emit_obj {
                    PathBuf::from(format!("{}.o", default_stem))
                } else {
                    PathBuf::from(&default_stem)
                }
            });

            match AotCompiler::new() {
                Ok(aot) => {
                    if emit_obj {
                        if let Err(e) = aot.compile_to_object(&fir_module, &target_out) {
                            eprintln!("Failed to emit native object file: {}", e);
                            return ExitCode::FAILURE;
                        }
                        println!("Emitted native object file: {:?}", target_out);
                        ExitCode::SUCCESS
                    } else {
                        let temp_obj = std::env::temp_dir().join(format!("{}.o", default_stem));
                        if let Err(e) = aot.compile_to_object(&fir_module, &temp_obj) {
                            eprintln!("Failed to emit native object file: {}", e);
                            return ExitCode::FAILURE;
                        }
                        if let Err(e) = AotCompiler::link_executable(&temp_obj, &target_out) {
                            eprintln!("Linker error: {}", e);
                            let _ = fs::remove_file(&temp_obj);
                            return ExitCode::FAILURE;
                        }
                        let _ = fs::remove_file(&temp_obj);
                        println!("Compiled standalone native executable: {:?}", target_out);
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("Failed to initialize Cranelift AOT compiler: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
    }
}
