use clap::{Parser as ClapParser, Subcommand};
use ifa_comptime::ComptimeVM;
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::{sym, SourceMap, Span, INTERNER};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

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
    /// Run an IFA program
    Run {
        /// Source file path (.ifa)
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut source_map = SourceMap::new();

    match cli.command {
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

            if !diags.is_empty() {
                for diag in &diags {
                    eprint!("{}", diag.render_to_string(&source_map));
                }
                return ExitCode::FAILURE;
            }

            println!(
                "AST généré avec succès ({} déclarations) :",
                prog.items.len()
            );
            for (idx, item) in prog.items.iter().enumerate() {
                println!("  [{}] {:?}", idx, item);
            }
            ExitCode::SUCCESS
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

            let func_count = analysis.symbols.functions.len();
            let struct_count = analysis.symbols.structs.len();
            println!(
                "Vérification réussie : {:?} ({} déclarations, {} fonctions, {} structures, 0 erreur)",
                file,
                prog.items.len(),
                func_count,
                struct_count
            );
            ExitCode::SUCCESS
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
        Commands::Run { file } => {
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

            println!(
                "Programme IFA vérifié et validé : {:?} ({} items)",
                file,
                prog.items.len()
            );
            println!("(Backend d'exécution JIT Cranelift en cours d'intégration)");
            ExitCode::SUCCESS
        }
    }
}
