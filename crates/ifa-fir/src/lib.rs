pub mod cfg;
pub mod cow;
pub mod dominance;
pub mod gen_opt;
pub mod interp;
pub mod ir;
pub mod lower;
pub mod printer;
pub mod sroa;
pub mod types;
pub mod vectorize;
pub mod verify;

pub use cfg::ControlFlowGraph;
pub use cow::{CowPass, SharingState};
pub use dominance::DominanceTree;
pub use gen_opt::{GenOptStats, GenerationalOptPass, NaturalLoop};
pub use interp::{FirInterpreter, FirValue, GenHeader, GenHeap, InterpError};
pub use ir::*;
pub use lower::lower_program;
pub use printer::{format_function, format_module, FirPrinter};
pub use sroa::{SroaPass, SroaStats};
pub use types::{mangle_instantiation_symbol, mangle_sema_type, FirType};
pub use vectorize::{VectorizePass, VectorizeStats};
pub use verify::{FirVerifier, FirVerifyError};

use ifa_ast::Program;
use ifa_diagnostics::Diagnostic;
use ifa_sema::SymbolTable;

/// High-level entrypoint: Lowers an AST + SymbolTable into SSA FIR, optionally executing
/// Copy-on-Write, Generational Reference elimination, SROA, and SIMD vectorization passes,
/// and verifying SSA invariants.
pub fn compile_to_fir(
    program: &Program,
    symbols: &SymbolTable,
    opt_cow: bool,
    opt_gen: bool,
) -> Result<FirModule, Vec<Diagnostic>> {
    compile_to_fir_with_opts(program, symbols, opt_cow, opt_gen, true, true)
}

/// Extended compilation entrypoint allowing granular control over all FIR optimization passes.
pub fn compile_to_fir_with_opts(
    program: &Program,
    symbols: &SymbolTable,
    opt_cow: bool,
    opt_gen: bool,
    opt_sroa: bool,
    opt_vectorize: bool,
) -> Result<FirModule, Vec<Diagnostic>> {
    let mut module = lower_program(program, symbols);

    if opt_sroa {
        let mut sroa_pass = SroaPass::new();
        sroa_pass.run_on_module(&mut module);
    }

    if opt_cow {
        let mut cow_pass = CowPass::new();
        cow_pass.run_on_module(&mut module);
    }

    if opt_gen {
        let mut gen_pass = GenerationalOptPass::new();
        gen_pass.run_on_module(&mut module);
    }

    if opt_vectorize {
        let mut vec_pass = VectorizePass::new();
        vec_pass.run_on_module(&mut module);
    }

    if let Err(errors) = FirVerifier::verify_module(&module) {
        return Err(errors.iter().map(|e| e.to_diagnostic()).collect());
    }

    Ok(module)
}
