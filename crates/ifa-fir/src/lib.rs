pub mod cfg;
pub mod cow;
pub mod dominance;
pub mod gen_opt;
pub mod interp;
pub mod ir;
pub mod lower;
pub mod printer;
pub mod types;
pub mod verify;

pub use cfg::ControlFlowGraph;
pub use cow::{CowPass, SharingState};
pub use dominance::DominanceTree;
pub use gen_opt::{GenOptStats, GenerationalOptPass};
pub use interp::{FirInterpreter, FirValue, GenHeader, GenHeap, InterpError};
pub use ir::*;
pub use lower::lower_program;
pub use printer::{format_function, format_module, FirPrinter};
pub use types::FirType;
pub use verify::{FirVerifier, FirVerifyError};

use ifa_ast::Program;
use ifa_diagnostics::Diagnostic;
use ifa_sema::SymbolTable;

/// High-level entrypoint: Lowers an AST + SymbolTable into SSA FIR, optionally executing
/// Copy-on-Write and Generational Reference elimination passes, and verifying SSA invariants.
pub fn compile_to_fir(
    program: &Program,
    symbols: &SymbolTable,
    opt_cow: bool,
    opt_gen: bool,
) -> Result<FirModule, Vec<Diagnostic>> {
    let mut module = lower_program(program, symbols);

    if opt_cow {
        let mut cow_pass = CowPass::new();
        cow_pass.run_on_module(&mut module);
    }

    if opt_gen {
        let mut gen_pass = GenerationalOptPass::new();
        gen_pass.run_on_module(&mut module);
    }

    if let Err(errors) = FirVerifier::verify_module(&module) {
        return Err(errors.iter().map(|e| e.to_diagnostic()).collect());
    }

    Ok(module)
}
