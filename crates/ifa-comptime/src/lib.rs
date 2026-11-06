pub mod compiler;
pub mod error;
pub mod intrinsics;
pub mod op;
pub mod value;
pub mod vm;

pub use compiler::{Compiler, FunctionBytecode};
pub use error::{ComptimeError, ComptimeErrorKind};
pub use intrinsics::compute_crc32;
pub use op::{Chunk, OpCode};
pub use value::Value;
pub use vm::ComptimeVM;

use ifa_ast::{Expr, Function};

/// Evaluates a standalone constant AST expression and returns the computed Value.
pub fn eval_expr(expr: &Expr) -> Result<Value, ComptimeError> {
    let mut vm = ComptimeVM::new();
    vm.eval_expr(expr)
}

/// Evaluates a function statically with the given argument values.
pub fn eval_function(func: &Function, args: Vec<Value>) -> Result<Value, ComptimeError> {
    let mut vm = ComptimeVM::new();
    let bc = Compiler::compile_function(func)?;
    let name = bc.name;
    let span = bc.span;
    vm.register_function(bc);
    vm.call_function(name, args, span)
}

/// Folds a constant AST expression at compile time into its equivalent literal AST expression.
pub fn fold_expr(expr: &Expr) -> Result<Expr, ComptimeError> {
    let val = eval_expr(expr)?;
    Ok(val.to_ast_expr(expr.span))
}
