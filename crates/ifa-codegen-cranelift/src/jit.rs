use crate::error::CodegenError;
use crate::translator::FunctionTranslator;
use crate::types::fir_signature_to_cranelift;
use cranelift_codegen::ir::{AbiParam, Signature};
use cranelift_codegen::Context;
use cranelift_frontend::FunctionBuilderContext;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module};
use ifa_fir::FirModule;
use ifa_span::INTERNER;
use std::collections::HashMap;

extern "C" fn ifa_rt_println(ptr: *const u8) {
    if !ptr.is_null() {
        unsafe {
            if let Ok(s) = std::ffi::CStr::from_ptr(ptr as *const i8).to_str() {
                println!("{}", s);
            }
        }
    } else {
        println!();
    }
}

/// JIT Execution engine compiling FIR SSA into native machine code in-memory.
pub struct JitEngine {
    builder_context: FunctionBuilderContext,
    ctx: Context,
    module: JITModule,
    func_ids: HashMap<String, FuncId>,
}

impl JitEngine {
    /// Create a new JIT engine initialized with the host machine's native ISA.
    pub fn new() -> Result<Self, CodegenError> {
        let flag_builder = cranelift_codegen::settings::builder();
        let isa_builder = cranelift_native::builder()
            .map_err(|e| CodegenError::Codegen(format!("Failed to build native ISA: {}", e)))?;
        let isa = isa_builder
            .finish(cranelift_codegen::settings::Flags::new(flag_builder))
            .map_err(|e| CodegenError::Codegen(format!("Failed to finish ISA: {}", e)))?;

        let mut builder = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());
        builder.symbol("println", ifa_rt_println as *const u8);
        let module = JITModule::new(builder);

        Ok(Self {
            builder_context: FunctionBuilderContext::new(),
            ctx: module.make_context(),
            module,
            func_ids: HashMap::new(),
        })
    }

    /// Compile all functions in a FIR module into machine code.
    pub fn compile_module(&mut self, fir_module: &FirModule) -> Result<(), CodegenError> {
        let ptr_type = self.module.target_config().pointer_type();
        let call_conv = self.module.target_config().default_call_conv;

        // Register runtime intrinsic signatures
        let mut println_sig = Signature::new(call_conv);
        println_sig.params.push(AbiParam::new(ptr_type));
        let println_id = self
            .module
            .declare_function("println", Linkage::Import, &println_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("println".into(), println_id);

        // 1. Declare all functions first to enable mutual recursion and forward calls
        for fir_func in &fir_module.functions {
            let fn_name = INTERNER.resolve(&fir_func.name);
            let sig = fir_signature_to_cranelift(fir_func, call_conv, ptr_type)?;
            let linkage = if fir_func.is_pub {
                Linkage::Export
            } else {
                Linkage::Local
            };
            let func_id = self
                .module
                .declare_function(&fn_name, linkage, &sig)
                .map_err(|e| CodegenError::Module(e.to_string()))?;
            self.func_ids.insert(fn_name, func_id);
        }

        // 2. Translate and define each function
        for fir_func in &fir_module.functions {
            let fn_name = INTERNER.resolve(&fir_func.name);
            let func_id = self.func_ids[&fn_name];

            let sig = fir_signature_to_cranelift(fir_func, call_conv, ptr_type)?;
            self.ctx.func.signature = sig;

            {
                let builder = cranelift_frontend::FunctionBuilder::new(
                    &mut self.ctx.func,
                    &mut self.builder_context,
                );
                let translator =
                    FunctionTranslator::new(builder, &mut self.module, &self.func_ids, ptr_type);
                translator.translate(fir_func)?;
            }

            self.module
                .define_function(func_id, &mut self.ctx)
                .map_err(|e| {
                    CodegenError::Module(format!(
                        "Failed to define function `{}`: {}\nFunction IR:\n{}",
                        fn_name, e, self.ctx.func
                    ))
                })?;

            self.module.clear_context(&mut self.ctx);
        }

        self.module
            .finalize_definitions()
            .map_err(|e| CodegenError::Module(e.to_string()))?;

        Ok(())
    }

    /// Execute the compiled `main` function and return its integer result.
    pub fn run_main(&self) -> Result<i64, CodegenError> {
        let func_id = self
            .func_ids
            .get("main")
            .copied()
            .ok_or_else(|| CodegenError::FunctionNotFound("main".into()))?;

        let code_ptr = self.module.get_finalized_function(func_id);
        let main_fn: fn() -> i64 = unsafe { std::mem::transmute(code_ptr) };
        let result = main_fn();
        Ok(result)
    }
}
