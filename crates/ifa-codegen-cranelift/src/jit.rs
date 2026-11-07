use crate::error::CodegenError;
use crate::translator::FunctionTranslator;
use crate::types::fir_signature_to_cranelift;
use cranelift_codegen::ir::{types, AbiParam, Signature};
use cranelift_codegen::Context;
use cranelift_frontend::FunctionBuilderContext;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module};
use ifa_fir::FirModule;
use ifa_runtime::*;
use ifa_span::INTERNER;
use std::collections::HashMap;

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
        builder.symbol("ifa_rt_println", ifa_rt_println as *const u8);
        builder.symbol("ifa_rt_print", ifa_rt_print as *const u8);
        builder.symbol("ifa_rt_println_i64", ifa_rt_println_i64 as *const u8);
        builder.symbol("ifa_rt_print_i64", ifa_rt_print_i64 as *const u8);
        builder.symbol("ifa_rt_gen_alloc", ifa_rt_gen_alloc as *const u8);
        builder.symbol("ifa_rt_gen_free", ifa_rt_gen_free as *const u8);
        builder.symbol("ifa_rt_gen_check", ifa_rt_gen_check as *const u8);
        builder.symbol("ifa_rt_fiber_yield", ifa_rt_fiber_yield as *const u8);
        builder.symbol("ifa_rt_channel_create", ifa_rt_channel_create as *const u8);
        builder.symbol(
            "ifa_rt_channel_destroy",
            ifa_rt_channel_destroy as *const u8,
        );
        builder.symbol("ifa_rt_channel_send", ifa_rt_channel_send as *const u8);
        builder.symbol("ifa_rt_channel_recv", ifa_rt_channel_recv as *const u8);
        builder.symbol(
            "ifa_rt_channel_try_recv",
            ifa_rt_channel_try_recv as *const u8,
        );
        builder.symbol("ifa_rt_channel_close", ifa_rt_channel_close as *const u8);
        builder.symbol("ifa_rt_channel_select", ifa_rt_channel_select as *const u8);
        builder.symbol("ifa_rt_string_concat", ifa_rt_string_concat as *const u8);
        builder.symbol(
            "ifa_rt_string_from_i64",
            ifa_rt_string_from_i64 as *const u8,
        );
        builder.symbol(
            "ifa_rt_string_from_f64",
            ifa_rt_string_from_f64 as *const u8,
        );
        builder.symbol(
            "ifa_rt_string_from_bool",
            ifa_rt_string_from_bool as *const u8,
        );

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

        let mut print_i64_sig = Signature::new(call_conv);
        print_i64_sig.params.push(AbiParam::new(types::I64));
        let print_i64_id = self
            .module
            .declare_function("ifa_rt_println_i64", Linkage::Import, &print_i64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_println_i64".into(), print_i64_id);

        let mut gen_alloc_sig = Signature::new(call_conv);
        gen_alloc_sig.params.push(AbiParam::new(ptr_type));
        gen_alloc_sig.params.push(AbiParam::new(ptr_type));
        gen_alloc_sig.params.push(AbiParam::new(types::I32));
        gen_alloc_sig.returns.push(AbiParam::new(ptr_type));
        let gen_alloc_id = self
            .module
            .declare_function("ifa_rt_gen_alloc", Linkage::Import, &gen_alloc_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_gen_alloc".into(), gen_alloc_id);

        let mut gen_free_sig = Signature::new(call_conv);
        gen_free_sig.params.push(AbiParam::new(ptr_type));
        let gen_free_id = self
            .module
            .declare_function("ifa_rt_gen_free", Linkage::Import, &gen_free_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_gen_free".into(), gen_free_id);

        let mut gen_check_sig = Signature::new(call_conv);
        gen_check_sig.params.push(AbiParam::new(ptr_type));
        gen_check_sig.params.push(AbiParam::new(types::I32));
        let gen_check_id = self
            .module
            .declare_function("ifa_rt_gen_check", Linkage::Import, &gen_check_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_gen_check".into(), gen_check_id);

        let yield_sig = Signature::new(call_conv);
        let yield_id = self
            .module
            .declare_function("ifa_rt_fiber_yield", Linkage::Import, &yield_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_fiber_yield".into(), yield_id);

        let mut chan_create_sig = Signature::new(call_conv);
        chan_create_sig.params.push(AbiParam::new(ptr_type));
        chan_create_sig.returns.push(AbiParam::new(ptr_type));
        let chan_create_id = self
            .module
            .declare_function("ifa_rt_channel_create", Linkage::Import, &chan_create_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_create".into(), chan_create_id);

        let mut chan_send_sig = Signature::new(call_conv);
        chan_send_sig.params.push(AbiParam::new(ptr_type));
        chan_send_sig.params.push(AbiParam::new(ptr_type));
        chan_send_sig.returns.push(AbiParam::new(types::I32));
        let chan_send_id = self
            .module
            .declare_function("ifa_rt_channel_send", Linkage::Import, &chan_send_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_send".into(), chan_send_id);

        let mut chan_recv_sig = Signature::new(call_conv);
        chan_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_recv_sig.returns.push(AbiParam::new(types::I32));
        let chan_recv_id = self
            .module
            .declare_function("ifa_rt_channel_recv", Linkage::Import, &chan_recv_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_recv".into(), chan_recv_id);

        let mut chan_try_recv_sig = Signature::new(call_conv);
        chan_try_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_try_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_try_recv_sig.returns.push(AbiParam::new(types::I32));
        let chan_try_recv_id = self
            .module
            .declare_function(
                "ifa_rt_channel_try_recv",
                Linkage::Import,
                &chan_try_recv_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_try_recv".into(), chan_try_recv_id);

        let mut chan_close_sig = Signature::new(call_conv);
        chan_close_sig.params.push(AbiParam::new(ptr_type));
        let chan_close_id = self
            .module
            .declare_function("ifa_rt_channel_close", Linkage::Import, &chan_close_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_close".into(), chan_close_id);

        let mut chan_select_sig = Signature::new(call_conv);
        chan_select_sig.params.push(AbiParam::new(ptr_type));
        chan_select_sig.params.push(AbiParam::new(ptr_type));
        chan_select_sig.params.push(AbiParam::new(types::I32));
        chan_select_sig.returns.push(AbiParam::new(types::I64));
        let chan_select_id = self
            .module
            .declare_function("ifa_rt_channel_select", Linkage::Import, &chan_select_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_select".into(), chan_select_id);

        let mut str_concat_sig = Signature::new(call_conv);
        str_concat_sig.params.push(AbiParam::new(ptr_type));
        str_concat_sig.params.push(AbiParam::new(ptr_type));
        str_concat_sig.returns.push(AbiParam::new(ptr_type));
        let str_concat_id = self
            .module
            .declare_function("ifa_rt_string_concat", Linkage::Import, &str_concat_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_concat".into(), str_concat_id);

        let mut str_i64_sig = Signature::new(call_conv);
        str_i64_sig.params.push(AbiParam::new(types::I64));
        str_i64_sig.returns.push(AbiParam::new(ptr_type));
        let str_i64_id = self
            .module
            .declare_function("ifa_rt_string_from_i64", Linkage::Import, &str_i64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_i64".into(), str_i64_id);

        let mut str_f64_sig = Signature::new(call_conv);
        str_f64_sig.params.push(AbiParam::new(types::F64));
        str_f64_sig.returns.push(AbiParam::new(ptr_type));
        let str_f64_id = self
            .module
            .declare_function("ifa_rt_string_from_f64", Linkage::Import, &str_f64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_f64".into(), str_f64_id);

        let mut str_bool_sig = Signature::new(call_conv);
        str_bool_sig.params.push(AbiParam::new(types::I8));
        str_bool_sig.returns.push(AbiParam::new(ptr_type));
        let str_bool_id = self
            .module
            .declare_function("ifa_rt_string_from_bool", Linkage::Import, &str_bool_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_bool".into(), str_bool_id);

        // 1. Declare all functions first to enable mutual recursion and forward calls
        for fir_func in &fir_module.functions {
            let fn_name = INTERNER.resolve(&fir_func.name);
            let sig = fir_signature_to_cranelift(fir_func, call_conv, ptr_type)?;
            let linkage = if fir_func.blocks.is_empty() {
                Linkage::Import
            } else if fir_func.is_pub {
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

        let struct_defs: HashMap<ifa_span::Symbol, Vec<(ifa_span::Symbol, ifa_fir::FirType)>> =
            fir_module
                .structs
                .iter()
                .map(|s| (s.name, s.fields.clone()))
                .collect();

        // 2. Translate and define each function
        for fir_func in &fir_module.functions {
            if fir_func.blocks.is_empty() {
                continue;
            }
            let fn_name = INTERNER.resolve(&fir_func.name);
            let func_id = self.func_ids[&fn_name];

            let sig = fir_signature_to_cranelift(fir_func, call_conv, ptr_type)?;
            self.ctx.func.signature = sig;

            {
                let builder = cranelift_frontend::FunctionBuilder::new(
                    &mut self.ctx.func,
                    &mut self.builder_context,
                );
                let translator = FunctionTranslator::new(
                    builder,
                    &mut self.module,
                    &self.func_ids,
                    ptr_type,
                    &struct_defs,
                );
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
        self.run_function("main")
    }

    /// Execute any compiled parameterless function by name and return its integer result.
    pub fn run_function(&self, name: &str) -> Result<i64, CodegenError> {
        let func_id = self
            .func_ids
            .get(name)
            .copied()
            .ok_or_else(|| CodegenError::FunctionNotFound(name.into()))?;

        let code_ptr = self.module.get_finalized_function(func_id);
        let target_fn: fn() -> i64 = unsafe { std::mem::transmute(code_ptr) };
        let result = target_fn();
        Ok(result)
    }
}
