use crate::error::CodegenError;
use crate::translator::FunctionTranslator;
use crate::types::fir_signature_to_cranelift;
use cranelift_codegen::Context;
use cranelift_frontend::FunctionBuilderContext;
use cranelift_module::{FuncId, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use ifa_fir::FirModule;
use ifa_span::INTERNER;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Ahead-of-Time (AOT) compiler producing native object files (.o) and linked ELF binaries.
pub struct AotCompiler {
    builder_context: FunctionBuilderContext,
    ctx: Context,
    module: ObjectModule,
    func_ids: HashMap<String, FuncId>,
}

impl AotCompiler {
    /// Create a new AOT compiler targeted for the host platform.
    pub fn new() -> Result<Self, CodegenError> {
        let flag_builder = cranelift_codegen::settings::builder();
        let isa_builder = cranelift_native::builder()
            .map_err(|e| CodegenError::Codegen(format!("Failed to build native ISA: {}", e)))?;
        let isa = isa_builder
            .finish(cranelift_codegen::settings::Flags::new(flag_builder))
            .map_err(|e| CodegenError::Codegen(format!("Failed to finish ISA: {}", e)))?;

        let builder =
            ObjectBuilder::new(isa, "ifa_module", cranelift_module::default_libcall_names())
                .map_err(|e| CodegenError::Module(e.to_string()))?;
        let module = ObjectModule::new(builder);

        Ok(Self {
            builder_context: FunctionBuilderContext::new(),
            ctx: module.make_context(),
            module,
            func_ids: HashMap::new(),
        })
    }

    /// Compile a FIR module and emit a native object file (.o).
    pub fn compile_to_object(
        mut self,
        fir_module: &FirModule,
        output_object: &Path,
    ) -> Result<(), CodegenError> {
        let ptr_type = self.module.target_config().pointer_type();
        let call_conv = self.module.target_config().default_call_conv;

        // Declare standard runtime intrinsic: println
        let mut println_sig = cranelift_codegen::ir::Signature::new(call_conv);
        println_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let println_id = self
            .module
            .declare_function("println", Linkage::Import, &println_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("println".into(), println_id);

        // 1. Declare functions
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

        // 2. Translate and define functions
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

        let product = self.module.finish();
        let bytes = product
            .emit()
            .map_err(|e| CodegenError::Codegen(format!("Failed to emit object bytes: {}", e)))?;

        if let Some(parent) = output_object.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output_object, bytes)?;

        Ok(())
    }

    /// Link an emitted native object file into a standalone executable using the host C toolchain.
    pub fn link_executable(object_path: &Path, output_binary: &Path) -> Result<(), CodegenError> {
        let compilers = ["cc", "gcc", "clang"];
        let mut last_err = String::new();

        let rt_stub = "#include <stdio.h>\nvoid println(const char *s) { if (s) { puts(s); } else { putchar('\\n'); } }\n";
        let rt_path =
            std::env::temp_dir().join(format!("ifa_runtime_stub_{}.c", std::process::id()));
        fs::write(&rt_path, rt_stub)?;

        for compiler in &compilers {
            let status = Command::new(compiler)
                .arg(object_path)
                .arg(&rt_path)
                .arg("-no-pie")
                .arg("-o")
                .arg(output_binary)
                .status();

            match status {
                Ok(s) if s.success() => {
                    let _ = fs::remove_file(&rt_path);
                    return Ok(());
                }
                Ok(s) => {
                    last_err = format!("Compiler `{}` failed with exit status {}", compiler, s);
                }
                Err(e) => {
                    last_err = format!("Failed to spawn `{}`: {}", compiler, e);
                }
            }
        }

        let _ = fs::remove_file(&rt_path);

        Err(CodegenError::LinkError(last_err))
    }
}
