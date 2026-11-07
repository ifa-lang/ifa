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

/// Minimal C runtime stub provided during standalone linking of native executables.
pub const RUNTIME_STUB_C: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void println(const char *s) { if (s) { puts(s); } else { putchar('\n'); } }
void ifa_rt_println(const char *s) { if (s) { puts(s); } else { putchar('\n'); } }
void ifa_rt_print(const char *s) { if (s) { fputs(s, stdout); fflush(stdout); } }
void ifa_rt_println_i64(int64_t n) { printf("%ld\n", n); }
void ifa_rt_print_i64(int64_t n) { printf("%ld", n); fflush(stdout); }

typedef struct {
    uint32_t generation_counter;
    uint16_t allocation_flags;
    uint16_t arena_id;
} ifa_gen_header_t;

void* ifa_rt_gen_alloc(size_t size, size_t align, uint16_t arena_id) {
    (void)align;
    size_t total = sizeof(ifa_gen_header_t) + size;
    void* mem = malloc(total);
    if (!mem) abort();
    ifa_gen_header_t* h = (ifa_gen_header_t*)mem;
    h->generation_counter = 1;
    h->allocation_flags = 1;
    h->arena_id = arena_id;
    return (void*)((uint8_t*)mem + sizeof(ifa_gen_header_t));
}

void ifa_rt_gen_free(void* ptr) {
    if (!ptr) return;
    ifa_gen_header_t* h = (ifa_gen_header_t*)((uint8_t*)ptr - sizeof(ifa_gen_header_t));
    if (!(h->allocation_flags & 1)) abort();
    h->allocation_flags &= ~1;
    h->generation_counter++;
    free(h);
}

void ifa_rt_gen_check(const void* ptr, uint32_t remembered_gen) {
    if (!ptr) abort();
    const ifa_gen_header_t* h = (const ifa_gen_header_t*)((const uint8_t*)ptr - sizeof(ifa_gen_header_t));
    if (!(h->allocation_flags & 1) || h->generation_counter != remembered_gen) {
        fprintf(stderr, "\n[IFA RUNTIME ERROR: SAFE INTERCEPTION] Use-After-Free intercepted at %p (actual gen: %u, expected: %u)\n", ptr, h->generation_counter, remembered_gen);
        abort();
    }
}

void ifa_rt_fiber_yield(void) {}

typedef struct ifa_channel_stub {
    void* val;
    int has_val;
    int closed;
} ifa_channel_stub_t;

void* ifa_rt_channel_create(size_t capacity) {
    (void)capacity;
    ifa_channel_stub_t* c = (ifa_channel_stub_t*)calloc(1, sizeof(ifa_channel_stub_t));
    return c;
}

void ifa_rt_channel_destroy(void* chan) {
    if (chan) free(chan);
}

int32_t ifa_rt_channel_send(void* chan, void* val) {
    if (!chan) return -1;
    ifa_channel_stub_t* c = (ifa_channel_stub_t*)chan;
    if (c->closed) return -2;
    c->val = val;
    c->has_val = 1;
    return 0;
}

int32_t ifa_rt_channel_recv(void* chan, void** out_val) {
    if (!chan || !out_val) return -1;
    ifa_channel_stub_t* c = (ifa_channel_stub_t*)chan;
    if (c->has_val) {
        *out_val = c->val;
        c->has_val = 0;
        return 0;
    }
    if (c->closed) return -2;
    *out_val = NULL;
    return 0;
}

int32_t ifa_rt_channel_try_recv(void* chan, void** out_val) {
    return ifa_rt_channel_recv(chan, out_val);
}

void ifa_rt_channel_close(void* chan) {
    if (!chan) return;
    ifa_channel_stub_t* c = (ifa_channel_stub_t*)chan;
    c->closed = 1;
}

int64_t ifa_rt_channel_select(void** channels, size_t num_channels, int32_t has_default) {
    if (!channels || num_channels == 0) return has_default ? 0 : -2;
    for (size_t i = 0; i < num_channels; i++) {
        ifa_channel_stub_t* c = (ifa_channel_stub_t*)channels[i];
        if (c && c->has_val) return (int64_t)i;
    }
    if (has_default) return (int64_t)num_channels;
    return 0;
}
"#;

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

        // Declare standard runtime intrinsics
        let mut println_sig = cranelift_codegen::ir::Signature::new(call_conv);
        println_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let println_id = self
            .module
            .declare_function("println", Linkage::Import, &println_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("println".into(), println_id);

        let mut print_i64_sig = cranelift_codegen::ir::Signature::new(call_conv);
        print_i64_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        let print_i64_id = self
            .module
            .declare_function("ifa_rt_println_i64", Linkage::Import, &print_i64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_println_i64".into(), print_i64_id);

        let mut gen_alloc_sig = cranelift_codegen::ir::Signature::new(call_conv);
        gen_alloc_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        gen_alloc_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        gen_alloc_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        gen_alloc_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let gen_alloc_id = self
            .module
            .declare_function("ifa_rt_gen_alloc", Linkage::Import, &gen_alloc_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_gen_alloc".into(), gen_alloc_id);

        let mut gen_free_sig = cranelift_codegen::ir::Signature::new(call_conv);
        gen_free_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let gen_free_id = self
            .module
            .declare_function("ifa_rt_gen_free", Linkage::Import, &gen_free_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_gen_free".into(), gen_free_id);

        let mut gen_check_sig = cranelift_codegen::ir::Signature::new(call_conv);
        gen_check_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        gen_check_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        let gen_check_id = self
            .module
            .declare_function("ifa_rt_gen_check", Linkage::Import, &gen_check_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_gen_check".into(), gen_check_id);

        let yield_sig = cranelift_codegen::ir::Signature::new(call_conv);
        let yield_id = self
            .module
            .declare_function("ifa_rt_fiber_yield", Linkage::Import, &yield_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_fiber_yield".into(), yield_id);

        let mut chan_create_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_create_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_create_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let chan_create_id = self
            .module
            .declare_function("ifa_rt_channel_create", Linkage::Import, &chan_create_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_create".into(), chan_create_id);

        let mut chan_send_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_send_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_send_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_send_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        let chan_send_id = self
            .module
            .declare_function("ifa_rt_channel_send", Linkage::Import, &chan_send_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_send".into(), chan_send_id);

        let mut chan_recv_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_recv_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_recv_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_recv_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        let chan_recv_id = self
            .module
            .declare_function("ifa_rt_channel_recv", Linkage::Import, &chan_recv_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_recv".into(), chan_recv_id);

        let mut chan_try_recv_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_try_recv_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_try_recv_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_try_recv_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
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

        let mut chan_close_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_close_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let chan_close_id = self
            .module
            .declare_function("ifa_rt_channel_close", Linkage::Import, &chan_close_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_close".into(), chan_close_id);

        let mut chan_select_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_select_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_select_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_select_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        chan_select_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        let chan_select_id = self
            .module
            .declare_function("ifa_rt_channel_select", Linkage::Import, &chan_select_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_select".into(), chan_select_id);

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

        let rt_stub = RUNTIME_STUB_C;
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
