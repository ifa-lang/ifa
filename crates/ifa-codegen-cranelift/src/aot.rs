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
#include <string.h>

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

uint64_t ifa_rt_fiber_spawn(void (*entry)(void*), void* arg) {
    if (entry) {
        entry(arg);
    }
    return 1;
}

void ifa_rt_fiber_join(uint64_t fid) {
    (void)fid;
}

uint64_t ifa_rt_coro_spawn(void* coro) {
    (void)coro;
    return 1;
}

void* ifa_rt_coro_create(size_t frame_size, void* resume_fn, void* destroy_fn) {
    (void)frame_size; (void)resume_fn; (void)destroy_fn;
    return (void*)1;
}

void* ifa_rt_coro_create_custom(void* frame, void* resume_fn, void* destroy_fn) {
    (void)frame; (void)resume_fn; (void)destroy_fn;
    return frame ? frame : (void*)1;
}

int32_t ifa_rt_coro_resume(void* coro) { (void)coro; return 1; }
int32_t ifa_rt_coro_is_done(void* coro) { (void)coro; return 1; }
void ifa_rt_coro_destroy(void* coro) { (void)coro; }
void* ifa_rt_coro_frame(void* coro) { return coro; }
void* ifa_rt_coro_iter_create(void* coro, void* slot, size_t size) { (void)coro; (void)slot; (void)size; return (void*)1; }
int32_t ifa_rt_coro_iter_next(void* iter, void* out) { (void)iter; (void)out; return 0; }
int32_t ifa_rt_coro_iter_is_done(void* iter) { (void)iter; return 1; }
void ifa_rt_coro_iter_destroy(void* iter) { (void)iter; }

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

typedef struct {
    const char* ptr;
    size_t len;
} ifa_slice_t;

typedef struct {
    char* ptr;
    size_t len;
    size_t cap;
} ifa_mut_slice_t;

uint16_t ifa_rt_arena_create(size_t capacity) {
    (void)capacity;
    return 1;
}

void ifa_rt_arena_reset(uint16_t arena_id) {
    (void)arena_id;
}

void ifa_rt_arena_destroy(uint16_t arena_id) {
    (void)arena_id;
}

void* ifa_rt_arena_alloc(uint16_t arena_id, size_t size, size_t align) {
    return ifa_rt_gen_alloc(size, align, arena_id);
}

static __thread char ifa_rt_call_arena_buf[65536];
static __thread size_t ifa_rt_call_arena_off = 0;
static __thread uint32_t ifa_rt_call_arena_gen = 1;

void* ifa_rt_call_arena_alloc(size_t size, size_t align) {
    if (align < 8) align = 8;
    size_t header_size = sizeof(ifa_gen_header_t);
    size_t aligned_header_offset = (ifa_rt_call_arena_off + 7) & ~7;
    size_t payload_offset = aligned_header_offset + header_size;
    size_t aligned_payload_offset = (payload_offset + align - 1) & ~(align - 1);
    size_t actual_header_offset = aligned_payload_offset - header_size;
    size_t total_needed = aligned_payload_offset + size;
    if (total_needed > sizeof(ifa_rt_call_arena_buf)) {
        return ifa_rt_gen_alloc(size, align, 0xFFF0);
    }
    ifa_gen_header_t* header = (ifa_gen_header_t*)(ifa_rt_call_arena_buf + actual_header_offset);
    header->generation_counter = ifa_rt_call_arena_gen++;
    header->allocation_flags = 0x0001 | 0x0008;
    header->arena_id = 0xFFF0;
    ifa_rt_call_arena_off = total_needed;
    return (void*)(ifa_rt_call_arena_buf + aligned_payload_offset);
}

size_t ifa_rt_call_arena_mark(void) {
    return ifa_rt_call_arena_off;
}

void ifa_rt_call_arena_rewind(size_t mark) {
    if (mark < ifa_rt_call_arena_off) {
        ifa_rt_call_arena_gen++;
        ifa_rt_call_arena_off = mark;
    }
}

void ifa_rt_call_arena_reset(void) {
    if (ifa_rt_call_arena_off > 0) {
        ifa_rt_call_arena_gen++;
    }
    ifa_rt_call_arena_off = 0;
}

ifa_slice_t ifa_rt_slice_from_raw(const char* ptr, size_t len) {
    ifa_slice_t s;
    s.ptr = ptr;
    s.len = len;
    return s;
}

ifa_mut_slice_t ifa_rt_slice_alloc(size_t len, uint16_t arena_id) {
    ifa_mut_slice_t s;
    s.ptr = (char*)ifa_rt_gen_alloc(len > 0 ? len : 1, 8, arena_id);
    s.len = 0;
    s.cap = len > 0 ? len : 1;
    return s;
}

void ifa_rt_slice_free(ifa_mut_slice_t slice) {
    if (slice.ptr) {
        ifa_rt_gen_free((void*)slice.ptr);
    }
}

char* ifa_rt_string_concat(const char* a, const char* b) {
    size_t len_a = a ? strlen(a) : 0;
    size_t len_b = b ? strlen(b) : 0;
    char* res = (char*)malloc(len_a + len_b + 1);
    if (!res) abort();
    if (len_a > 0) memcpy(res, a, len_a);
    if (len_b > 0) memcpy(res + len_a, b, len_b);
    res[len_a + len_b] = '\0';
    return res;
}

char* ifa_rt_string_from_i64(int64_t val) {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%ld", (long)val);
    char* res = (char*)malloc(len + 1);
    if (!res) abort();
    memcpy(res, buf, len + 1);
    return res;
}

char* ifa_rt_string_from_f64(double val) {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%g", val);
    char* res = (char*)malloc(len + 1);
    if (!res) abort();
    memcpy(res, buf, len + 1);
    return res;
}

char* ifa_rt_string_from_bool(int8_t val) {
    const char* s = val ? "true" : "false";
    size_t len = strlen(s);
    char* res = (char*)malloc(len + 1);
    if (!res) abort();
    memcpy(res, s, len + 1);
    return res;
}

const char* ifa_rt_version_string(void) {
    return "IFA Runtime 0.1.0 (Zero-GC Generational Concurrency)";
}

void ifa_rt_bounds_check(size_t index, size_t len, const char* msg) {
    if (index >= len) {
        if (msg) {
            fprintf(stderr, "\n[IFA RUNTIME ERROR: SAFE BOUNDS CHECK] %s (index: %zu, length: %zu)\n", msg, index, len);
        } else {
            fprintf(stderr, "\n[IFA RUNTIME ERROR: SAFE BOUNDS CHECK] Out of bounds (index: %zu, length: %zu)\n", index, len);
        }
        abort();
    }
}

void ifa_rt_slice_bounds_check(size_t start, size_t end, size_t len, const char* msg) {
    if (start > end || end > len) {
        if (msg) {
            fprintf(stderr, "\n[IFA RUNTIME ERROR: SAFE SLICE BOUNDS CHECK] %s (range [%zu..%zu], length: %zu)\n", msg, start, end, len);
        } else {
            fprintf(stderr, "\n[IFA RUNTIME ERROR: SAFE SLICE BOUNDS CHECK] Slice range [%zu..%zu] exceeds length %zu\n", start, end, len);
        }
        abort();
    }
}

int ifa_rt_buffer_verify_bounds(const void* ptr, size_t len, size_t required_min, size_t align) {
    if (!ptr || len < required_min) return 0;
    size_t actual_align = align == 0 ? 1 : align;
    return ((uintptr_t)ptr % actual_align) == 0;
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

        let mut str_concat_sig = cranelift_codegen::ir::Signature::new(call_conv);
        str_concat_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        str_concat_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        str_concat_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let str_concat_id = self
            .module
            .declare_function("ifa_rt_string_concat", Linkage::Import, &str_concat_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_concat".into(), str_concat_id);

        let mut str_i64_sig = cranelift_codegen::ir::Signature::new(call_conv);
        str_i64_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        str_i64_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let str_i64_id = self
            .module
            .declare_function("ifa_rt_string_from_i64", Linkage::Import, &str_i64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_i64".into(), str_i64_id);

        let mut str_f64_sig = cranelift_codegen::ir::Signature::new(call_conv);
        str_f64_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::F64,
            ));
        str_f64_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let str_f64_id = self
            .module
            .declare_function("ifa_rt_string_from_f64", Linkage::Import, &str_f64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_f64".into(), str_f64_id);

        let mut str_bool_sig = cranelift_codegen::ir::Signature::new(call_conv);
        str_bool_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I8,
            ));
        str_bool_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let str_bool_id = self
            .module
            .declare_function("ifa_rt_string_from_bool", Linkage::Import, &str_bool_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_bool".into(), str_bool_id);

        // 1. Declare functions
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

        // 2. Translate and define functions
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

        static STUB_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stub_id = STUB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let rt_stub = RUNTIME_STUB_C;
        let rt_path = std::env::temp_dir().join(format!(
            "ifa_runtime_stub_{}_{}_{}.c",
            std::process::id(),
            stub_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
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
