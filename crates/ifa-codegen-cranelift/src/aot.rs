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

void println(const char *s) { if (s) { puts(s); } else { putchar('\n'); } fflush(stdout); }
void ifa_rt_println(const char *s) { if (s) { puts(s); } else { putchar('\n'); } fflush(stdout); }
void ifa_rt_print(const char *s) { if (s) { fputs(s, stdout); fflush(stdout); } }
void ifa_rt_println_i64(int64_t n) { printf("%ld\n", n); fflush(stdout); }
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
    if (!ptr) return;
    const ifa_gen_header_t* h = (const ifa_gen_header_t*)((const uint8_t*)ptr - sizeof(ifa_gen_header_t));
    if (!(h->allocation_flags & 1) || h->generation_counter != remembered_gen) {
        fprintf(stderr, "\n[IFA RUNTIME ERROR: SAFE INTERCEPTION] Use-After-Free intercepted at %p (actual gen: %u, expected: %u)\n", ptr, h->generation_counter, remembered_gen);
        abort();
    }
}

void ifa_rt_panic_uaf(const void* ptr, uint32_t expected_gen, uint32_t actual_gen) {
    fprintf(stderr, "\n[IFA RUNTIME ERROR: SAFE INTERCEPTION] Use-After-Free intercepted at %p (actual gen: %u, expected: %u)\n", ptr, actual_gen, expected_gen);
    abort();
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

#include <stdatomic.h>

typedef struct ifa_coro_runtime {
    void* frame;
    int32_t (*resume_fn)(void*);
    void (*destroy_fn)(void*);
    int32_t status;
    uint64_t fiber_id;
    int owns_frame;
} ifa_coro_runtime_t;

void* ifa_rt_coro_create(size_t frame_size, void* resume_fn, void* destroy_fn) {
    size_t actual_size = frame_size < 16 ? 16 : frame_size;
    void* frame = calloc(1, actual_size);
    ifa_coro_runtime_t* coro = (ifa_coro_runtime_t*)calloc(1, sizeof(ifa_coro_runtime_t));
    if (!coro) return NULL;
    coro->frame = frame;
    coro->resume_fn = (int32_t (*)(void*))resume_fn;
    coro->destroy_fn = (void (*)(void*))destroy_fn;
    coro->status = 0;
    coro->owns_frame = 1;
    return coro;
}

void* ifa_rt_coro_create_custom(void* frame, void* resume_fn, void* destroy_fn) {
    ifa_coro_runtime_t* coro = (ifa_coro_runtime_t*)calloc(1, sizeof(ifa_coro_runtime_t));
    if (!coro) return NULL;
    coro->frame = frame;
    coro->resume_fn = (int32_t (*)(void*))resume_fn;
    coro->destroy_fn = (void (*)(void*))destroy_fn;
    coro->status = 0;
    coro->owns_frame = 0;
    return coro;
}

int32_t ifa_rt_coro_resume(void* coro) {
    if (!coro) return 2;
    ifa_coro_runtime_t* c = (ifa_coro_runtime_t*)coro;
    if (c->status == 1) return 1;
    if (!c->resume_fn) return 1;
    int32_t res = c->resume_fn(c->frame);
    c->status = res;
    return res;
}

int32_t ifa_rt_coro_is_done(void* coro) {
    if (!coro) return 1;
    ifa_coro_runtime_t* c = (ifa_coro_runtime_t*)coro;
    return c->status == 1 ? 1 : 0;
}

int32_t ifa_rt_coro_status(void* coro) {
    if (!coro) return 2;
    ifa_coro_runtime_t* c = (ifa_coro_runtime_t*)coro;
    return c->status;
}

void* ifa_rt_coro_frame(void* coro) {
    if (!coro) return NULL;
    ifa_coro_runtime_t* c = (ifa_coro_runtime_t*)coro;
    return c->frame;
}

void ifa_rt_coro_destroy(void* coro) {
    if (!coro) return;
    ifa_coro_runtime_t* c = (ifa_coro_runtime_t*)coro;
    if (c->destroy_fn && c->frame) {
        c->destroy_fn(c->frame);
        c->frame = NULL;
    }
    if (c->owns_frame && c->frame) {
        free(c->frame);
        c->frame = NULL;
    }
    free(c);
}

uint64_t ifa_rt_coro_spawn(void* coro) {
    if (!coro) return 0;
    static _Atomic uint64_t next_coro_fid = 1000;
    uint64_t fid = atomic_fetch_add(&next_coro_fid, 1);
    ifa_coro_runtime_t* c = (ifa_coro_runtime_t*)coro;
    c->fiber_id = fid;
    ifa_rt_coro_resume(coro);
    return fid;
}

void* ifa_rt_coro_iter_create(void* coro, void* slot, size_t size) {
    (void)slot; (void)size;
    return coro;
}

int32_t ifa_rt_coro_iter_next(void* iter, void* out) {
    if (!iter) return 0;
    ifa_coro_runtime_t* c = (ifa_coro_runtime_t*)iter;
    if (c->status == 1) return 0;
    int32_t res = ifa_rt_coro_resume(iter);
    if (out && c->frame) {
        memcpy(out, (char*)c->frame + 8, 8);
    }
    return res == 0 ? 1 : 0;
}

int32_t ifa_rt_coro_iter_is_done(void* iter) {
    return ifa_rt_coro_is_done(iter);
}

void ifa_rt_coro_iter_destroy(void* iter) {
    ifa_rt_coro_destroy(iter);
}

#define IFA_CHAN_STATE_OPEN 0
#define IFA_CHAN_STATE_CLOSED 1

typedef struct ifa_channel_sync {
    void** buffer;
    size_t capacity;
    _Atomic size_t head;
    _Atomic size_t tail;
    _Atomic size_t count;
    _Atomic int state;
} ifa_channel_sync_t;

void* ifa_rt_channel_create(size_t capacity) {
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)calloc(1, sizeof(ifa_channel_sync_t));
    if (!c) return NULL;
    size_t cap = capacity == 0 ? 1 : capacity;
    c->buffer = (void**)calloc(cap, sizeof(void*));
    c->capacity = cap;
    atomic_init(&c->head, 0);
    atomic_init(&c->tail, 0);
    atomic_init(&c->count, 0);
    atomic_init(&c->state, IFA_CHAN_STATE_OPEN);
    return c;
}

void ifa_rt_channel_destroy(void* chan) {
    if (!chan) return;
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)chan;
    if (c->buffer) free(c->buffer);
    free(c);
}

int32_t ifa_rt_channel_try_send(void* chan, void* val) {
    if (!chan) return -1;
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)chan;
    if (atomic_load(&c->state) == IFA_CHAN_STATE_CLOSED) return -2;

    size_t cur_cnt = atomic_load(&c->count);
    while (cur_cnt < c->capacity) {
        if (atomic_compare_exchange_weak(&c->count, &cur_cnt, cur_cnt + 1)) {
            size_t tail_idx = atomic_fetch_add(&c->tail, 1) % c->capacity;
            c->buffer[tail_idx] = val;
            return 0; // Success
        }
        if (atomic_load(&c->state) == IFA_CHAN_STATE_CLOSED) return -2;
    }
    return 1; // Channel is full (non-blocking backpressure)
}

int32_t ifa_rt_channel_send(void* chan, void* val) {
    if (!chan) return -1;
    while (1) {
        int32_t res = ifa_rt_channel_try_send(chan, val);
        if (res != 1) return res;
        ifa_rt_fiber_yield();
    }
}

int32_t ifa_rt_channel_try_recv(void* chan, void** out_val) {
    if (!chan || !out_val) return -1;
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)chan;

    size_t cur_cnt = atomic_load(&c->count);
    while (cur_cnt > 0) {
        if (atomic_compare_exchange_weak(&c->count, &cur_cnt, cur_cnt - 1)) {
            size_t head_idx = atomic_fetch_add(&c->head, 1) % c->capacity;
            *out_val = c->buffer[head_idx];
            return 0; // Success
        }
    }
    if (atomic_load(&c->state) == IFA_CHAN_STATE_CLOSED) {
        *out_val = NULL;
        return -2; // Closed and empty
    }
    *out_val = NULL;
    return 1; // Empty (non-blocking)
}

int32_t ifa_rt_channel_recv(void* chan, void** out_val) {
    if (!chan || !out_val) return -1;
    while (1) {
        int32_t res = ifa_rt_channel_try_recv(chan, out_val);
        if (res != 1) return res;
        ifa_rt_fiber_yield();
    }
}

void ifa_rt_channel_close(void* chan) {
    if (!chan) return;
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)chan;
    atomic_store(&c->state, IFA_CHAN_STATE_CLOSED);
}

int32_t ifa_rt_channel_is_closed(void* chan) {
    if (!chan) return 1;
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)chan;
    return atomic_load(&c->state) == IFA_CHAN_STATE_CLOSED ? 1 : 0;
}

int64_t ifa_rt_channel_len(void* chan) {
    if (!chan) return 0;
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)chan;
    return (int64_t)atomic_load(&c->count);
}

int64_t ifa_rt_channel_capacity(void* chan) {
    if (!chan) return 0;
    ifa_channel_sync_t* c = (ifa_channel_sync_t*)chan;
    return (int64_t)c->capacity;
}

int64_t ifa_rt_channel_select(void** channels, size_t num_channels, int32_t has_default) {
    if (!channels || num_channels == 0) return has_default ? 0 : -2;
    int any_open = 0;
    for (size_t i = 0; i < num_channels; i++) {
        if (!channels[i]) continue;
        ifa_channel_sync_t* c = (ifa_channel_sync_t*)channels[i];
        if (atomic_load(&c->count) > 0) return (int64_t)i;
        if (atomic_load(&c->state) != IFA_CHAN_STATE_CLOSED) any_open = 1;
    }
    if (has_default) return (int64_t)num_channels;
    if (!any_open) return -2;
    return -1;
}

int64_t ifa_rt_channel_select_prioritized(void** channels, const int32_t* priorities, size_t num_channels, int32_t has_default) {
    if (!channels || num_channels == 0) return has_default ? 0 : -2;
    int any_open = 0;
    int64_t best_idx = -1;
    int32_t best_prio = -2147483647;
    for (size_t i = 0; i < num_channels; i++) {
        if (!channels[i]) continue;
        ifa_channel_sync_t* c = (ifa_channel_sync_t*)channels[i];
        int32_t prio = priorities ? priorities[i] : 0;
        if (atomic_load(&c->count) > 0) {
            if (best_idx == -1 || prio > best_prio) {
                best_idx = (int64_t)i;
                best_prio = prio;
            }
        }
        if (atomic_load(&c->state) != IFA_CHAN_STATE_CLOSED) any_open = 1;
    }
    if (best_idx != -1) return best_idx;
    if (has_default) return (int64_t)num_channels;
    if (!any_open) return -2;
    return -1;
}

int64_t ifa_rt_channel_select_timed(void** channels, const int32_t* priorities, size_t num_channels, uint64_t timeout_ns, int32_t has_default) {
    int64_t res = ifa_rt_channel_select_prioritized(channels, priorities, num_channels, has_default);
    if (res != -1) return res;
    if (timeout_ns > 0) return (int64_t)num_channels;
    return -1;
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

size_t ifa_rt_call_arena_capacity(void) {
    return sizeof(ifa_rt_call_arena_buf);
}

size_t ifa_rt_call_arena_high_water_mark(void) {
    return ifa_rt_call_arena_off;
}

void ifa_rt_call_arena_shrink_to_fit(size_t max_idle_capacity) {
    (void)max_idle_capacity;
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

int8_t ifa_rt_string_eq(const char* a, const char* b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    return strcmp(a, b) == 0 ? 1 : 0;
}

int64_t ifa_rt_string_len(const char* s) {
    if (!s) return 0;
    int64_t count = 0;
    const unsigned char* p = (const unsigned char*)s;
    while (*p) {
        if ((*p & 0xC0) != 0x80) {
            count++;
        }
        p++;
    }
    return count;
}

int64_t ifa_rt_string_char_at(const char* s, int64_t index) {
    if (!s || index < 0) return -1;
    const unsigned char* p = (const unsigned char*)s;
    int64_t cur = 0;
    while (*p) {
        if ((*p & 0xC0) != 0x80) {
            if (cur == index) {
                if (*p < 0x80) {
                    return *p;
                } else if ((*p & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
                    return ((p[0] & 0x1F) << 6) | (p[1] & 0x3F);
                } else if ((*p & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
                    return ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
                } else if ((*p & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
                    return ((p[0] & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
                }
                return *p;
            }
            cur++;
        }
        p++;
    }
    return -1;
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

char* ifa_rt_fs_read_to_string(const char* path) {
    if (!path) {
        char* empty = (char*)malloc(1);
        empty[0] = '\0';
        return empty;
    }
    FILE* f = fopen(path, "rb");
    if (!f) {
        char* empty = (char*)malloc(1);
        empty[0] = '\0';
        return empty;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { sz = 0; }
    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); abort(); }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    return buf;
}

int8_t ifa_rt_fs_write_string(const char* path, const char* content) {
    if (!path || !content) return 0;
    FILE* f = fopen(path, "wb");
    if (!f) return 0;
    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);
    fclose(f);
    return written == len ? 1 : 0;
}

int8_t ifa_rt_fs_exists(const char* path) {
    if (!path) return 0;
    FILE* f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

uint64_t ifa_rt_fs_file_size(const char* path) {
    if (!path) return 0;
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    return sz >= 0 ? (uint64_t)sz : 0;
}

int64_t ifa_rt_process_exec(const char* cmd, const char* args) {
    if (!cmd) return -1;
    char full_cmd[1024];
    if (args && strlen(args) > 0) {
        snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd, args);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
    }
    int code = system(full_cmd);
    return (int64_t)code;
}

char* ifa_rt_process_exec_output(const char* cmd, const char* args) {
    if (!cmd) {
        char* empty = (char*)malloc(1);
        empty[0] = '\0';
        return empty;
    }
    char full_cmd[1024];
    if (args && strlen(args) > 0) {
        snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd, args);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
    }
    FILE* pipe = popen(full_cmd, "r");
    if (!pipe) {
        char* empty = (char*)malloc(1);
        empty[0] = '\0';
        return empty;
    }
    size_t cap = 1024;
    size_t len = 0;
    char* buf = (char*)malloc(cap);
    if (!buf) { pclose(pipe); abort(); }
    while (1) {
        size_t rd = fread(buf + len, 1, cap - len - 1, pipe);
        if (rd == 0) break;
        len += rd;
        if (len + 128 >= cap) {
            cap *= 2;
            buf = (char*)realloc(buf, cap);
            if (!buf) { pclose(pipe); abort(); }
        }
    }
    buf[len] = '\0';
    pclose(pipe);
    return buf;
}

char* ifa_rt_env_var(const char* name) {
    if (!name) {
        char* empty = (char*)malloc(1);
        empty[0] = '\0';
        return empty;
    }
    const char* val = getenv(name);
    if (!val) {
        char* empty = (char*)malloc(1);
        empty[0] = '\0';
        return empty;
    }
    size_t len = strlen(val);
    char* buf = (char*)malloc(len + 1);
    if (!buf) abort();
    memcpy(buf, val, len + 1);
    return buf;
}

static int s_ifa_args_initialized = 0;
static int s_ifa_argc = 0;
static char* s_ifa_argv[256];

static void ifa_rt_init_args(void) {
    if (s_ifa_args_initialized) return;
    s_ifa_args_initialized = 1;
    s_ifa_argc = 0;
    FILE* f = fopen("/proc/self/cmdline", "rb");
    if (!f) return;
    char buf[4096];
    size_t rd = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (rd == 0) return;
    buf[rd] = '\0';
    size_t pos = 0;
    while (pos < rd && s_ifa_argc < 256) {
        size_t arg_len = strlen(buf + pos);
        char* arg_copy = (char*)malloc(arg_len + 1);
        if (arg_copy) {
            memcpy(arg_copy, buf + pos, arg_len + 1);
            s_ifa_argv[s_ifa_argc++] = arg_copy;
        }
        pos += arg_len + 1;
    }
}

int64_t ifa_rt_args_count(void) {
    ifa_rt_init_args();
    return (int64_t)s_ifa_argc;
}

char* ifa_rt_args_get(int64_t index) {
    ifa_rt_init_args();
    if (index < 0 || index >= (int64_t)s_ifa_argc || !s_ifa_argv[index]) {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    size_t len = strlen(s_ifa_argv[index]);
    char* copy = (char*)malloc(len + 1);
    if (copy) {
        memcpy(copy, s_ifa_argv[index], len + 1);
    }
    return copy;
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

        let mut chan_try_send_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_try_send_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_try_send_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_try_send_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        let chan_try_send_id = self
            .module
            .declare_function(
                "ifa_rt_channel_try_send",
                Linkage::Import,
                &chan_try_send_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_try_send".into(), chan_try_send_id);

        let mut chan_is_closed_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_is_closed_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_is_closed_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        let chan_is_closed_id = self
            .module
            .declare_function(
                "ifa_rt_channel_is_closed",
                Linkage::Import,
                &chan_is_closed_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_is_closed".into(), chan_is_closed_id);

        let mut chan_len_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_len_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_len_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        let chan_len_id = self
            .module
            .declare_function("ifa_rt_channel_len", Linkage::Import, &chan_len_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_len".into(), chan_len_id);

        let mut chan_cap_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_cap_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_cap_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        let chan_cap_id = self
            .module
            .declare_function("ifa_rt_channel_capacity", Linkage::Import, &chan_cap_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_capacity".into(), chan_cap_id);

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

        let mut chan_select_timed_sig = cranelift_codegen::ir::Signature::new(call_conv);
        chan_select_timed_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_select_timed_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_select_timed_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        chan_select_timed_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        chan_select_timed_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        chan_select_timed_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        let chan_select_timed_id = self
            .module
            .declare_function(
                "ifa_rt_channel_select_timed",
                Linkage::Import,
                &chan_select_timed_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_select_timed".into(), chan_select_timed_id);

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

        // Register stackless coroutine intrinsics
        let mut coro_create_sig = cranelift_codegen::ir::Signature::new(call_conv);
        coro_create_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        coro_create_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        coro_create_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        coro_create_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let coro_create_id = self
            .module
            .declare_function("ifa_rt_coro_create", Linkage::Import, &coro_create_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_create".into(), coro_create_id);

        let mut coro_frame_sig = cranelift_codegen::ir::Signature::new(call_conv);
        coro_frame_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        coro_frame_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let coro_frame_id = self
            .module
            .declare_function("ifa_rt_coro_frame", Linkage::Import, &coro_frame_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_frame".into(), coro_frame_id);

        let mut coro_resume_sig = cranelift_codegen::ir::Signature::new(call_conv);
        coro_resume_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        coro_resume_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        let coro_resume_id = self
            .module
            .declare_function("ifa_rt_coro_resume", Linkage::Import, &coro_resume_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_resume".into(), coro_resume_id);

        let mut coro_spawn_sig = cranelift_codegen::ir::Signature::new(call_conv);
        coro_spawn_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        coro_spawn_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I64,
            ));
        let coro_spawn_id = self
            .module
            .declare_function("ifa_rt_coro_spawn", Linkage::Import, &coro_spawn_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_spawn".into(), coro_spawn_id);

        let mut coro_is_done_sig = cranelift_codegen::ir::Signature::new(call_conv);
        coro_is_done_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        coro_is_done_sig
            .returns
            .push(cranelift_codegen::ir::AbiParam::new(
                cranelift_codegen::ir::types::I32,
            ));
        let coro_is_done_id = self
            .module
            .declare_function("ifa_rt_coro_is_done", Linkage::Import, &coro_is_done_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_is_done".into(), coro_is_done_id);

        let mut coro_destroy_sig = cranelift_codegen::ir::Signature::new(call_conv);
        coro_destroy_sig
            .params
            .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
        let coro_destroy_id = self
            .module
            .declare_function("ifa_rt_coro_destroy", Linkage::Import, &coro_destroy_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_destroy".into(), coro_destroy_id);

        let coro_funcs: std::collections::HashSet<ifa_span::Symbol> = fir_module
            .functions
            .iter()
            .filter(|f| f.is_coroutine())
            .map(|f| f.name)
            .collect();

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
            self.func_ids.insert(fn_name.clone(), func_id);

            if fir_func.is_coroutine() && !fir_func.blocks.is_empty() {
                let resume_name = format!("{}$resume", fn_name);
                let mut resume_sig = cranelift_codegen::ir::Signature::new(call_conv);
                resume_sig
                    .params
                    .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
                resume_sig
                    .returns
                    .push(cranelift_codegen::ir::AbiParam::new(
                        cranelift_codegen::ir::types::I32,
                    ));
                let resume_func_id = self
                    .module
                    .declare_function(&resume_name, Linkage::Local, &resume_sig)
                    .map_err(|e| CodegenError::Module(e.to_string()))?;
                self.func_ids.insert(resume_name, resume_func_id);
            }
        }

        let struct_defs: HashMap<ifa_span::Symbol, Vec<(ifa_span::Symbol, ifa_fir::FirType)>> =
            fir_module
                .structs
                .iter()
                .map(|s| (s.name, s.fields.clone()))
                .collect();

        let fn_param_types: HashMap<String, Vec<ifa_fir::FirType>> = fir_module
            .functions
            .iter()
            .map(|f| {
                (
                    INTERNER.resolve(&f.name).to_string(),
                    f.params.iter().map(|p| p.ty.clone()).collect(),
                )
            })
            .collect();

        // 2. Translate and define functions
        for fir_func in &fir_module.functions {
            if fir_func.blocks.is_empty() {
                continue;
            }
            let fn_name = INTERNER.resolve(&fir_func.name);

            if fir_func.is_coroutine() {
                // A) Define coroutine resume function
                let resume_name = format!("{}$resume", fn_name);
                let resume_id = self.func_ids[&resume_name];
                let mut resume_sig = cranelift_codegen::ir::Signature::new(call_conv);
                resume_sig
                    .params
                    .push(cranelift_codegen::ir::AbiParam::new(ptr_type));
                resume_sig
                    .returns
                    .push(cranelift_codegen::ir::AbiParam::new(
                        cranelift_codegen::ir::types::I32,
                    ));
                self.ctx.func.signature = resume_sig;

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
                        &coro_funcs,
                        &fn_param_types,
                    );
                    translator.translate_coroutine_resume(fir_func)?;
                }

                self.module
                    .define_function(resume_id, &mut self.ctx)
                    .map_err(|e| {
                        CodegenError::Module(format!(
                            "Failed to define coroutine resume `{}`: {}\nFunction IR:\n{}",
                            resume_name, e, self.ctx.func
                        ))
                    })?;

                self.module.clear_context(&mut self.ctx);

                // B) Define coroutine factory instantiator function
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
                        &coro_funcs,
                        &fn_param_types,
                    );
                    translator.translate_coroutine_factory(fir_func, &resume_name)?;
                }

                self.module
                    .define_function(func_id, &mut self.ctx)
                    .map_err(|e| {
                        CodegenError::Module(format!(
                            "Failed to define coroutine factory `{}`: {}\nFunction IR:\n{}",
                            fn_name, e, self.ctx.func
                        ))
                    })?;

                self.module.clear_context(&mut self.ctx);
            } else {
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
                        &coro_funcs,
                        &fn_param_types,
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
        let rt_path = object_path.with_extension("rt.c");
        fs::write(&rt_path, rt_stub)?;

        // Remove destination executable if present to avoid ETXTBSY on Linux
        let _ = fs::remove_file(output_binary);

        for compiler in &compilers {
            let status = Command::new(compiler)
                .arg(object_path)
                .arg(&rt_path)
                .arg("-no-pie")
                .arg("-fno-ident")
                .arg("-Wl,--build-id=none")
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
