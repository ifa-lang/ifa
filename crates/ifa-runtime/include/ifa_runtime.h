/**
 * @file ifa_runtime.h
 * @brief IFA Programming Language - Standard C-ABI Runtime Header
 *
 * Provides deterministic zero-GC generational memory allocation,
 * fiber concurrency primitives, and stream I/O for native execution
 * and high-performance cross-language C-ABI FFI integration.
 */

#ifndef IFA_RUNTIME_H
#define IFA_RUNTIME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Allocation Flags --- */
#define IFA_FLAG_FREE         0x0000
#define IFA_FLAG_ACTIVE       0x0001
#define IFA_FLAG_PINNED       0x0002
#define IFA_FLAG_READONLY     0x0004
#define IFA_FLAG_ARENA_SCOPED 0x0008
#define IFA_ARENA_THREAD_LOCAL_CALL 0xFFF0

/**
 * 64-bit Generational Header placed directly before each allocated payload.
 */
typedef struct {
    uint32_t generation_counter; /**< Generation counter incremented on free */
    uint16_t allocation_flags;   /**< Status flags */
    uint16_t arena_id;           /**< Owning arena identifier */
} ifa_gen_header_t;

/**
 * 128-bit Generational Fat Pointer (`ref`).
 */
typedef struct {
    void*    ptr;            /**< Raw 64-bit pointer to payload */
    uint32_t remembered_gen; /**< Generation recorded at reference creation */
    uint16_t arena_id;       /**< Owning arena identifier */
    uint16_t _reserved;      /**< Reserved padding */
} ifa_gen_ref_t;

/**
 * Binary representation of an IFA Error Union result (`Error!T`).
 * Status 0 indicates success, non-zero indicates an error code or tag.
 */
typedef struct {
    int64_t status; /**< 0 = OK, non-zero = error code / tag */
    void*   value;  /**< Pointer or scalar payload */
} ifa_error_union_t;

/**
 * Immutable contiguous byte/data slice for zero-copy FFI data exchange.
 */
typedef struct {
    const char* ptr; /**< Pointer to contiguous memory buffer */
    size_t      len; /**< Length in bytes */
} ifa_slice_t;

/**
 * Mutable contiguous byte/data slice with capacity for zero-copy FFI buffer exchange.
 */
typedef struct {
    char*  ptr; /**< Mutable pointer to allocated buffer */
    size_t len; /**< Length of written content in bytes */
    size_t cap; /**< Total allocated capacity in bytes */
} ifa_mut_slice_t;

/* --- Generational Memory Allocator API --- */

/**
 * Allocate a generational memory slot.
 * Returns pointer to the object payload (preceded by 8-byte ifa_gen_header_t).
 */
void* ifa_rt_gen_alloc(size_t size, size_t align, uint16_t arena_id);

/**
 * Free a generational memory slot, incrementing generation counter.
 */
void ifa_rt_gen_free(void* ptr);

/**
 * 1-cycle CPU generation check: aborts deterministically on Use-After-Free.
 */
void ifa_rt_gen_check(const void* ptr, uint32_t remembered_gen);

/**
 * Create a scoped generational arena.
 */
uint16_t ifa_rt_arena_create(size_t capacity);

/**
 * Reset an arena, invalidating all contained generational references in O(1).
 */
void ifa_rt_arena_reset(uint16_t arena_id);

/**
 * Destroy an arena and free all associated pages.
 */
void ifa_rt_arena_destroy(uint16_t arena_id);

/**
 * Allocate memory directly inside a scoped generational arena.
 */
void* ifa_rt_arena_alloc(uint16_t arena_id, size_t size, size_t align);

/**
 * Allocate memory inside the fast thread-local call arena for bounded closure environments.
 */
void* ifa_rt_call_arena_alloc(size_t size, size_t align);

/**
 * Mark the active thread's call arena bump position to establish a rewind point.
 */
size_t ifa_rt_call_arena_mark(void);

/**
 * Rewind the active thread's call arena bump position, resetting allocations above mark.
 */
void ifa_rt_call_arena_rewind(size_t mark);

/**
 * Reset the active thread's call arena completely.
 */
void ifa_rt_call_arena_reset(void);

/**
 * Retrieve the active thread's call arena capacity in bytes.
 */
size_t ifa_rt_call_arena_capacity(void);

/**
 * Retrieve the active thread's peak bump allocation offset (high-water mark).
 */
size_t ifa_rt_call_arena_high_water_mark(void);

/**
 * Consolidate and shrink the active thread's call arena buffer if currently idle.
 */
void ifa_rt_call_arena_shrink_to_fit(size_t max_idle_capacity);

/* --- Zero-Copy Slices & Buffers API --- */

/**
 * Construct an immutable slice from a raw pointer and length without memory copy.
 */
ifa_slice_t ifa_rt_slice_from_raw(const char* ptr, size_t len);

/**
 * Allocate a mutable zero-copy buffer on the generational heap or specified arena.
 */
ifa_mut_slice_t ifa_rt_slice_alloc(size_t len, uint16_t arena_id);

/**
 * Deallocate a mutable zero-copy buffer.
 */
void ifa_rt_slice_free(ifa_mut_slice_t slice);

/**
 * Returns a static null-terminated C string identifying the IFA runtime engine.
 */
const char* ifa_rt_version_string(void);

/* --- Concurrency & Colorless Fibers API --- */

typedef void (*ifa_fiber_entry_fn)(void* arg);

/**
 * Spawn a new lightweight colorless fiber.
 */
uint64_t ifa_rt_fiber_spawn(ifa_fiber_entry_fn entry, void* arg);

/**
 * Relinquish CPU execution slice to other fibers.
 */
void ifa_rt_fiber_yield(void);

/**
 * Wait for a fiber to terminate.
 */
void ifa_rt_fiber_join(uint64_t fiber_id);

/* --- Stackless Native Coroutines & Continuous Fibers API --- */

#define IFA_CORO_STATUS_SUSPENDED  0
#define IFA_CORO_STATUS_COMPLETED  1
#define IFA_CORO_STATUS_PANICKED   2
#define IFA_CORO_STATUS_WAITING_IO 3

typedef int32_t (*ifa_coro_resume_fn)(void* frame);
typedef void (*ifa_coro_destroy_fn)(void* frame);
typedef struct ifa_coroutine ifa_coroutine_t;

/**
 * Allocate and initialize a stackless native coroutine.
 */
ifa_coroutine_t* ifa_rt_coro_create(size_t frame_size, ifa_coro_resume_fn resume_fn, ifa_coro_destroy_fn destroy_fn);

/**
 * Initialize a stackless coroutine from an externally managed handle or LLVM coroutine frame.
 */
ifa_coroutine_t* ifa_rt_coro_create_custom(void* handle, ifa_coro_resume_fn resume_fn, ifa_coro_destroy_fn destroy_fn);

/**
 * Resume execution of a stackless coroutine for one cooperative step.
 */
int32_t ifa_rt_coro_resume(ifa_coroutine_t* coro);

/**
 * Spawn a stackless coroutine into the global M:N scheduler for continuous execution.
 */
uint64_t ifa_rt_coro_spawn(ifa_coroutine_t* coro);

/**
 * Destroy a stackless coroutine and release its frame.
 */
void ifa_rt_coro_destroy(ifa_coroutine_t* coro);

/**
 * Check if a stackless coroutine has completed.
 */
int32_t ifa_rt_coro_is_done(ifa_coroutine_t* coro);

/**
 * Get the current status code of a stackless coroutine.
 */
int32_t ifa_rt_coro_status(ifa_coroutine_t* coro);

/**
 * Access the state memory frame of a stackless coroutine.
 */
void* ifa_rt_coro_frame(ifa_coroutine_t* coro);

/* --- Concurrency Channels API --- */

typedef struct ifa_channel_handle ifa_channel_handle_t;

/**
 * Create an asynchronous communication channel.
 * Pass capacity = 0 for unbounded, or >0 for a bounded lock-free atomic ring buffer.
 */
ifa_channel_handle_t* ifa_rt_channel_create(size_t capacity);

/**
 * Destroy a channel handle and release associated buffers.
 */
void ifa_rt_channel_destroy(ifa_channel_handle_t* chan);

/**
 * Send a pointer value over the channel (blocks or yields fiber on backpressure).
 * Returns 0 on success, -1 on null handle, -2 if channel is closed.
 */
int32_t ifa_rt_channel_send(ifa_channel_handle_t* chan, void* val);

/**
 * Receive a pointer value from the channel (blocks or yields fiber until data arrives).
 * Returns 0 on success, -1 on invalid argument, -2 if channel is closed and empty.
 */
int32_t ifa_rt_channel_recv(ifa_channel_handle_t* chan, void** out_val);

/**
 * Non-blocking send: returns 0 on success, 1 if full, -1 if null handle, -2 if closed.
 */
int32_t ifa_rt_channel_try_send(ifa_channel_handle_t* chan, void* val);

/**
 * Non-blocking receive: returns 0 on success, 1 if empty, -1 if null, -2 if closed.
 */
int32_t ifa_rt_channel_try_recv(ifa_channel_handle_t* chan, void** out_val);

/**
 * Close the channel, waking all waiting receivers and rejecting further sends.
 */
void ifa_rt_channel_close(ifa_channel_handle_t* chan);

/**
 * Check if the channel is closed. Returns 1 if closed or null, 0 if active.
 */
int32_t ifa_rt_channel_is_closed(ifa_channel_handle_t* chan);

/**
 * Query the number of elements queued in the channel buffer.
 */
int64_t ifa_rt_channel_len(ifa_channel_handle_t* chan);

/**
 * Query the capacity of the channel buffer.
 */
int64_t ifa_rt_channel_capacity(ifa_channel_handle_t* chan);

#define IFA_SELECT_OP_RECV 0
#define IFA_SELECT_OP_SEND 1

#define IFA_SELECT_STATUS_PENDING 0
#define IFA_SELECT_STATUS_READY 1
#define IFA_SELECT_STATUS_CLOSED 2

/**
 * A single wait entry for zero-allocation multi-channel multiplexing.
 */
typedef struct ifa_select_wait_entry {
    ifa_channel_handle_t* chan;
    uint32_t op;
    uint32_t status;
    void* val;
} ifa_select_wait_entry_t;

/**
 * Zero-allocation select wait table descriptor.
 */
typedef struct ifa_select_wait_table {
    ifa_select_wait_entry_t* entries;
    size_t count;
    int32_t has_default;
} ifa_select_wait_table_t;

/**
 * Zero-allocation non-blocking multiplexing evaluation of a select wait table.
 * Returns index >= 0 if ready, count if has_default, -2 if closed, -1 if waiting (coroutine suspend).
 */
int64_t ifa_rt_channel_select_table(ifa_select_wait_table_t* table);

/**
 * Zero-allocation blocking/cooperative multiplexing evaluation of a select wait table.
 */
int64_t ifa_rt_channel_select_wait_table(ifa_select_wait_table_t* table);

/**
 * Multiplex multiple channels non-blocking or cooperatively yielding until one has data.
 * Returns the index of the ready channel, num_channels if has_default and none ready, or -2 if all closed.
 */
int64_t ifa_rt_channel_select(ifa_channel_handle_t** channels, size_t num_channels, int32_t has_default);

/* --- Stream I/O API --- */

void ifa_rt_print(const char* str);
void ifa_rt_println(const char* str);
void ifa_rt_print_i64(int64_t n);
void ifa_rt_println_i64(int64_t n);

/* --- Asynchronous Non-Blocking Reactor API (io_uring / IOCP) --- */

int32_t ifa_rt_async_io_uring_supported(void);
int32_t ifa_rt_async_iocp_supported(void);
void ifa_rt_async_sleep(uint64_t millis);
int32_t ifa_rt_async_tcp_listen(uint16_t port, int32_t backlog);
int32_t ifa_rt_async_tcp_accept(int32_t listener_fd);
int32_t ifa_rt_async_tcp_connect(const char* host, uint16_t port);
intptr_t ifa_rt_async_read(int32_t stream_fd, uint8_t* buf, size_t len);
intptr_t ifa_rt_async_write(int32_t stream_fd, const uint8_t* buf, size_t len);
int32_t ifa_rt_async_close(int32_t handle_fd);

uint64_t ifa_rt_coro_register_io_uring_read(ifa_coroutine_t* coro, int32_t fd, uint8_t* buf, uint32_t len, uint64_t offset, int64_t* out_result);
uint64_t ifa_rt_coro_register_io_uring_write(ifa_coroutine_t* coro, int32_t fd, const uint8_t* buf, uint32_t len, uint64_t offset, int64_t* out_result);
uint64_t ifa_rt_coro_register_iocp_read(ifa_coroutine_t* coro, size_t key, uint8_t* buf, uint32_t len, int64_t* out_result);
uint64_t ifa_rt_coro_register_iocp_write(ifa_coroutine_t* coro, size_t key, const uint8_t* buf, uint32_t len, int64_t* out_result);
void ifa_rt_coro_set_waiting_io(ifa_coroutine_t* coro, uint64_t token, int64_t* out_result);
int32_t ifa_rt_coro_wake_io(uint64_t token, int64_t result);
size_t ifa_rt_reactor_poll(uint32_t timeout_ms);
size_t ifa_rt_coro_pending_io_count(void);

/* --- Isolated Blocking FFI Worker Pool API --- */

typedef void* (*ifa_blocking_fn)(void*);
typedef void (*ifa_completion_cb)(void*, void*);

/**
 * Execute a blocking external C-ABI function on the dedicated background pool.
 * Cooperatively yields the current fiber to ensure M:N scheduler workers never freeze.
 */
void* ifa_rt_blocking_call(ifa_blocking_fn func, void* arg);

/**
 * Asynchronously spawn a blocking C-ABI function on the background pool with an optional completion callback.
 */
uint64_t ifa_rt_blocking_spawn(ifa_blocking_fn func, void* arg, ifa_completion_cb done_cb, void* cb_arg);

/**
 * Returns number of worker threads currently running blocking FFI operations.
 */
size_t ifa_rt_blocking_pool_active_workers(void);

/**
 * Returns total capacity of the background blocking worker pool.
 */
size_t ifa_rt_blocking_pool_capacity(void);

/* --- Safe Bounds Verification & C-ABI Protection API --- */

/**
 * 1-cycle CPU bounds verification for universal buffer and slice index access.
 * Aborts safely on index out of bounds detection without memory corruption or undefined behavior.
 */
void ifa_rt_bounds_check(size_t index, size_t len, const char* msg);

/**
 * Verify that a sub-slice range [start..end] is strictly within bounds [0..len].
 */
void ifa_rt_slice_bounds_check(size_t start, size_t end, size_t len, const char* msg);

/**
 * Verify that a strided sub-slice range [start..end:stride] is strictly within bounds [0..len].
 */
void ifa_rt_slice_strided_bounds_check(size_t start, size_t end, size_t stride, size_t len, const char* msg);

/**
 * Validate external buffer pointer alignment, non-null status, and minimum byte length.
 */
int ifa_rt_buffer_verify_bounds(const void* ptr, size_t len, size_t required_min, size_t align);

/**
 * Validate an external IfaSlice passed across foreign boundaries.
 */
int ifa_rt_c_abi_validate_slice(ifa_slice_t slice, size_t elem_size, size_t min_elements);

/**
 * Abort program deterministically on detected out-of-bounds access.
 */
void ifa_rt_panic_out_of_bounds(size_t index, size_t len);

/* --- Bare-Metal Panic Interception & Diagnostic Driver API --- */

#define IFA_PANIC_NONE             0
#define IFA_PANIC_USE_AFTER_FREE   1
#define IFA_PANIC_DOUBLE_FREE      2
#define IFA_PANIC_NULL_DEREF       3
#define IFA_PANIC_EPOCH_MISMATCH   4
#define IFA_PANIC_OUT_OF_BOUNDS    5
#define IFA_PANIC_ASSERT_FAILED    6
#define IFA_PANIC_GENERIC          7

#define IFA_MAX_BARE_METAL_FRAMES 32
#define IFA_MAX_PANIC_MSG_LEN     256

typedef struct {
    uintptr_t frames[IFA_MAX_BARE_METAL_FRAMES];
    size_t    count;
} ifa_bare_metal_stack_trace_t;

typedef struct {
    int32_t                      kind;
    uintptr_t                    fault_address;
    uint32_t                     expected_gen;
    uint32_t                     actual_gen;
    uint16_t                     expected_epoch;
    uint16_t                     actual_epoch;
    uint16_t                     arena_id;
    uint16_t                     _reserved;
    size_t                       message_len;
    char                         message[IFA_MAX_PANIC_MSG_LEN];
    ifa_bare_metal_stack_trace_t stack_trace;
} ifa_panic_record_t;

typedef void (*ifa_panic_handler_fn)(const ifa_panic_record_t* record);

/**
 * Register a custom panic hook callback.
 */
void ifa_rt_set_panic_handler(ifa_panic_handler_fn handler);

/**
 * Reset panic handler to default.
 */
void ifa_rt_reset_panic_handler(void);

/**
 * Retrieve pointer to the last intercepted panic record (thread-local or global).
 */
const ifa_panic_record_t* ifa_rt_get_last_panic(void);

/**
 * Clear the last recorded panic.
 */
void ifa_rt_clear_last_panic(void);

/**
 * Execute a function within the panic interception driver.
 * Returns 0 on success, or panic kind code on exception.
 */
int32_t ifa_rt_catch_panic(ifa_fiber_entry_fn func, void* arg);

/**
 * Capture current bare-metal stack trace frames into buffer.
 */
size_t ifa_rt_capture_stack_trace(uintptr_t* buffer, size_t max_depth);

/**
 * Format bare-metal stack trace into byte buffer without heap allocation.
 */
size_t ifa_rt_format_stack_trace(char* buffer, size_t buffer_len);

/**
 * Retrieve execution status of a fiber (1: Completed, 2: Panicked, 3: Running, 4: Suspended, 5: WaitingIo, 0: Ready, -1: Unknown).
 */
int32_t ifa_rt_fiber_status(uint64_t fiber_id);

#ifdef __cplusplus
}
#endif

#endif /* IFA_RUNTIME_H */
