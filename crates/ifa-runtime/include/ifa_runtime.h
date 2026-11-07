/**
 * @file ifa_runtime.h
 * @brief IFA Programming Language - Standard C-ABI Runtime Header
 *
 * Provides deterministic zero-GC generational memory allocation,
 * fiber concurrency primitives, and stream I/O for native execution
 * and PHP 8.4+ / Symfony 8.1 FFI integration.
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

#define IFA_CORO_STATUS_SUSPENDED 0
#define IFA_CORO_STATUS_COMPLETED 1
#define IFA_CORO_STATUS_PANICKED  2

typedef int32_t (*ifa_coro_resume_fn)(void* frame);
typedef void (*ifa_coro_destroy_fn)(void* frame);
typedef struct ifa_coroutine ifa_coroutine_t;

/**
 * Allocate and initialize a stackless native coroutine.
 */
ifa_coroutine_t* ifa_rt_coro_create(size_t frame_size, ifa_coro_resume_fn resume_fn, ifa_coro_destroy_fn destroy_fn);

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

#ifdef __cplusplus
}
#endif

#endif /* IFA_RUNTIME_H */
