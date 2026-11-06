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

/* --- Stream I/O API --- */

void ifa_rt_print(const char* str);
void ifa_rt_println(const char* str);
void ifa_rt_print_i64(int64_t n);
void ifa_rt_println_i64(int64_t n);

#ifdef __cplusplus
}
#endif

#endif /* IFA_RUNTIME_H */
