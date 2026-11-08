//! IFA Runtime: Deterministic zero-GC generational memory allocator, fiber scheduler, and standard library runtime.

pub mod allocator;
pub mod benchmarks;
pub mod blocking;
pub mod collections;
pub mod ffi;
pub mod fiber;
pub mod header;
pub mod io;
pub mod panic;
pub mod reactor;
pub mod string;
pub mod wasi;

pub use allocator::{
    EpochGuard, EpochManager, EpochStats, GenArena, GlobalGenAllocator, GLOBAL_ALLOCATOR,
};
pub use benchmarks::{
    profile_allocator_engine, run_allocator_multithread_suite, run_generational_benchmark_suite,
    AllocatorEngine, AllocatorThroughputResult, BenchmarkReport, BenchmarkResult,
    MultithreadBenchmarkSuiteReport,
};
pub use blocking::{
    ifa_rt_blocking_call, ifa_rt_blocking_pool_active_workers, ifa_rt_blocking_pool_capacity,
    ifa_rt_blocking_spawn, BlockingHandle, BlockingPool, ExternBlockingFn, ExternCompletionCb,
    GLOBAL_BLOCKING_POOL,
};
pub use collections::{IfaList, IfaMap};
pub use ffi::*;
pub use fiber::{
    AtomicRingBuffer, Channel, CoroDestroyFn, CoroResumeFn, CoroStatus, FiberId, FiberScheduler,
    FiberState, FiberStepResult, FiberTask, RecvError, SendError, StacklessCoro, TryRecvError,
    TrySendError, GLOBAL_SCHEDULER,
};
pub use header::{
    EpochTransition, GenHeader, GenRef, FLAG_ACTIVE, FLAG_ARENA_SCOPED, FLAG_EPOCH_1, FLAG_FREE,
    FLAG_PINNED, FLAG_QUARANTINED, FLAG_READONLY,
};
pub use panic::{
    catch_panic, clear_last_panic, dispatch_panic, get_last_panic, get_last_panic_raw_ptr,
    reset_panic_handler, set_panic_handler, IfaBareMetalStackTrace, IfaPanicKind, IfaPanicRecord,
    PanicHandlerFn, MAX_BARE_METAL_FRAMES, MAX_PANIC_MSG_LEN,
};
pub use reactor::{
    ifa_rt_async_close, ifa_rt_async_io_uring_supported, ifa_rt_async_iocp_supported,
    ifa_rt_async_read, ifa_rt_async_sleep, ifa_rt_async_tcp_accept, ifa_rt_async_tcp_connect,
    ifa_rt_async_tcp_listen, ifa_rt_async_write, AsyncReactor, AsyncTcpListener, AsyncTcpStream,
    AsyncTimer, IoUringConnector, IocpConnector, GLOBAL_REACTOR,
};
pub use string::IfaString;
pub use wasi::*;
