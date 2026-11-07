//! IFA Runtime: Deterministic zero-GC generational memory allocator, fiber scheduler, and standard library runtime.

pub mod allocator;
pub mod benchmarks;
pub mod collections;
pub mod ffi;
pub mod fiber;
pub mod header;
pub mod io;
pub mod reactor;
pub mod string;
pub mod wasi;

pub use allocator::{GenArena, GlobalGenAllocator, GLOBAL_ALLOCATOR};
pub use benchmarks::{run_generational_benchmark_suite, BenchmarkReport, BenchmarkResult};
pub use collections::{IfaList, IfaMap};
pub use ffi::*;
pub use fiber::{
    AtomicRingBuffer, Channel, FiberId, FiberScheduler, FiberState, RecvError, SendError,
    TryRecvError, TrySendError, GLOBAL_SCHEDULER,
};
pub use header::{
    GenHeader, GenRef, FLAG_ACTIVE, FLAG_ARENA_SCOPED, FLAG_FREE, FLAG_PINNED, FLAG_READONLY,
};
pub use reactor::{
    ifa_rt_async_close, ifa_rt_async_io_uring_supported, ifa_rt_async_iocp_supported,
    ifa_rt_async_read, ifa_rt_async_sleep, ifa_rt_async_tcp_accept, ifa_rt_async_tcp_connect,
    ifa_rt_async_tcp_listen, ifa_rt_async_write, AsyncReactor, AsyncTcpListener, AsyncTcpStream,
    AsyncTimer, IoUringConnector, IocpConnector, GLOBAL_REACTOR,
};
pub use string::IfaString;
pub use wasi::*;
