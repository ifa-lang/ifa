//! IFA Runtime: Deterministic zero-GC generational memory allocator, fiber scheduler, and standard library runtime.

pub mod allocator;
pub mod benchmarks;
pub mod collections;
pub mod ffi;
pub mod fiber;
pub mod header;
pub mod io;
pub mod string;
pub mod wasi;

pub use allocator::{GenArena, GlobalGenAllocator, GLOBAL_ALLOCATOR};
pub use benchmarks::{run_generational_benchmark_suite, BenchmarkReport, BenchmarkResult};
pub use collections::{IfaList, IfaMap};
pub use ffi::*;
pub use fiber::{Channel, FiberId, FiberScheduler, FiberState, GLOBAL_SCHEDULER};
pub use header::{
    GenHeader, GenRef, FLAG_ACTIVE, FLAG_ARENA_SCOPED, FLAG_FREE, FLAG_PINNED, FLAG_READONLY,
};
pub use string::IfaString;
pub use wasi::*;
