//! Dedicated background worker pool for isolating blocking external FFI calls and synchronous system operations.
//!
//! Prevents M:N fiber scheduler thread starvation by offloading blocking foreign function calls
//! (C-ABI libraries, synchronous file/socket I/O, intensive computations) onto dedicated background threads.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use std::thread::{self, JoinHandle};

use lazy_static::lazy_static;

use crate::fiber::{FiberScheduler, GLOBAL_SCHEDULER};

/// Handle representing the future result of a task submitted to the `BlockingPool`.
pub struct BlockingHandle<T> {
    result: Arc<Mutex<Option<T>>>,
    done: Arc<AtomicBool>,
    cond: Arc<Condvar>,
}

type HandleComponents<T> = (
    BlockingHandle<T>,
    Arc<Mutex<Option<T>>>,
    Arc<AtomicBool>,
    Arc<Condvar>,
);

impl<T> BlockingHandle<T> {
    fn new() -> HandleComponents<T> {
        let result = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let cond = Arc::new(Condvar::new());
        let handle = Self {
            result: Arc::clone(&result),
            done: Arc::clone(&done),
            cond: Arc::clone(&cond),
        };
        (handle, result, done, cond)
    }

    /// Check if the blocking operation has finished without waiting.
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Try to retrieve the result if finished, without blocking.
    pub fn try_get(&self) -> Option<T> {
        if self.is_done() {
            let mut guard = self.result.lock().unwrap();
            guard.take()
        } else {
            None
        }
    }

    /// Wait synchronously for the result using standard thread condition variables.
    /// Suitable when called from outside the M:N fiber scheduler.
    pub fn wait(self) -> T {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut guard = self.result.lock().unwrap();
            while !self.done.load(Ordering::Acquire) && guard.is_none() {
                guard = self.cond.wait(guard).unwrap();
            }
            guard
                .take()
                .expect("BlockingHandle result missing after done")
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut guard = self.result.lock().unwrap();
            guard.take().expect("BlockingHandle result missing")
        }
    }

    /// Wait cooperatively within an M:N fiber context by yielding control back to the scheduler.
    /// Ensures M:N worker threads continue executing other ready fibers during the blocking call.
    pub fn wait_cooperative(self, scheduler: &FiberScheduler) -> T {
        while !self.is_done() {
            scheduler.yield_now();
            #[cfg(not(target_arch = "wasm32"))]
            thread::sleep(Duration::from_micros(50));
        }
        let mut guard = self.result.lock().unwrap();
        guard
            .take()
            .expect("BlockingHandle result missing after done")
    }
}

type TaskFn = Box<dyn FnOnce() + Send + 'static>;

/// A dedicated pool of background worker threads specifically reserved for blocking FFI and I/O calls.
pub struct BlockingPool {
    task_queue: Arc<Mutex<VecDeque<TaskFn>>>,
    notifier: Arc<Condvar>,
    is_running: Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
    capacity: usize,
    #[cfg(not(target_arch = "wasm32"))]
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl BlockingPool {
    /// Create a new blocking pool with `capacity` dedicated OS threads.
    pub fn new(capacity: usize) -> Self {
        let workers_count = if capacity == 0 { 8 } else { capacity };
        let task_queue: Arc<Mutex<VecDeque<TaskFn>>> = Arc::new(Mutex::new(VecDeque::new()));
        let notifier = Arc::new(Condvar::new());
        let is_running = Arc::new(AtomicBool::new(true));
        let active_workers = Arc::new(AtomicUsize::new(0));

        #[cfg(not(target_arch = "wasm32"))]
        let mut workers = Vec::with_capacity(workers_count);

        #[cfg(not(target_arch = "wasm32"))]
        {
            for _ in 0..workers_count {
                let queue = Arc::clone(&task_queue);
                let notif = Arc::clone(&notifier);
                let running = Arc::clone(&is_running);
                let active = Arc::clone(&active_workers);

                let handle = thread::spawn(move || loop {
                    let task = {
                        let mut lock = queue.lock().unwrap();
                        while lock.is_empty() && running.load(Ordering::Relaxed) {
                            lock = notif.wait(lock).unwrap();
                        }
                        if !running.load(Ordering::Relaxed) && lock.is_empty() {
                            break;
                        }
                        lock.pop_front()
                    };

                    if let Some(work) = task {
                        active.fetch_add(1, Ordering::Relaxed);
                        work();
                        active.fetch_sub(1, Ordering::Relaxed);
                    }
                });

                workers.push(handle);
            }
        }

        Self {
            task_queue,
            notifier,
            is_running,
            active_workers,
            capacity: workers_count,
            #[cfg(not(target_arch = "wasm32"))]
            workers: Mutex::new(workers),
        }
    }

    /// Submit a blocking closure to the background worker pool and receive a cooperative `BlockingHandle`.
    pub fn spawn<F, R>(&self, f: F) -> BlockingHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (handle, res_slot, done_flag, condvar) = BlockingHandle::new();

        let task: TaskFn = Box::new(move || {
            let value = f();
            {
                let mut guard = res_slot.lock().unwrap();
                *guard = Some(value);
            }
            done_flag.store(true, Ordering::Release);
            condvar.notify_all();
        });

        {
            let mut queue = self.task_queue.lock().unwrap();
            queue.push_back(task);
        }
        self.notifier.notify_one();

        handle
    }

    /// Execute a blocking operation isolated on the worker pool, yielding the calling fiber cooperatively.
    pub fn call_cooperative<F, R>(&self, scheduler: &FiberScheduler, f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let handle = self.spawn(f);
        handle.wait_cooperative(scheduler)
    }

    /// Number of actively busy worker threads currently running blocking tasks.
    pub fn active_workers(&self) -> usize {
        self.active_workers.load(Ordering::Relaxed)
    }

    /// Total configured thread capacity of the blocking pool.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Gracefully shutdown all background worker threads.
    pub fn shutdown(&self) {
        self.is_running.store(false, Ordering::Release);
        {
            let mut queue = self.task_queue.lock().unwrap();
            queue.clear();
        }
        self.notifier.notify_all();
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut workers = self.workers.lock().unwrap();
            for handle in workers.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for BlockingPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

lazy_static! {
    /// Global background blocking pool for isolated FFI and synchronous operations.
    pub static ref GLOBAL_BLOCKING_POOL: BlockingPool = BlockingPool::new(8);
    static ref NEXT_BLOCKING_TASK_ID: AtomicU64 = AtomicU64::new(1);
}

// -----------------------------------------------------------------------------
// Universal C-ABI Exports for FFI Isolation and LLVM Codegen Lowering
// -----------------------------------------------------------------------------

/// Type definition for an isolated blocking C-ABI function.
pub type ExternBlockingFn = extern "C" fn(*mut c_void) -> *mut c_void;

/// Type definition for an asynchronous completion callback.
pub type ExternCompletionCb = extern "C" fn(*mut c_void, *mut c_void);

/// Execute a blocking C-ABI function isolated on the dedicated background pool.
///
/// Yields the calling fiber cooperatively so M:N scheduler worker threads
/// are never paralyzed by long-running or blocking foreign calls.
#[no_mangle]
pub extern "C" fn ifa_rt_blocking_call(func: ExternBlockingFn, arg: *mut c_void) -> *mut c_void {
    let arg_ptr = arg as usize;
    let handle = GLOBAL_BLOCKING_POOL.spawn(move || {
        let raw_arg = arg_ptr as *mut c_void;
        func(raw_arg) as usize
    });

    let res_usize = handle.wait_cooperative(&GLOBAL_SCHEDULER);
    res_usize as *mut c_void
}

/// Asynchronously dispatch a blocking C-ABI function onto the background pool with an optional completion callback.
#[no_mangle]
pub extern "C" fn ifa_rt_blocking_spawn(
    func: ExternBlockingFn,
    arg: *mut c_void,
    done_cb: Option<ExternCompletionCb>,
    cb_arg: *mut c_void,
) -> u64 {
    let task_id = NEXT_BLOCKING_TASK_ID.fetch_add(1, Ordering::SeqCst);
    let arg_ptr = arg as usize;
    let cb_arg_ptr = cb_arg as usize;

    GLOBAL_BLOCKING_POOL.spawn(move || {
        let raw_arg = arg_ptr as *mut c_void;
        let res = func(raw_arg);
        if let Some(cb) = done_cb {
            cb(res, cb_arg_ptr as *mut c_void);
        }
    });

    task_id
}

/// Query the number of busy workers currently running blocking FFI operations.
#[no_mangle]
pub extern "C" fn ifa_rt_blocking_pool_active_workers() -> usize {
    GLOBAL_BLOCKING_POOL.active_workers()
}

/// Query total worker thread capacity of the blocking pool.
#[no_mangle]
pub extern "C" fn ifa_rt_blocking_pool_capacity() -> usize {
    GLOBAL_BLOCKING_POOL.capacity()
}
