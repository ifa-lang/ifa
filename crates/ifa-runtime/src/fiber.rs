//! Colorless concurrency primitives and M:N lightweight fibers without GC.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
#[cfg(not(target_arch = "wasm32"))]
use std::thread;
#[cfg(not(target_arch = "wasm32"))]
use std::thread::JoinHandle;
use std::time::Duration;

/// Unique identifier for an IFA lightweight fiber.
pub type FiberId = u64;

/// Execution status of a fiber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiberState {
    Ready,
    Running,
    Suspended,
    Completed,
}

/// A lightweight unit of execution running cooperatively or on worker pools.
pub struct Fiber {
    pub id: FiberId,
    pub state: FiberState,
    task: Option<Box<dyn FnOnce() + Send + 'static>>,
}

/// Global M:N Fiber Scheduler managing colorless asynchronous tasks without GC.
pub struct FiberScheduler {
    ready_queue: Arc<Mutex<VecDeque<Fiber>>>,
    completed_fibers: Arc<Mutex<HashMap<FiberId, FiberState>>>,
    notifier: Arc<Condvar>,
    next_fiber_id: AtomicU64,
    is_running: Arc<AtomicBool>,
    #[cfg(not(target_arch = "wasm32"))]
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl FiberScheduler {
    /// Create a new fiber scheduler configured with standard worker threads.
    pub fn new(num_workers: usize) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let workers_count = if num_workers == 0 {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(2)
        } else {
            num_workers
        };
        #[cfg(target_arch = "wasm32")]
        let _ = num_workers;

        let ready_queue: Arc<Mutex<VecDeque<Fiber>>> = Arc::new(Mutex::new(VecDeque::new()));
        let completed_fibers = Arc::new(Mutex::new(HashMap::new()));
        let notifier = Arc::new(Condvar::new());
        let is_running = Arc::new(AtomicBool::new(true));

        #[cfg(not(target_arch = "wasm32"))]
        let mut workers = Vec::with_capacity(workers_count);

        #[cfg(not(target_arch = "wasm32"))]
        {
            for _ in 0..workers_count {
                let queue = Arc::clone(&ready_queue);
                let completed = Arc::clone(&completed_fibers);
                let notif = Arc::clone(&notifier);
                let is_run = Arc::clone(&is_running);

                let handle = thread::spawn(move || loop {
                    let task = {
                        let mut lock = queue.lock().unwrap();
                        while lock.is_empty() && is_run.load(Ordering::Relaxed) {
                            lock = notif.wait(lock).unwrap();
                        }
                        if !is_run.load(Ordering::Relaxed) && lock.is_empty() {
                            break;
                        }
                        lock.pop_front()
                    };

                    if let Some(mut fiber) = task {
                        if let Some(exec) = fiber.task.take() {
                            fiber.state = FiberState::Running;
                            exec();
                            fiber.state = FiberState::Completed;

                            let mut comp = completed.lock().unwrap();
                            comp.insert(fiber.id, FiberState::Completed);
                            notif.notify_all();
                        }
                    }
                });

                workers.push(handle);
            }
        }

        Self {
            ready_queue,
            completed_fibers,
            notifier,
            next_fiber_id: AtomicU64::new(1),
            is_running,
            #[cfg(not(target_arch = "wasm32"))]
            workers: Mutex::new(workers),
        }
    }

    /// Spawn a new colorless fiber running the provided closure.
    pub fn spawn<F>(&self, task: F) -> FiberId
    where
        F: FnOnce() + Send + 'static,
    {
        let id = self.next_fiber_id.fetch_add(1, Ordering::SeqCst);
        let fiber = Fiber {
            id,
            state: FiberState::Ready,
            task: Some(Box::new(task)),
        };

        {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.push_back(fiber);
        }
        self.notifier.notify_one();

        id
    }

    /// Cooperative yield: relinquishes current execution slice to allow other fibers to run.
    pub fn yield_now(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        thread::yield_now();
        #[cfg(target_arch = "wasm32")]
        let _ = self.step();
    }

    /// Execute a single fiber from the ready queue cooperatively.
    /// Returns true if a task was executed, false if the queue was empty.
    pub fn step(&self) -> bool {
        let task = {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.pop_front()
        };

        if let Some(mut fiber) = task {
            if let Some(exec) = fiber.task.take() {
                fiber.state = FiberState::Running;
                exec();
                fiber.state = FiberState::Completed;

                let mut comp = self.completed_fibers.lock().unwrap();
                comp.insert(fiber.id, FiberState::Completed);
                self.notifier.notify_all();
                return true;
            }
        }
        false
    }

    /// Run all queued fibers sequentially until no runnable fibers remain.
    pub fn run_until_idle(&self) {
        while self.step() {}
    }

    /// Check if a specific fiber has completed execution.
    pub fn is_completed(&self, fiber_id: FiberId) -> bool {
        let completed = self.completed_fibers.lock().unwrap();
        completed.contains_key(&fiber_id)
    }

    /// Block current context until the specified fiber has finished execution.
    pub fn join(&self, fiber_id: FiberId) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut completed = self.completed_fibers.lock().unwrap();
            while !completed.contains_key(&fiber_id) {
                completed = self.notifier.wait(completed).unwrap();
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            while !self.is_completed(fiber_id) {
                if !self.step() {
                    break;
                }
            }
        }
    }

    /// Block current context until the specified fiber finishes execution or timeout expires.
    /// Returns true if fiber completed, false if timed out.
    pub fn join_timeout(&self, fiber_id: FiberId, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut completed = self.completed_fibers.lock().unwrap();
            while !completed.contains_key(&fiber_id) {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return false;
                }
                let remaining = deadline - now;
                let (new_completed, wait_res) =
                    self.notifier.wait_timeout(completed, remaining).unwrap();
                completed = new_completed;
                if wait_res.timed_out() && !completed.contains_key(&fiber_id) {
                    return false;
                }
            }
            true
        }
        #[cfg(target_arch = "wasm32")]
        {
            while !self.is_completed(fiber_id) {
                if std::time::Instant::now() >= deadline || !self.step() {
                    break;
                }
            }
            self.is_completed(fiber_id)
        }
    }

    /// Check if scheduler is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    /// Gracefully shutdown all background worker threads.
    pub fn shutdown(&self) {
        self.is_running.store(false, Ordering::Release);
        self.notifier.notify_all();
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut workers = self.workers.lock().unwrap();
            for handle in workers.drain(..) {
                let _ = handle.join();
            }
        }
    }

    /// Number of worker threads.
    pub fn worker_count(&self) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.workers.lock().unwrap().len()
        }
        #[cfg(target_arch = "wasm32")]
        {
            0
        }
    }
}

impl Drop for FiberScheduler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Communication channel between fibers ensuring message passing without shared mutable memory.
pub struct Channel<T> {
    queue: Mutex<VecDeque<T>>,
    cond: Condvar,
    capacity: Option<usize>,
}

impl<T> Channel<T> {
    /// Create an unbounded communication channel.
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            cond: Condvar::new(),
            capacity: None,
        }
    }

    /// Create a bounded communication channel with backpressure.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            cond: Condvar::new(),
            capacity: Some(capacity.max(1)),
        }
    }

    /// Send a value to the channel (blocks if bounded and full).
    pub fn send(&self, val: T) {
        let mut q = self.queue.lock().unwrap();
        if let Some(cap) = self.capacity {
            while q.len() >= cap {
                q = self.cond.wait(q).unwrap();
            }
        }
        q.push_back(val);
        self.cond.notify_all();
    }

    /// Non-blocking send: returns Err(val) if channel capacity is exhausted.
    pub fn try_send(&self, val: T) -> Result<(), T> {
        let mut q = self.queue.lock().unwrap();
        if let Some(cap) = self.capacity {
            if q.len() >= cap {
                return Err(val);
            }
        }
        q.push_back(val);
        self.cond.notify_all();
        Ok(())
    }

    /// Receive a value from the channel, waiting if empty.
    pub fn recv(&self) -> T {
        let mut q = self.queue.lock().unwrap();
        while q.is_empty() {
            q = self.cond.wait(q).unwrap();
        }
        let val = q.pop_front().unwrap();
        self.cond.notify_all();
        val
    }

    /// Non-blocking receive: returns None immediately if empty.
    pub fn try_recv(&self) -> Option<T> {
        let mut q = self.queue.lock().unwrap();
        let val = q.pop_front();
        if val.is_some() {
            self.cond.notify_all();
        }
        val
    }

    /// Timed receive: returns None if timeout expires before a value arrives.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<T> {
        let deadline = std::time::Instant::now() + timeout;
        let mut q = self.queue.lock().unwrap();
        while q.is_empty() {
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline - now;
            let (new_q, wait_res) = self.cond.wait_timeout(q, remaining).unwrap();
            q = new_q;
            if wait_res.timed_out() && q.is_empty() {
                return None;
            }
        }
        let val = q.pop_front();
        if val.is_some() {
            self.cond.notify_all();
        }
        val
    }
}

impl<T> Default for Channel<T> {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static::lazy_static! {
    /// Global scheduler instance for IFA colorless fibers.
    pub static ref GLOBAL_SCHEDULER: FiberScheduler = FiberScheduler::new(2);
}
