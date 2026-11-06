//! Colorless concurrency primitives and M:N lightweight fibers without GC.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

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
    is_running: AtomicBool,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl FiberScheduler {
    /// Create a new fiber scheduler configured with standard worker threads.
    pub fn new(num_workers: usize) -> Self {
        let workers_count = if num_workers == 0 {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(2)
        } else {
            num_workers
        };

        let ready_queue: Arc<Mutex<VecDeque<Fiber>>> = Arc::new(Mutex::new(VecDeque::new()));
        let completed_fibers = Arc::new(Mutex::new(HashMap::new()));
        let notifier = Arc::new(Condvar::new());
        let is_running = AtomicBool::new(true);

        let mut workers = Vec::with_capacity(workers_count);

        for _ in 0..workers_count {
            let queue = Arc::clone(&ready_queue);
            let completed = Arc::clone(&completed_fibers);
            let notif = Arc::clone(&notifier);

            let is_run = Arc::new(AtomicBool::new(true));
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

        Self {
            ready_queue,
            completed_fibers,
            notifier,
            next_fiber_id: AtomicU64::new(1),
            is_running,
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
        thread::yield_now();
    }

    /// Block current context until the specified fiber has finished execution.
    pub fn join(&self, fiber_id: FiberId) {
        let mut completed = self.completed_fibers.lock().unwrap();
        while !completed.contains_key(&fiber_id) {
            completed = self.notifier.wait(completed).unwrap();
        }
    }

    /// Check if scheduler is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    /// Number of worker threads.
    pub fn worker_count(&self) -> usize {
        self.workers.lock().unwrap().len()
    }
}

/// Communication channel between fibers ensuring message passing without shared mutable memory.
pub struct Channel<T> {
    queue: Mutex<VecDeque<T>>,
    cond: Condvar,
}

impl<T> Channel<T> {
    /// Create a new channel.
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            cond: Condvar::new(),
        }
    }

    /// Send a value to the channel.
    pub fn send(&self, val: T) {
        let mut q = self.queue.lock().unwrap();
        q.push_back(val);
        self.cond.notify_one();
    }

    /// Receive a value from the channel, waiting if empty.
    pub fn recv(&self) -> T {
        let mut q = self.queue.lock().unwrap();
        while q.is_empty() {
            q = self.cond.wait(q).unwrap();
        }
        q.pop_front().unwrap()
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
