//! Colorless concurrency primitives and M:N lightweight fibers without GC.

use std::cell::UnsafeCell;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    WaitingIo(u64),
    Completed,
    Panicked,
}

/// Execution outcome of resuming a stackless fiber / coroutine.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoroStatus {
    /// Coroutine yielded/suspended execution and can be resumed later.
    Suspended = 0,
    /// Coroutine completed execution normally.
    Completed = 1,
    /// Coroutine terminated due to an error or panic.
    Panicked = 2,
    /// Coroutine suspended waiting for an asynchronous I/O completion event.
    WaitingIo = 3,
}

/// Function signature for resuming a stackless native coroutine.
/// Receives the coroutine state frame pointer, returns CoroStatus as i32.
pub type CoroResumeFn = extern "C" fn(frame: *mut u8) -> i32;

/// Function signature for destroying a stackless native coroutine frame.
pub type CoroDestroyFn = extern "C" fn(frame: *mut u8);

/// A stackless native coroutine context without system call stacks.
pub struct StacklessCoro {
    pub frame: *mut u8,
    pub resume_fn: CoroResumeFn,
    pub destroy_fn: Option<CoroDestroyFn>,
    pub status: CoroStatus,
    pub pending_io_token: Option<u64>,
    pub pending_result_slot: Option<*mut i64>,
}

unsafe impl Send for StacklessCoro {}
unsafe impl Sync for StacklessCoro {}

impl Drop for StacklessCoro {
    fn drop(&mut self) {
        if let Some(destroy) = self.destroy_fn {
            if !self.frame.is_null() {
                destroy(self.frame);
                self.frame = std::ptr::null_mut();
            }
        }
    }
}

/// Dynamic task carried by an IFA fiber.
pub enum FiberTask {
    /// One-off closure running to completion.
    Once(Box<dyn FnOnce() + Send + 'static>),
    /// Resumable closure called repeatedly across scheduler cycles until completion.
    Resumable(Box<dyn FnMut() -> CoroStatus + Send + 'static>),
    /// Stackless native C-ABI coroutine frame.
    Stackless(StacklessCoro),
}

/// Result of executing a single step of a fiber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiberStepResult {
    Completed,
    Suspended,
    WaitingIo(u64, Option<*mut i64>),
    Panicked,
}

/// Entry tracking a fiber parked waiting for an asynchronous I/O completion event.
pub struct IoWaitEntry {
    pub fiber: Fiber,
    pub result_slot: Option<*mut i64>,
}

unsafe impl Send for IoWaitEntry {}
unsafe impl Sync for IoWaitEntry {}

thread_local! {
    static CURRENT_FIBER_ID: std::cell::Cell<FiberId> = const { std::cell::Cell::new(0) };
    static CURRENT_FIBER_ARENA: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
    static CURRENT_FIBER_IO_TOKEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static CURRENT_FIBER_RESULT_SLOT: std::cell::Cell<Option<*mut i64>> = const { std::cell::Cell::new(None) };
}

/// Set the pending I/O token for the current executing fiber/coroutine context.
pub fn set_current_fiber_io_token(token: u64) {
    CURRENT_FIBER_IO_TOKEN.with(|c| c.set(token));
}

/// Retrieve the pending I/O token of the current executing fiber context (0 if none).
pub fn current_fiber_io_token() -> u64 {
    CURRENT_FIBER_IO_TOKEN.with(|c| c.get())
}

/// Set the pending result slot for the current executing fiber/coroutine context.
pub fn set_current_fiber_result_slot(slot: Option<*mut i64>) {
    CURRENT_FIBER_RESULT_SLOT.with(|c| c.set(slot));
}

/// Retrieve the pending result slot of the current executing fiber context.
pub fn current_fiber_result_slot() -> Option<*mut i64> {
    CURRENT_FIBER_RESULT_SLOT.with(|c| c.get())
}

/// Retrieve the identifier of the currently executing fiber on this worker thread (0 if unassigned / main thread).
pub fn current_fiber_id() -> FiberId {
    CURRENT_FIBER_ID.with(|c| c.get())
}

/// Retrieve the isolated arena ID of the currently executing fiber on this worker thread (0 if none).
pub fn current_fiber_arena() -> u16 {
    CURRENT_FIBER_ARENA.with(|c| c.get())
}

/// A lightweight unit of execution running cooperatively or on worker pools.
pub struct Fiber {
    pub id: FiberId,
    pub state: FiberState,
    pub task: Option<FiberTask>,
    pub arena_id: Option<u16>,
}

impl Fiber {
    /// Execute one step of the fiber.
    pub fn step(&mut self) -> FiberStepResult {
        let prev_id = CURRENT_FIBER_ID.with(|c| c.replace(self.id));
        let prev_arena = CURRENT_FIBER_ARENA.with(|c| c.replace(self.arena_id.unwrap_or(0)));
        let prev_token = CURRENT_FIBER_IO_TOKEN.with(|c| c.replace(0));
        let prev_slot = CURRENT_FIBER_RESULT_SLOT.with(|c| c.replace(None));

        let step_res = match &mut self.task {
            Some(FiberTask::Once(_)) => {
                let task = self.task.take().unwrap();
                if let FiberTask::Once(exec) = task {
                    self.state = FiberState::Running;
                    let outcome = crate::panic::catch_panic(std::panic::AssertUnwindSafe(exec));
                    match outcome {
                        Ok(()) => {
                            self.state = FiberState::Completed;
                            FiberStepResult::Completed
                        }
                        Err(_) => {
                            self.state = FiberState::Panicked;
                            FiberStepResult::Panicked
                        }
                    }
                } else {
                    FiberStepResult::Completed
                }
            }
            Some(FiberTask::Resumable(closure)) => {
                self.state = FiberState::Running;
                let outcome = crate::panic::catch_panic(std::panic::AssertUnwindSafe(closure));
                match outcome {
                    Ok(status) => {
                        if status == CoroStatus::Completed {
                            self.state = FiberState::Completed;
                            FiberStepResult::Completed
                        } else if status == CoroStatus::WaitingIo {
                            let tok = current_fiber_io_token();
                            let slot = current_fiber_result_slot();
                            self.state = FiberState::WaitingIo(tok);
                            FiberStepResult::WaitingIo(tok, slot)
                        } else if status == CoroStatus::Suspended {
                            self.state = FiberState::Suspended;
                            FiberStepResult::Suspended
                        } else {
                            self.state = FiberState::Panicked;
                            FiberStepResult::Panicked
                        }
                    }
                    Err(_) => {
                        self.state = FiberState::Panicked;
                        FiberStepResult::Panicked
                    }
                }
            }
            Some(FiberTask::Stackless(coro)) => {
                self.state = FiberState::Running;
                let res = (coro.resume_fn)(coro.frame);
                let pending_token = coro.pending_io_token.take();
                let pending_slot = coro.pending_result_slot.take();
                if res == CoroStatus::Completed as i32 {
                    coro.status = CoroStatus::Completed;
                    self.state = FiberState::Completed;
                    FiberStepResult::Completed
                } else if res == CoroStatus::WaitingIo as i32 || pending_token.is_some() {
                    let tok = pending_token.unwrap_or_else(current_fiber_io_token);
                    let slot = pending_slot.or_else(current_fiber_result_slot);
                    coro.status = CoroStatus::WaitingIo;
                    self.state = FiberState::WaitingIo(tok);
                    FiberStepResult::WaitingIo(tok, slot)
                } else if res == CoroStatus::Suspended as i32 {
                    coro.status = CoroStatus::Suspended;
                    self.state = FiberState::Suspended;
                    FiberStepResult::Suspended
                } else {
                    coro.status = CoroStatus::Panicked;
                    self.state = FiberState::Panicked;
                    FiberStepResult::Panicked
                }
            }
            None => FiberStepResult::Completed,
        };

        CURRENT_FIBER_ID.with(|c| c.set(prev_id));
        CURRENT_FIBER_ARENA.with(|c| c.set(prev_arena));
        CURRENT_FIBER_IO_TOKEN.with(|c| c.set(prev_token));
        CURRENT_FIBER_RESULT_SLOT.with(|c| c.set(prev_slot));

        step_res
    }
}

/// Global M:N Fiber Scheduler managing colorless asynchronous tasks without GC.
pub struct FiberScheduler {
    ready_queue: Arc<Mutex<VecDeque<Fiber>>>,
    completed_fibers: Arc<Mutex<HashMap<FiberId, FiberState>>>,
    waiting_io_fibers: Arc<Mutex<HashMap<u64, IoWaitEntry>>>,
    completed_io_results: Arc<Mutex<HashMap<u64, i64>>>,
    work_notifier: Arc<Condvar>,
    completion_notifier: Arc<Condvar>,
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
        let waiting_io_fibers = Arc::new(Mutex::new(HashMap::new()));
        let completed_io_results = Arc::new(Mutex::new(HashMap::new()));
        let work_notifier = Arc::new(Condvar::new());
        let completion_notifier = Arc::new(Condvar::new());
        let is_running = Arc::new(AtomicBool::new(true));

        #[cfg(not(target_arch = "wasm32"))]
        let mut workers = Vec::with_capacity(workers_count);

        #[cfg(not(target_arch = "wasm32"))]
        {
            for _ in 0..workers_count {
                let queue = Arc::clone(&ready_queue);
                let completed = Arc::clone(&completed_fibers);
                let waiting_io = Arc::clone(&waiting_io_fibers);
                let completed_io = Arc::clone(&completed_io_results);
                let work_notif = Arc::clone(&work_notifier);
                let comp_notif = Arc::clone(&completion_notifier);
                let is_run = Arc::clone(&is_running);

                let handle = thread::spawn(move || loop {
                    let task = {
                        let mut lock = queue.lock().unwrap();
                        let mut spins = 0;
                        while lock.is_empty() && is_run.load(Ordering::Relaxed) {
                            drop(lock);
                            let woken = crate::reactor::GLOBAL_REACTOR.poll_and_wake();
                            lock = queue.lock().unwrap();
                            if !lock.is_empty() {
                                break;
                            }
                            if woken > 0 {
                                continue;
                            }
                            let has_io = {
                                let wm = waiting_io.lock().unwrap();
                                let cr = completed_io.lock().unwrap();
                                !wm.is_empty() || !cr.is_empty()
                            };
                            if has_io {
                                let (new_lock, _) = work_notif
                                    .wait_timeout(lock, Duration::from_millis(2))
                                    .unwrap();
                                lock = new_lock;
                            } else {
                                spins += 1;
                                if spins < 32 {
                                    drop(lock);
                                    std::hint::spin_loop();
                                    lock = queue.lock().unwrap();
                                } else {
                                    let (new_lock, _) = work_notif
                                        .wait_timeout(lock, Duration::from_millis(5))
                                        .unwrap();
                                    lock = new_lock;
                                    spins = 0;
                                }
                            }
                        }
                        if !is_run.load(Ordering::Relaxed) && lock.is_empty() {
                            break;
                        }
                        lock.pop_front()
                    };

                    if let Some(mut fiber) = task {
                        let step_res = fiber.step();
                        match step_res {
                            FiberStepResult::Completed | FiberStepResult::Panicked => {
                                if let Some(arena_id) = fiber.arena_id {
                                    crate::allocator::GLOBAL_ALLOCATOR.destroy_arena(arena_id);
                                }
                                let mut comp = completed.lock().unwrap();
                                comp.insert(fiber.id, fiber.state);
                                comp_notif.notify_all();
                            }
                            FiberStepResult::Suspended => {
                                let mut q = queue.lock().unwrap();
                                fiber.state = FiberState::Ready;
                                q.push_back(fiber);
                                work_notif.notify_one();
                            }
                            FiberStepResult::WaitingIo(token, slot) => {
                                let mut wm = waiting_io.lock().unwrap();
                                let mut cr = completed_io.lock().unwrap();
                                if let Some(res) = cr.remove(&token) {
                                    drop(cr);
                                    drop(wm);
                                    if let Some(s) = slot {
                                        if !s.is_null() {
                                            unsafe {
                                                *s = res;
                                            }
                                        }
                                    }
                                    let mut q = queue.lock().unwrap();
                                    fiber.state = FiberState::Ready;
                                    q.push_back(fiber);
                                    work_notif.notify_one();
                                } else {
                                    fiber.state = FiberState::WaitingIo(token);
                                    wm.insert(
                                        token,
                                        IoWaitEntry {
                                            fiber,
                                            result_slot: slot,
                                        },
                                    );
                                }
                            }
                        }
                    }
                });

                workers.push(handle);
            }
        }

        Self {
            ready_queue,
            completed_fibers,
            waiting_io_fibers,
            completed_io_results,
            work_notifier,
            completion_notifier,
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
            task: Some(FiberTask::Once(Box::new(task))),
            arena_id: None,
        };

        {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.push_back(fiber);
        }
        self.work_notifier.notify_one();

        id
    }

    /// Spawn a new colorless fiber configured with an isolated generational arena.
    pub fn spawn_with_arena<F>(&self, task: F) -> (FiberId, u16)
    where
        F: FnOnce() + Send + 'static,
    {
        let id = self.next_fiber_id.fetch_add(1, Ordering::SeqCst);
        let arena_id = crate::allocator::GLOBAL_ALLOCATOR.create_arena_for_fiber(id);
        let fiber = Fiber {
            id,
            state: FiberState::Ready,
            task: Some(FiberTask::Once(Box::new(task))),
            arena_id: Some(arena_id),
        };

        {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.push_back(fiber);
        }
        self.work_notifier.notify_one();

        (id, arena_id)
    }

    /// Spawn a new resumable task called repeatedly across scheduler cycles until completion.
    pub fn spawn_resumable<F>(&self, task: F) -> FiberId
    where
        F: FnMut() -> CoroStatus + Send + 'static,
    {
        let id = self.next_fiber_id.fetch_add(1, Ordering::SeqCst);
        let fiber = Fiber {
            id,
            state: FiberState::Ready,
            task: Some(FiberTask::Resumable(Box::new(task))),
            arena_id: None,
        };

        {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.push_back(fiber);
        }
        self.work_notifier.notify_one();

        id
    }

    /// Spawn a native stackless coroutine without system call stacks.
    pub fn spawn_coro(&self, coro: StacklessCoro) -> FiberId {
        let id = self.next_fiber_id.fetch_add(1, Ordering::SeqCst);
        let fiber = Fiber {
            id,
            state: FiberState::Ready,
            task: Some(FiberTask::Stackless(coro)),
            arena_id: None,
        };

        {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.push_back(fiber);
        }
        self.work_notifier.notify_one();

        id
    }

    /// Spawn a native stackless coroutine configured with an isolated generational arena.
    pub fn spawn_coro_with_arena(&self, coro: StacklessCoro) -> (FiberId, u16) {
        let id = self.next_fiber_id.fetch_add(1, Ordering::SeqCst);
        let arena_id = crate::allocator::GLOBAL_ALLOCATOR.create_arena_for_fiber(id);
        let fiber = Fiber {
            id,
            state: FiberState::Ready,
            task: Some(FiberTask::Stackless(coro)),
            arena_id: Some(arena_id),
        };

        {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.push_back(fiber);
        }
        self.work_notifier.notify_one();

        (id, arena_id)
    }

    /// Spawn a blocking operation on the dedicated background blocking pool.
    /// Returns a `BlockingHandle` that can be cooperatively awaited without stalling M:N workers.
    pub fn spawn_blocking<F, R>(&self, f: F) -> crate::blocking::BlockingHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        crate::blocking::GLOBAL_BLOCKING_POOL.spawn(f)
    }

    /// Cooperative yield: relinquishes current execution slice to allow other fibers to run.
    pub fn yield_now(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        thread::yield_now();
        #[cfg(target_arch = "wasm32")]
        let _ = self.step();
    }

    /// Wake a fiber waiting for the specified asynchronous I/O completion token.
    /// Injects `result` into the fiber's result slot if configured, and reschedules the fiber.
    pub fn wake_io(&self, token: u64, result: i64) -> bool {
        let mut wm = self.waiting_io_fibers.lock().unwrap();
        let mut cr = self.completed_io_results.lock().unwrap();
        if let Some(mut entry) = wm.remove(&token) {
            drop(cr);
            drop(wm);
            if let Some(slot) = entry.result_slot {
                if !slot.is_null() {
                    unsafe {
                        *slot = result;
                    }
                }
            }
            entry.fiber.state = FiberState::Ready;
            {
                let mut q = self.ready_queue.lock().unwrap();
                q.push_back(entry.fiber);
            }
            self.work_notifier.notify_one();
            true
        } else {
            cr.insert(token, result);
            true
        }
    }

    /// Check if there are any fibers currently waiting on asynchronous I/O events.
    pub fn has_pending_io(&self) -> bool {
        let wm = self.waiting_io_fibers.lock().unwrap();
        let cr = self.completed_io_results.lock().unwrap();
        !wm.is_empty() || !cr.is_empty()
    }

    /// Count of fibers currently waiting on asynchronous I/O events.
    pub fn pending_io_count(&self) -> usize {
        let wm = self.waiting_io_fibers.lock().unwrap();
        let cr = self.completed_io_results.lock().unwrap();
        wm.len() + cr.len()
    }

    /// Park a fiber directly into the waiting I/O table.
    pub fn park_fiber_for_io(&self, token: u64, mut fiber: Fiber, result_slot: Option<*mut i64>) {
        let mut wm = self.waiting_io_fibers.lock().unwrap();
        let mut cr = self.completed_io_results.lock().unwrap();
        if let Some(res) = cr.remove(&token) {
            drop(cr);
            drop(wm);
            if let Some(slot) = result_slot {
                if !slot.is_null() {
                    unsafe {
                        *slot = res;
                    }
                }
            }
            fiber.state = FiberState::Ready;
            let mut q = self.ready_queue.lock().unwrap();
            q.push_back(fiber);
            self.work_notifier.notify_one();
        } else {
            fiber.state = FiberState::WaitingIo(token);
            wm.insert(token, IoWaitEntry { fiber, result_slot });
        }
    }

    /// Execute a single fiber from the ready queue cooperatively.
    /// Returns true if a task was executed, false if the queue was empty.
    pub fn step(&self) -> bool {
        let _ = crate::reactor::GLOBAL_REACTOR.poll_and_wake();

        let task = {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.pop_front()
        };

        if let Some(mut fiber) = task {
            let step_res = fiber.step();
            match step_res {
                FiberStepResult::Completed | FiberStepResult::Panicked => {
                    if let Some(arena_id) = fiber.arena_id {
                        crate::allocator::GLOBAL_ALLOCATOR.destroy_arena(arena_id);
                    }
                    let mut comp = self.completed_fibers.lock().unwrap();
                    comp.insert(fiber.id, fiber.state);
                    self.completion_notifier.notify_all();
                    return true;
                }
                FiberStepResult::Suspended => {
                    let mut queue = self.ready_queue.lock().unwrap();
                    fiber.state = FiberState::Ready;
                    queue.push_back(fiber);
                    self.work_notifier.notify_one();
                    return true;
                }
                FiberStepResult::WaitingIo(token, slot) => {
                    let mut wm = self.waiting_io_fibers.lock().unwrap();
                    let mut cr = self.completed_io_results.lock().unwrap();
                    if let Some(res) = cr.remove(&token) {
                        drop(cr);
                        drop(wm);
                        if let Some(s) = slot {
                            if !s.is_null() {
                                unsafe {
                                    *s = res;
                                }
                            }
                        }
                        let mut queue = self.ready_queue.lock().unwrap();
                        fiber.state = FiberState::Ready;
                        queue.push_back(fiber);
                        self.work_notifier.notify_one();
                        return true;
                    }
                    fiber.state = FiberState::WaitingIo(token);
                    wm.insert(
                        token,
                        IoWaitEntry {
                            fiber,
                            result_slot: slot,
                        },
                    );
                    return true;
                }
            }
        }
        false
    }

    /// Run all queued fibers sequentially until no runnable fibers remain.
    pub fn run_until_idle(&self) {
        loop {
            let worked = self.step();
            if !worked {
                if self.has_pending_io() {
                    let woken =
                        crate::reactor::GLOBAL_REACTOR.wait_and_wake(Duration::from_millis(5));
                    if woken > 0 {
                        continue;
                    }
                }
                break;
            }
        }
    }

    /// Check if a specific fiber has completed execution.
    pub fn is_completed(&self, fiber_id: FiberId) -> bool {
        let completed = self.completed_fibers.lock().unwrap();
        completed.contains_key(&fiber_id)
    }

    /// Retrieve the final execution state of a fiber if finished.
    pub fn get_fiber_state(&self, fiber_id: FiberId) -> Option<FiberState> {
        let completed = self.completed_fibers.lock().unwrap();
        completed.get(&fiber_id).copied()
    }

    /// Block current context until the specified fiber has finished execution.
    pub fn join(&self, fiber_id: FiberId) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut completed = self.completed_fibers.lock().unwrap();
            while !completed.contains_key(&fiber_id) {
                let has_io = self.has_pending_io();
                drop(completed);
                let _ = crate::reactor::GLOBAL_REACTOR.poll_and_wake();
                let _ = self.step();
                completed = self.completed_fibers.lock().unwrap();
                if completed.contains_key(&fiber_id) {
                    break;
                }
                if has_io {
                    let (new_c, _) = self
                        .completion_notifier
                        .wait_timeout(completed, Duration::from_millis(2))
                        .unwrap();
                    completed = new_c;
                } else {
                    completed = self.completion_notifier.wait(completed).unwrap();
                }
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            while !self.is_completed(fiber_id) {
                if !self.step() {
                    if self.has_pending_io() {
                        let _ =
                            crate::reactor::GLOBAL_REACTOR.wait_and_wake(Duration::from_millis(2));
                    } else {
                        break;
                    }
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
                let has_io = self.has_pending_io();
                drop(completed);
                let _ = crate::reactor::GLOBAL_REACTOR.poll_and_wake();
                let _ = self.step();
                completed = self.completed_fibers.lock().unwrap();
                if completed.contains_key(&fiber_id) {
                    return true;
                }
                let wait_duration = if has_io {
                    remaining.min(Duration::from_millis(2))
                } else {
                    remaining.min(Duration::from_millis(10))
                };
                let (new_completed, _) = self
                    .completion_notifier
                    .wait_timeout(completed, wait_duration)
                    .unwrap();
                completed = new_completed;
            }
            true
        }
        #[cfg(target_arch = "wasm32")]
        {
            while !self.is_completed(fiber_id) {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                if !self.step() {
                    if self.has_pending_io() {
                        let _ =
                            crate::reactor::GLOBAL_REACTOR.wait_and_wake(Duration::from_millis(2));
                    } else {
                        break;
                    }
                }
            }
            self.is_completed(fiber_id)
        }
    }

    /// Check if scheduler is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    /// Explicitly wake an idle worker thread to service pending tasks or reactor completions.
    pub fn notify_work(&self) {
        self.work_notifier.notify_one();
    }

    /// Gracefully shutdown all background worker threads and clear pending fibers.
    pub fn shutdown(&self) {
        self.is_running.store(false, Ordering::Release);
        {
            let mut queue = self.ready_queue.lock().unwrap();
            queue.clear();
        }
        self.work_notifier.notify_all();
        self.completion_notifier.notify_all();
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

/// Error returned when sending to a closed channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError<T> {
    Closed(T),
}

/// Error returned when receiving from a closed empty channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    Closed,
}

/// Non-blocking send error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrySendError<T> {
    Full(T),
    Closed(T),
}

/// Non-blocking receive error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    Empty,
    Closed,
}

/// Cacheline-aligned slot in the lock-free atomic ring buffer.
#[repr(align(64))]
struct RingSlot<T> {
    sequence: AtomicUsize,
    value: UnsafeCell<Option<T>>,
}

/// High-performance lock-free bounded MPMC atomic ring buffer without GC.
/// Uses atomic sequence counters and cacheline alignment to eliminate false sharing.
pub struct AtomicRingBuffer<T> {
    buffer: Box<[RingSlot<T>]>,
    mask: usize,
    buffer_capacity: usize,
    capacity: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
}

unsafe impl<T: Send> Send for AtomicRingBuffer<T> {}
unsafe impl<T: Send> Sync for AtomicRingBuffer<T> {}

impl<T> AtomicRingBuffer<T> {
    /// Create a new atomic ring buffer with the requested user capacity.
    pub fn new(capacity: usize) -> Self {
        let user_cap = capacity.max(1);
        let cap = user_cap.max(2).next_power_of_two();
        let mask = cap - 1;
        let mut slots = Vec::with_capacity(cap);
        for i in 0..cap {
            slots.push(RingSlot {
                sequence: AtomicUsize::new(i),
                value: UnsafeCell::new(None),
            });
        }
        Self {
            buffer: slots.into_boxed_slice(),
            mask,
            buffer_capacity: cap,
            capacity: user_cap,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Maximum capacity of the ring buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Internal power-of-two buffer capacity.
    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    /// Approximate count of elements currently stored.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.saturating_sub(tail)
    }

    /// Check if the ring buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the ring buffer is full.
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// Attempt to push an element into the buffer without blocking.
    pub fn try_push(&self, val: T) -> Result<(), T> {
        let mut pos = self.head.load(Ordering::Relaxed);
        let mut item = Some(val);
        loop {
            let slot = &self.buffer[pos & self.mask];
            let seq = slot.sequence.load(Ordering::Acquire);
            let dif = seq as isize - pos as isize;

            if dif == 0 {
                let tail_pos = self.tail.load(Ordering::Relaxed);
                if pos >= tail_pos + self.capacity {
                    return Err(item.unwrap());
                }

                match self.head.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let to_store = item.take().unwrap();
                        unsafe {
                            *slot.value.get() = Some(to_store);
                        }
                        slot.sequence.store(pos + 1, Ordering::Release);
                        return Ok(());
                    }
                    Err(actual) => pos = actual,
                }
            } else if dif < 0 {
                return Err(item.unwrap());
            } else {
                pos = self.head.load(Ordering::Relaxed);
            }
        }
    }

    /// Attempt to pop an element from the buffer without blocking.
    pub fn try_pop(&self) -> Option<T> {
        let mut pos = self.tail.load(Ordering::Relaxed);
        loop {
            let slot = &self.buffer[pos & self.mask];
            let seq = slot.sequence.load(Ordering::Acquire);
            let dif = seq as isize - (pos + 1) as isize;

            if dif == 0 {
                match self.tail.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let val =
                            unsafe { (*slot.value.get()).take().expect("slot must contain value") };
                        slot.sequence.store(pos + self.mask + 1, Ordering::Release);
                        return Some(val);
                    }
                    Err(actual) => pos = actual,
                }
            } else if dif < 0 {
                return None;
            } else {
                pos = self.tail.load(Ordering::Relaxed);
            }
        }
    }
}

impl<T> Drop for AtomicRingBuffer<T> {
    fn drop(&mut self) {
        while self.try_pop().is_some() {}
    }
}

/// Communication channel between fibers ensuring message passing without shared mutable memory.
/// Powered by lock-free atomic ring buffers for bounded channels and cooperative fiber scheduling.
pub struct Channel<T> {
    ring: Option<AtomicRingBuffer<T>>,
    unbounded: Option<Mutex<VecDeque<T>>>,
    notif_mutex: Mutex<()>,
    cond: Condvar,
    is_closed: AtomicBool,
}

impl<T> Channel<T> {
    /// Create an unbounded communication channel.
    pub fn new() -> Self {
        Self {
            ring: None,
            unbounded: Some(Mutex::new(VecDeque::new())),
            notif_mutex: Mutex::new(()),
            cond: Condvar::new(),
            is_closed: AtomicBool::new(false),
        }
    }

    /// Create a bounded communication channel backed by lock-free atomic ring buffer.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ring: Some(AtomicRingBuffer::new(capacity)),
            unbounded: None,
            notif_mutex: Mutex::new(()),
            cond: Condvar::new(),
            is_closed: AtomicBool::new(false),
        }
    }

    #[inline]
    fn notify_waiters(&self) {
        self.cond.notify_all();
    }

    /// Send a value to the channel (blocks if bounded and full).
    /// Cooperatively yields the fiber on backpressure before thread wait.
    pub fn send(&self, mut val: T) {
        if let Some(ring) = &self.ring {
            let mut spins: u32 = 0;
            loop {
                if self.is_closed.load(Ordering::Acquire) {
                    panic!("Cannot send on closed channel");
                }
                match ring.try_push(val) {
                    Ok(()) => {
                        self.notify_waiters();
                        return;
                    }
                    Err(returned_val) => {
                        val = returned_val;
                        spins += 1;
                        if spins < 32 {
                            std::hint::spin_loop();
                        } else if spins < 64 {
                            GLOBAL_SCHEDULER.yield_now();
                        } else {
                            let guard = self.notif_mutex.lock().unwrap();
                            if ring.is_full() && !self.is_closed.load(Ordering::Relaxed) {
                                let _ = self.cond.wait_timeout(guard, Duration::from_micros(250));
                            }
                        }
                    }
                }
            }
        } else if let Some(queue) = &self.unbounded {
            if self.is_closed.load(Ordering::Acquire) {
                panic!("Cannot send on closed channel");
            }
            let mut q = queue.lock().unwrap();
            q.push_back(val);
            self.notify_waiters();
        }
    }

    /// Send a value returning Result with typed SendError if closed.
    pub fn send_checked(&self, mut val: T) -> Result<(), SendError<T>> {
        if let Some(ring) = &self.ring {
            let mut spins: u32 = 0;
            loop {
                if self.is_closed.load(Ordering::Acquire) {
                    return Err(SendError::Closed(val));
                }
                match ring.try_push(val) {
                    Ok(()) => {
                        self.notify_waiters();
                        return Ok(());
                    }
                    Err(returned_val) => {
                        val = returned_val;
                        spins += 1;
                        if spins < 32 {
                            std::hint::spin_loop();
                        } else if spins < 64 {
                            GLOBAL_SCHEDULER.yield_now();
                        } else {
                            let guard = self.notif_mutex.lock().unwrap();
                            if ring.is_full() && !self.is_closed.load(Ordering::Relaxed) {
                                let _ = self.cond.wait_timeout(guard, Duration::from_micros(250));
                            }
                        }
                    }
                }
            }
        } else if let Some(queue) = &self.unbounded {
            if self.is_closed.load(Ordering::Acquire) {
                return Err(SendError::Closed(val));
            }
            let mut q = queue.lock().unwrap();
            q.push_back(val);
            self.notify_waiters();
            Ok(())
        } else {
            Err(SendError::Closed(val))
        }
    }

    /// Non-blocking send: returns Err(val) if channel capacity is exhausted or channel is closed.
    pub fn try_send(&self, val: T) -> Result<(), T> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(val);
        }
        if let Some(ring) = &self.ring {
            let res = ring.try_push(val);
            if res.is_ok() {
                self.notify_waiters();
            }
            res
        } else if let Some(queue) = &self.unbounded {
            let mut q = queue.lock().unwrap();
            q.push_back(val);
            self.notify_waiters();
            Ok(())
        } else {
            Err(val)
        }
    }

    /// Typed non-blocking send distinguishing full from closed.
    pub fn try_send_checked(&self, val: T) -> Result<(), TrySendError<T>> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(TrySendError::Closed(val));
        }
        if let Some(ring) = &self.ring {
            match ring.try_push(val) {
                Ok(()) => {
                    self.notify_waiters();
                    Ok(())
                }
                Err(v) => Err(TrySendError::Full(v)),
            }
        } else if let Some(queue) = &self.unbounded {
            let mut q = queue.lock().unwrap();
            q.push_back(val);
            self.notify_waiters();
            Ok(())
        } else {
            Err(TrySendError::Closed(val))
        }
    }

    /// Receive a value from the channel, waiting if empty.
    /// Cooperatively yields the fiber when waiting before thread wait.
    pub fn recv(&self) -> T {
        if let Some(ring) = &self.ring {
            let mut spins: u32 = 0;
            loop {
                if let Some(val) = ring.try_pop() {
                    self.notify_waiters();
                    return val;
                }
                if self.is_closed.load(Ordering::Acquire) && ring.is_empty() {
                    panic!("Cannot receive on closed empty channel");
                }
                spins += 1;
                if spins < 32 {
                    std::hint::spin_loop();
                } else if spins < 64 {
                    GLOBAL_SCHEDULER.yield_now();
                } else {
                    let guard = self.notif_mutex.lock().unwrap();
                    if ring.is_empty() && !self.is_closed.load(Ordering::Relaxed) {
                        let _ = self.cond.wait_timeout(guard, Duration::from_micros(250));
                    }
                }
            }
        } else if let Some(queue) = &self.unbounded {
            let mut q = queue.lock().unwrap();
            while q.is_empty() {
                if self.is_closed.load(Ordering::Acquire) && q.is_empty() {
                    panic!("Cannot receive on closed empty channel");
                }
                q = self.cond.wait(q).unwrap();
            }
            let val = q.pop_front().unwrap();
            self.notify_waiters();
            val
        } else {
            panic!("Channel unintialized");
        }
    }

    /// Receive a value returning Result with typed RecvError if closed and empty.
    pub fn recv_checked(&self) -> Result<T, RecvError> {
        if let Some(ring) = &self.ring {
            let mut spins: u32 = 0;
            loop {
                if let Some(val) = ring.try_pop() {
                    self.notify_waiters();
                    return Ok(val);
                }
                if self.is_closed.load(Ordering::Acquire) && ring.is_empty() {
                    return Err(RecvError::Closed);
                }
                spins += 1;
                if spins < 32 {
                    std::hint::spin_loop();
                } else if spins < 64 {
                    GLOBAL_SCHEDULER.yield_now();
                } else {
                    let guard = self.notif_mutex.lock().unwrap();
                    if ring.is_empty() && !self.is_closed.load(Ordering::Relaxed) {
                        let _ = self.cond.wait_timeout(guard, Duration::from_micros(250));
                    }
                }
            }
        } else if let Some(queue) = &self.unbounded {
            let mut q = queue.lock().unwrap();
            while q.is_empty() {
                if self.is_closed.load(Ordering::Acquire) && q.is_empty() {
                    return Err(RecvError::Closed);
                }
                q = self.cond.wait(q).unwrap();
            }
            let val = q.pop_front().unwrap();
            self.notify_waiters();
            Ok(val)
        } else {
            Err(RecvError::Closed)
        }
    }

    /// Non-blocking receive: returns None immediately if empty.
    pub fn try_recv(&self) -> Option<T> {
        if let Some(ring) = &self.ring {
            let res = ring.try_pop();
            if res.is_some() {
                self.notify_waiters();
            }
            res
        } else if let Some(queue) = &self.unbounded {
            let mut q = queue.lock().unwrap();
            let val = q.pop_front();
            if val.is_some() {
                self.notify_waiters();
            }
            val
        } else {
            None
        }
    }

    /// Typed non-blocking receive distinguishing empty from closed.
    pub fn try_recv_checked(&self) -> Result<T, TryRecvError> {
        if let Some(ring) = &self.ring {
            if let Some(val) = ring.try_pop() {
                self.notify_waiters();
                Ok(val)
            } else if self.is_closed.load(Ordering::Acquire) {
                Err(TryRecvError::Closed)
            } else {
                Err(TryRecvError::Empty)
            }
        } else if let Some(queue) = &self.unbounded {
            let mut q = queue.lock().unwrap();
            if let Some(val) = q.pop_front() {
                self.notify_waiters();
                Ok(val)
            } else if self.is_closed.load(Ordering::Acquire) {
                Err(TryRecvError::Closed)
            } else {
                Err(TryRecvError::Empty)
            }
        } else {
            Err(TryRecvError::Closed)
        }
    }

    /// Timed receive: returns None if timeout expires before a value arrives.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<T> {
        let deadline = std::time::Instant::now() + timeout;
        if let Some(ring) = &self.ring {
            let mut spins: u32 = 0;
            loop {
                if let Some(val) = ring.try_pop() {
                    self.notify_waiters();
                    return Some(val);
                }
                if self.is_closed.load(Ordering::Acquire) && ring.is_empty() {
                    return None;
                }
                let now = std::time::Instant::now();
                if now >= deadline {
                    return None;
                }
                spins += 1;
                if spins < 32 {
                    std::hint::spin_loop();
                } else if spins < 64 {
                    GLOBAL_SCHEDULER.yield_now();
                } else {
                    let remaining = deadline - now;
                    let guard = self.notif_mutex.lock().unwrap();
                    if ring.is_empty() && !self.is_closed.load(Ordering::Relaxed) {
                        let _ = self
                            .cond
                            .wait_timeout(guard, remaining.min(Duration::from_millis(5)));
                    }
                }
            }
        } else if let Some(queue) = &self.unbounded {
            let mut q = queue.lock().unwrap();
            while q.is_empty() {
                if self.is_closed.load(Ordering::Acquire) {
                    return None;
                }
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
                self.notify_waiters();
            }
            val
        } else {
            None
        }
    }

    /// Close the channel, disallowing further sends and waking all waiting receivers.
    pub fn close(&self) {
        self.is_closed.store(true, Ordering::Release);
        self.notify_waiters();
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    /// Number of elements currently queued in the channel.
    pub fn len(&self) -> usize {
        if let Some(ring) = &self.ring {
            ring.len()
        } else if let Some(queue) = &self.unbounded {
            queue.lock().unwrap().len()
        } else {
            0
        }
    }

    /// Check if the channel is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the channel is at capacity (always false for unbounded channels).
    pub fn is_full(&self) -> bool {
        if let Some(ring) = &self.ring {
            ring.is_full()
        } else {
            false
        }
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
