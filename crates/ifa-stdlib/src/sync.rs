//! Colorless concurrency primitives, typed channels, atomic ring buffers, and inter-fiber synchronization for IFA.

use ifa_runtime::fiber::{
    Channel as RtChannel, RecvError, SendError, TryRecvError, TrySendError, GLOBAL_SCHEDULER,
};
use std::collections::{BinaryHeap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use ifa_runtime::fiber::{AdaptiveBackoff, FiberId, FiberScheduler, FiberState};

/// Error returned when timed receive expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvTimeoutError {
    Timeout,
    Closed,
}

/// Sending endpoint of a typed IFA channel.
pub struct Sender<T> {
    inner: Arc<RtChannel<T>>,
    sender_count: Arc<AtomicUsize>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.sender_count.fetch_add(1, Ordering::SeqCst);
        Self {
            inner: Arc::clone(&self.inner),
            sender_count: Arc::clone(&self.sender_count),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        if self.sender_count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.inner.close();
        }
    }
}

/// Receiving endpoint of a typed IFA channel.
#[derive(Clone)]
pub struct Receiver<T> {
    inner: Arc<RtChannel<T>>,
}

/// Create an unbounded asynchronous channel between fibers.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(RtChannel::new());
    let sender_count = Arc::new(AtomicUsize::new(1));
    (
        Sender {
            inner: Arc::clone(&inner),
            sender_count,
        },
        Receiver { inner },
    )
}

/// Create a bounded channel with lock-free atomic ring buffer backpressure.
pub fn bounded<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(RtChannel::with_capacity(capacity));
    let sender_count = Arc::new(AtomicUsize::new(1));
    (
        Sender {
            inner: Arc::clone(&inner),
            sender_count,
        },
        Receiver { inner },
    )
}

impl<T> Sender<T> {
    /// Send a message into the channel (suspends or yields fiber on backpressure).
    pub fn send(&self, val: T) -> Result<(), SendError<T>> {
        self.inner.send_checked(val)
    }

    /// Non-blocking send: returns Err(TrySendError::Full(val)) if capacity is reached.
    pub fn try_send(&self, val: T) -> Result<(), TrySendError<T>> {
        self.inner.try_send_checked(val)
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Close the channel from the sender endpoint.
    pub fn close(&self) {
        self.inner.close();
    }
}

impl<T> Receiver<T> {
    /// Receive a message from the channel (suspends or yields fiber until data arrives).
    pub fn recv(&self) -> Result<T, RecvError> {
        self.inner.recv_checked()
    }

    /// Non-blocking receive: returns Err(TryRecvError::Empty) if no message is available.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.inner.try_recv_checked()
    }

    /// Timed receive with timeout duration.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, RecvTimeoutError> {
        if self.inner.is_closed() && self.inner.is_empty() {
            return Err(RecvTimeoutError::Closed);
        }
        match self.inner.recv_timeout(timeout) {
            Some(v) => Ok(v),
            None => {
                if self.inner.is_closed() && self.inner.is_empty() {
                    Err(RecvTimeoutError::Closed)
                } else {
                    Err(RecvTimeoutError::Timeout)
                }
            }
        }
    }

    /// Number of buffered elements currently queued.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the channel is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Check if the channel has been closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Close the channel from receiver endpoint.
    pub fn close(&self) {
        self.inner.close();
    }

    /// Iterator over values received on this channel until it is closed.
    pub fn iter(&self) -> ReceiverIter<'_, T> {
        ReceiverIter { receiver: self }
    }
}

/// Iterator borrowing from a Receiver.
pub struct ReceiverIter<'a, T> {
    receiver: &'a Receiver<T>,
}

impl<'a, T> Iterator for ReceiverIter<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

impl<T> IntoIterator for Receiver<T> {
    type Item = T;
    type IntoIter = ReceiverIntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        ReceiverIntoIter { receiver: self }
    }
}

/// Owning iterator for Receiver.
pub struct ReceiverIntoIter<T> {
    receiver: Receiver<T>,
}

impl<T> Iterator for ReceiverIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

/// High-performance cooperative WaitGroup for coordinating multiple fibers without GC.
pub struct WaitGroup {
    counter: Arc<AtomicUsize>,
    notif: Arc<std::sync::Condvar>,
    mutex: Arc<std::sync::Mutex<()>>,
}

impl Default for WaitGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitGroup {
    /// Create a new WaitGroup with initial count of 0.
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
            notif: Arc::new(std::sync::Condvar::new()),
            mutex: Arc::new(std::sync::Mutex::new(())),
        }
    }

    /// Add a delta count to the wait group.
    pub fn add(&self, delta: usize) {
        self.counter.fetch_add(delta, Ordering::SeqCst);
    }

    /// Mark one task as completed, decrementing the counter.
    pub fn done(&self) {
        let prev = self.counter.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            self.notif.notify_all();
        }
    }

    /// Cooperatively wait until all tasks in the WaitGroup have completed.
    pub fn wait(&self) {
        let mut spins: u32 = 0;
        while self.counter.load(Ordering::Acquire) > 0 {
            spins += 1;
            if spins < 32 {
                std::hint::spin_loop();
            } else if spins < 64 {
                GLOBAL_SCHEDULER.yield_now();
            } else {
                let guard = self.mutex.lock().unwrap();
                if self.counter.load(Ordering::Relaxed) > 0 {
                    let _ = self.notif.wait_timeout(guard, Duration::from_micros(250));
                }
            }
        }
    }

    /// Timed wait returning true if counter reached zero, or false if timed out.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut spins: u32 = 0;
        while self.counter.load(Ordering::Acquire) > 0 {
            let now = std::time::Instant::now();
            if now >= deadline {
                return self.counter.load(Ordering::Acquire) == 0;
            }
            spins += 1;
            if spins < 32 {
                std::hint::spin_loop();
            } else if spins < 64 {
                GLOBAL_SCHEDULER.yield_now();
            } else {
                let remaining = deadline - now;
                let guard = self.mutex.lock().unwrap();
                if self.counter.load(Ordering::Relaxed) > 0 {
                    let _ = self
                        .notif
                        .wait_timeout(guard, remaining.min(Duration::from_millis(5)));
                }
            }
        }
        true
    }
}

/// Multi-channel select multiplexer polling multiple receivers.
pub struct Select;

impl Select {
    /// Non-blocking select over multiple receivers: returns index of ready receiver and value.
    pub fn try_select<T>(receivers: &[&Receiver<T>]) -> Option<(usize, T)> {
        for (idx, rx) in receivers.iter().enumerate() {
            if let Ok(val) = rx.try_recv() {
                return Some((idx, val));
            }
        }
        None
    }

    /// Blocking select over multiple receivers: waits cooperatively until any receiver receives.
    pub fn select<T>(receivers: &[&Receiver<T>]) -> Result<(usize, T), RecvError> {
        let mut spins: u32 = 0;
        loop {
            let mut any_open = false;
            for (idx, rx) in receivers.iter().enumerate() {
                if !rx.is_closed() {
                    any_open = true;
                }
                if let Ok(val) = rx.try_recv() {
                    return Ok((idx, val));
                }
            }
            if !any_open {
                return Err(RecvError::Closed);
            }
            spins += 1;
            if spins < 32 {
                std::hint::spin_loop();
            } else if spins < 64 {
                GLOBAL_SCHEDULER.yield_now();
            } else {
                std::thread::sleep(Duration::from_micros(100));
            }
        }
    }
}

/// Ergonomic 64-bit atomic integer wrapper with explicit memory semantics.
#[derive(Debug)]
pub struct AtomicInt(AtomicI64);

impl AtomicInt {
    pub fn new(val: i64) -> Self {
        Self(AtomicI64::new(val))
    }

    pub fn load(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn store(&self, val: i64) {
        self.0.store(val, Ordering::SeqCst)
    }

    pub fn fetch_add(&self, delta: i64) -> i64 {
        self.0.fetch_add(delta, Ordering::SeqCst)
    }

    pub fn fetch_sub(&self, delta: i64) -> i64 {
        self.0.fetch_sub(delta, Ordering::SeqCst)
    }

    pub fn compare_exchange(&self, current: i64, new: i64) -> Result<i64, i64> {
        self.0
            .compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
    }
}

/// Ergonomic atomic boolean wrapper with explicit memory semantics.
#[derive(Debug)]
pub struct AtomicFlag(AtomicBool);

impl AtomicFlag {
    pub fn new(val: bool) -> Self {
        Self(AtomicBool::new(val))
    }

    pub fn load(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub fn store(&self, val: bool) {
        self.0.store(val, Ordering::SeqCst)
    }

    pub fn swap(&self, val: bool) -> bool {
        self.0.swap(val, Ordering::SeqCst)
    }
}

/// Ergonomic 64-bit unsigned atomic integer wrapper with explicit memory semantics.
#[derive(Debug, Default)]
pub struct AtomicUint(AtomicU64);

impl AtomicUint {
    pub fn new(val: u64) -> Self {
        Self(AtomicU64::new(val))
    }

    pub fn load(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn store(&self, val: u64) {
        self.0.store(val, Ordering::SeqCst)
    }

    pub fn fetch_add(&self, delta: u64) -> u64 {
        self.0.fetch_add(delta, Ordering::SeqCst)
    }

    pub fn fetch_sub(&self, delta: u64) -> u64 {
        self.0.fetch_sub(delta, Ordering::SeqCst)
    }

    pub fn compare_exchange(&self, current: u64, new: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
    }
}

/// Thread-safe and fiber-safe one-time initialization primitive.
#[derive(Default, Debug)]
pub struct Once {
    inner: std::sync::Once,
}

impl Once {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Once::new(),
        }
    }

    pub fn call_once<F: FnOnce()>(&self, f: F) {
        self.inner.call_once(f);
    }

    pub fn is_completed(&self) -> bool {
        self.inner.is_completed()
    }
}

/// Fiber-cooperative counting semaphore for managing shared resources.
#[derive(Debug)]
pub struct Semaphore {
    permits: Arc<AtomicUsize>,
    notif: Arc<std::sync::Condvar>,
    mutex: Arc<std::sync::Mutex<()>>,
}

impl Semaphore {
    /// Create a counting semaphore with an initial number of permits.
    pub fn new(permits: usize) -> Self {
        Self {
            permits: Arc::new(AtomicUsize::new(permits)),
            notif: Arc::new(std::sync::Condvar::new()),
            mutex: Arc::new(std::sync::Mutex::new(())),
        }
    }

    /// Try to acquire one permit immediately without blocking.
    pub fn try_acquire(&self) -> bool {
        let mut current = self.permits.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return false;
            }
            match self.permits.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Acquire one permit, yielding or waiting cooperatively until available.
    pub fn acquire(&self) {
        let mut spins: u32 = 0;
        loop {
            if self.try_acquire() {
                return;
            }
            spins += 1;
            if spins < 32 {
                std::hint::spin_loop();
            } else if spins < 64 {
                GLOBAL_SCHEDULER.yield_now();
            } else {
                let guard = self.mutex.lock().unwrap();
                if self.try_acquire() {
                    return;
                }
                let _ = self.notif.wait_timeout(guard, Duration::from_micros(250));
            }
        }
    }

    /// Release one permit back to the semaphore and notify waiting fibers/threads.
    pub fn release(&self) {
        self.permits.fetch_add(1, Ordering::Release);
        self.notif.notify_one();
    }

    /// Return the number of currently available permits.
    pub fn available_permits(&self) -> usize {
        self.permits.load(Ordering::Acquire)
    }
}

// ── PriorityChannel ──────────────────────────────────────────────────────────

/// Inter-fiber prioritized communication channel.
/// Supports multi-level priority scheduling (0 = lowest, levels - 1 = highest priority).
/// Strictly enforces memory invariance (`T: Send + 'static`) to guarantee that no local
/// references can escape across fiber or thread scheduling boundaries.
pub struct PriorityChannel<T> {
    levels: usize,
    queues: Vec<Mutex<VecDeque<T>>>,
    notif_mutex: Mutex<()>,
    cond: std::sync::Condvar,
    is_closed: AtomicBool,
    total_len: AtomicUsize,
}

impl<T: Send + 'static> PriorityChannel<T> {
    /// Create a priority channel with the given number of priority levels.
    /// `levels` is clamped to at least 1.
    pub fn new(levels: usize) -> Self {
        let actual_levels = levels.max(1);
        let mut queues = Vec::with_capacity(actual_levels);
        for _ in 0..actual_levels {
            queues.push(Mutex::new(VecDeque::new()));
        }
        Self {
            levels: actual_levels,
            queues,
            notif_mutex: Mutex::new(()),
            cond: std::sync::Condvar::new(),
            is_closed: AtomicBool::new(false),
            total_len: AtomicUsize::new(0),
        }
    }

    /// Return the number of priority levels.
    pub fn levels(&self) -> usize {
        self.levels
    }

    /// Send a message with a specific priority level.
    /// The priority is clamped to `self.levels - 1`.
    /// Returns `Err(SendError(item))` if the channel is closed.
    pub fn send(&self, item: T, priority: usize) -> Result<(), SendError<T>> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(SendError::Closed(item));
        }
        let prio = priority.min(self.levels - 1);
        {
            let mut q = self.queues[prio].lock().unwrap();
            q.push_back(item);
        }
        self.total_len.fetch_add(1, Ordering::SeqCst);
        self.cond.notify_one();
        Ok(())
    }

    /// Non-blocking send.
    pub fn try_send(&self, item: T, priority: usize) -> Result<(), TrySendError<T>> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(TrySendError::Closed(item));
        }
        let prio = priority.min(self.levels - 1);
        {
            let mut q = self.queues[prio].lock().unwrap();
            q.push_back(item);
        }
        self.total_len.fetch_add(1, Ordering::SeqCst);
        self.cond.notify_one();
        Ok(())
    }

    /// Receive the highest-priority available message.
    /// Cooperatively yields the current fiber when waiting.
    pub fn recv(&self) -> Result<T, RecvError> {
        let mut backoff = AdaptiveBackoff::new();
        loop {
            if let Ok(item) = self.try_recv() {
                return Ok(item);
            }
            if self.is_closed.load(Ordering::Acquire) {
                if let Ok(item) = self.try_recv() {
                    return Ok(item);
                }
                return Err(RecvError::Closed);
            }

            if !backoff.is_completed_spinning() {
                backoff.snooze();
            } else if !backoff.is_completed_yielding() {
                backoff.snooze_cooperative();
            } else {
                let guard = self.notif_mutex.lock().unwrap();
                if self.total_len.load(Ordering::Acquire) == 0
                    && !self.is_closed.load(Ordering::Acquire)
                {
                    let _ = self.cond.wait_timeout(guard, Duration::from_micros(250));
                }
                backoff.reset();
            }
        }
    }

    /// Try receiving the highest-priority available message immediately without blocking.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        if self.total_len.load(Ordering::Acquire) == 0 {
            if self.is_closed.load(Ordering::Acquire) {
                return Err(TryRecvError::Closed);
            }
            return Err(TryRecvError::Empty);
        }

        // Scan from highest priority to lowest priority (strict priority arbitration)
        for prio in (0..self.levels).rev() {
            let mut q = self.queues[prio].lock().unwrap();
            if let Some(item) = q.pop_front() {
                self.total_len.fetch_sub(1, Ordering::SeqCst);
                return Ok(item);
            }
        }

        if self.is_closed.load(Ordering::Acquire) {
            Err(TryRecvError::Closed)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    /// Close the priority channel. Pending messages remain readable.
    pub fn close(&self) {
        self.is_closed.store(true, Ordering::Release);
        self.cond.notify_all();
    }

    /// Check if the priority channel is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    /// Return the total number of queued messages across all priority levels.
    pub fn len(&self) -> usize {
        self.total_len.load(Ordering::Acquire)
    }

    /// Return true if there are no messages in any priority level.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the highest priority level that currently has at least one message, or None if empty.
    pub fn peek_highest_priority(&self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        for prio in (0..self.levels).rev() {
            let q = self.queues[prio].lock().unwrap();
            if !q.is_empty() {
                return Some(prio);
            }
        }
        None
    }
}

// ── TimerQueue ───────────────────────────────────────────────────────────────

/// Internal timer entry with ordered deadline and unique identifier.
struct TimerEntry<T> {
    id: u64,
    deadline: Instant,
    payload: T,
}

impl<T> PartialEq for TimerEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.id == other.id
    }
}

impl<T> Eq for TimerEntry<T> {}

impl<T> PartialOrd for TimerEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for TimerEntry<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse ordering so BinaryHeap acts as a min-heap (earliest deadline at top)
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.id.cmp(&self.id))
    }
}

/// Thread-safe and fiber-safe priority timer queue.
/// Dispatches scheduled events strictly based on deadline expiration.
/// Guarantees static memory invariance (`T: Send + 'static`) preventing reference escapes.
pub struct TimerQueue<T> {
    heap: Mutex<BinaryHeap<TimerEntry<T>>>,
    next_id: AtomicU64,
    notif_mutex: Mutex<()>,
    cond: std::sync::Condvar,
    is_closed: AtomicBool,
}

impl<T: Send + 'static> Default for TimerQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + 'static> TimerQueue<T> {
    /// Construct a new empty timer queue.
    pub fn new() -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            next_id: AtomicU64::new(1),
            notif_mutex: Mutex::new(()),
            cond: std::sync::Condvar::new(),
            is_closed: AtomicBool::new(false),
        }
    }

    /// Schedule an item to be dispatched at `deadline`. Returns a unique timer ID.
    pub fn schedule(&self, item: T, deadline: Instant) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut heap = self.heap.lock().unwrap();
            heap.push(TimerEntry {
                id,
                deadline,
                payload: item,
            });
        }
        self.cond.notify_one();
        id
    }

    /// Schedule an item to be dispatched after `delay`. Returns a unique timer ID.
    pub fn schedule_after(&self, item: T, delay: Duration) -> u64 {
        self.schedule(item, Instant::now() + delay)
    }

    /// Poll for an expired timer entry up to `now`. Returns `Some(payload)` if ready.
    pub fn poll(&self, now: Instant) -> Option<T> {
        let mut heap = self.heap.lock().unwrap();
        if let Some(top) = heap.peek() {
            if top.deadline <= now {
                return heap.pop().map(|e| e.payload);
            }
        }
        None
    }

    /// Peek at the deadline of the earliest scheduled item without removing it.
    pub fn peek_deadline(&self) -> Option<Instant> {
        let heap = self.heap.lock().unwrap();
        heap.peek().map(|e| e.deadline)
    }

    /// Cancel a scheduled timer by its unique ID. Returns true if found and removed.
    pub fn cancel(&self, timer_id: u64) -> bool {
        let mut heap = self.heap.lock().unwrap();
        let initial_len = heap.len();
        let entries: Vec<TimerEntry<T>> = heap.drain().filter(|e| e.id != timer_id).collect();
        let removed = entries.len() < initial_len;
        for entry in entries {
            heap.push(entry);
        }
        removed
    }

    /// Wait for the next timer to expire or for the queue to close.
    /// Cooperatively yields current fiber/thread when waiting.
    pub fn wait_next(&self) -> Result<T, RecvError> {
        let mut backoff = AdaptiveBackoff::new();
        loop {
            let now = Instant::now();
            if let Some(item) = self.poll(now) {
                return Ok(item);
            }
            if self.is_closed.load(Ordering::Acquire) {
                let now = Instant::now();
                if let Some(item) = self.poll(now) {
                    return Ok(item);
                }
                return Err(RecvError::Closed);
            }

            let peek = self.peek_deadline();
            match peek {
                Some(deadline) if deadline <= now => {
                    continue;
                }
                Some(deadline) => {
                    let wait_dur = deadline
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(50));
                    if !backoff.is_completed_spinning() && wait_dur < Duration::from_micros(10) {
                        backoff.snooze();
                    } else if !backoff.is_completed_yielding()
                        && wait_dur < Duration::from_micros(100)
                    {
                        backoff.snooze_cooperative();
                    } else {
                        let guard = self.notif_mutex.lock().unwrap();
                        let _ = self.cond.wait_timeout(guard, wait_dur);
                        backoff.reset();
                    }
                }
                None => {
                    let guard = self.notif_mutex.lock().unwrap();
                    if self.is_empty() && !self.is_closed.load(Ordering::Acquire) {
                        let _ = self.cond.wait_timeout(guard, Duration::from_millis(50));
                    }
                    backoff.reset();
                }
            }
        }
    }

    /// Close the timer queue.
    pub fn close(&self) {
        self.is_closed.store(true, Ordering::Release);
        self.cond.notify_all();
    }

    /// Check if the timer queue is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    /// Return the number of scheduled timers.
    pub fn len(&self) -> usize {
        let heap = self.heap.lock().unwrap();
        heap.len()
    }

    /// Return true if the timer queue has no scheduled items.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all pending timers.
    pub fn clear(&self) {
        let mut heap = self.heap.lock().unwrap();
        heap.clear();
    }
}

/// Create a new priority channel with `levels` priority tiers.
pub fn priority_channel<T: Send + 'static>(levels: usize) -> PriorityChannel<T> {
    PriorityChannel::new(levels)
}

/// Create a new timer queue for scheduled events.
pub fn timer_queue<T: Send + 'static>() -> TimerQueue<T> {
    TimerQueue::new()
}

pub use ifa_runtime::fiber::AtomicRingBuffer as RingBuffer;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ── channel (unbounded) ───────────────────────────────────────────────────

    #[test]
    fn channel_send_recv_roundtrip() {
        let (tx, rx) = channel::<u32>();
        tx.send(42).unwrap();
        assert_eq!(rx.recv().unwrap(), 42);
    }

    #[test]
    fn channel_send_multiple_values_fifo() {
        let (tx, rx) = channel::<i32>();
        for i in 0..5 {
            tx.send(i).unwrap();
        }
        for i in 0..5 {
            assert_eq!(rx.recv().unwrap(), i);
        }
    }

    #[test]
    fn channel_try_recv_empty_returns_none() {
        let (_tx, rx) = channel::<u8>();
        assert!(rx.try_recv().is_err()); // TryRecvError::Empty
    }

    #[test]
    fn channel_closed_sender_recv_returns_error() {
        let (tx, rx) = channel::<u8>();
        drop(tx);
        assert!(rx.recv().is_err());
    }

    #[test]
    fn channel_sender_clone_still_works() {
        let (tx, rx) = channel::<u8>();
        let tx2 = tx.clone();
        tx2.send(7).unwrap();
        assert_eq!(rx.recv().unwrap(), 7);
    }

    #[test]
    fn channel_is_closed_after_explicit_close() {
        let (tx, _rx) = channel::<u8>();
        assert!(!tx.is_closed());
        tx.close();
        assert!(tx.is_closed());
    }

    // ── bounded channel ───────────────────────────────────────────────────────

    #[test]
    fn bounded_channel_try_send_full_returns_error() {
        let (tx, _rx) = bounded::<u8>(1);
        tx.send(1).unwrap();
        // channel is full — try_send must fail
        assert!(tx.try_send(2).is_err());
    }

    #[test]
    fn bounded_channel_len_tracks_pending_messages() {
        let (tx, rx) = bounded::<i32>(4);
        assert_eq!(rx.len(), 0);
        tx.send(10).unwrap();
        tx.send(20).unwrap();
        assert_eq!(rx.len(), 2);
        rx.recv().unwrap();
        assert_eq!(rx.len(), 1);
    }

    #[test]
    fn bounded_channel_is_empty_initial() {
        let (_tx, rx) = bounded::<u8>(8);
        assert!(rx.is_empty());
    }

    // ── cross-thread channel ──────────────────────────────────────────────────

    #[test]
    fn channel_cross_thread_send_recv() {
        let (tx, rx) = channel::<u32>();
        let handle = thread::spawn(move || {
            tx.send(99).unwrap();
        });
        handle.join().unwrap();
        assert_eq!(rx.recv().unwrap(), 99);
    }

    // ── Receiver::iter ────────────────────────────────────────────────────────

    #[test]
    fn receiver_iter_drains_all_messages() {
        let (tx, rx) = channel::<i32>();
        for v in [1, 2, 3] {
            tx.send(v).unwrap();
        }
        drop(tx); // close sender so iterator terminates
        let collected: Vec<i32> = rx.iter().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    // ── WaitGroup ────────────────────────────────────────────────────────────

    #[test]
    fn waitgroup_add_done_wait() {
        let wg = WaitGroup::new();
        wg.add(3);
        for _ in 0..3 {
            wg.done();
        }
        // Should return immediately (counter already 0)
        wg.wait();
    }

    #[test]
    fn waitgroup_cross_thread() {
        let wg = Arc::new(WaitGroup::new());
        wg.add(2);
        let wg2 = Arc::clone(&wg);
        let wg3 = Arc::clone(&wg);
        thread::spawn(move || wg2.done()).join().unwrap();
        thread::spawn(move || wg3.done()).join().unwrap();
        wg.wait();
    }

    #[test]
    fn waitgroup_wait_timeout_expires() {
        let wg = WaitGroup::new();
        wg.add(1); // never done — timeout must fire
        let done = wg.wait_timeout(Duration::from_millis(20));
        assert!(!done);
    }

    // ── AtomicInt ─────────────────────────────────────────────────────────────

    #[test]
    fn atomic_int_load_store() {
        let a = AtomicInt::new(0);
        assert_eq!(a.load(), 0);
        a.store(42);
        assert_eq!(a.load(), 42);
    }

    #[test]
    fn atomic_int_fetch_add_sub() {
        let a = AtomicInt::new(10);
        assert_eq!(a.fetch_add(5), 10);
        assert_eq!(a.load(), 15);
        assert_eq!(a.fetch_sub(3), 15);
        assert_eq!(a.load(), 12);
    }

    #[test]
    fn atomic_int_compare_exchange_success() {
        let a = AtomicInt::new(1);
        let result = a.compare_exchange(1, 99);
        assert_eq!(result, Ok(1));
        assert_eq!(a.load(), 99);
    }

    #[test]
    fn atomic_int_compare_exchange_failure() {
        let a = AtomicInt::new(5);
        let result = a.compare_exchange(0, 99); // wrong current value
        assert_eq!(result, Err(5));
        assert_eq!(a.load(), 5); // unchanged
    }

    // ── AtomicFlag ───────────────────────────────────────────────────────────

    #[test]
    fn atomic_flag_load_store() {
        let f = AtomicFlag::new(false);
        assert!(!f.load());
        f.store(true);
        assert!(f.load());
    }

    #[test]
    fn atomic_flag_swap() {
        let f = AtomicFlag::new(true);
        let old = f.swap(false);
        assert!(old);
        assert!(!f.load());
    }

    // ── Select ───────────────────────────────────────────────────────────────

    #[test]
    fn select_try_select_picks_ready_receiver() {
        let (tx1, rx1) = channel::<i32>();
        let (_tx2, rx2) = channel::<i32>();
        tx1.send(7).unwrap();
        let result = Select::try_select(&[&rx1, &rx2]);
        assert!(result.is_some());
        let (idx, val) = result.unwrap();
        assert_eq!(idx, 0);
        assert_eq!(val, 7);
    }

    #[test]
    fn select_try_select_empty_channels_returns_none() {
        let (_tx1, rx1) = channel::<i32>();
        let (_tx2, rx2) = channel::<i32>();
        assert!(Select::try_select(&[&rx1, &rx2]).is_none());
    }

    // ── AtomicUint ───────────────────────────────────────────────────────────

    #[test]
    fn atomic_uint_load_store() {
        let u = AtomicUint::new(100);
        assert_eq!(u.load(), 100);
        u.store(200);
        assert_eq!(u.load(), 200);
    }

    #[test]
    fn atomic_uint_fetch_add_sub() {
        let u = AtomicUint::new(50);
        assert_eq!(u.fetch_add(25), 50);
        assert_eq!(u.load(), 75);
        assert_eq!(u.fetch_sub(15), 75);
        assert_eq!(u.load(), 60);
    }

    #[test]
    fn atomic_uint_compare_exchange() {
        let u = AtomicUint::new(10);
        assert_eq!(u.compare_exchange(10, 42), Ok(10));
        assert_eq!(u.load(), 42);
        assert_eq!(u.compare_exchange(99, 100), Err(42));
        assert_eq!(u.load(), 42);
    }

    // ── Once ─────────────────────────────────────────────────────────────────

    #[test]
    fn once_call_once_executes_only_once() {
        let once = Once::new();
        let mut count = 0;
        assert!(!once.is_completed());
        once.call_once(|| {
            count += 1;
        });
        assert_eq!(count, 1);
        assert!(once.is_completed());

        once.call_once(|| {
            count += 1;
        });
        assert_eq!(count, 1);
    }

    #[test]
    fn once_cross_thread_execution() {
        let once = Arc::new(Once::new());
        let count = Arc::new(AtomicInt::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let o = Arc::clone(&once);
            let c = Arc::clone(&count);
            handles.push(thread::spawn(move || {
                o.call_once(|| {
                    c.fetch_add(1);
                });
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(count.load(), 1);
        assert!(once.is_completed());
    }

    // ── Semaphore ────────────────────────────────────────────────────────────

    #[test]
    fn semaphore_try_acquire_and_release() {
        let sem = Semaphore::new(2);
        assert_eq!(sem.available_permits(), 2);

        assert!(sem.try_acquire());
        assert_eq!(sem.available_permits(), 1);

        assert!(sem.try_acquire());
        assert_eq!(sem.available_permits(), 0);

        // No permits left
        assert!(!sem.try_acquire());

        sem.release();
        assert_eq!(sem.available_permits(), 1);
        assert!(sem.try_acquire());
    }

    #[test]
    fn semaphore_cross_thread_acquire_release() {
        let sem = Arc::new(Semaphore::new(0));
        let sem_clone = Arc::clone(&sem);

        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            sem_clone.release();
        });

        sem.acquire();
        assert_eq!(sem.available_permits(), 0);
        handle.join().unwrap();
    }

    // ── PriorityChannel ──────────────────────────────────────────────────────

    #[test]
    fn priority_channel_order_preservation() {
        let chan = PriorityChannel::<i64>::new(4);
        assert_eq!(chan.levels(), 4);
        assert!(chan.is_empty());

        // Send messages at priority 1 and priority 3
        chan.send(10, 1).unwrap();
        chan.send(20, 1).unwrap();
        chan.send(99, 3).unwrap();
        chan.send(100, 3).unwrap();

        assert_eq!(chan.len(), 4);
        assert_eq!(chan.peek_highest_priority(), Some(3));

        // Highest priority messages (prio 3) must come out first in FIFO order
        assert_eq!(chan.recv().unwrap(), 99);
        assert_eq!(chan.recv().unwrap(), 100);
        // Then priority 1
        assert_eq!(chan.recv().unwrap(), 10);
        assert_eq!(chan.recv().unwrap(), 20);

        assert!(chan.is_empty());
        assert_eq!(chan.peek_highest_priority(), None);
    }

    #[test]
    fn priority_channel_try_recv_and_close() {
        let chan = PriorityChannel::<String>::new(2);
        assert!(chan.try_recv().is_err());

        chan.try_send("low".to_string(), 0).unwrap();
        chan.try_send("high".to_string(), 1).unwrap();

        assert_eq!(chan.try_recv().unwrap(), "high");
        chan.close();
        assert!(chan.is_closed());

        // Low message is still drained after close
        assert_eq!(chan.try_recv().unwrap(), "low");
        // Subsequent calls return Closed
        assert_eq!(chan.try_recv().unwrap_err(), TryRecvError::Closed);
    }

    // ── TimerQueue ───────────────────────────────────────────────────────────

    #[test]
    fn timer_queue_schedule_and_poll() {
        let tq = TimerQueue::<i64>::new();
        assert!(tq.is_empty());

        let now = Instant::now();
        // Schedule in reverse deadline order
        let _id2 = tq.schedule(200, now + Duration::from_millis(50));
        let _id1 = tq.schedule(100, now + Duration::from_millis(10));
        let _id3 = tq.schedule(300, now + Duration::from_millis(100));

        assert_eq!(tq.len(), 3);
        // Immediately, nothing has expired yet
        assert_eq!(tq.poll(now), None);

        // At now + 15ms, id1 (100) expires
        assert_eq!(tq.poll(now + Duration::from_millis(15)), Some(100));
        assert_eq!(tq.len(), 2);

        // At now + 60ms, id2 (200) expires
        assert_eq!(tq.poll(now + Duration::from_millis(60)), Some(200));

        // At now + 120ms, id3 (300) expires
        assert_eq!(tq.poll(now + Duration::from_millis(120)), Some(300));
        assert!(tq.is_empty());
    }

    #[test]
    fn timer_queue_cancel() {
        let tq = TimerQueue::<String>::new();
        let now = Instant::now();
        let id1 = tq.schedule("first".to_string(), now + Duration::from_millis(50));
        let _id2 = tq.schedule("second".to_string(), now + Duration::from_millis(100));

        assert_eq!(tq.len(), 2);
        assert!(tq.cancel(id1));
        assert!(!tq.cancel(id1)); // already cancelled
        assert_eq!(tq.len(), 1);

        // Only second remains
        assert_eq!(
            tq.poll(now + Duration::from_millis(150)),
            Some("second".to_string())
        );
        assert!(tq.is_empty());
    }
}
