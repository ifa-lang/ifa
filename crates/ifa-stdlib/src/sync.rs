//! Colorless concurrency primitives, typed channels, atomic ring buffers, and inter-fiber synchronization for IFA.

use ifa_runtime::fiber::{
    Channel as RtChannel, RecvError, SendError, TryRecvError, TrySendError, GLOBAL_SCHEDULER,
};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub use ifa_runtime::fiber::{FiberId, FiberScheduler, FiberState};

/// Error returned when timed receive expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvTimeoutError {
    Timeout,
    Closed,
}

/// Sending endpoint of a typed IFA channel.
#[derive(Clone)]
pub struct Sender<T> {
    inner: Arc<RtChannel<T>>,
}

/// Receiving endpoint of a typed IFA channel.
#[derive(Clone)]
pub struct Receiver<T> {
    inner: Arc<RtChannel<T>>,
}

/// Create an unbounded asynchronous channel between fibers.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(RtChannel::new());
    (
        Sender {
            inner: Arc::clone(&inner),
        },
        Receiver { inner },
    )
}

/// Create a bounded channel with lock-free atomic ring buffer backpressure.
pub fn bounded<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(RtChannel::with_capacity(capacity));
    (
        Sender {
            inner: Arc::clone(&inner),
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

pub use ifa_runtime::fiber::AtomicRingBuffer as RingBuffer;
