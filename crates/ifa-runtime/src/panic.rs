//! IFA Runtime bare-metal panic and exception capture driver.
//!
//! Provides zero-allocation bare-metal diagnostic reporting, frame pointer stack trace walking,
//! and pluggable panic interception for deterministic Use-After-Free (UAF), double-free,
//! epoch wrap-around, and generational invariant violations.

use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::RwLock;

/// Maximum number of stack frames captured in bare-metal zero-heap mode.
pub const MAX_BARE_METAL_FRAMES: usize = 32;

/// Maximum length of bare-metal panic diagnostic message.
pub const MAX_PANIC_MSG_LEN: usize = 256;

/// Classification of deterministic runtime panics and invariant failures.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfaPanicKind {
    None = 0,
    UseAfterFree = 1,
    DoubleFree = 2,
    NullDereference = 3,
    EpochMismatch = 4,
    OutOfBounds = 5,
    AssertionFailed = 6,
    Generic = 7,
}

impl IfaPanicKind {
    /// Human-readable description of the panic kind.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::UseAfterFree => "Use-After-Free (Generational Invariant Mismatch)",
            Self::DoubleFree => "Double-Free (Slot Already Inactive)",
            Self::NullDereference => "Null Reference Dereference",
            Self::EpochMismatch => "Epoch Wrap-Around Mismatch (ABA Mitigation)",
            Self::OutOfBounds => "Out of Bounds Access",
            Self::AssertionFailed => "Assertion Failed",
            Self::Generic => "Generic / Unspecified Panic",
        }
    }
}

/// Zero-heap fixed-size bare-metal stack trace captured via frame pointer walking.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaBareMetalStackTrace {
    /// Instruction pointers (return addresses) of captured call stack frames.
    pub frames: [usize; MAX_BARE_METAL_FRAMES],
    /// Number of valid frames captured in `frames`.
    pub count: usize,
}

impl Default for IfaBareMetalStackTrace {
    fn default() -> Self {
        Self::empty()
    }
}

impl IfaBareMetalStackTrace {
    /// Create an empty stack trace record.
    pub const fn empty() -> Self {
        Self {
            frames: [0; MAX_BARE_METAL_FRAMES],
            count: 0,
        }
    }

    /// Walk call stack frame pointers in bare-metal zero-heap mode.
    #[inline(never)]
    pub fn capture() -> Self {
        let mut trace = Self::empty();

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        unsafe {
            let mut sp: usize = 0;
            let mut fp: usize = 0;

            #[cfg(target_arch = "x86_64")]
            {
                core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
                core::arch::asm!("mov {}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags));
            }

            #[cfg(target_arch = "aarch64")]
            {
                core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
                core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags));
            }

            // In stack architectures with down-growing stacks, fp >= sp.
            // Typical threads have maximum stack bounds of 8 MB.
            const MAX_STACK_SIZE: usize = 8 * 1024 * 1024;
            if sp != 0 && fp >= sp && (fp - sp) <= MAX_STACK_SIZE {
                let stack_top = sp.saturating_add(MAX_STACK_SIZE);
                let align = core::mem::align_of::<usize>();
                let mut cur_fp = fp;
                let mut visited = 0;

                while cur_fp >= sp && cur_fp < stack_top && visited < MAX_BARE_METAL_FRAMES {
                    if !cur_fp.is_multiple_of(align) {
                        break;
                    }
                    let fp_ptr = cur_fp as *const usize;
                    let next_fp = *fp_ptr;
                    let ret_ip = *fp_ptr.add(1);

                    if ret_ip > 0x1000 && ret_ip != usize::MAX {
                        trace.frames[trace.count] = ret_ip;
                        trace.count += 1;
                    }

                    // Strict monotonic progression for frames on down-growing stack
                    if next_fp <= cur_fp || next_fp > stack_top {
                        break;
                    }

                    cur_fp = next_fp;
                    visited += 1;
                }
            }
        }

        trace
    }

    /// Format stack trace into provided byte buffer without dynamic allocations.
    pub fn format_bare_metal(&self, buf: &mut [u8]) -> usize {
        let mut writer = BufferWriter::new(buf);
        writer.write_str("BARE-METAL STACK TRACE (");
        writer.write_u64(self.count as u64);
        writer.write_str(" frame(s)):\n");

        if self.count == 0 {
            writer.write_str("  <no frame pointer trace available>\n");
            return writer.offset;
        }

        for i in 0..self.count {
            writer.write_str("  #");
            if i < 10 {
                writer.write_str("0");
            }
            writer.write_u64(i as u64);
            writer.write_str(": ");
            writer.write_hex_usize(self.frames[i]);
            writer.write_str("\n");
        }
        writer.offset
    }
}

/// Comprehensive panic diagnostic record containing exact fault metadata,
/// generational counters, arena identity, and bare-metal stack trace.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfaPanicRecord {
    /// Failure category.
    pub kind: IfaPanicKind,
    /// Memory address that caused the invariant violation.
    pub fault_address: usize,
    /// Expected generation counter from reference.
    pub expected_gen: u32,
    /// Actual generation counter found in slot header.
    pub actual_gen: u32,
    /// Expected epoch counter or bit flag.
    pub expected_epoch: u16,
    /// Actual epoch counter or bit flag found in header.
    pub actual_epoch: u16,
    /// Arena identifier if scoped arena.
    pub arena_id: u16,
    /// Reserved for 64-bit alignment padding.
    pub _reserved: u16,
    /// Length of active diagnostic message in `message`.
    pub message_len: usize,
    /// Null-terminated diagnostic message buffer.
    pub message: [u8; MAX_PANIC_MSG_LEN],
    /// Bare-metal stack trace frames captured at panic site.
    pub stack_trace: IfaBareMetalStackTrace,
}

impl Default for IfaPanicRecord {
    fn default() -> Self {
        Self::empty()
    }
}

impl IfaPanicRecord {
    /// Create an empty panic record.
    pub const fn empty() -> Self {
        Self {
            kind: IfaPanicKind::None,
            fault_address: 0,
            expected_gen: 0,
            actual_gen: 0,
            expected_epoch: 0,
            actual_epoch: 0,
            arena_id: 0,
            _reserved: 0,
            message_len: 0,
            message: [0; MAX_PANIC_MSG_LEN],
            stack_trace: IfaBareMetalStackTrace::empty(),
        }
    }

    /// Set diagnostic message string safely within fixed buffer.
    pub fn set_message(&mut self, msg: &str) {
        let bytes = msg.as_bytes();
        let len = bytes.len().min(MAX_PANIC_MSG_LEN);
        self.message[..len].copy_from_slice(&bytes[..len]);
        self.message_len = len;
    }

    /// Read diagnostic message as string slice.
    pub fn message_str(&self) -> &str {
        if self.message_len == 0 {
            return "";
        }
        core::str::from_utf8(&self.message[..self.message_len]).unwrap_or("<invalid utf-8 message>")
    }

    /// Create Use-After-Free panic record with diagnostic details and bare-metal trace.
    pub fn new_uaf(
        fault_address: usize,
        expected_gen: u32,
        actual_gen: u32,
        arena_id: u16,
    ) -> Self {
        let mut rec = Self::empty();
        rec.kind = IfaPanicKind::UseAfterFree;
        rec.fault_address = fault_address;
        rec.expected_gen = expected_gen;
        rec.actual_gen = actual_gen;
        rec.arena_id = arena_id;
        rec.set_message("Use-After-Free detected: generational reference counter mismatch");
        rec.stack_trace = IfaBareMetalStackTrace::capture();
        rec
    }

    /// Create Double-Free panic record.
    pub fn new_double_free(fault_address: usize, arena_id: u16) -> Self {
        let mut rec = Self::empty();
        rec.kind = IfaPanicKind::DoubleFree;
        rec.fault_address = fault_address;
        rec.arena_id = arena_id;
        rec.set_message("Double-free detected: slot already freed or inactive");
        rec.stack_trace = IfaBareMetalStackTrace::capture();
        rec
    }

    /// Create Null Reference Dereference panic record.
    pub fn new_null_deref() -> Self {
        let mut rec = Self::empty();
        rec.kind = IfaPanicKind::NullDereference;
        rec.fault_address = 0;
        rec.set_message("Attempted to dereference null generational reference");
        rec.stack_trace = IfaBareMetalStackTrace::capture();
        rec
    }

    /// Create Epoch Mismatch panic record.
    pub fn new_epoch_mismatch(
        fault_address: usize,
        expected_epoch: u16,
        actual_epoch: u16,
        arena_id: u16,
    ) -> Self {
        let mut rec = Self::empty();
        rec.kind = IfaPanicKind::EpochMismatch;
        rec.fault_address = fault_address;
        rec.expected_epoch = expected_epoch;
        rec.actual_epoch = actual_epoch;
        rec.arena_id = arena_id;
        rec.set_message("Epoch mismatch detected: potential ABA wrap-around safely intercepted");
        rec.stack_trace = IfaBareMetalStackTrace::capture();
        rec
    }

    /// Create Out of Bounds panic record.
    pub fn new_out_of_bounds(index: usize, len: usize) -> Self {
        let mut rec = Self::empty();
        rec.kind = IfaPanicKind::OutOfBounds;
        rec.fault_address = index;
        rec.actual_gen = len as u32;
        rec.set_message("Out of bounds slice or array access");
        rec.stack_trace = IfaBareMetalStackTrace::capture();
        rec
    }

    /// Create Assertion Failure panic record.
    pub fn new_assertion(msg: &str) -> Self {
        let mut rec = Self::empty();
        rec.kind = IfaPanicKind::AssertionFailed;
        rec.set_message(msg);
        rec.stack_trace = IfaBareMetalStackTrace::capture();
        rec
    }

    /// Format full bare-metal diagnostic output into a preallocated byte buffer without dynamic heap allocations.
    pub fn format_bare_metal(&self, buf: &mut [u8]) -> usize {
        let mut writer = BufferWriter::new(buf);
        writer.write_str(
            "\n================================================================================\n",
        );
        writer.write_str("[IFA RUNTIME BARE-METAL DIAGNOSTIC: ");
        match self.kind {
            IfaPanicKind::UseAfterFree => writer.write_str("USE-AFTER-FREE INTERCEPTED"),
            IfaPanicKind::DoubleFree => writer.write_str("DOUBLE-FREE INTERCEPTED"),
            IfaPanicKind::NullDereference => writer.write_str("NULL DEREFERENCE INTERCEPTED"),
            IfaPanicKind::EpochMismatch => writer.write_str("EPOCH ABA MISMATCH INTERCEPTED"),
            IfaPanicKind::OutOfBounds => writer.write_str("OUT-OF-BOUNDS INTERCEPTED"),
            IfaPanicKind::AssertionFailed => writer.write_str("ASSERTION FAILURE"),
            _ => writer.write_str("RUNTIME PANIC"),
        }
        writer.write_str("]\n");

        writer.write_str("  Kind                : ");
        writer.write_str(self.kind.as_str());
        writer.write_str("\n");

        if self.fault_address != 0 || self.kind == IfaPanicKind::NullDereference {
            writer.write_str("  Fault Address       : ");
            writer.write_hex_usize(self.fault_address);
            writer.write_str("\n");
        }

        if self.arena_id != 0 {
            writer.write_str("  Arena Identifier    : 0x");
            writer.write_hex_u16(self.arena_id);
            writer.write_str("\n");
        }

        if self.kind == IfaPanicKind::UseAfterFree {
            writer.write_str("  Expected Generation : ");
            writer.write_u64(self.expected_gen as u64);
            writer.write_str("\n  Actual Generation   : ");
            writer.write_u64(self.actual_gen as u64);
            let delta = (self.actual_gen as i64) - (self.expected_gen as i64);
            writer.write_str(" (Delta: ");
            if delta > 0 {
                writer.write_str("+");
            }
            writer.write_i64(delta);
            writer.write_str(")\n");
        } else if self.kind == IfaPanicKind::EpochMismatch {
            writer.write_str("  Expected Epoch      : 0x");
            writer.write_hex_u16(self.expected_epoch);
            writer.write_str("\n  Actual Epoch        : 0x");
            writer.write_hex_u16(self.actual_epoch);
            writer.write_str("\n");
        } else if self.kind == IfaPanicKind::OutOfBounds {
            writer.write_str("  Index Attempted     : ");
            writer.write_u64(self.fault_address as u64);
            writer.write_str("\n  Length Bound        : ");
            writer.write_u64(self.actual_gen as u64);
            writer.write_str("\n");
        }

        if self.message_len > 0 {
            writer.write_str("  Diagnostic Message  : ");
            writer.write_str(self.message_str());
            writer.write_str("\n");
        }

        writer.write_str(
            "--------------------------------------------------------------------------------\n",
        );
        let remaining_start = writer.offset;
        let written = self
            .stack_trace
            .format_bare_metal(&mut writer.buf[remaining_start..]);
        writer.offset += written;
        writer.write_str(
            "================================================================================\n\n",
        );
        writer.offset
    }

    /// Print bare-metal diagnostic output directly to standard error using zero-allocation primitives.
    pub fn print_bare_metal(&self) {
        let mut buf = [0u8; 2048];
        let len = self.format_bare_metal(&mut buf);
        zero_alloc_stderr_write(&buf[..len]);
    }
}

/// Zero-allocation buffer formatter helper.
struct BufferWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> BufferWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn write_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.offset);
        let to_copy = bytes.len().min(avail);
        if to_copy > 0 {
            self.buf[self.offset..self.offset + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.offset += to_copy;
        }
    }

    fn write_hex_usize(&mut self, val: usize) {
        self.write_str("0x");
        let hex_chars = b"0123456789abcdef";
        let width = core::mem::size_of::<usize>() * 2;
        let mut tmp = [b'0'; 16];
        for (i, item) in tmp.iter_mut().enumerate().take(width) {
            let shift = (width - 1 - i) * 4;
            let nibble = ((val >> shift) & 0x0f) as usize;
            *item = hex_chars[nibble];
        }
        let avail = self.buf.len().saturating_sub(self.offset);
        let to_copy = width.min(avail);
        if to_copy > 0 {
            self.buf[self.offset..self.offset + to_copy].copy_from_slice(&tmp[..to_copy]);
            self.offset += to_copy;
        }
    }

    fn write_hex_u16(&mut self, val: u16) {
        let hex_chars = b"0123456789abcdef";
        let tmp = [
            hex_chars[((val >> 12) & 0x0f) as usize],
            hex_chars[((val >> 8) & 0x0f) as usize],
            hex_chars[((val >> 4) & 0x0f) as usize],
            hex_chars[(val & 0x0f) as usize],
        ];
        let avail = self.buf.len().saturating_sub(self.offset);
        let to_copy = 4.min(avail);
        if to_copy > 0 {
            self.buf[self.offset..self.offset + to_copy].copy_from_slice(&tmp[..to_copy]);
            self.offset += to_copy;
        }
    }

    fn write_u64(&mut self, mut val: u64) {
        if val == 0 {
            self.write_str("0");
            return;
        }
        let mut tmp = [0u8; 20];
        let mut len = 0;
        while val > 0 {
            tmp[len] = b'0' + (val % 10) as u8;
            val /= 10;
            len += 1;
        }
        tmp[..len].reverse();
        let avail = self.buf.len().saturating_sub(self.offset);
        let to_copy = len.min(avail);
        if to_copy > 0 {
            self.buf[self.offset..self.offset + to_copy].copy_from_slice(&tmp[..to_copy]);
            self.offset += to_copy;
        }
    }

    fn write_i64(&mut self, val: i64) {
        if val < 0 {
            self.write_str("-");
            self.write_u64(val.unsigned_abs());
        } else {
            self.write_u64(val as u64);
        }
    }
}

/// Output bytes to stderr without memory allocations.
#[inline(always)]
fn zero_alloc_stderr_write(bytes: &[u8]) {
    #[cfg(unix)]
    unsafe {
        libc::write(2, bytes.as_ptr() as *const libc::c_void, bytes.len());
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let _ = std::io::stderr().write_all(bytes);
    }
}

/// Pluggable panic callback type for custom interception and external diagnostics.
pub type PanicHandlerFn = extern "C" fn(*const IfaPanicRecord);

static GLOBAL_PANIC_HANDLER: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

static GLOBAL_LAST_PANIC: RwLock<Option<IfaPanicRecord>> = RwLock::new(None);

thread_local! {
    static CATCHING_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static THREAD_LAST_PANIC: std::cell::RefCell<Option<IfaPanicRecord>> = const { std::cell::RefCell::new(None) };
    static PERSISTED_RECORD: std::cell::UnsafeCell<IfaPanicRecord> = const { std::cell::UnsafeCell::new(IfaPanicRecord::empty()) };
}

/// Register a global panic interception callback hook.
pub fn set_panic_handler(handler: Option<PanicHandlerFn>) {
    let ptr = match handler {
        Some(h) => h as *const () as *mut (),
        None => std::ptr::null_mut(),
    };
    GLOBAL_PANIC_HANDLER.store(ptr, Ordering::Release);
}

/// Reset global panic interception callback to none.
pub fn reset_panic_handler() {
    set_panic_handler(None);
}

/// Retrieve the last intercepted panic record (thread-local or global).
pub fn get_last_panic() -> Option<IfaPanicRecord> {
    if let Some(rec) = THREAD_LAST_PANIC.with(|tl| *tl.borrow()) {
        return Some(rec);
    }
    if let Ok(guard) = GLOBAL_LAST_PANIC.read() {
        return *guard;
    }
    None
}

/// Retrieve a raw C-ABI pointer to the last intercepted panic record.
/// The returned pointer remains valid until `clear_last_panic` is called.
pub fn get_last_panic_raw_ptr() -> *const IfaPanicRecord {
    if let Some(rec) = get_last_panic() {
        THREAD_LAST_PANIC.with(|_| {
            let ptr = PERSISTED_RECORD.with(|p| p.get());
            unsafe {
                *ptr = rec;
                ptr as *const IfaPanicRecord
            }
        })
    } else {
        std::ptr::null()
    }
}

/// Clear the recorded panic state.
pub fn clear_last_panic() {
    THREAD_LAST_PANIC.with(|tl| *tl.borrow_mut() = None);
    if let Ok(mut guard) = GLOBAL_LAST_PANIC.write() {
        *guard = None;
    }
}

/// Set the thread-local last panic record.
pub fn set_thread_last_panic(record: IfaPanicRecord) {
    THREAD_LAST_PANIC.with(|tl| *tl.borrow_mut() = Some(record));
}

/// Dispatch a deterministic runtime panic with bare-metal diagnostics.
pub fn dispatch_panic(record: IfaPanicRecord) -> ! {
    // 1. Invoke custom panic hook if registered
    let handler_ptr = GLOBAL_PANIC_HANDLER.load(Ordering::Acquire);
    if !handler_ptr.is_null() {
        let handler: PanicHandlerFn = unsafe { std::mem::transmute(handler_ptr) };
        handler(&record);
    }

    // 2. Persist into global record
    if let Ok(mut guard) = GLOBAL_LAST_PANIC.write() {
        *guard = Some(record);
    }

    // 3. Thread-local panic capture if catching mode active
    let catching = CATCHING_ACTIVE.with(|c| c.get());
    if catching {
        THREAD_LAST_PANIC.with(|tl| *tl.borrow_mut() = Some(record));
        std::panic::panic_any(record.kind);
    }

    // 4. In bare-metal or uncaught mode: print zero-allocation diagnostic and abort safely
    record.print_bare_metal();
    std::process::abort();
}

/// Catch any deterministic IFA runtime panic triggered within the provided closure.
#[allow(clippy::result_large_err)]
pub fn catch_panic<F, R>(f: F) -> Result<R, IfaPanicRecord>
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    let prev = CATCHING_ACTIVE.with(|c| c.replace(true));
    THREAD_LAST_PANIC.with(|tl| *tl.borrow_mut() = None);

    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let res = std::panic::catch_unwind(f);

    std::panic::set_hook(prev_hook);
    CATCHING_ACTIVE.with(|c| c.set(prev));

    match res {
        Ok(val) => Ok(val),
        Err(_) => {
            let captured = THREAD_LAST_PANIC.with(|tl| *tl.borrow());
            if let Some(rec) = captured {
                Err(rec)
            } else {
                let mut fallback = IfaPanicRecord::empty();
                fallback.kind = IfaPanicKind::Generic;
                fallback.set_message("Unidentified panic caught by runtime panic driver");
                fallback.stack_trace = IfaBareMetalStackTrace::capture();
                Err(fallback)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bare_metal_stack_trace_capture() {
        let trace = IfaBareMetalStackTrace::capture();
        let mut buf = [0u8; 1024];
        let len = trace.format_bare_metal(&mut buf);
        assert!(len > 0);
        let s = core::str::from_utf8(&buf[..len]).unwrap();
        assert!(s.contains("BARE-METAL STACK TRACE"));
    }

    #[test]
    fn test_zero_alloc_diagnostic_formatting() {
        let rec = IfaPanicRecord::new_uaf(0x00007ffeeb42a180, 42, 43, 0x0002);
        let mut buf = [0u8; 2048];
        let len = rec.format_bare_metal(&mut buf);
        assert!(len > 0);
        let output = core::str::from_utf8(&buf[..len]).unwrap();
        assert!(output.contains("USE-AFTER-FREE INTERCEPTED"));
        assert!(output.contains("Expected Generation : 42"));
        assert!(output.contains("Actual Generation   : 43"));
        assert!(output.contains("Delta: +1"));
        assert!(output.contains("Arena Identifier    : 0x0002"));
    }

    #[test]
    fn test_catch_panic_uaf_interception() {
        let res = catch_panic(|| {
            let rec = IfaPanicRecord::new_uaf(0x1000, 10, 11, 1);
            dispatch_panic(rec);
        });

        assert!(res.is_err());
        let panic_rec = res.unwrap_err();
        assert_eq!(panic_rec.kind, IfaPanicKind::UseAfterFree);
        assert_eq!(panic_rec.fault_address, 0x1000);
        assert_eq!(panic_rec.expected_gen, 10);
        assert_eq!(panic_rec.actual_gen, 11);
        assert_eq!(panic_rec.arena_id, 1);
    }

    #[test]
    fn test_catch_panic_double_free_interception() {
        let res = catch_panic(|| {
            let rec = IfaPanicRecord::new_double_free(0x2000, 2);
            dispatch_panic(rec);
        });

        assert!(res.is_err());
        let panic_rec = res.unwrap_err();
        assert_eq!(panic_rec.kind, IfaPanicKind::DoubleFree);
        assert_eq!(panic_rec.fault_address, 0x2000);
        assert_eq!(panic_rec.arena_id, 2);
    }

    #[test]
    fn test_catch_panic_epoch_mismatch_interception() {
        let res = catch_panic(|| {
            let rec = IfaPanicRecord::new_epoch_mismatch(0x3000, 0x0000, 0x0020, 3);
            dispatch_panic(rec);
        });

        assert!(res.is_err());
        let panic_rec = res.unwrap_err();
        assert_eq!(panic_rec.kind, IfaPanicKind::EpochMismatch);
        assert_eq!(panic_rec.expected_epoch, 0x0000);
        assert_eq!(panic_rec.actual_epoch, 0x0020);
    }

    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;

    static HOOK_CALLED: AtomicBool = AtomicBool::new(false);
    static HOOK_KIND: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn custom_hook(record: *const IfaPanicRecord) {
        unsafe {
            HOOK_CALLED.store(true, Ordering::SeqCst);
            HOOK_KIND.store((*record).kind as usize, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_custom_panic_handler_hook() {
        set_panic_handler(Some(custom_hook));
        HOOK_CALLED.store(false, Ordering::SeqCst);
        HOOK_KIND.store(0, Ordering::SeqCst);

        let _ = catch_panic(|| {
            let rec = IfaPanicRecord::new_null_deref();
            dispatch_panic(rec);
        });

        assert!(HOOK_CALLED.load(Ordering::SeqCst));
        assert_eq!(
            HOOK_KIND.load(Ordering::SeqCst),
            IfaPanicKind::NullDereference as usize
        );
        reset_panic_handler();
    }
}
