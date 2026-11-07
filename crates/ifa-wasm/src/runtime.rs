use std::collections::HashMap;

/// WebAssembly standard page size (64 KiB = 65,536 bytes).
pub const WASM_PAGE_SIZE: usize = 65536;

/// Deterministic, zero-GC linear memory manager for IFA WebAssembly modules.
#[derive(Debug, Clone)]
pub struct WasmLinearMemory {
    bytes: Vec<u8>,
    max_pages: usize,
    bump_offset: usize,
    free_blocks: HashMap<usize, Vec<usize>>, // size_class -> free offsets
}

impl WasmLinearMemory {
    pub fn new(initial_pages: usize, max_pages: usize) -> Self {
        let size = initial_pages * WASM_PAGE_SIZE;
        Self {
            bytes: vec![0u8; size],
            max_pages,
            bump_offset: 1024, // Reserve first 1024 bytes for null checks & runtime headers
            free_blocks: HashMap::new(),
        }
    }

    /// Current number of allocated 64 KiB pages.
    pub fn page_count(&self) -> usize {
        self.bytes.len() / WASM_PAGE_SIZE
    }

    /// Grow linear memory by `delta_pages`. Returns previous page count, or None if exceeding max.
    pub fn grow(&mut self, delta_pages: usize) -> Option<usize> {
        let current = self.page_count();
        let new_pages = current.checked_add(delta_pages)?;
        if new_pages > self.max_pages {
            return None;
        }
        self.bytes.resize(new_pages * WASM_PAGE_SIZE, 0);
        Some(current)
    }

    /// Allocate a chunk of memory of given size with 8-byte alignment.
    pub fn alloc(&mut self, size: usize) -> usize {
        let aligned_size = (size + 7) & !7;
        let size_class = aligned_size.max(16);

        // Check reusable free list
        if let Some(list) = self.free_blocks.get_mut(&size_class) {
            if let Some(offset) = list.pop() {
                return offset;
            }
        }

        // Allocate from bump pointer
        let alloc_offset = self.bump_offset;
        let next_offset = alloc_offset + size_class;

        if next_offset > self.bytes.len() {
            let required_pages = (next_offset - self.bytes.len()).div_ceil(WASM_PAGE_SIZE);
            if self.grow(required_pages).is_none() {
                panic!("WasmLinearMemory: out of linear memory pages");
            }
        }

        self.bump_offset = next_offset;
        alloc_offset
    }

    /// Deallocate a memory chunk back to its size-class free list.
    pub fn dealloc(&mut self, offset: usize, size: usize) {
        let aligned_size = (size + 7) & !7;
        let size_class = aligned_size.max(16);
        self.free_blocks.entry(size_class).or_default().push(offset);
    }

    /// Write raw byte slice into linear memory at given offset.
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) -> Result<(), String> {
        if offset + data.len() > self.bytes.len() {
            return Err(format!(
                "Memory access out of bounds: offset {} + len {} exceeds capacity {}",
                offset,
                data.len(),
                self.bytes.len()
            ));
        }
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Read raw byte slice from linear memory.
    pub fn read_bytes(&self, offset: usize, len: usize) -> Result<&[u8], String> {
        if offset + len > self.bytes.len() {
            return Err(format!(
                "Memory read out of bounds: offset {} + len {} exceeds capacity {}",
                offset,
                len,
                self.bytes.len()
            ));
        }
        Ok(&self.bytes[offset..offset + len])
    }

    /// Write a UTF-8 string into linear memory. Returns allocated (pointer, length).
    pub fn write_str(&mut self, s: &str) -> (usize, usize) {
        let bytes = s.as_bytes();
        let ptr = self.alloc(bytes.len() + 1);
        self.bytes[ptr..ptr + bytes.len()].copy_from_slice(bytes);
        self.bytes[ptr + bytes.len()] = 0; // Null-terminator
        (ptr, bytes.len())
    }

    /// Read a UTF-8 string from linear memory.
    pub fn read_str(&self, ptr: usize, len: usize) -> Result<String, String> {
        let slice = self.read_bytes(ptr, len)?;
        std::str::from_utf8(slice)
            .map(|s| s.to_string())
            .map_err(|e| format!("Invalid UTF-8 sequence in Wasm memory: {}", e))
    }
}

/// WebAssembly standard funcref function table (Section 4 & 9) for indirect dispatch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WasmFunctionTable {
    slots: Vec<Option<u32>>,
    min_size: usize,
    max_size: Option<usize>,
}

impl WasmFunctionTable {
    pub fn new(min_size: usize, max_size: Option<usize>) -> Self {
        Self {
            slots: vec![None; min_size],
            min_size,
            max_size,
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<u32> {
        self.slots.get(index).copied().flatten()
    }

    pub fn set(&mut self, index: usize, func_idx: u32) -> Result<(), String> {
        if index >= self.slots.len() {
            if let Some(max) = self.max_size {
                if index >= max {
                    return Err(format!(
                        "Table index {} exceeds maximum limit {}",
                        index, max
                    ));
                }
            }
            self.slots.resize(index + 1, None);
        }
        self.slots[index] = Some(func_idx);
        Ok(())
    }

    pub fn load_elements(&mut self, offset: usize, func_indices: &[u32]) -> Result<(), String> {
        for (i, &f_idx) in func_indices.iter().enumerate() {
            self.set(offset + i, f_idx)?;
        }
        Ok(())
    }
}

/// Simulated WASI Preview 1 host environment for standalone execution.
#[derive(Debug, Default)]
pub struct WasiHostEnvironment {
    pub stdout_buffer: Vec<u8>,
    pub stderr_buffer: Vec<u8>,
    pub exit_code: Option<i32>,
    pub table: WasmFunctionTable,
}

impl WasiHostEnvironment {
    pub fn new() -> Self {
        Self::default()
    }

    /// Dispatches an indirect function call via the host WebAssembly function table.
    pub fn dispatch_indirect(
        &self,
        table_idx: usize,
        _args: &[i64],
    ) -> Result<Option<i64>, String> {
        let func_idx = self.table.get(table_idx).ok_or_else(|| {
            format!(
                "Indirect call error: uninitialized element at table index {}",
                table_idx
            )
        })?;
        Ok(Some(func_idx as i64))
    }

    /// Implementation of WASI `fd_write(fd, *iovs, iovs_len, *nwritten)`.
    pub fn fd_write(
        &mut self,
        memory: &mut WasmLinearMemory,
        fd: i32,
        iovs_ptr: usize,
        iovs_len: usize,
        nwritten_ptr: usize,
    ) -> i32 {
        let mut total_written: usize = 0;

        for i in 0..iovs_len {
            let iov_offset = iovs_ptr + i * 8;
            let buf_ptr = match memory.read_bytes(iov_offset, 4) {
                Ok(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
                Err(_) => return 28, // __WASI_ERRNO_INVAL
            };
            let buf_len = match memory.read_bytes(iov_offset + 4, 4) {
                Ok(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
                Err(_) => return 28, // __WASI_ERRNO_INVAL
            };

            let data = match memory.read_bytes(buf_ptr, buf_len) {
                Ok(d) => d,
                Err(_) => return 28, // __WASI_ERRNO_INVAL
            };

            match fd {
                1 => self.stdout_buffer.extend_from_slice(data),
                2 => self.stderr_buffer.extend_from_slice(data),
                _ => return 8, // __WASI_ERRNO_BADF
            }

            total_written += buf_len;
        }

        let written_bytes = (total_written as u32).to_le_bytes();
        let _ = memory.write_bytes(nwritten_ptr, &written_bytes);
        0 // __WASI_ERRNO_SUCCESS
    }

    /// Implementation of WASI `proc_exit(rval)`.
    pub fn proc_exit(&mut self, exit_code: i32) {
        self.exit_code = Some(exit_code);
    }
}
