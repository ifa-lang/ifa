//! Stream I/O primitives and buffered reader/writer utilities (`std::io`).

use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};

/// Print a message to standard output followed by a newline.
pub fn println(msg: &str) {
    println!("{}", msg);
}

/// Print a message to standard output without trailing newline.
pub fn print(msg: &str) {
    print!("{}", msg);
    let _ = io::stdout().flush();
}

/// Read a single line from standard input.
pub fn read_line() -> io::Result<String> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// Buffered reader wrapper providing convenient line and block reading.
pub struct BufferedReader<R: Read> {
    inner: BufReader<R>,
}

impl<R: Read> BufferedReader<R> {
    /// Create a new buffered reader.
    pub fn new(reader: R) -> Self {
        Self {
            inner: BufReader::new(reader),
        }
    }

    /// Read next line as a String. Returns None on EOF.
    pub fn read_line(&mut self) -> io::Result<Option<String>> {
        let mut line = String::new();
        let bytes_read = self.inner.read_line(&mut line)?;
        if bytes_read == 0 {
            Ok(None)
        } else {
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            }
            Ok(Some(line))
        }
    }

    /// Read all remaining lines into a vector.
    pub fn lines(mut self) -> io::Result<Vec<String>> {
        let mut lines = Vec::new();
        while let Some(line) = self.read_line()? {
            lines.push(line);
        }
        Ok(lines)
    }

    /// Unwrap inner reader.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }
}

/// Buffered writer wrapper providing batch flushing.
pub struct BufferedWriter<W: Write> {
    inner: BufWriter<W>,
}

impl<W: Write> BufferedWriter<W> {
    /// Create a new buffered writer.
    pub fn new(writer: W) -> Self {
        Self {
            inner: BufWriter::new(writer),
        }
    }

    /// Write byte slice to buffer.
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    /// Write all bytes to buffer.
    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)
    }

    /// Write a string slice followed by a newline.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.inner.write_all(line.as_bytes())?;
        self.inner.write_all(b"\n")
    }

    /// Flush buffer to destination.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Unwrap inner writer after flushing.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.inner.flush()?;
        self.inner.into_inner().map_err(|e| e.into_error())
    }
}

/// In-memory stream buffer for fast byte operations without OS syscalls.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryStream {
    buffer: Vec<u8>,
    position: usize,
}

impl MemoryStream {
    /// Create an empty in-memory stream.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Create an in-memory stream initialized with data.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            buffer: bytes.to_vec(),
            position: 0,
        }
    }

    /// Current cursor position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set cursor position.
    pub fn seek(&mut self, pos: usize) {
        self.position = pos.min(self.buffer.len());
    }

    /// Total byte length of data.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Access underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume stream into byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Read up to `len` bytes from stream.
    pub fn read_bytes(&mut self, len: usize) -> Vec<u8> {
        if self.position >= self.buffer.len() {
            return Vec::new();
        }
        let end = (self.position + len).min(self.buffer.len());
        let slice = self.buffer[self.position..end].to_vec();
        self.position = end;
        slice
    }

    /// Write bytes at current cursor position, expanding if necessary.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        if self.position + bytes.len() > self.buffer.len() {
            self.buffer.resize(self.position + bytes.len(), 0);
        }
        self.buffer[self.position..self.position + bytes.len()].copy_from_slice(bytes);
        self.position += bytes.len();
    }
}
