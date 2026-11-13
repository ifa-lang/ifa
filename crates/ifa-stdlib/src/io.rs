//! Stream I/O primitives and buffered reader/writer utilities (`std::io`).

use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

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

impl<R: Read> Read for BufferedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read> BufRead for BufferedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
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

impl<W: Write> Write for BufferedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Line-buffered writer wrapper that automatically flushes when a newline is written.
pub struct LineWriter<W: Write> {
    inner: BufWriter<W>,
}

impl<W: Write> LineWriter<W> {
    /// Create a new line-buffered writer.
    pub fn new(writer: W) -> Self {
        Self {
            inner: BufWriter::new(writer),
        }
    }

    /// Write byte slice and flush if it contains a newline.
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if buf[..n].contains(&b'\n') {
            self.inner.flush()?;
        }
        Ok(n)
    }

    /// Write all bytes and flush if it contains a newline.
    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)?;
        if buf.contains(&b'\n') {
            self.inner.flush()?;
        }
        Ok(())
    }

    /// Write a string slice followed by a newline and flush.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.inner.write_all(line.as_bytes())?;
        self.inner.write_all(b"\n")?;
        self.inner.flush()
    }

    /// Explicitly flush internal buffer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Unwrap inner writer after flushing.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.inner.flush()?;
        self.inner.into_inner().map_err(|e| e.into_error())
    }
}

impl<W: Write> Write for LineWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush()
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

    /// Create an in-memory stream with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            position: 0,
        }
    }

    /// Clear all data and reset position to 0.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.position = 0;
    }

    /// Truncate internal buffer to `size` bytes.
    pub fn truncate(&mut self, size: usize) {
        self.buffer.truncate(size);
        if self.position > self.buffer.len() {
            self.position = self.buffer.len();
        }
    }

    /// Allocated capacity of internal buffer.
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Reserve capacity for at least `additional` more bytes.
    pub fn reserve(&mut self, additional: usize) {
        self.buffer.reserve(additional);
    }

    /// Current cursor position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set cursor position.
    pub fn set_position(&mut self, pos: usize) {
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

    /// Read exactly `len` bytes from the current position or return UnexpectedEof.
    pub fn read_exact_bytes(&mut self, len: usize) -> io::Result<Vec<u8>> {
        if self.position + len > self.buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected end of memory stream",
            ));
        }
        let slice = self.buffer[self.position..self.position + len].to_vec();
        self.position += len;
        Ok(slice)
    }

    /// Write an unsigned 8-bit integer.
    pub fn write_u8(&mut self, val: u8) {
        self.write_bytes(&[val]);
    }

    /// Write a 16-bit unsigned integer in big-endian byte order.
    pub fn write_u16_be(&mut self, val: u16) {
        self.write_bytes(&val.to_be_bytes());
    }

    /// Write a 16-bit unsigned integer in little-endian byte order.
    pub fn write_u16_le(&mut self, val: u16) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Write a 32-bit unsigned integer in big-endian byte order.
    pub fn write_u32_be(&mut self, val: u32) {
        self.write_bytes(&val.to_be_bytes());
    }

    /// Write a 32-bit unsigned integer in little-endian byte order.
    pub fn write_u32_le(&mut self, val: u32) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Write a 64-bit unsigned integer in big-endian byte order.
    pub fn write_u64_be(&mut self, val: u64) {
        self.write_bytes(&val.to_be_bytes());
    }

    /// Write a 64-bit unsigned integer in little-endian byte order.
    pub fn write_u64_le(&mut self, val: u64) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Read an unsigned 8-bit integer.
    pub fn read_u8(&mut self) -> io::Result<u8> {
        let b = self.read_exact_bytes(1)?;
        Ok(b[0])
    }

    /// Read a 16-bit unsigned integer in big-endian byte order.
    pub fn read_u16_be(&mut self) -> io::Result<u16> {
        let b = self.read_exact_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a 16-bit unsigned integer in little-endian byte order.
    pub fn read_u16_le(&mut self) -> io::Result<u16> {
        let b = self.read_exact_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a 32-bit unsigned integer in big-endian byte order.
    pub fn read_u32_be(&mut self) -> io::Result<u32> {
        let b = self.read_exact_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a 32-bit unsigned integer in little-endian byte order.
    pub fn read_u32_le(&mut self) -> io::Result<u32> {
        let b = self.read_exact_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a 64-bit unsigned integer in big-endian byte order.
    pub fn read_u64_be(&mut self) -> io::Result<u64> {
        let b = self.read_exact_bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a 64-bit unsigned integer in little-endian byte order.
    pub fn read_u64_le(&mut self) -> io::Result<u64> {
        let b = self.read_exact_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.buffer.len() {
            return Ok(0);
        }
        let available = self.buffer.len() - self.position;
        let amt = available.min(buf.len());
        buf[..amt].copy_from_slice(&self.buffer[self.position..self.position + amt]);
        self.position += amt;
        Ok(amt)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_bytes(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for MemoryStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::End(offset) => self.buffer.len() as i128 + offset as i128,
            SeekFrom::Current(offset) => self.position as i128 + offset as i128,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek before start of stream",
            ));
        }
        self.position = (new_pos as usize).min(self.buffer.len());
        Ok(self.position as u64)
    }
}

impl BufRead for MemoryStream {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position >= self.buffer.len() {
            Ok(&[])
        } else {
            Ok(&self.buffer[self.position..])
        }
    }

    fn consume(&mut self, amt: usize) {
        self.position = (self.position + amt).min(self.buffer.len());
    }
}

/// Copy all bytes from reader to writer using an efficient internal buffer.
pub fn copy_stream<R: ?Sized + Read, W: ?Sized + Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<u64> {
    io::copy(reader, writer)
}

/// Read all bytes from a reader into a string.
pub fn read_to_string<R: Read>(mut reader: R) -> io::Result<String> {
    let mut s = String::new();
    reader.read_to_string(&mut s)?;
    Ok(s)
}

/// Read all bytes from a reader into a vector.
pub fn read_to_end<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Pipe lines from a buffered reader into a buffered writer.
pub fn pipe_lines<R: Read, W: Write>(
    reader: &mut BufferedReader<R>,
    writer: &mut BufferedWriter<W>,
) -> io::Result<usize> {
    let mut count = 0;
    while let Some(line) = reader.read_line()? {
        writer.write_line(&line)?;
        count += 1;
    }
    writer.flush()?;
    Ok(count)
}

/// Reader wrapper that counts the total number of bytes read.
pub struct CountingReader<R: Read> {
    inner: R,
    bytes_read: u64,
}

impl<R: Read> CountingReader<R> {
    /// Create a new counting reader starting at 0 bytes.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            bytes_read: 0,
        }
    }

    /// Total number of bytes successfully read so far.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Reset the byte counter to zero.
    pub fn reset_count(&mut self) {
        self.bytes_read = 0;
    }

    /// Borrow the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutably borrow the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

impl<R: BufRead> BufRead for CountingReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
        self.bytes_read += amt as u64;
    }
}

/// Writer wrapper that counts the total number of bytes written.
pub struct CountingWriter<W: Write> {
    inner: W,
    bytes_written: u64,
}

impl<W: Write> CountingWriter<W> {
    /// Create a new counting writer starting at 0 bytes.
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            bytes_written: 0,
        }
    }

    /// Total number of bytes successfully written so far.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Reset the byte counter to zero.
    pub fn reset_count(&mut self) {
        self.bytes_written = 0;
    }

    /// Borrow the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutably borrow the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reader wrapper that reads at most `limit` bytes from the underlying reader.
pub struct LimitedReader<R: Read> {
    inner: R,
    limit: u64,
}

impl<R: Read> LimitedReader<R> {
    /// Create a new reader with an upper limit of `limit` bytes.
    pub fn new(reader: R, limit: u64) -> Self {
        Self {
            inner: reader,
            limit,
        }
    }

    /// Remaining allowed byte count before reaching EOF.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Set a new limit for remaining bytes.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Borrow the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutably borrow the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.limit == 0 {
            return Ok(0);
        }
        let max_read = (buf.len() as u64).min(self.limit) as usize;
        let n = self.inner.read(&mut buf[..max_read])?;
        self.limit -= n as u64;
        Ok(n)
    }
}

/// Helper function to create a new `LimitedReader`.
pub fn limited<R: Read>(reader: R, limit: u64) -> LimitedReader<R> {
    LimitedReader::new(reader, limit)
}

/// Writer wrapper that writes at most `limit` bytes to the underlying writer.
/// Once the limit is reached, further writes return 0 bytes written.
#[derive(Debug, Clone)]
pub struct LimitedWriter<W: Write> {
    inner: W,
    limit: u64,
}

impl<W: Write> LimitedWriter<W> {
    /// Create a new writer with an upper limit of `limit` bytes.
    pub fn new(writer: W, limit: u64) -> Self {
        Self {
            inner: writer,
            limit,
        }
    }

    /// Remaining allowed byte count before reaching the limit.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Set a new limit for remaining bytes.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Borrow the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutably borrow the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Helper function to create a new `LimitedWriter`.
pub fn limited_writer<W: Write>(writer: W, limit: u64) -> LimitedWriter<W> {
    LimitedWriter::new(writer, limit)
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.limit == 0 {
            return Ok(0);
        }
        let max_write = (buf.len() as u64).min(self.limit) as usize;
        let n = self.inner.write(&buf[..max_write])?;
        self.limit -= n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reader that sequentially chains two readers together.
pub struct ChainedReader<R1: Read, R2: Read> {
    first: Option<R1>,
    second: R2,
}

impl<R1: Read, R2: Read> ChainedReader<R1, R2> {
    /// Create a chained reader yielding bytes from `first` then `second`.
    pub fn new(first: R1, second: R2) -> Self {
        Self {
            first: Some(first),
            second,
        }
    }

    /// Borrow the second reader.
    pub fn get_second(&self) -> &R2 {
        &self.second
    }

    /// Mutably borrow the second reader.
    pub fn get_second_mut(&mut self) -> &mut R2 {
        &mut self.second
    }
}

impl<R1: Read, R2: Read> Read for ChainedReader<R1, R2> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(first) = &mut self.first {
            let n = first.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            self.first = None;
        }
        self.second.read(buf)
    }
}

/// Helper function to chain two readers together into a `ChainedReader`.
pub fn chain<R1: Read, R2: Read>(first: R1, second: R2) -> ChainedReader<R1, R2> {
    ChainedReader::new(first, second)
}

/// Reader wrapper that duplicates each byte read into a secondary writer.
/// Analogous to the UNIX `tee` utility or Go's `io.TeeReader`.
pub struct TeeReader<R: Read, W: Write> {
    reader: R,
    writer: W,
}

impl<R: Read, W: Write> TeeReader<R, W> {
    /// Create a new `TeeReader` reading from `reader` and mirroring to `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    /// Access the underlying reader.
    pub fn get_reader(&self) -> &R {
        &self.reader
    }

    /// Mutably access the underlying reader.
    pub fn get_reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Access the underlying writer.
    pub fn get_writer(&self) -> &W {
        &self.writer
    }

    /// Mutably access the underlying writer.
    pub fn get_writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Unpack both the reader and writer.
    pub fn into_inner(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<R: Read, W: Write> Read for TeeReader<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        if n > 0 {
            self.writer.write_all(&buf[..n])?;
        }
        Ok(n)
    }
}

/// Writer wrapper that writes each byte to two destinations simultaneously.
pub struct TeeWriter<W1: Write, W2: Write> {
    writer1: W1,
    writer2: W2,
}

impl<W1: Write, W2: Write> TeeWriter<W1, W2> {
    /// Create a new `TeeWriter` copying writes to both writers.
    pub fn new(writer1: W1, writer2: W2) -> Self {
        Self { writer1, writer2 }
    }

    /// Access the first writer.
    pub fn get_first(&self) -> &W1 {
        &self.writer1
    }

    /// Mutably access the first writer.
    pub fn get_first_mut(&mut self) -> &mut W1 {
        &mut self.writer1
    }

    /// Access the second writer.
    pub fn get_second(&self) -> &W2 {
        &self.writer2
    }

    /// Mutably access the second writer.
    pub fn get_second_mut(&mut self) -> &mut W2 {
        &mut self.writer2
    }

    /// Unpack both underlying writers.
    pub fn into_inner(self) -> (W1, W2) {
        (self.writer1, self.writer2)
    }
}

impl<W1: Write, W2: Write> Write for TeeWriter<W1, W2> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer1.write_all(buf)?;
        self.writer2.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer1.flush()?;
        self.writer2.flush()
    }
}

/// An empty stream reader that immediately yields EOF (0 bytes read).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct EmptyReader;

impl EmptyReader {
    /// Create a new empty reader.
    pub fn new() -> Self {
        Self
    }
}

/// Create a new reader that always yields EOF immediately.
pub fn empty() -> EmptyReader {
    EmptyReader
}

impl Read for EmptyReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl BufRead for EmptyReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(&[])
    }

    fn consume(&mut self, _amt: usize) {}
}

impl Seek for EmptyReader {
    fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}

/// A sink writer that silently discards all written bytes (analogous to `/dev/null`).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SinkWriter;

impl SinkWriter {
    /// Create a new sink writer.
    pub fn new() -> Self {
        Self
    }
}

/// Create a new sink writer that silently consumes and discards all data.
pub fn sink() -> SinkWriter {
    SinkWriter
}

impl Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A reader that infinitely yields a repeated single byte.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RepeatReader {
    byte: u8,
}

impl RepeatReader {
    /// Create a new repeated byte reader.
    pub fn new(byte: u8) -> Self {
        Self { byte }
    }

    /// Return the byte value being repeated.
    pub fn byte(&self) -> u8 {
        self.byte
    }
}

/// Create a new reader that infinitely repeats a given byte value.
pub fn repeat(byte: u8) -> RepeatReader {
    RepeatReader::new(byte)
}

impl Read for RepeatReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for b in buf.iter_mut() {
            *b = self.byte;
        }
        Ok(buf.len())
    }
}

/// Reader wrapper that prefixes a stream with an in-memory byte buffer.
/// Useful for peeking, replaying headers, or injecting handshake bytes on non-seekable streams.
#[derive(Debug, Clone)]
pub struct PrefixedReader<R: Read> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R: Read> PrefixedReader<R> {
    /// Create a new `PrefixedReader` that yields `prefix` bytes before reading from `inner`.
    pub fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// Total length of the prefix buffer in bytes.
    pub fn prefix_len(&self) -> usize {
        self.prefix.len()
    }

    /// Number of remaining prefix bytes waiting to be read.
    pub fn prefix_remaining(&self) -> usize {
        self.prefix.len().saturating_sub(self.pos)
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader, discarding any remaining unread prefix bytes.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Helper function to create a new `PrefixedReader`.
pub fn prefixed<R: Read>(prefix: Vec<u8>, reader: R) -> PrefixedReader<R> {
    PrefixedReader::new(prefix, reader)
}

impl<R: Read> Read for PrefixedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos < self.prefix.len() {
            let available = self.prefix.len() - self.pos;
            let to_read = available.min(buf.len());
            buf[..to_read].copy_from_slice(&self.prefix[self.pos..self.pos + to_read]);
            self.pos += to_read;
            Ok(to_read)
        } else {
            self.inner.read(buf)
        }
    }
}

impl<R: Read + BufRead> BufRead for PrefixedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos < self.prefix.len() {
            Ok(&self.prefix[self.pos..])
        } else {
            self.inner.fill_buf()
        }
    }

    fn consume(&mut self, amt: usize) {
        if self.pos < self.prefix.len() {
            let available = self.prefix.len() - self.pos;
            let taken = available.min(amt);
            self.pos += taken;
            let rem = amt - taken;
            if rem > 0 {
                self.inner.consume(rem);
            }
        } else {
            self.inner.consume(amt);
        }
    }
}

/// Writer that duplicates all writes and flushes across multiple destination writers.
#[derive(Debug, Default, Clone)]
pub struct MultiWriter<W: Write> {
    writers: Vec<W>,
}

impl<W: Write> MultiWriter<W> {
    /// Create a new `MultiWriter` targeting the provided list of writers.
    pub fn new(writers: Vec<W>) -> Self {
        Self { writers }
    }

    /// Create a new empty `MultiWriter` with preallocated writer capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            writers: Vec::with_capacity(capacity),
        }
    }

    /// Add a destination writer.
    pub fn add_writer(&mut self, writer: W) {
        self.writers.push(writer);
    }

    /// Number of configured destination writers.
    pub fn len(&self) -> usize {
        self.writers.len()
    }

    /// Check if no destination writers are configured.
    pub fn is_empty(&self) -> bool {
        self.writers.is_empty()
    }

    /// Slice reference to all destination writers.
    pub fn writers(&self) -> &[W] {
        &self.writers
    }

    /// Mutable slice reference to all destination writers.
    pub fn writers_mut(&mut self) -> &mut [W] {
        &mut self.writers
    }

    /// Consume this writer and return the vector of destination writers.
    pub fn into_writers(self) -> Vec<W> {
        self.writers
    }
}

/// Helper function to create a new `MultiWriter`.
pub fn multi_writer<W: Write>(writers: Vec<W>) -> MultiWriter<W> {
    MultiWriter::new(writers)
}

impl<W: Write> Write for MultiWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for w in &mut self.writers {
            w.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        for w in &mut self.writers {
            w.flush()?;
        }
        Ok(())
    }
}

/// Reader that sequentially concatenates multiple readers into a single continuous stream.
/// When the current reader reaches EOF (returns 0 bytes), `MultiReader` advances to the next reader.
#[derive(Debug, Default, Clone)]
pub struct MultiReader<R: Read> {
    readers: Vec<R>,
    current: usize,
}

impl<R: Read> MultiReader<R> {
    /// Create a new `MultiReader` from a vector of readers.
    pub fn new(readers: Vec<R>) -> Self {
        Self {
            readers,
            current: 0,
        }
    }

    /// Create an empty `MultiReader` with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            readers: Vec::with_capacity(capacity),
            current: 0,
        }
    }

    /// Add a reader to the end of the sequence.
    pub fn add_reader(&mut self, reader: R) {
        self.readers.push(reader);
    }

    /// Total number of readers configured in the sequence.
    pub fn len(&self) -> usize {
        self.readers.len()
    }

    /// Check if no readers are configured.
    pub fn is_empty(&self) -> bool {
        self.readers.is_empty()
    }

    /// Index of the current active reader.
    pub fn current_index(&self) -> usize {
        self.current
    }

    /// Number of remaining readers (including the current active reader, if any).
    pub fn remaining_readers(&self) -> usize {
        self.readers.len().saturating_sub(self.current)
    }

    /// Slice reference to all readers.
    pub fn readers(&self) -> &[R] {
        &self.readers
    }

    /// Mutable slice reference to all readers.
    pub fn readers_mut(&mut self) -> &mut [R] {
        &mut self.readers
    }

    /// Consume this reader and return the vector of readers.
    pub fn into_readers(self) -> Vec<R> {
        self.readers
    }
}

/// Helper function to create a new `MultiReader`.
pub fn multi_reader<R: Read>(readers: Vec<R>) -> MultiReader<R> {
    MultiReader::new(readers)
}

impl<R: Read> Read for MultiReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.current < self.readers.len() {
            let n = self.readers[self.current].read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.current += 1;
        }
        Ok(0)
    }
}

impl<R: Read + BufRead> BufRead for MultiReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.current < self.readers.len() {
            if !self.readers[self.current].fill_buf()?.is_empty() {
                return self.readers[self.current].fill_buf();
            }
            self.current += 1;
        }
        Ok(&[])
    }

    fn consume(&mut self, amt: usize) {
        if self.current < self.readers.len() {
            self.readers[self.current].consume(amt);
        }
    }
}

/// Reader wrapper that constrains read requests to at most `chunk_size` bytes.
/// Also provides helpers to read discrete byte chunks (`read_chunk`, `read_exact_chunk`)
/// and to convert into a streaming chunk iterator.
#[derive(Debug, Clone)]
pub struct ChunkReader<R: Read> {
    inner: R,
    chunk_size: usize,
}

impl<R: Read> ChunkReader<R> {
    /// Create a new `ChunkReader` with the specified chunk size (at least 1 byte).
    pub fn new(reader: R, chunk_size: usize) -> Self {
        Self {
            inner: reader,
            chunk_size: chunk_size.max(1),
        }
    }

    /// Return the configured maximum chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Set a new maximum chunk size (at least 1 byte).
    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        self.chunk_size = chunk_size.max(1);
    }

    /// Read the next available chunk of up to `chunk_size` bytes.
    /// Returns `Ok(None)` on EOF (when 0 bytes are read).
    pub fn read_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; self.chunk_size];
        let n = self.inner.read(&mut buf)?;
        if n == 0 {
            Ok(None)
        } else {
            buf.truncate(n);
            Ok(Some(buf))
        }
    }

    /// Read an exact full chunk of `chunk_size` bytes.
    /// Returns `Ok(None)` if stream is at EOF before reading any bytes.
    /// Returns `Err(UnexpectedEof)` if EOF is reached with fewer than `chunk_size` bytes read.
    pub fn read_exact_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; self.chunk_size];
        let mut total = 0;
        while total < self.chunk_size {
            let n = self.inner.read(&mut buf[total..])?;
            if n == 0 {
                if total == 0 {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "incomplete chunk: read {} bytes, expected {}",
                            total, self.chunk_size
                        ),
                    ));
                }
            }
            total += n;
        }
        Ok(Some(buf))
    }

    /// Convert this `ChunkReader` into an iterator yielding byte chunks.
    pub fn into_chunks(self) -> ChunkIter<R> {
        ChunkIter {
            reader: self.inner,
            chunk_size: self.chunk_size,
        }
    }

    /// Borrow the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutably borrow the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Helper function to create a new `ChunkReader`.
pub fn chunk_reader<R: Read>(reader: R, chunk_size: usize) -> ChunkReader<R> {
    ChunkReader::new(reader, chunk_size)
}

impl<R: Read> Read for ChunkReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let to_read = buf.len().min(self.chunk_size);
        self.inner.read(&mut buf[..to_read])
    }
}

impl<R: Read + BufRead> BufRead for ChunkReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let buf = self.inner.fill_buf()?;
        let len = buf.len().min(self.chunk_size);
        Ok(&buf[..len])
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
    }
}

/// Iterator yielding consecutive byte chunks of up to `chunk_size` bytes from an underlying reader.
#[derive(Debug)]
pub struct ChunkIter<R: Read> {
    reader: R,
    chunk_size: usize,
}

impl<R: Read> Iterator for ChunkIter<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = vec![0u8; self.chunk_size];
        match self.reader.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Helper function to create a chunk iterator from any reader.
pub fn chunks<R: Read>(reader: R, chunk_size: usize) -> ChunkIter<R> {
    chunk_reader(reader, chunk_size).into_chunks()
}

/// Writer wrapper that splits write requests into chunks of at most `chunk_size` bytes.
#[derive(Debug, Clone)]
pub struct ChunkWriter<W: Write> {
    inner: W,
    chunk_size: usize,
}

impl<W: Write> ChunkWriter<W> {
    /// Create a new `ChunkWriter` with the specified chunk size (at least 1 byte).
    pub fn new(writer: W, chunk_size: usize) -> Self {
        Self {
            inner: writer,
            chunk_size: chunk_size.max(1),
        }
    }

    /// Return the configured maximum chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Set a new maximum chunk size (at least 1 byte).
    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        self.chunk_size = chunk_size.max(1);
    }

    /// Borrow the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutably borrow the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Helper function to create a new `ChunkWriter`.
pub fn chunk_writer<W: Write>(writer: W, chunk_size: usize) -> ChunkWriter<W> {
    ChunkWriter::new(writer, chunk_size)
}

impl<W: Write> Write for ChunkWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let to_write = buf.len().min(self.chunk_size);
        self.inner.write(&buf[..to_write])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reader wrapper that skips (discards) the first `skip` bytes of an underlying reader.
#[derive(Debug, Clone)]
pub struct SkipReader<R: Read> {
    inner: R,
    remaining_skip: u64,
}

impl<R: Read> SkipReader<R> {
    /// Create a new `SkipReader` that discards up to `skip` bytes from `reader`.
    pub fn new(reader: R, skip: u64) -> Self {
        Self {
            inner: reader,
            remaining_skip: skip,
        }
    }

    /// Number of bytes remaining to skip.
    pub fn remaining_skip(&self) -> u64 {
        self.remaining_skip
    }

    /// Returns `true` if all requested skip bytes have been discarded.
    pub fn is_skipped(&self) -> bool {
        self.remaining_skip == 0
    }

    /// Set a new number of bytes to skip.
    pub fn set_remaining_skip(&mut self, skip: u64) {
        self.remaining_skip = skip;
    }

    /// Eagerly read and discard all remaining skip bytes from the underlying reader.
    ///
    /// Returns the number of bytes successfully skipped before reaching EOF.
    pub fn skip_all(&mut self) -> io::Result<u64> {
        let mut total_skipped = 0u64;
        let mut buf = [0u8; 8192];
        while self.remaining_skip > 0 {
            let to_read = (self.remaining_skip.min(buf.len() as u64)) as usize;
            let n = self.inner.read(&mut buf[..to_read])?;
            if n == 0 {
                // Reached EOF before skipping all bytes
                break;
            }
            self.remaining_skip -= n as u64;
            total_skipped += n as u64;
        }
        Ok(total_skipped)
    }

    /// Borrow the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutably borrow the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Helper function to create a new `SkipReader`.
pub fn skip_reader<R: Read>(reader: R, skip: u64) -> SkipReader<R> {
    SkipReader::new(reader, skip)
}

impl<R: Read> Read for SkipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining_skip > 0 {
            let mut discard_buf = [0u8; 4096];
            while self.remaining_skip > 0 {
                let to_read = (self.remaining_skip.min(discard_buf.len() as u64)) as usize;
                let n = self.inner.read(&mut discard_buf[..to_read])?;
                if n == 0 {
                    // EOF encountered while skipping
                    return Ok(0);
                }
                self.remaining_skip -= n as u64;
            }
        }
        self.inner.read(buf)
    }
}

impl<R: BufRead> BufRead for SkipReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.remaining_skip > 0 {
            let available = self.inner.fill_buf()?;
            if available.is_empty() {
                return Ok(&[]);
            }
            let to_consume = (self.remaining_skip.min(available.len() as u64)) as usize;
            self.inner.consume(to_consume);
            self.remaining_skip -= to_consume as u64;
        }
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
    }
}

/// Writer wrapper that tracks bytes written and allows padding the output stream
/// to align with a specified block size boundary (e.g., 512-byte tar blocks, 16-byte crypto blocks).
#[derive(Debug, Clone)]
pub struct PadWriter<W: Write> {
    inner: W,
    block_size: usize,
    bytes_written: u64,
}

impl<W: Write> PadWriter<W> {
    /// Create a new `PadWriter` with the specified block size (minimum 1).
    pub fn new(writer: W, block_size: usize) -> Self {
        Self {
            inner: writer,
            block_size: block_size.max(1),
            bytes_written: 0,
        }
    }

    /// Block size in bytes used for alignment.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Set a new block size (minimum 1).
    pub fn set_block_size(&mut self, block_size: usize) {
        self.block_size = block_size.max(1);
    }

    /// Total number of bytes written so far through this writer (including padding).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Number of bytes needed to align to the next block boundary.
    /// Returns 0 if already block-aligned.
    pub fn padding_needed(&self) -> usize {
        let rem = (self.bytes_written % (self.block_size as u64)) as usize;
        if rem == 0 {
            0
        } else {
            self.block_size - rem
        }
    }

    /// Pad the stream with `pad_byte` to the next block boundary.
    /// Returns the number of pad bytes written (0 if already aligned).
    pub fn pad(&mut self, pad_byte: u8) -> io::Result<usize> {
        let needed = self.padding_needed();
        if needed == 0 {
            return Ok(0);
        }
        let padding = vec![pad_byte; needed];
        self.inner.write_all(&padding)?;
        self.bytes_written += needed as u64;
        Ok(needed)
    }

    /// Pad the stream with zero bytes (`0x00`) to the next block boundary.
    /// Returns the number of pad bytes written (0 if already aligned).
    pub fn pad_zero(&mut self) -> io::Result<usize> {
        self.pad(0)
    }

    /// Borrow the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutably borrow the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Helper function to create a new `PadWriter`.
pub fn pad_writer<W: Write>(writer: W, block_size: usize) -> PadWriter<W> {
    PadWriter::new(writer, block_size)
}

impl<W: Write> Write for PadWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reader wrapper that allows bytes to be pushed back (unread) into the stream
/// to be consumed by subsequent read operations, and provides lookahead peeking functionality.
#[derive(Debug, Clone)]
pub struct PushbackReader<R: Read> {
    inner: R,
    buffer: Vec<u8>,
    pos: usize,
}

impl<R: Read> PushbackReader<R> {
    /// Create a new `PushbackReader` wrapping `inner`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            pos: 0,
        }
    }

    /// Create a new `PushbackReader` with preallocated buffer capacity.
    pub fn with_capacity(inner: R, capacity: usize) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(capacity),
            pos: 0,
        }
    }

    /// Push bytes back onto the stream so they will be read next.
    /// If multiple bytes are pushed back, they will be read in the order provided:
    /// e.g. pushing `[1, 2]` means `1` will be read before `2`.
    pub fn unread(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.pos > 0 {
            self.buffer.drain(..self.pos);
            self.pos = 0;
        }
        let mut new_buf = Vec::with_capacity(bytes.len() + self.buffer.len());
        new_buf.extend_from_slice(bytes);
        new_buf.extend_from_slice(&self.buffer);
        self.buffer = new_buf;
    }

    /// Push a single byte back onto the stream.
    pub fn unread_byte(&mut self, byte: u8) {
        self.unread(&[byte]);
    }

    /// Number of bytes currently held in the pushback buffer.
    pub fn unread_len(&self) -> usize {
        self.buffer.len().saturating_sub(self.pos)
    }

    /// Returns `true` if there are pushback bytes waiting to be read.
    pub fn has_unread(&self) -> bool {
        self.unread_len() > 0
    }

    /// Clear all pushback bytes.
    pub fn clear_unread(&mut self) {
        self.buffer.clear();
        self.pos = 0;
    }

    /// Peek up to `buf.len()` bytes from the stream without advancing the read position.
    pub fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let available = self.unread_len();
        if available < buf.len() {
            let needed = buf.len() - available;
            let mut temp = vec![0u8; needed];
            let n = self.inner.read(&mut temp)?;
            if n > 0 {
                if self.pos > 0 {
                    self.buffer.drain(..self.pos);
                    self.pos = 0;
                }
                self.buffer.extend_from_slice(&temp[..n]);
            }
        }
        let available_now = self.unread_len();
        let to_copy = buf.len().min(available_now);
        buf[..to_copy].copy_from_slice(&self.buffer[self.pos..self.pos + to_copy]);
        Ok(to_copy)
    }

    /// Peek a single byte from the stream without consuming it.
    pub fn peek_byte(&mut self) -> io::Result<Option<u8>> {
        let mut b = [0u8; 1];
        let n = self.peek(&mut b)?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(b[0]))
        }
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consume this wrapper, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Helper function to create a new `PushbackReader`.
pub fn pushback_reader<R: Read>(reader: R) -> PushbackReader<R> {
    PushbackReader::new(reader)
}

impl<R: Read> Read for PushbackReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos < self.buffer.len() {
            let available = self.buffer.len() - self.pos;
            let to_read = available.min(buf.len());
            buf[..to_read].copy_from_slice(&self.buffer[self.pos..self.pos + to_read]);
            self.pos += to_read;
            if self.pos >= self.buffer.len() {
                self.buffer.clear();
                self.pos = 0;
            }
            Ok(to_read)
        } else {
            self.inner.read(buf)
        }
    }
}

impl<R: BufRead> BufRead for PushbackReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos < self.buffer.len() {
            Ok(&self.buffer[self.pos..])
        } else {
            self.inner.fill_buf()
        }
    }

    fn consume(&mut self, amt: usize) {
        if self.pos < self.buffer.len() {
            let available = self.buffer.len() - self.pos;
            let consumed = amt.min(available);
            self.pos += consumed;
            if self.pos >= self.buffer.len() {
                self.buffer.clear();
                self.pos = 0;
            }
            let remaining = amt.saturating_sub(consumed);
            if remaining > 0 {
                self.inner.consume(remaining);
            }
        } else {
            self.inner.consume(amt);
        }
    }
}

/// Writer wrapper that automatically writes a specified prefix (header, magic bytes)
/// to the underlying stream before any payload bytes are written or upon the first flush.
#[derive(Debug, Clone)]
pub struct PrefixWriter<W: Write> {
    inner: W,
    prefix: Vec<u8>,
    prefix_written: bool,
}

impl<W: Write> PrefixWriter<W> {
    /// Create a new `PrefixWriter` that prepends `prefix` on the first write or flush.
    pub fn new(inner: W, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_written: false,
        }
    }

    /// The prefix bytes to be written.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Whether the prefix has already been written to the underlying stream.
    pub fn is_prefix_written(&self) -> bool {
        self.prefix_written
    }

    /// Explicitly ensure the prefix has been written to the underlying writer.
    pub fn write_prefix(&mut self) -> io::Result<()> {
        if !self.prefix_written {
            if !self.prefix.is_empty() {
                self.inner.write_all(&self.prefix)?;
            }
            self.prefix_written = true;
        }
        Ok(())
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consume this wrapper, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Helper function to create a new `PrefixWriter`.
pub fn prefix_writer<W: Write>(writer: W, prefix: Vec<u8>) -> PrefixWriter<W> {
    PrefixWriter::new(writer, prefix)
}

impl<W: Write> Write for PrefixWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_prefix()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_prefix()?;
        self.inner.flush()
    }
}

/// Reader wrapper that reads completely from an underlying reader and then appends a suffix.
#[derive(Debug, Clone)]
pub struct SuffixedReader<R: Read> {
    inner: R,
    suffix: Vec<u8>,
    suffix_pos: usize,
    inner_done: bool,
}

impl<R: Read> SuffixedReader<R> {
    /// Create a new `SuffixedReader` that appends `suffix` bytes after `inner` reaches EOF.
    pub fn new(inner: R, suffix: Vec<u8>) -> Self {
        Self {
            inner,
            suffix,
            suffix_pos: 0,
            inner_done: false,
        }
    }

    /// Access the suffix bytes.
    pub fn suffix(&self) -> &[u8] {
        &self.suffix
    }

    /// Total length of the suffix buffer in bytes.
    pub fn suffix_len(&self) -> usize {
        self.suffix.len()
    }

    /// Number of remaining suffix bytes waiting to be read.
    pub fn suffix_remaining(&self) -> usize {
        self.suffix.len().saturating_sub(self.suffix_pos)
    }

    /// Whether the underlying reader has reached EOF.
    pub fn is_inner_exhausted(&self) -> bool {
        self.inner_done
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader, discarding remaining suffix.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Unwrap the components: inner reader, suffix bytes, and current suffix position.
    pub fn into_parts(self) -> (R, Vec<u8>, usize) {
        (self.inner, self.suffix, self.suffix_pos)
    }
}

/// Helper function to create a new `SuffixedReader`.
pub fn suffixed<R: Read>(reader: R, suffix: Vec<u8>) -> SuffixedReader<R> {
    SuffixedReader::new(reader, suffix)
}

impl<R: Read> Read for SuffixedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.inner_done {
            let n = self.inner.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.inner_done = true;
        }

        if self.suffix_pos < self.suffix.len() {
            let available = self.suffix.len() - self.suffix_pos;
            let to_read = available.min(buf.len());
            buf[..to_read]
                .copy_from_slice(&self.suffix[self.suffix_pos..self.suffix_pos + to_read]);
            self.suffix_pos += to_read;
            Ok(to_read)
        } else {
            Ok(0)
        }
    }
}

impl<R: Read + BufRead> BufRead for SuffixedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if !self.inner_done {
            let n = self.inner.fill_buf()?.len();
            if n > 0 {
                return self.inner.fill_buf();
            }
            self.inner_done = true;
        }
        Ok(&self.suffix[self.suffix_pos..])
    }

    fn consume(&mut self, amt: usize) {
        if !self.inner_done {
            self.inner.consume(amt);
        } else {
            self.suffix_pos = (self.suffix_pos + amt).min(self.suffix.len());
        }
    }
}

/// Writer wrapper that writes data to the underlying stream and guarantees a suffix is appended upon completion.
#[derive(Debug, Clone)]
pub struct SuffixWriter<W: Write> {
    inner: W,
    suffix: Vec<u8>,
    suffix_written: bool,
}

impl<W: Write> SuffixWriter<W> {
    /// Create a new `SuffixWriter` that will append `suffix` on completion.
    pub fn new(inner: W, suffix: Vec<u8>) -> Self {
        Self {
            inner,
            suffix,
            suffix_written: false,
        }
    }

    /// The suffix bytes to be written.
    pub fn suffix(&self) -> &[u8] {
        &self.suffix
    }

    /// Whether the suffix has already been written to the underlying stream.
    pub fn is_suffix_written(&self) -> bool {
        self.suffix_written
    }

    /// Explicitly ensure the suffix has been written to the underlying writer.
    pub fn write_suffix(&mut self) -> io::Result<()> {
        if !self.suffix_written {
            if !self.suffix.is_empty() {
                self.inner.write_all(&self.suffix)?;
            }
            self.suffix_written = true;
        }
        Ok(())
    }

    /// Finish writing by ensuring the suffix is written, flushing, and returning the underlying writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.write_suffix()?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consume this wrapper, returning the underlying writer without forcing suffix write.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consume this wrapper, returning the underlying writer, suffix and completion status.
    pub fn into_parts(self) -> (W, Vec<u8>, bool) {
        (self.inner, self.suffix, self.suffix_written)
    }
}

/// Helper function to create a new `SuffixWriter`.
pub fn suffix_writer<W: Write>(writer: W, suffix: Vec<u8>) -> SuffixWriter<W> {
    SuffixWriter::new(writer, suffix)
}

impl<W: Write> Write for SuffixWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.suffix_written {
            return Err(io::Error::other(
                "cannot write data after suffix has already been written",
            ));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Encoding and byte width of length prefix for framed streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthFieldKind {
    /// 1 byte prefix (payloads up to 255 bytes).
    U8,
    /// 2 bytes big-endian prefix (payloads up to 65,535 bytes).
    U16Be,
    /// 2 bytes little-endian prefix (payloads up to 65,535 bytes).
    U16Le,
    /// 4 bytes big-endian prefix (standard network byte order, payloads up to 4 GiB).
    U32Be,
    /// 4 bytes little-endian prefix (payloads up to 4 GiB).
    U32Le,
    /// 8 bytes big-endian prefix (payloads up to 64-bit address space).
    U64Be,
    /// 8 bytes little-endian prefix (payloads up to 64-bit address space).
    U64Le,
}

impl LengthFieldKind {
    /// Size of the length prefix in bytes.
    pub const fn header_len(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16Be | Self::U16Le => 2,
            Self::U32Be | Self::U32Le => 4,
            Self::U64Be | Self::U64Le => 8,
        }
    }

    /// Maximum payload length supported by this length encoding.
    pub const fn max_length(self) -> usize {
        match self {
            Self::U8 => u8::MAX as usize,
            Self::U16Be | Self::U16Le => u16::MAX as usize,
            Self::U32Be | Self::U32Le => u32::MAX as usize,
            Self::U64Be | Self::U64Le => usize::MAX,
        }
    }

    /// Encode the length into the destination slice. Returns number of header bytes written.
    pub fn encode_len(self, len: usize, buf: &mut [u8]) -> io::Result<usize> {
        let needed = self.header_len();
        if buf.len() < needed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for frame length prefix",
            ));
        }
        match self {
            Self::U8 => {
                if len > u8::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("payload length {} exceeds u8 maximum ({})", len, u8::MAX),
                    ));
                }
                buf[0] = len as u8;
            }
            Self::U16Be => {
                if len > u16::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("payload length {} exceeds u16 maximum ({})", len, u16::MAX),
                    ));
                }
                buf[..2].copy_from_slice(&(len as u16).to_be_bytes());
            }
            Self::U16Le => {
                if len > u16::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("payload length {} exceeds u16 maximum ({})", len, u16::MAX),
                    ));
                }
                buf[..2].copy_from_slice(&(len as u16).to_le_bytes());
            }
            Self::U32Be => {
                if len > u32::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("payload length {} exceeds u32 maximum ({})", len, u32::MAX),
                    ));
                }
                buf[..4].copy_from_slice(&(len as u32).to_be_bytes());
            }
            Self::U32Le => {
                if len > u32::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("payload length {} exceeds u32 maximum ({})", len, u32::MAX),
                    ));
                }
                buf[..4].copy_from_slice(&(len as u32).to_le_bytes());
            }
            Self::U64Be => {
                buf[..8].copy_from_slice(&(len as u64).to_be_bytes());
            }
            Self::U64Le => {
                buf[..8].copy_from_slice(&(len as u64).to_le_bytes());
            }
        }
        Ok(needed)
    }

    /// Decode the length from an exact slice matching `header_len()`.
    pub fn decode_len(self, bytes: &[u8]) -> usize {
        match self {
            Self::U8 => bytes[0] as usize,
            Self::U16Be => u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
            Self::U16Le => u16::from_le_bytes([bytes[0], bytes[1]]) as usize,
            Self::U32Be => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            Self::U32Le => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            Self::U64Be => {
                let val = u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                val.min(usize::MAX as u64) as usize
            }
            Self::U64Le => {
                let val = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                val.min(usize::MAX as u64) as usize
            }
        }
    }
}

/// Stream writer that prefixes each payload with its byte length according to a `LengthFieldKind`.
#[derive(Debug, Clone)]
pub struct FramedWriter<W: Write> {
    inner: W,
    field_kind: LengthFieldKind,
    frames_written: u64,
    bytes_written: u64,
}

impl<W: Write> FramedWriter<W> {
    /// Create a new `FramedWriter` with standard 4-byte big-endian length prefix.
    pub fn new(writer: W) -> Self {
        Self::with_length_field(writer, LengthFieldKind::U32Be)
    }

    /// Create a new `FramedWriter` with the specified length field encoding.
    pub fn with_length_field(writer: W, field_kind: LengthFieldKind) -> Self {
        Self {
            inner: writer,
            field_kind,
            frames_written: 0,
            bytes_written: 0,
        }
    }

    /// Return the length field kind.
    pub fn length_field(&self) -> LengthFieldKind {
        self.field_kind
    }

    /// Total number of complete frames written.
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// Total number of bytes written (including length prefixes and payloads).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Write a frame payload prefixed by its encoded length.
    pub fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut header = [0u8; 8];
        let hlen = self.field_kind.encode_len(payload.len(), &mut header)?;
        self.inner.write_all(&header[..hlen])?;
        if !payload.is_empty() {
            self.inner.write_all(payload)?;
        }
        self.frames_written += 1;
        self.bytes_written += (hlen + payload.len()) as u64;
        Ok(())
    }

    /// Write a UTF-8 string frame.
    pub fn write_frame_str(&mut self, text: &str) -> io::Result<()> {
        self.write_frame(text.as_bytes())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consume this writer, returning the inner writer, field kind, frames written, and bytes written.
    pub fn into_parts(self) -> (W, LengthFieldKind, u64, u64) {
        (
            self.inner,
            self.field_kind,
            self.frames_written,
            self.bytes_written,
        )
    }
}

/// Helper function to create a new `FramedWriter` with standard 4-byte big-endian framing.
pub fn framed_writer<W: Write>(writer: W) -> FramedWriter<W> {
    FramedWriter::new(writer)
}

/// Default maximum frame size allowed (16 MiB) to guard against unbounded memory allocation.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Stream reader that unpacks length-delimited frames according to a `LengthFieldKind`.
#[derive(Debug, Clone)]
pub struct FramedReader<R: Read> {
    inner: R,
    field_kind: LengthFieldKind,
    max_frame_size: usize,
    frames_read: u64,
}

impl<R: Read> FramedReader<R> {
    /// Create a new `FramedReader` with standard 4-byte big-endian length prefix and 16 MiB max frame size.
    pub fn new(reader: R) -> Self {
        Self::with_options(reader, LengthFieldKind::U32Be, DEFAULT_MAX_FRAME_SIZE)
    }

    /// Create a new `FramedReader` with specified length field encoding and maximum frame size.
    pub fn with_options(reader: R, field_kind: LengthFieldKind, max_frame_size: usize) -> Self {
        Self {
            inner: reader,
            field_kind,
            max_frame_size: max_frame_size.max(1),
            frames_read: 0,
        }
    }

    /// Configured length field encoding.
    pub fn length_field(&self) -> LengthFieldKind {
        self.field_kind
    }

    /// Configured maximum payload size in bytes.
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Set a new maximum payload size in bytes (at least 1 byte).
    pub fn set_max_frame_size(&mut self, max: usize) {
        self.max_frame_size = max.max(1);
    }

    /// Number of frames successfully read so far.
    pub fn frames_read(&self) -> u64 {
        self.frames_read
    }

    /// Read the next frame payload into the provided reusable buffer.
    ///
    /// Clears `buf` before reading.
    /// Returns `Ok(Some(bytes_read))` or `Ok(None)` on clean EOF before any header bytes are read.
    /// Returns `Err(UnexpectedEof)` if EOF occurs midway through reading the header or payload.
    /// Returns `Err(InvalidData)` if the header indicates a frame larger than `max_frame_size`.
    pub fn read_frame_buf(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<usize>> {
        buf.clear();
        let hlen = self.field_kind.header_len();
        let mut header = [0u8; 8];
        let mut header_read = 0;

        while header_read < hlen {
            let n = self.inner.read(&mut header[header_read..hlen])?;
            if n == 0 {
                if header_read == 0 {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "incomplete length prefix: read {} of {} bytes",
                            header_read, hlen
                        ),
                    ));
                }
            }
            header_read += n;
        }

        let payload_len = self.field_kind.decode_len(&header[..hlen]);
        if payload_len > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame payload length {} exceeds configured maximum {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        buf.resize(payload_len, 0);
        if payload_len > 0 {
            self.inner.read_exact(buf)?;
        }

        self.frames_read += 1;
        Ok(Some(payload_len))
    }

    /// Read the next complete frame from the stream into a new `Vec<u8>`.
    ///
    /// Returns `Ok(None)` on clean EOF before any header byte is read.
    pub fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        match self.read_frame_buf(&mut buf)? {
            Some(_) => Ok(Some(buf)),
            None => Ok(None),
        }
    }

    /// Read the next frame and parse it as a UTF-8 string.
    pub fn read_frame_to_string(&mut self) -> io::Result<Option<String>> {
        match self.read_frame()? {
            Some(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid UTF-8 in frame: {}", e),
                )
            }),
            None => Ok(None),
        }
    }

    /// Convert this `FramedReader` into an iterator yielding frame byte buffers.
    pub fn into_frames(self) -> FramedIter<R> {
        FramedIter { reader: self }
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consume this reader, returning inner reader, field kind, max frame size, and frames read.
    pub fn into_parts(self) -> (R, LengthFieldKind, usize, u64) {
        (
            self.inner,
            self.field_kind,
            self.max_frame_size,
            self.frames_read,
        )
    }
}

/// Helper function to create a new `FramedReader` with standard 4-byte big-endian framing.
pub fn framed_reader<R: Read>(reader: R) -> FramedReader<R> {
    FramedReader::new(reader)
}

/// Iterator over frames produced by a `FramedReader`.
#[derive(Debug)]
pub struct FramedIter<R: Read> {
    reader: FramedReader<R>,
}

impl<R: Read> FramedIter<R> {
    /// Reference to the underlying framed reader.
    pub fn get_ref(&self) -> &FramedReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying framed reader.
    pub fn get_mut(&mut self) -> &mut FramedReader<R> {
        &mut self.reader
    }

    /// Unwrap the inner `FramedReader`.
    pub fn into_inner(self) -> FramedReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for FramedIter<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// CRC-32 Verified Framed Reader & Writer
// ---------------------------------------------------------------------------

/// Stream writer that prefixes each payload with its byte length and an IEEE 802.3 CRC-32 checksum.
///
/// Each frame written has the structure:
/// `[length: header_len][crc32: 4 bytes BE][payload: length bytes]`
#[derive(Debug, Clone)]
pub struct CrcFramedWriter<W: Write> {
    inner: W,
    field_kind: LengthFieldKind,
    frames_written: u64,
    bytes_written: u64,
}

impl<W: Write> CrcFramedWriter<W> {
    /// Create a new `CrcFramedWriter` with standard 4-byte big-endian length prefix.
    pub fn new(writer: W) -> Self {
        Self::with_length_field(writer, LengthFieldKind::U32Be)
    }

    /// Create a new `CrcFramedWriter` with the specified length field encoding.
    pub fn with_length_field(writer: W, field_kind: LengthFieldKind) -> Self {
        Self {
            inner: writer,
            field_kind,
            frames_written: 0,
            bytes_written: 0,
        }
    }

    /// Return the length field kind.
    pub fn length_field(&self) -> LengthFieldKind {
        self.field_kind
    }

    /// Total number of complete frames written.
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// Total number of bytes written (including length prefixes, CRC-32 checksums, and payloads).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Write a frame payload prefixed by its encoded length and 4-byte big-endian CRC-32 checksum.
    pub fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut header = [0u8; 8];
        let hlen = self.field_kind.encode_len(payload.len(), &mut header)?;
        let crc = crc32_digest(payload);
        self.inner.write_all(&header[..hlen])?;
        self.inner.write_all(&crc.to_be_bytes())?;
        if !payload.is_empty() {
            self.inner.write_all(payload)?;
        }
        self.frames_written += 1;
        self.bytes_written += (hlen + 4 + payload.len()) as u64;
        Ok(())
    }

    /// Write a UTF-8 string frame.
    pub fn write_frame_str(&mut self, text: &str) -> io::Result<()> {
        self.write_frame(text.as_bytes())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consume this writer, returning the inner writer, field kind, frames written, and bytes written.
    pub fn into_parts(self) -> (W, LengthFieldKind, u64, u64) {
        (
            self.inner,
            self.field_kind,
            self.frames_written,
            self.bytes_written,
        )
    }
}

/// Helper function to create a new `CrcFramedWriter` with standard 4-byte big-endian framing.
pub fn crc_framed_writer<W: Write>(writer: W) -> CrcFramedWriter<W> {
    CrcFramedWriter::new(writer)
}

/// Stream reader that unpacks length-delimited frames verified by an IEEE 802.3 CRC-32 checksum.
#[derive(Debug, Clone)]
pub struct CrcFramedReader<R: Read> {
    inner: R,
    field_kind: LengthFieldKind,
    max_frame_size: usize,
    frames_read: u64,
}

impl<R: Read> CrcFramedReader<R> {
    /// Create a new `CrcFramedReader` with standard 4-byte big-endian length prefix and default max frame size (16 MiB).
    pub fn new(reader: R) -> Self {
        Self::with_options(reader, LengthFieldKind::U32Be, DEFAULT_MAX_FRAME_SIZE)
    }

    /// Create a new `CrcFramedReader` with specified length field encoding and maximum frame size.
    pub fn with_options(reader: R, field_kind: LengthFieldKind, max_frame_size: usize) -> Self {
        Self {
            inner: reader,
            field_kind,
            max_frame_size: max_frame_size.max(1),
            frames_read: 0,
        }
    }

    /// Configured length field encoding.
    pub fn length_field(&self) -> LengthFieldKind {
        self.field_kind
    }

    /// Configured maximum payload size in bytes.
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Set a new maximum payload size in bytes (at least 1 byte).
    pub fn set_max_frame_size(&mut self, max: usize) {
        self.max_frame_size = max.max(1);
    }

    /// Number of frames successfully read and verified so far.
    pub fn frames_read(&self) -> u64 {
        self.frames_read
    }

    /// Read the next frame payload into the provided reusable buffer and verify CRC-32 checksum.
    ///
    /// Clears `buf` before reading.
    /// Returns `Ok(Some(bytes_read))` or `Ok(None)` on clean EOF before any header bytes are read.
    /// Returns `Err(UnexpectedEof)` if EOF occurs midway through reading the header, CRC, or payload.
    /// Returns `Err(InvalidData)` if the header indicates a frame larger than `max_frame_size` or if CRC-32 verification fails.
    pub fn read_frame_buf(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<usize>> {
        buf.clear();
        let hlen = self.field_kind.header_len();
        let mut header = [0u8; 8];
        let mut header_read = 0;

        while header_read < hlen {
            let n = self.inner.read(&mut header[header_read..hlen])?;
            if n == 0 {
                if header_read == 0 {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "incomplete CRC frame length prefix: read {} of {} bytes",
                            header_read, hlen
                        ),
                    ));
                }
            }
            header_read += n;
        }

        let payload_len = self.field_kind.decode_len(&header[..hlen]);
        if payload_len > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "CRC frame payload length {} exceeds configured maximum {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        let mut crc_buf = [0u8; 4];
        self.inner.read_exact(&mut crc_buf)?;
        let expected_crc = u32::from_be_bytes(crc_buf);

        buf.resize(payload_len, 0);
        if payload_len > 0 {
            self.inner.read_exact(buf)?;
        }

        let actual_crc = crc32_digest(buf);
        if actual_crc != expected_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "CRC-32 checksum mismatch: expected 0x{:08X}, computed 0x{:08X}",
                    expected_crc, actual_crc
                ),
            ));
        }

        self.frames_read += 1;
        Ok(Some(payload_len))
    }

    /// Read the next complete verified frame from the stream into a new `Vec<u8>`.
    ///
    /// Returns `Ok(None)` on clean EOF before any header byte is read.
    pub fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        match self.read_frame_buf(&mut buf)? {
            Some(_) => Ok(Some(buf)),
            None => Ok(None),
        }
    }

    /// Read the next frame and parse it as a UTF-8 string.
    pub fn read_frame_to_string(&mut self) -> io::Result<Option<String>> {
        match self.read_frame()? {
            Some(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid UTF-8 in CRC frame: {}", e),
                )
            }),
            None => Ok(None),
        }
    }

    /// Convert this `CrcFramedReader` into an iterator yielding verified frame byte buffers.
    pub fn into_frames(self) -> CrcFramedIter<R> {
        CrcFramedIter { reader: self }
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consume this reader, returning inner reader, field kind, max frame size, and frames read.
    pub fn into_parts(self) -> (R, LengthFieldKind, usize, u64) {
        (
            self.inner,
            self.field_kind,
            self.max_frame_size,
            self.frames_read,
        )
    }
}

/// Helper function to create a new `CrcFramedReader` with standard 4-byte big-endian framing.
pub fn crc_framed_reader<R: Read>(reader: R) -> CrcFramedReader<R> {
    CrcFramedReader::new(reader)
}

/// Iterator over CRC-validated frames produced by a `CrcFramedReader`.
#[derive(Debug)]
pub struct CrcFramedIter<R: Read> {
    reader: CrcFramedReader<R>,
}

impl<R: Read> CrcFramedIter<R> {
    /// Reference to the underlying framed reader.
    pub fn get_ref(&self) -> &CrcFramedReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying framed reader.
    pub fn get_mut(&mut self) -> &mut CrcFramedReader<R> {
        &mut self.reader
    }

    /// Unwrap the inner `CrcFramedReader`.
    pub fn into_inner(self) -> CrcFramedReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for CrcFramedIter<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

// ─── Varint / LEB128 & ZigZag Encoding and I/O Adapters ──────────────────────

/// Maximum length in bytes of an encoded 64-bit unsigned integer (LEB128 varint).
pub const MAX_VARINT_LEN_U64: usize = 10;

/// Maximum length in bytes of an encoded 32-bit unsigned integer (LEB128 varint).
pub const MAX_VARINT_LEN_U32: usize = 5;

/// ZigZag-encodes a signed 64-bit integer into an unsigned 64-bit integer.
///
/// Maps small signed integers (positive or negative) to small unsigned integers:
/// `0 -> 0`, `-1 -> 1`, `1 -> 2`, `-2 -> 3`, etc.
#[inline]
pub const fn zigzag_encode(val: i64) -> u64 {
    ((val as u64) << 1) ^ ((val >> 63) as u64)
}

/// Decodes a ZigZag-encoded unsigned 64-bit integer back to a signed 64-bit integer.
#[inline]
pub const fn zigzag_decode(val: u64) -> i64 {
    let half = (val >> 1) as i64;
    if (val & 1) == 1 {
        !half
    } else {
        half
    }
}

/// Encodes a 64-bit unsigned integer into standard LEB128 varint format into `buf`.
///
/// Returns the number of bytes written (between 1 and 10).
///
/// # Panics
/// Panics if `buf.len()` is insufficient to hold the encoded value.
pub fn encode_uvarint(mut val: u64, buf: &mut [u8]) -> usize {
    let mut i = 0;
    while val >= 0x80 {
        assert!(i < buf.len(), "buffer too small for varint encoding");
        buf[i] = ((val & 0x7F) as u8) | 0x80;
        val >>= 7;
        i += 1;
    }
    assert!(i < buf.len(), "buffer too small for varint encoding");
    buf[i] = val as u8;
    i + 1
}

/// Encodes a 64-bit unsigned integer into standard LEB128 varint format, appending bytes to `out`.
///
/// Returns the number of bytes appended (between 1 and 10).
pub fn encode_uvarint_vec(mut val: u64, out: &mut Vec<u8>) -> usize {
    let mut count = 0;
    while val >= 0x80 {
        out.push(((val & 0x7F) as u8) | 0x80);
        val >>= 7;
        count += 1;
    }
    out.push(val as u8);
    count + 1
}

/// Decodes a 64-bit unsigned integer from a LEB128 varint byte slice.
///
/// Returns `Ok((value, bytes_consumed))` on success.
/// Returns `ErrorKind::UnexpectedEof` if the slice ends before the termination byte.
/// Returns `ErrorKind::InvalidData` if the encoded integer overflows 64 bits.
pub fn decode_uvarint(slice: &[u8]) -> io::Result<(u64, usize)> {
    let mut res: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in slice.iter().enumerate() {
        if i >= MAX_VARINT_LEN_U64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varint overflow: exceeds 64-bit integer representation",
            ));
        }
        let val = (byte & 0x7F) as u64;
        if i == 9 && val > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varint overflow: 10th byte exceeds 1-bit capacity for 64-bit unsigned integer",
            ));
        }
        res |= val << shift;
        if (byte & 0x80) == 0 {
            return Ok((res, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Unexpected EOF while decoding varint",
    ))
}

/// Encodes a signed 64-bit integer using ZigZag encoding and LEB128 varint into `buf`.
///
/// Returns the number of bytes written.
pub fn encode_ivarint(val: i64, buf: &mut [u8]) -> usize {
    encode_uvarint(zigzag_encode(val), buf)
}

/// Decodes a signed 64-bit integer from a ZigZag-encoded LEB128 byte slice.
///
/// Returns `Ok((value, bytes_consumed))`.
pub fn decode_ivarint(slice: &[u8]) -> io::Result<(i64, usize)> {
    let (u, len) = decode_uvarint(slice)?;
    Ok((zigzag_decode(u), len))
}

/// Writes an unsigned 64-bit integer as a LEB128 varint to `writer`.
///
/// Returns the number of bytes written.
pub fn write_uvarint<W: Write>(writer: &mut W, val: u64) -> io::Result<usize> {
    let mut buf = [0u8; MAX_VARINT_LEN_U64];
    let n = encode_uvarint(val, &mut buf);
    writer.write_all(&buf[..n])?;
    Ok(n)
}

/// Writes a signed 64-bit integer as a ZigZag-encoded LEB128 varint to `writer`.
///
/// Returns the number of bytes written.
pub fn write_ivarint<W: Write>(writer: &mut W, val: i64) -> io::Result<usize> {
    write_uvarint(writer, zigzag_encode(val))
}

/// Attempts to read an unsigned 64-bit integer as a LEB128 varint from `reader`.
///
/// Returns `Ok(Some(value))` if successfully decoded.
/// Returns `Ok(None)` if clean EOF is encountered before any byte is read.
/// Returns `ErrorKind::UnexpectedEof` if EOF occurs after reading partial continuation bytes.
/// Returns `ErrorKind::InvalidData` if the integer exceeds 64 bits.
pub fn try_read_uvarint<R: Read>(reader: &mut R) -> io::Result<Option<u64>> {
    let mut res: u64 = 0;
    let mut shift: u32 = 0;
    let mut buf = [0u8; 1];
    let mut bytes_read = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            if bytes_read == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading varint sequence",
            ));
        }

        let byte = buf[0];
        bytes_read += 1;

        if bytes_read > MAX_VARINT_LEN_U64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varint overflow: exceeds 64-bit integer representation",
            ));
        }

        let val = (byte & 0x7F) as u64;
        if bytes_read == 10 && val > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varint overflow: 10th byte exceeds 1-bit capacity for 64-bit unsigned integer",
            ));
        }

        res |= val << shift;
        if (byte & 0x80) == 0 {
            return Ok(Some(res));
        }
        shift += 7;
    }
}

/// Reads an unsigned 64-bit integer as a LEB128 varint from `reader`.
///
/// Returns `ErrorKind::UnexpectedEof` if no bytes are available or stream ends prematurely.
pub fn read_uvarint<R: Read>(reader: &mut R) -> io::Result<u64> {
    match try_read_uvarint(reader)? {
        Some(v) => Ok(v),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Unexpected EOF: no varint data available",
        )),
    }
}

/// Attempts to read a signed 64-bit ZigZag-encoded LEB128 varint from `reader`.
pub fn try_read_ivarint<R: Read>(reader: &mut R) -> io::Result<Option<i64>> {
    Ok(try_read_uvarint(reader)?.map(zigzag_decode))
}

/// Reads a signed 64-bit ZigZag-encoded LEB128 varint from `reader`.
pub fn read_ivarint<R: Read>(reader: &mut R) -> io::Result<i64> {
    let u = read_uvarint(reader)?;
    Ok(zigzag_decode(u))
}

/// Encodes a signed 64-bit integer using two's-complement SLEB128 into `buf`.
///
/// Returns the number of bytes written (between 1 and 10).
///
/// # Panics
/// Panics if `buf.len()` is insufficient to hold the encoded value.
pub fn encode_sleb128(mut val: i64, buf: &mut [u8]) -> usize {
    let mut i = 0;
    let mut more = true;
    while more {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if (val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0) {
            more = false;
            assert!(i < buf.len(), "buffer too small for SLEB128 encoding");
            buf[i] = byte;
        } else {
            assert!(i < buf.len(), "buffer too small for SLEB128 encoding");
            buf[i] = byte | 0x80;
        }
        i += 1;
    }
    i
}

/// Encodes a signed 64-bit integer using two's-complement SLEB128, appending bytes to `out`.
///
/// Returns the number of bytes appended (between 1 and 10).
pub fn encode_sleb128_vec(mut val: i64, out: &mut Vec<u8>) -> usize {
    let mut count = 0;
    let mut more = true;
    while more {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if (val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0) {
            more = false;
            out.push(byte);
        } else {
            out.push(byte | 0x80);
        }
        count += 1;
    }
    count
}

/// Decodes a signed 64-bit integer from a two's-complement SLEB128 byte slice.
///
/// Returns `Ok((value, bytes_consumed))` on success.
/// Returns `ErrorKind::UnexpectedEof` if the slice ends before the termination byte.
/// Returns `ErrorKind::InvalidData` if the encoded integer overflows 64 bits.
pub fn decode_sleb128(slice: &[u8]) -> io::Result<(i64, usize)> {
    let mut res: i64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in slice.iter().enumerate() {
        if i >= MAX_VARINT_LEN_U64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SLEB128 overflow: exceeds 64-bit signed integer representation",
            ));
        }

        if i == 9 && byte != 0x00 && byte != 0x7F {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SLEB128 overflow: 10th byte contains invalid sign-extension bits",
            ));
        }

        res |= ((byte & 0x7F) as i64) << shift;
        shift += 7;

        if (byte & 0x80) == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                res |= !0i64 << shift;
            }
            return Ok((res, i + 1));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Unexpected EOF while decoding SLEB128",
    ))
}

/// Writes a signed 64-bit integer as a two's-complement SLEB128 varint to `writer`.
///
/// Returns the number of bytes written.
pub fn write_sleb128<W: Write>(writer: &mut W, val: i64) -> io::Result<usize> {
    let mut buf = [0u8; MAX_VARINT_LEN_U64];
    let n = encode_sleb128(val, &mut buf);
    writer.write_all(&buf[..n])?;
    Ok(n)
}

/// Attempts to read a signed 64-bit integer as a two's-complement SLEB128 varint from `reader`.
///
/// Returns `Ok(Some(value))` if successfully decoded.
/// Returns `Ok(None)` if clean EOF is encountered before any byte is read.
/// Returns `ErrorKind::UnexpectedEof` if EOF occurs after reading partial continuation bytes.
/// Returns `ErrorKind::InvalidData` if the integer exceeds 64 bits.
pub fn try_read_sleb128<R: Read>(reader: &mut R) -> io::Result<Option<i64>> {
    let mut res: i64 = 0;
    let mut shift: u32 = 0;
    let mut buf = [0u8; 1];
    let mut bytes_read = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            if bytes_read == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading SLEB128 sequence",
            ));
        }

        let byte = buf[0];
        bytes_read += 1;

        if bytes_read > MAX_VARINT_LEN_U64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SLEB128 overflow: exceeds 64-bit signed integer representation",
            ));
        }

        if bytes_read == 10 && byte != 0x00 && byte != 0x7F {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SLEB128 overflow: 10th byte contains invalid sign-extension bits",
            ));
        }

        res |= ((byte & 0x7F) as i64) << shift;
        shift += 7;

        if (byte & 0x80) == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                res |= !0i64 << shift;
            }
            return Ok(Some(res));
        }
    }
}

/// Reads a signed 64-bit integer as a two's-complement SLEB128 varint from `reader`.
///
/// Returns `ErrorKind::UnexpectedEof` if no bytes are available or stream ends prematurely.
pub fn read_sleb128<R: Read>(reader: &mut R) -> io::Result<i64> {
    match try_read_sleb128(reader)? {
        Some(v) => Ok(v),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Unexpected EOF: no SLEB128 data available",
        )),
    }
}

/// Stream writer adapter that encodes integers as compact LEB128 / ZigZag varints.
#[derive(Debug, Clone)]
pub struct VarintWriter<W: Write> {
    inner: W,
    values_written: u64,
    bytes_written: u64,
}

impl<W: Write> VarintWriter<W> {
    /// Create a new `VarintWriter` wrapping `inner`.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            values_written: 0,
            bytes_written: 0,
        }
    }

    /// Write an unsigned 64-bit integer in LEB128 format.
    pub fn write_uvarint(&mut self, val: u64) -> io::Result<usize> {
        let n = write_uvarint(&mut self.inner, val)?;
        self.values_written += 1;
        self.bytes_written += n as u64;
        Ok(n)
    }

    /// Write a signed 64-bit integer in ZigZag LEB128 format.
    pub fn write_ivarint(&mut self, val: i64) -> io::Result<usize> {
        let n = write_ivarint(&mut self.inner, val)?;
        self.values_written += 1;
        self.bytes_written += n as u64;
        Ok(n)
    }

    /// Write an unsigned 32-bit integer in LEB128 format.
    pub fn write_u32(&mut self, val: u32) -> io::Result<usize> {
        self.write_uvarint(val as u64)
    }

    /// Write a signed 32-bit integer in ZigZag LEB128 format.
    pub fn write_i32(&mut self, val: i32) -> io::Result<usize> {
        self.write_ivarint(val as i64)
    }

    /// Write a signed 64-bit integer in two's-complement SLEB128 format.
    pub fn write_sleb128(&mut self, val: i64) -> io::Result<usize> {
        let n = write_sleb128(&mut self.inner, val)?;
        self.values_written += 1;
        self.bytes_written += n as u64;
        Ok(n)
    }

    /// Write a signed 32-bit integer in two's-complement SLEB128 format.
    pub fn write_sleb128_i32(&mut self, val: i32) -> io::Result<usize> {
        self.write_sleb128(val as i64)
    }

    /// Total count of integer values written through this adapter.
    pub fn values_written(&self) -> u64 {
        self.values_written
    }

    /// Total count of bytes written through this adapter.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consume this adapter, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consume this adapter, returning `(inner, values_written, bytes_written)`.
    pub fn into_parts(self) -> (W, u64, u64) {
        (self.inner, self.values_written, self.bytes_written)
    }
}

impl<W: Write> Write for VarintWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Stream reader adapter that decodes compact LEB128 / ZigZag varints.
#[derive(Debug, Clone)]
pub struct VarintReader<R: Read> {
    inner: R,
    values_read: u64,
    bytes_read: u64,
}

impl<R: Read> VarintReader<R> {
    /// Create a new `VarintReader` wrapping `inner`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            values_read: 0,
            bytes_read: 0,
        }
    }

    /// Attempt to read the next unsigned 64-bit LEB128 varint.
    ///
    /// Returns `Ok(Some(val))` on success, or `Ok(None)` if clean EOF is reached.
    pub fn try_read_uvarint(&mut self) -> io::Result<Option<u64>> {
        let mut res: u64 = 0;
        let mut shift: u32 = 0;
        let mut buf = [0u8; 1];
        let mut bytes_for_this = 0;

        loop {
            let n = self.inner.read(&mut buf)?;
            if n == 0 {
                if bytes_for_this == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF in the middle of varint byte sequence",
                ));
            }

            let byte = buf[0];
            bytes_for_this += 1;
            self.bytes_read += 1;

            if bytes_for_this > MAX_VARINT_LEN_U64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Varint overflow: exceeds 64-bit integer representation",
                ));
            }

            let val = (byte & 0x7F) as u64;
            if bytes_for_this == 10 && val > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Varint overflow: 10th byte exceeds 1-bit capacity for 64-bit unsigned integer",
                ));
            }

            res |= val << shift;
            if (byte & 0x80) == 0 {
                self.values_read += 1;
                return Ok(Some(res));
            }
            shift += 7;
        }
    }

    /// Read the next unsigned 64-bit LEB128 varint.
    pub fn read_uvarint(&mut self) -> io::Result<u64> {
        match self.try_read_uvarint()? {
            Some(v) => Ok(v),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF: no varint data available",
            )),
        }
    }

    /// Attempt to read the next signed 64-bit ZigZag LEB128 varint.
    pub fn try_read_ivarint(&mut self) -> io::Result<Option<i64>> {
        Ok(self.try_read_uvarint()?.map(zigzag_decode))
    }

    /// Read the next signed 64-bit ZigZag LEB128 varint.
    pub fn read_ivarint(&mut self) -> io::Result<i64> {
        let u = self.read_uvarint()?;
        Ok(zigzag_decode(u))
    }

    /// Read the next unsigned 32-bit LEB128 varint.
    pub fn read_u32(&mut self) -> io::Result<u32> {
        let val = self.read_uvarint()?;
        if val > u32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varint value exceeds u32 range",
            ));
        }
        Ok(val as u32)
    }

    /// Read the next signed 32-bit ZigZag LEB128 varint.
    pub fn read_i32(&mut self) -> io::Result<i32> {
        let val = self.read_ivarint()?;
        if val < (i32::MIN as i64) || val > (i32::MAX as i64) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varint value exceeds i32 range",
            ));
        }
        Ok(val as i32)
    }

    /// Attempt to read the next signed 64-bit integer in two's-complement SLEB128 format.
    pub fn try_read_sleb128(&mut self) -> io::Result<Option<i64>> {
        let mut res: i64 = 0;
        let mut shift: u32 = 0;
        let mut buf = [0u8; 1];
        let mut bytes_for_this = 0;

        loop {
            let n = self.inner.read(&mut buf)?;
            if n == 0 {
                if bytes_for_this == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF in the middle of SLEB128 byte sequence",
                ));
            }

            let byte = buf[0];
            bytes_for_this += 1;
            self.bytes_read += 1;

            if bytes_for_this > MAX_VARINT_LEN_U64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 overflow: exceeds 64-bit signed integer representation",
                ));
            }

            if bytes_for_this == 10 && byte != 0x00 && byte != 0x7F {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 overflow: 10th byte contains invalid sign-extension bits",
                ));
            }

            res |= ((byte & 0x7F) as i64) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                if shift < 64 && (byte & 0x40) != 0 {
                    res |= !0i64 << shift;
                }
                self.values_read += 1;
                return Ok(Some(res));
            }
        }
    }

    /// Read the next signed 64-bit integer in two's-complement SLEB128 format.
    pub fn read_sleb128(&mut self) -> io::Result<i64> {
        match self.try_read_sleb128()? {
            Some(v) => Ok(v),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF: no SLEB128 data available",
            )),
        }
    }

    /// Read the next signed 32-bit integer in two's-complement SLEB128 format.
    pub fn read_sleb128_i32(&mut self) -> io::Result<i32> {
        let val = self.read_sleb128()?;
        if val < (i32::MIN as i64) || val > (i32::MAX as i64) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SLEB128 value exceeds i32 range",
            ));
        }
        Ok(val as i32)
    }

    /// Total count of integer values read through this adapter.
    pub fn values_read(&self) -> u64 {
        self.values_read
    }

    /// Total count of bytes read through this adapter.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consume this adapter, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consume this adapter, returning `(inner, values_read, bytes_read)`.
    pub fn into_parts(self) -> (R, u64, u64) {
        (self.inner, self.values_read, self.bytes_read)
    }

    /// Create an iterator yielding `io::Result<u64>` until clean EOF.
    pub fn into_uvarints(self) -> UVarintIter<R> {
        UVarintIter { reader: self }
    }

    /// Create an iterator yielding `io::Result<i64>` until clean EOF.
    pub fn into_ivarints(self) -> IVarintIter<R> {
        IVarintIter { reader: self }
    }

    /// Create an iterator yielding `io::Result<i64>` decoded as two's-complement SLEB128 until clean EOF.
    pub fn into_sleb128s(self) -> Sleb128Iter<R> {
        Sleb128Iter { reader: self }
    }
}

impl<R: Read> Read for VarintReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

/// Iterator over unsigned 64-bit varints read from a `VarintReader`.
#[derive(Debug)]
pub struct UVarintIter<R: Read> {
    reader: VarintReader<R>,
}

impl<R: Read> UVarintIter<R> {
    /// Reference to the underlying `VarintReader`.
    pub fn get_ref(&self) -> &VarintReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying `VarintReader`.
    pub fn get_mut(&mut self) -> &mut VarintReader<R> {
        &mut self.reader
    }

    /// Consume this iterator, returning the underlying `VarintReader`.
    pub fn into_inner(self) -> VarintReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for UVarintIter<R> {
    type Item = io::Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.try_read_uvarint() {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Iterator over signed 64-bit varints read from a `VarintReader`.
#[derive(Debug)]
pub struct IVarintIter<R: Read> {
    reader: VarintReader<R>,
}

impl<R: Read> IVarintIter<R> {
    /// Reference to the underlying `VarintReader`.
    pub fn get_ref(&self) -> &VarintReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying `VarintReader`.
    pub fn get_mut(&mut self) -> &mut VarintReader<R> {
        &mut self.reader
    }

    /// Consume this iterator, returning the underlying `VarintReader`.
    pub fn into_inner(self) -> VarintReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for IVarintIter<R> {
    type Item = io::Result<i64>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.try_read_ivarint() {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Iterator over two's-complement SLEB128 signed integers read from a `VarintReader`.
#[derive(Debug)]
pub struct Sleb128Iter<R: Read> {
    reader: VarintReader<R>,
}

impl<R: Read> Sleb128Iter<R> {
    /// Reference to the underlying `VarintReader`.
    pub fn get_ref(&self) -> &VarintReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying `VarintReader`.
    pub fn get_mut(&mut self) -> &mut VarintReader<R> {
        &mut self.reader
    }

    /// Consume this iterator, returning the underlying `VarintReader`.
    pub fn into_inner(self) -> VarintReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for Sleb128Iter<R> {
    type Item = io::Result<i64>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.try_read_sleb128() {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Convenience constructor for [`VarintWriter`].
pub fn varint_writer<W: Write>(writer: W) -> VarintWriter<W> {
    VarintWriter::new(writer)
}

/// Convenience constructor for [`VarintReader`].
pub fn varint_reader<R: Read>(reader: R) -> VarintReader<R> {
    VarintReader::new(reader)
}

// ─── Varint-Delimited Framed Stream Adapters ─────────────────────────────────

/// Stream writer that prefixes each payload with its byte length encoded as a compact LEB128 varint.
///
/// Varint framing is used in binary streaming protocols (such as Protocol Buffers length-delimited
/// messages, QUIC stream chunks, and WebAssembly modules) to avoid fixed multi-byte header overhead.
/// Payloads up to 127 bytes require only a single-byte length prefix.
#[derive(Debug, Clone)]
pub struct VarintFramedWriter<W: Write> {
    inner: W,
    frames_written: u64,
    bytes_written: u64,
}

impl<W: Write> VarintFramedWriter<W> {
    /// Create a new `VarintFramedWriter` wrapping `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            frames_written: 0,
            bytes_written: 0,
        }
    }

    /// Total number of complete frames written.
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// Total number of bytes written (including varint length prefixes and payloads).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Write a frame payload prefixed by its LEB128 varint length.
    pub fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut header = [0u8; MAX_VARINT_LEN_U64];
        let hlen = encode_uvarint(payload.len() as u64, &mut header);
        self.inner.write_all(&header[..hlen])?;
        if !payload.is_empty() {
            self.inner.write_all(payload)?;
        }
        self.frames_written += 1;
        self.bytes_written += (hlen + payload.len()) as u64;
        Ok(())
    }

    /// Write a UTF-8 string frame.
    pub fn write_frame_str(&mut self, text: &str) -> io::Result<()> {
        self.write_frame(text.as_bytes())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consume this writer, returning the inner writer, frames written, and bytes written.
    pub fn into_parts(self) -> (W, u64, u64) {
        (self.inner, self.frames_written, self.bytes_written)
    }
}

/// Helper constructor to create a new [`VarintFramedWriter`].
pub fn varint_framed_writer<W: Write>(writer: W) -> VarintFramedWriter<W> {
    VarintFramedWriter::new(writer)
}

/// Stream reader that unpacks frames delimited by a compact LEB128 varint length prefix.
#[derive(Debug, Clone)]
pub struct VarintFramedReader<R: Read> {
    inner: R,
    max_frame_size: usize,
    frames_read: u64,
}

impl<R: Read> VarintFramedReader<R> {
    /// Create a new `VarintFramedReader` with the default maximum frame size (16 MiB).
    pub fn new(reader: R) -> Self {
        Self::with_max_frame_size(reader, DEFAULT_MAX_FRAME_SIZE)
    }

    /// Create a new `VarintFramedReader` with a specified maximum frame size in bytes.
    pub fn with_max_frame_size(reader: R, max_frame_size: usize) -> Self {
        Self {
            inner: reader,
            max_frame_size: max_frame_size.max(1),
            frames_read: 0,
        }
    }

    /// Configured maximum payload size in bytes.
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Set a new maximum payload size in bytes (at least 1 byte).
    pub fn set_max_frame_size(&mut self, max: usize) {
        self.max_frame_size = max.max(1);
    }

    /// Number of frames successfully read so far.
    pub fn frames_read(&self) -> u64 {
        self.frames_read
    }

    /// Read the next frame payload into the provided reusable buffer.
    ///
    /// Clears `buf` before reading.
    /// Returns `Ok(Some(bytes_read))` or `Ok(None)` on clean EOF before any header bytes are read.
    /// Returns `Err(UnexpectedEof)` if EOF occurs midway through reading the varint header or payload.
    /// Returns `Err(InvalidData)` if the header indicates a frame larger than `max_frame_size`.
    pub fn read_frame_buf(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<usize>> {
        buf.clear();
        let payload_len = match try_read_uvarint(&mut self.inner)? {
            Some(len) => len,
            None => return Ok(None),
        };

        if payload_len > (self.max_frame_size as u64) || payload_len > (usize::MAX as u64) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "varint frame payload length {} exceeds configured maximum {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        let len = payload_len as usize;
        buf.resize(len, 0);
        self.inner.read_exact(buf)?;
        self.frames_read += 1;
        Ok(Some(len))
    }

    /// Read the next frame payload into a newly allocated `Vec<u8>`.
    ///
    /// Returns `Ok(Some(frame))` or `Ok(None)` on clean EOF.
    pub fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        match self.read_frame_buf(&mut buf)? {
            Some(_) => Ok(Some(buf)),
            None => Ok(None),
        }
    }

    /// Read the next frame and parse it as a UTF-8 string.
    pub fn read_frame_to_string(&mut self) -> io::Result<Option<String>> {
        match self.read_frame()? {
            Some(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid UTF-8 in varint frame: {}", e),
                )
            }),
            None => Ok(None),
        }
    }

    /// Convert this `VarintFramedReader` into an iterator yielding frame byte buffers.
    pub fn into_frames(self) -> VarintFramedIter<R> {
        VarintFramedIter { reader: self }
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consume this reader, returning inner reader, max frame size, and frames read.
    pub fn into_parts(self) -> (R, usize, u64) {
        (self.inner, self.max_frame_size, self.frames_read)
    }
}

/// Helper constructor to create a new [`VarintFramedReader`].
pub fn varint_framed_reader<R: Read>(reader: R) -> VarintFramedReader<R> {
    VarintFramedReader::new(reader)
}

/// Iterator over frames produced by a [`VarintFramedReader`].
#[derive(Debug)]
pub struct VarintFramedIter<R: Read> {
    reader: VarintFramedReader<R>,
}

impl<R: Read> VarintFramedIter<R> {
    /// Reference to the underlying framed reader.
    pub fn get_ref(&self) -> &VarintFramedReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying framed reader.
    pub fn get_mut(&mut self) -> &mut VarintFramedReader<R> {
        &mut self.reader
    }

    /// Unwrap the inner `VarintFramedReader`.
    pub fn into_inner(self) -> VarintFramedReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for VarintFramedIter<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Helper function to locate a byte needle in a haystack slice without allocations.
#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Default maximum record size for delimited streams (16 MiB).
pub const DEFAULT_MAX_DELIMITED_RECORD_SIZE: usize = 16 * 1024 * 1024;

/// A writer wrapper that writes structured records separated by a custom multi-byte delimiter.
#[derive(Debug)]
pub struct DelimitedWriter<W: Write> {
    inner: W,
    delimiter: Vec<u8>,
    records_written: usize,
    bytes_written: usize,
}

impl<W: Write> DelimitedWriter<W> {
    /// Create a new `DelimitedWriter` with the specified delimiter.
    pub fn new(inner: W, delimiter: impl Into<Vec<u8>>) -> Self {
        let delimiter = delimiter.into();
        assert!(!delimiter.is_empty(), "delimiter must not be empty");
        Self {
            inner,
            delimiter,
            records_written: 0,
            bytes_written: 0,
        }
    }

    /// Returns a slice to the delimiter.
    pub fn delimiter(&self) -> &[u8] {
        &self.delimiter
    }

    /// Number of records successfully written through `write_record` or `write_record_str`.
    pub fn records_written(&self) -> usize {
        self.records_written
    }

    /// Total number of bytes written to the underlying sink.
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Write a record followed by the configured delimiter.
    pub fn write_record(&mut self, record: &[u8]) -> io::Result<()> {
        self.inner.write_all(record)?;
        self.inner.write_all(&self.delimiter)?;
        self.records_written += 1;
        self.bytes_written += record.len() + self.delimiter.len();
        Ok(())
    }

    /// Write a string slice record followed by the configured delimiter.
    pub fn write_record_str(&mut self, record: &str) -> io::Result<()> {
        self.write_record(record.as_bytes())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Immutably borrow the inner writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutably borrow the inner writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consume the writer and return `(inner, delimiter, records_written, bytes_written)`.
    pub fn into_parts(self) -> (W, Vec<u8>, usize, usize) {
        (
            self.inner,
            self.delimiter,
            self.records_written,
            self.bytes_written,
        )
    }
}

impl<W: Write> Write for DelimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Helper function to create a new `DelimitedWriter`.
pub fn delimited_writer<W: Write>(writer: W, delimiter: impl Into<Vec<u8>>) -> DelimitedWriter<W> {
    DelimitedWriter::new(writer, delimiter)
}

/// A reader wrapper that extracts records separated by a custom multi-byte delimiter.
#[derive(Debug)]
pub struct DelimitedReader<R: Read> {
    inner: R,
    delimiter: Vec<u8>,
    buf: Vec<u8>,
    pos: usize,
    max_record_size: usize,
    strip_delimiter: bool,
    records_read: usize,
    bytes_read: usize,
    eof_reached: bool,
}

impl<R: Read> DelimitedReader<R> {
    /// Create a new `DelimitedReader` with the specified delimiter and default max record size (16 MiB).
    pub fn new(inner: R, delimiter: impl Into<Vec<u8>>) -> Self {
        Self::with_max_record_size(inner, delimiter, DEFAULT_MAX_DELIMITED_RECORD_SIZE)
    }

    /// Create a new `DelimitedReader` with specified delimiter and maximum record size.
    pub fn with_max_record_size(
        inner: R,
        delimiter: impl Into<Vec<u8>>,
        max_record_size: usize,
    ) -> Self {
        let delimiter = delimiter.into();
        assert!(!delimiter.is_empty(), "delimiter must not be empty");
        Self {
            inner,
            delimiter,
            buf: Vec::with_capacity(8192),
            pos: 0,
            max_record_size,
            strip_delimiter: true,
            records_read: 0,
            bytes_read: 0,
            eof_reached: false,
        }
    }

    /// Get configured delimiter slice.
    pub fn delimiter(&self) -> &[u8] {
        &self.delimiter
    }

    /// Get maximum record size allowed.
    pub fn max_record_size(&self) -> usize {
        self.max_record_size
    }

    /// Set maximum record size allowed.
    pub fn set_max_record_size(&mut self, max: usize) {
        self.max_record_size = max;
    }

    /// Whether the delimiter is stripped from the returned records.
    pub fn strip_delimiter(&self) -> bool {
        self.strip_delimiter
    }

    /// Configure whether the delimiter should be stripped from returned records.
    pub fn set_strip_delimiter(&mut self, strip: bool) {
        self.strip_delimiter = strip;
    }

    /// Number of records read so far.
    pub fn records_read(&self) -> usize {
        self.records_read
    }

    /// Total number of raw stream bytes consumed.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Immutably borrow inner reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutably borrow inner reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consume the reader and return `(inner, delimiter, max_record_size, records_read)`.
    pub fn into_parts(self) -> (R, Vec<u8>, usize, usize) {
        (
            self.inner,
            self.delimiter,
            self.max_record_size,
            self.records_read,
        )
    }

    /// Convert this `DelimitedReader` into an iterator yielding record byte buffers.
    pub fn into_records(self) -> DelimitedIter<R> {
        DelimitedIter { reader: self }
    }

    /// Read the next record into the supplied buffer, clearing it first.
    ///
    /// Returns `Ok(Some(n))` with number of bytes in record, or `Ok(None)` when EOF is reached.
    pub fn read_record_buf(&mut self, out: &mut Vec<u8>) -> io::Result<Option<usize>> {
        out.clear();
        let delim_len = self.delimiter.len();

        loop {
            // Search for delimiter in remaining buffer: self.buf[self.pos..]
            let available = &self.buf[self.pos..];
            if let Some(idx) = find_subslice(available, &self.delimiter) {
                let record_len = if self.strip_delimiter {
                    idx
                } else {
                    idx + delim_len
                };

                if record_len > self.max_record_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "delimited record size ({} bytes) exceeds configured maximum ({} bytes)",
                            record_len, self.max_record_size
                        ),
                    ));
                }

                out.extend_from_slice(&available[..record_len]);
                self.pos += idx + delim_len;
                self.records_read += 1;
                self.bytes_read += idx + delim_len;
                return Ok(Some(out.len()));
            }

            // Check if buffer exceeds max_record_size without finding delimiter
            let current_len = self.buf.len() - self.pos;
            if current_len > self.max_record_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "delimited record size exceeds configured maximum ({} bytes)",
                        self.max_record_size
                    ),
                ));
            }

            // If EOF already reached on inner stream
            if self.eof_reached {
                if current_len > 0 {
                    // Final trailing record without trailing delimiter
                    if current_len > self.max_record_size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "delimited record size ({} bytes) exceeds configured maximum ({} bytes)",
                                current_len, self.max_record_size
                            ),
                        ));
                    }
                    out.extend_from_slice(&self.buf[self.pos..]);
                    self.pos = self.buf.len();
                    self.records_read += 1;
                    self.bytes_read += current_len;
                    return Ok(Some(out.len()));
                } else {
                    return Ok(None);
                }
            }

            // Compact buffer if pos > 0
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }

            // Read more data from inner reader
            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk)?;
            if n == 0 {
                self.eof_reached = true;
                // Loop around to either yield trailing bytes or return None
            } else {
                self.buf.extend_from_slice(&chunk[..n]);
            }
        }
    }

    /// Read next record returning a new `Vec<u8>`.
    pub fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        match self.read_record_buf(&mut out)? {
            Some(_) => Ok(Some(out)),
            None => Ok(None),
        }
    }

    /// Read next record and parse it as a UTF-8 String.
    pub fn read_record_to_string(&mut self) -> io::Result<Option<String>> {
        match self.read_record()? {
            Some(bytes) => {
                let s = String::from_utf8(bytes).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid utf-8 record: {e}"),
                    )
                })?;
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }
}

/// Helper function to create a new `DelimitedReader`.
pub fn delimited_reader<R: Read>(reader: R, delimiter: impl Into<Vec<u8>>) -> DelimitedReader<R> {
    DelimitedReader::new(reader, delimiter)
}

/// Iterator over records produced by a `DelimitedReader`.
#[derive(Debug)]
pub struct DelimitedIter<R: Read> {
    reader: DelimitedReader<R>,
}

impl<R: Read> DelimitedIter<R> {
    /// Reference to the underlying delimited reader.
    pub fn get_ref(&self) -> &DelimitedReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying delimited reader.
    pub fn get_mut(&mut self) -> &mut DelimitedReader<R> {
        &mut self.reader
    }

    /// Unwrap the inner `DelimitedReader`.
    pub fn into_inner(self) -> DelimitedReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for DelimitedIter<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// CRC-32/ISO-HDLC (polynomial 0xEDB88320, reflected input/output, init 0xFFFFFFFF)
// Pure-Rust, no external crate required.
// ---------------------------------------------------------------------------

/// CRC-32 lookup table (reflected polynomial 0xEDB88320).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0xEDB8_8320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Update a running CRC-32 state with additional bytes.
#[inline]
fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        crc = CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Compute the CRC-32/ISO-HDLC checksum of a byte slice.
///
/// # Examples
/// ```rust
/// use ifa_stdlib::io::crc32_digest;
/// assert_eq!(crc32_digest(b"123456789"), 0xCBF4_3926);
/// ```
pub fn crc32_digest(data: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

/// Incremental CRC-32 hasher.
///
/// Processes data chunk by chunk and returns the final checksum via [`Crc32Hasher::finalize`].
///
/// # Examples
/// ```rust
/// use ifa_stdlib::io::Crc32Hasher;
/// let mut h = Crc32Hasher::new();
/// h.update(b"hello");
/// h.update(b" world");
/// let crc = h.finalize();
/// use ifa_stdlib::io::crc32_digest;
/// assert_eq!(crc, crc32_digest(b"hello world"));
/// ```
#[derive(Debug, Clone)]
pub struct Crc32Hasher {
    state: u32,
}

impl Default for Crc32Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32Hasher {
    /// Create a new hasher with the standard CRC-32 initial value.
    pub fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Process additional bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.state = crc32_update(self.state, data);
    }

    /// Finalise and return the CRC-32 checksum.
    ///
    /// **Note**: calling `finalize` does not reset the hasher. Create a new
    /// [`Crc32Hasher`] for each independent message.
    pub fn finalize(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    /// Reset the hasher to its initial state.
    pub fn reset(&mut self) {
        self.state = 0xFFFF_FFFF;
    }
}

// ---------------------------------------------------------------------------
// Crc32Writer
// ---------------------------------------------------------------------------

/// A [`Write`] adapter that computes the CRC-32 checksum of everything written
/// through it, forwarding all bytes to the wrapped writer unchanged.
///
/// # Examples
/// ```rust
/// use std::io::Write;
/// use ifa_stdlib::io::{Crc32Writer, crc32_digest};
/// let mut buf = Vec::new();
/// let mut w = Crc32Writer::new(&mut buf);
/// w.write_all(b"hello").unwrap();
/// w.write_all(b" world").unwrap();
/// let crc = w.checksum();
/// assert_eq!(crc, crc32_digest(b"hello world"));
/// assert_eq!(buf, b"hello world");
/// ```
pub struct Crc32Writer<W: Write> {
    inner: W,
    hasher: Crc32Hasher,
    bytes_written: usize,
}

impl<W: Write> Crc32Writer<W> {
    /// Wrap `writer` and start accumulating a CRC-32 checksum.
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            hasher: Crc32Hasher::new(),
            bytes_written: 0,
        }
    }

    /// Return the current CRC-32 checksum over all bytes written so far.
    pub fn checksum(&self) -> u32 {
        self.hasher.finalize()
    }

    /// Return the total number of bytes written through this adapter.
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Obtain a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Obtain a mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap this adapter, returning `(inner_writer, final_checksum, bytes_written)`.
    pub fn into_parts(self) -> (W, u32, usize) {
        let crc = self.hasher.finalize();
        (self.inner, crc, self.bytes_written)
    }

    /// Unwrap this adapter, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Crc32Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Crc32Reader
// ---------------------------------------------------------------------------

/// A [`Read`] adapter that computes the CRC-32 checksum of everything read
/// from the wrapped reader, forwarding the data unchanged to the caller.
///
/// # Examples
/// ```rust
/// use std::io::Read;
/// use ifa_stdlib::io::{Crc32Reader, crc32_digest};
/// let data = b"hello world";
/// let mut r = Crc32Reader::new(data.as_ref());
/// let mut out = Vec::new();
/// r.read_to_end(&mut out).unwrap();
/// assert_eq!(r.checksum(), crc32_digest(b"hello world"));
/// assert_eq!(out, b"hello world");
/// ```
pub struct Crc32Reader<R: Read> {
    inner: R,
    hasher: Crc32Hasher,
    bytes_read: usize,
}

impl<R: Read> Crc32Reader<R> {
    /// Wrap `reader` and start accumulating a CRC-32 checksum.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            hasher: Crc32Hasher::new(),
            bytes_read: 0,
        }
    }

    /// Return the current CRC-32 checksum over all bytes read so far.
    pub fn checksum(&self) -> u32 {
        self.hasher.finalize()
    }

    /// Return the total number of bytes read through this adapter.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Obtain a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Obtain a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap this adapter, returning `(inner_reader, final_checksum, bytes_read)`.
    pub fn into_parts(self) -> (R, u32, usize) {
        let crc = self.hasher.finalize();
        (self.inner, crc, self.bytes_read)
    }

    /// Unwrap this adapter, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Crc32Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_read += n;
        Ok(n)
    }
}

/// Convenience constructor — equivalent to [`Crc32Writer::new`].
pub fn crc32_writer<W: Write>(writer: W) -> Crc32Writer<W> {
    Crc32Writer::new(writer)
}

/// Convenience constructor — equivalent to [`Crc32Reader::new`].
pub fn crc32_reader<R: Read>(reader: R) -> Crc32Reader<R> {
    Crc32Reader::new(reader)
}

// ---------------------------------------------------------------------------
// Adler-32 Checksum Primitives & Streaming Adapters
// ---------------------------------------------------------------------------

const ADLER32_BASE: u32 = 65521;
const ADLER32_NMAX: usize = 5552;

/// Update running Adler-32 state (s1, s2) with additional bytes.
#[inline]
fn adler32_update(mut s1: u32, mut s2: u32, bytes: &[u8]) -> (u32, u32) {
    for chunk in bytes.chunks(ADLER32_NMAX) {
        for &b in chunk {
            s1 += b as u32;
            s2 += s1;
        }
        s1 %= ADLER32_BASE;
        s2 %= ADLER32_BASE;
    }
    (s1, s2)
}

/// Compute the Adler-32 checksum (RFC 1950) of a byte slice.
///
/// # Examples
/// ```rust
/// use ifa_stdlib::io::adler32_digest;
/// assert_eq!(adler32_digest(b"Wikipedia"), 300286872);
/// assert_eq!(adler32_digest(b""), 1);
/// ```
pub fn adler32_digest(data: &[u8]) -> u32 {
    let (s1, s2) = adler32_update(1, 0, data);
    (s2 << 16) | s1
}

/// Incremental Adler-32 hasher.
///
/// Processes data chunk by chunk and returns the final checksum via [`Adler32Hasher::finalize`].
///
/// # Examples
/// ```rust
/// use ifa_stdlib::io::Adler32Hasher;
/// let mut h = Adler32Hasher::new();
/// h.update(b"Wiki");
/// h.update(b"pedia");
/// let adler = h.finalize();
/// use ifa_stdlib::io::adler32_digest;
/// assert_eq!(adler, adler32_digest(b"Wikipedia"));
/// ```
#[derive(Debug, Clone)]
pub struct Adler32Hasher {
    s1: u32,
    s2: u32,
}

impl Default for Adler32Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Adler32Hasher {
    /// Create a new hasher with the standard Adler-32 initial values (`s1 = 1`, `s2 = 0`).
    pub fn new() -> Self {
        Self { s1: 1, s2: 0 }
    }

    /// Process additional bytes.
    pub fn update(&mut self, data: &[u8]) {
        let (s1, s2) = adler32_update(self.s1, self.s2, data);
        self.s1 = s1;
        self.s2 = s2;
    }

    /// Finalise and return the Adler-32 checksum.
    ///
    /// **Note**: calling `finalize` does not reset the hasher. Create a new
    /// [`Adler32Hasher`] or call [`Adler32Hasher::reset`] for independent messages.
    pub fn finalize(&self) -> u32 {
        (self.s2 << 16) | self.s1
    }

    /// Reset the hasher to its initial state.
    pub fn reset(&mut self) {
        self.s1 = 1;
        self.s2 = 0;
    }
}

// ---------------------------------------------------------------------------
// Adler32Writer
// ---------------------------------------------------------------------------

/// A [`Write`] adapter that computes the Adler-32 checksum of everything written
/// through it, forwarding all bytes to the wrapped writer unchanged.
///
/// # Examples
/// ```rust
/// use std::io::Write;
/// use ifa_stdlib::io::{Adler32Writer, adler32_digest};
/// let mut buf = Vec::new();
/// let mut w = Adler32Writer::new(&mut buf);
/// w.write_all(b"Wiki").unwrap();
/// w.write_all(b"pedia").unwrap();
/// let adler = w.checksum();
/// assert_eq!(adler, adler32_digest(b"Wikipedia"));
/// assert_eq!(buf, b"Wikipedia");
/// ```
pub struct Adler32Writer<W: Write> {
    inner: W,
    hasher: Adler32Hasher,
    bytes_written: usize,
}

impl<W: Write> Adler32Writer<W> {
    /// Wrap `writer` and start accumulating an Adler-32 checksum.
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            hasher: Adler32Hasher::new(),
            bytes_written: 0,
        }
    }

    /// Return the current Adler-32 checksum over all bytes written so far.
    pub fn checksum(&self) -> u32 {
        self.hasher.finalize()
    }

    /// Return the total number of bytes written through this adapter.
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Obtain a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Obtain a mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap this adapter, returning `(inner_writer, final_checksum, bytes_written)`.
    pub fn into_parts(self) -> (W, u32, usize) {
        let adler = self.hasher.finalize();
        (self.inner, adler, self.bytes_written)
    }

    /// Unwrap this adapter, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Adler32Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Adler32Reader
// ---------------------------------------------------------------------------

/// A [`Read`] adapter that computes the Adler-32 checksum of everything read
/// from the wrapped reader, forwarding the data unchanged to the caller.
///
/// # Examples
/// ```rust
/// use std::io::Read;
/// use ifa_stdlib::io::{Adler32Reader, adler32_digest};
/// let data = b"Wikipedia";
/// let mut r = Adler32Reader::new(data.as_ref());
/// let mut out = Vec::new();
/// r.read_to_end(&mut out).unwrap();
/// assert_eq!(r.checksum(), adler32_digest(b"Wikipedia"));
/// assert_eq!(out, b"Wikipedia");
/// ```
pub struct Adler32Reader<R: Read> {
    inner: R,
    hasher: Adler32Hasher,
    bytes_read: usize,
}

impl<R: Read> Adler32Reader<R> {
    /// Wrap `reader` and start accumulating an Adler-32 checksum.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            hasher: Adler32Hasher::new(),
            bytes_read: 0,
        }
    }

    /// Return the current Adler-32 checksum over all bytes read so far.
    pub fn checksum(&self) -> u32 {
        self.hasher.finalize()
    }

    /// Return the total number of bytes read through this adapter.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Obtain a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Obtain a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap this adapter, returning `(inner_reader, final_checksum, bytes_read)`.
    pub fn into_parts(self) -> (R, u32, usize) {
        let adler = self.hasher.finalize();
        (self.inner, adler, self.bytes_read)
    }

    /// Unwrap this adapter, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Adler32Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_read += n;
        Ok(n)
    }
}

/// Convenience constructor — equivalent to [`Adler32Writer::new`].
pub fn adler32_writer<W: Write>(writer: W) -> Adler32Writer<W> {
    Adler32Writer::new(writer)
}

/// Convenience constructor — equivalent to [`Adler32Reader::new`].
pub fn adler32_reader<R: Read>(reader: R) -> Adler32Reader<R> {
    Adler32Reader::new(reader)
}

// ---------------------------------------------------------------------------
// Adler-32 Verified Framed Reader & Writer
// ---------------------------------------------------------------------------

/// Stream writer that prefixes each payload with its byte length and an Adler-32 checksum.
///
/// Each frame written has the structure:
/// `[length: header_len][adler32: 4 bytes BE][payload: length bytes]`
#[derive(Debug, Clone)]
pub struct AdlerFramedWriter<W: Write> {
    inner: W,
    field_kind: LengthFieldKind,
    frames_written: u64,
    bytes_written: u64,
}

impl<W: Write> AdlerFramedWriter<W> {
    /// Create a new `AdlerFramedWriter` with standard 4-byte big-endian length prefix.
    pub fn new(writer: W) -> Self {
        Self::with_length_field(writer, LengthFieldKind::U32Be)
    }

    /// Create a new `AdlerFramedWriter` with the specified length field encoding.
    pub fn with_length_field(writer: W, field_kind: LengthFieldKind) -> Self {
        Self {
            inner: writer,
            field_kind,
            frames_written: 0,
            bytes_written: 0,
        }
    }

    /// Return the length field kind.
    pub fn length_field(&self) -> LengthFieldKind {
        self.field_kind
    }

    /// Total number of complete frames written.
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// Total number of bytes written (including length prefixes, Adler-32 checksums, and payloads).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Write a frame payload prefixed by its encoded length and 4-byte big-endian Adler-32 checksum.
    pub fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut header = [0u8; 8];
        let hlen = self.field_kind.encode_len(payload.len(), &mut header)?;
        let adler = adler32_digest(payload);
        self.inner.write_all(&header[..hlen])?;
        self.inner.write_all(&adler.to_be_bytes())?;
        if !payload.is_empty() {
            self.inner.write_all(payload)?;
        }
        self.frames_written += 1;
        self.bytes_written += (hlen + 4 + payload.len()) as u64;
        Ok(())
    }

    /// Write a UTF-8 string frame.
    pub fn write_frame_str(&mut self, text: &str) -> io::Result<()> {
        self.write_frame(text.as_bytes())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwrap the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consume this writer, returning the inner writer, field kind, frames written, and bytes written.
    pub fn into_parts(self) -> (W, LengthFieldKind, u64, u64) {
        (
            self.inner,
            self.field_kind,
            self.frames_written,
            self.bytes_written,
        )
    }
}

/// Helper function to create a new `AdlerFramedWriter` with standard 4-byte big-endian framing.
pub fn adler_framed_writer<W: Write>(writer: W) -> AdlerFramedWriter<W> {
    AdlerFramedWriter::new(writer)
}

/// Stream reader that unpacks length-delimited frames verified by an Adler-32 checksum.
#[derive(Debug, Clone)]
pub struct AdlerFramedReader<R: Read> {
    inner: R,
    field_kind: LengthFieldKind,
    max_frame_size: usize,
    frames_read: u64,
}

impl<R: Read> AdlerFramedReader<R> {
    /// Create a new `AdlerFramedReader` with standard 4-byte big-endian length prefix and default max frame size (16 MiB).
    pub fn new(reader: R) -> Self {
        Self::with_options(reader, LengthFieldKind::U32Be, DEFAULT_MAX_FRAME_SIZE)
    }

    /// Create a new `AdlerFramedReader` with specified length field encoding and maximum frame size.
    pub fn with_options(reader: R, field_kind: LengthFieldKind, max_frame_size: usize) -> Self {
        Self {
            inner: reader,
            field_kind,
            max_frame_size: max_frame_size.max(1),
            frames_read: 0,
        }
    }

    /// Configured length field encoding.
    pub fn length_field(&self) -> LengthFieldKind {
        self.field_kind
    }

    /// Configured maximum payload size in bytes.
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Set a new maximum payload size in bytes (at least 1 byte).
    pub fn set_max_frame_size(&mut self, max: usize) {
        self.max_frame_size = max.max(1);
    }

    /// Number of frames successfully read and verified so far.
    pub fn frames_read(&self) -> u64 {
        self.frames_read
    }

    /// Read the next frame payload into the provided reusable buffer and verify Adler-32 checksum.
    ///
    /// Clears `buf` before reading.
    /// Returns `Ok(Some(bytes_read))` or `Ok(None)` on clean EOF before any header bytes are read.
    /// Returns `Err(UnexpectedEof)` if EOF occurs midway through reading the header, checksum, or payload.
    /// Returns `Err(InvalidData)` if the header indicates a frame larger than `max_frame_size` or if Adler-32 verification fails.
    pub fn read_frame_buf(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<usize>> {
        buf.clear();
        let hlen = self.field_kind.header_len();
        let mut header = [0u8; 8];
        let mut header_read = 0;

        while header_read < hlen {
            let n = self.inner.read(&mut header[header_read..hlen])?;
            if n == 0 {
                if header_read == 0 {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "incomplete Adler frame length prefix: read {} of {} bytes",
                            header_read, hlen
                        ),
                    ));
                }
            }
            header_read += n;
        }

        let payload_len = self.field_kind.decode_len(&header[..hlen]);
        if payload_len > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Adler frame payload length {} exceeds configured maximum {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        let mut adler_buf = [0u8; 4];
        self.inner.read_exact(&mut adler_buf)?;
        let expected_adler = u32::from_be_bytes(adler_buf);

        buf.resize(payload_len, 0);
        if payload_len > 0 {
            self.inner.read_exact(buf)?;
        }

        let actual_adler = adler32_digest(buf);
        if actual_adler != expected_adler {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Adler-32 checksum mismatch: expected 0x{:08X}, computed 0x{:08X}",
                    expected_adler, actual_adler
                ),
            ));
        }

        self.frames_read += 1;
        Ok(Some(payload_len))
    }

    /// Read the next complete verified frame from the stream into a new `Vec<u8>`.
    ///
    /// Returns `Ok(None)` on clean EOF before any header byte is read.
    pub fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        match self.read_frame_buf(&mut buf)? {
            Some(_) => Ok(Some(buf)),
            None => Ok(None),
        }
    }

    /// Read the next frame and parse it as a UTF-8 string.
    pub fn read_frame_to_string(&mut self) -> io::Result<Option<String>> {
        match self.read_frame()? {
            Some(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid UTF-8 in Adler frame: {}", e),
                )
            }),
            None => Ok(None),
        }
    }

    /// Convert this `AdlerFramedReader` into an iterator yielding verified frame byte buffers.
    pub fn into_frames(self) -> AdlerFramedIter<R> {
        AdlerFramedIter { reader: self }
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consume this reader, returning inner reader, field kind, max frame size, and frames read.
    pub fn into_parts(self) -> (R, LengthFieldKind, usize, u64) {
        (
            self.inner,
            self.field_kind,
            self.max_frame_size,
            self.frames_read,
        )
    }
}

/// Helper function to create a new `AdlerFramedReader` with standard 4-byte big-endian framing.
pub fn adler_framed_reader<R: Read>(reader: R) -> AdlerFramedReader<R> {
    AdlerFramedReader::new(reader)
}

/// Iterator over Adler-32 validated frames produced by an `AdlerFramedReader`.
#[derive(Debug)]
pub struct AdlerFramedIter<R: Read> {
    reader: AdlerFramedReader<R>,
}

impl<R: Read> AdlerFramedIter<R> {
    /// Reference to the underlying framed reader.
    pub fn get_ref(&self) -> &AdlerFramedReader<R> {
        &self.reader
    }

    /// Mutable reference to the underlying framed reader.
    pub fn get_mut(&mut self) -> &mut AdlerFramedReader<R> {
        &mut self.reader
    }

    /// Unwrap the inner `AdlerFramedReader`.
    pub fn into_inner(self) -> AdlerFramedReader<R> {
        self.reader
    }
}

impl<R: Read> Iterator for AdlerFramedIter<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_stream_basic_read_write() {
        let mut stream = MemoryStream::new();
        assert!(stream.is_empty());
        assert_eq!(stream.len(), 0);
        assert_eq!(stream.position(), 0);

        stream.write_bytes(b"hello world");
        assert_eq!(stream.len(), 11);
        assert_eq!(stream.position(), 11);
        assert_eq!(stream.as_bytes(), b"hello world");

        stream.set_position(0);
        assert_eq!(stream.position(), 0);

        let data = stream.read_bytes(5);
        assert_eq!(data, b"hello");
        assert_eq!(stream.position(), 5);

        let remaining = stream.read_bytes(100);
        assert_eq!(remaining, b" world");
        assert_eq!(stream.position(), 11);

        // seek
        stream.seek(SeekFrom::Start(6)).expect("seek start");
        assert_eq!(stream.position(), 6);
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).expect("read exact");
        assert_eq!(&buf, b"world");

        // truncate & clear
        stream.truncate(5);
        assert_eq!(stream.len(), 5);
        assert_eq!(stream.as_bytes(), b"hello");
        stream.clear();
        assert!(stream.is_empty());
    }

    #[test]
    fn test_memory_stream_binary_endian() {
        let mut stream = MemoryStream::new();
        stream.write_u8(0x42);
        stream.write_u16_be(0x1234);
        stream.write_u16_le(0x1234);
        stream.write_u32_be(0xAABBCCDD);
        stream.write_u32_le(0xAABBCCDD);
        stream.write_u64_be(0x0102030405060708);
        stream.write_u64_le(0x0102030405060708);

        stream.set_position(0);
        assert_eq!(stream.read_u8().unwrap(), 0x42);
        assert_eq!(stream.read_u16_be().unwrap(), 0x1234);
        assert_eq!(stream.read_u16_le().unwrap(), 0x1234);
        assert_eq!(stream.read_u32_be().unwrap(), 0xAABBCCDD);
        assert_eq!(stream.read_u32_le().unwrap(), 0xAABBCCDD);
        assert_eq!(stream.read_u64_be().unwrap(), 0x0102030405060708);
        assert_eq!(stream.read_u64_le().unwrap(), 0x0102030405060708);

        // UnexpectedEof test
        assert!(stream.read_u8().is_err());
    }

    #[test]
    fn test_buffered_reader_and_writer() {
        let source = b"line 1\nline 2\r\nline 3";
        let mut reader = BufferedReader::new(&source[..]);

        assert_eq!(reader.read_line().unwrap(), Some("line 1".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line 2".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line 3".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);

        let mut output = Vec::new();
        {
            let mut writer = BufferedWriter::new(&mut output);
            writer.write_line("first").unwrap();
            writer.write_line("second").unwrap();
            writer.flush().unwrap();
        }
        assert_eq!(output, b"first\nsecond\n");
    }

    #[test]
    fn test_line_writer() {
        let mut output = Vec::new();
        {
            let mut line_writer = LineWriter::new(&mut output);
            line_writer.write_all(b"partial ").unwrap();
            line_writer.write_line("done").unwrap();
        }
        assert_eq!(output, b"partial done\n");
    }

    #[test]
    fn test_counting_reader_and_writer() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut cr = CountingReader::new(&data[..]);
        let mut buf = [0u8; 10];
        let n1 = cr.read(&mut buf).unwrap();
        assert_eq!(n1, 10);
        assert_eq!(cr.bytes_read(), 10);

        let mut rem = Vec::new();
        let n2 = cr.read_to_end(&mut rem).unwrap();
        assert_eq!(n2, data.len() - 10);
        assert_eq!(cr.bytes_read(), data.len() as u64);

        let mut dest = Vec::new();
        {
            let mut cw = CountingWriter::new(&mut dest);
            cw.write_all(b"hello").unwrap();
            assert_eq!(cw.bytes_written(), 5);
            cw.write_all(b" world").unwrap();
            assert_eq!(cw.bytes_written(), 11);
            cw.flush().unwrap();
        }
        assert_eq!(dest, b"hello world");
    }

    #[test]
    fn test_limited_and_chained_reader() {
        let data = b"0123456789abcdef";
        let mut limited = LimitedReader::new(&data[..], 8);
        let mut read_buf = Vec::new();
        limited.read_to_end(&mut read_buf).unwrap();
        assert_eq!(read_buf, b"01234567");
        assert_eq!(limited.limit(), 0);

        let part1 = b"abc";
        let part2 = b"def";
        let mut chained = ChainedReader::new(&part1[..], &part2[..]);
        let mut chained_buf = Vec::new();
        chained.read_to_end(&mut chained_buf).unwrap();
        assert_eq!(chained_buf, b"abcdef");
    }

    #[test]
    fn test_pipe_and_copy_helpers() {
        let input = b"alpha\nbeta\ngamma\n";
        let mut reader = BufferedReader::new(&input[..]);
        let mut dest = Vec::new();
        {
            let mut writer = BufferedWriter::new(&mut dest);
            let count = pipe_lines(&mut reader, &mut writer).unwrap();
            assert_eq!(count, 3);
        }
        assert_eq!(dest, b"alpha\nbeta\ngamma\n");

        let mut mem_src = MemoryStream::from_bytes(b"stream copy test");
        let mut mem_dst = MemoryStream::new();
        let copied = copy_stream(&mut mem_src, &mut mem_dst).unwrap();
        assert_eq!(copied, 16);
        assert_eq!(mem_dst.as_bytes(), b"stream copy test");
    }

    #[test]
    fn test_tee_reader_and_writer() {
        // Test TeeReader
        let src = b"hello stream tee";
        let mut mirrored = Vec::new();
        let mut tee = TeeReader::new(&src[..], &mut mirrored);
        let mut consumed = Vec::new();
        tee.read_to_end(&mut consumed).unwrap();

        assert_eq!(consumed, b"hello stream tee");
        assert_eq!(mirrored, b"hello stream tee");

        // Test TeeWriter
        let mut out1 = Vec::new();
        let mut out2 = Vec::new();
        {
            let mut tw = TeeWriter::new(&mut out1, &mut out2);
            tw.write_all(b"dual output").unwrap();
            tw.flush().unwrap();
        }
        assert_eq!(out1, b"dual output");
        assert_eq!(out2, b"dual output");
    }

    #[test]
    fn test_empty_sink_repeat_primitives() {
        // EmptyReader
        let mut empty_reader = empty();
        let mut buf = [0u8; 16];
        assert_eq!(empty_reader.read(&mut buf).unwrap(), 0);
        assert!(empty_reader.fill_buf().unwrap().is_empty());
        empty_reader.consume(10);
        assert_eq!(empty_reader.seek(SeekFrom::Start(100)).unwrap(), 0);

        // SinkWriter
        let mut sink_writer = sink();
        assert_eq!(sink_writer.write(b"discarded data").unwrap(), 14);
        sink_writer.flush().unwrap();

        // RepeatReader alone
        let mut rep = repeat(0x42);
        assert_eq!(rep.byte(), 0x42);
        let mut rep_buf = [0u8; 5];
        assert_eq!(rep.read(&mut rep_buf).unwrap(), 5);
        assert_eq!(rep_buf, [0x42; 5]);

        // RepeatReader with LimitedReader
        let mut limited = LimitedReader::new(repeat(b'Z'), 8);
        let mut limited_buf = Vec::new();
        let n = limited.read_to_end(&mut limited_buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(limited_buf, b"ZZZZZZZZ");
    }

    #[test]
    fn test_prefixed_reader() {
        let prefix = b"GET / HTTP/1.1\r\n".to_vec();
        let payload = b"Host: localhost\r\n\r\n";
        let mut reader = prefixed(prefix.clone(), &payload[..]);

        assert_eq!(reader.prefix_len(), 16);
        assert_eq!(reader.prefix_remaining(), 16);

        // Read first part (part of prefix)
        let mut chunk1 = [0u8; 4];
        let n1 = reader.read(&mut chunk1).unwrap();
        assert_eq!(n1, 4);
        assert_eq!(&chunk1, b"GET ");
        assert_eq!(reader.prefix_remaining(), 12);

        // Read remaining all together
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(reader.prefix_remaining(), 0);

        let expected = b"/ HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
        assert_eq!(rest, expected);

        // Test BufRead implementation
        let mut buf_reader = prefixed(b"line 1\n".to_vec(), &b"line 2\n"[..]);
        let mut line1 = String::new();
        buf_reader.read_line(&mut line1).unwrap();
        assert_eq!(line1, "line 1\n");

        let mut line2 = String::new();
        buf_reader.read_line(&mut line2).unwrap();
        assert_eq!(line2, "line 2\n");
    }

    #[test]
    fn test_multi_writer() {
        let mut dest1 = Vec::new();
        let mut dest2 = Vec::new();
        let mut dest3 = Vec::new();

        {
            let mut mw = multi_writer(vec![&mut dest1, &mut dest2, &mut dest3]);
            assert_eq!(mw.len(), 3);
            assert!(!mw.is_empty());

            let n = mw.write(b"broadcast data ").unwrap();
            assert_eq!(n, 15);
            mw.write_all(b"stream test").unwrap();
            mw.flush().unwrap();
        }

        assert_eq!(dest1, b"broadcast data stream test");
        assert_eq!(dest2, b"broadcast data stream test");
        assert_eq!(dest3, b"broadcast data stream test");

        // Test with_capacity and add_writer
        let mut mw2: MultiWriter<Vec<u8>> = MultiWriter::with_capacity(2);
        assert!(mw2.is_empty());
        mw2.add_writer(Vec::new());
        mw2.add_writer(Vec::new());
        assert_eq!(mw2.len(), 2);
        mw2.write_all(b"test").unwrap();
        let writers = mw2.into_writers();
        assert_eq!(writers[0], b"test");
        assert_eq!(writers[1], b"test");
    }

    #[test]
    fn test_limited_writer() {
        let mut out = Vec::new();
        {
            let mut lw = limited_writer(&mut out, 10);
            assert_eq!(lw.limit(), 10);
            let n1 = lw.write(b"0123456789extra").unwrap();
            assert_eq!(n1, 10);
            assert_eq!(lw.limit(), 0);
            let n2 = lw.write(b"more").unwrap();
            assert_eq!(n2, 0);
            lw.flush().unwrap();
        }
        assert_eq!(out, b"0123456789");

        // Test set_limit, get_ref, get_mut, into_inner
        let mut lw2 = limited_writer(Vec::new(), 5);
        lw2.write_all(b"abc").unwrap();
        assert_eq!(lw2.limit(), 2);
        assert_eq!(lw2.get_ref(), b"abc");
        lw2.get_mut().extend_from_slice(b"!");
        lw2.set_limit(10);
        assert_eq!(lw2.limit(), 10);
        let inner = lw2.into_inner();
        assert_eq!(inner, b"abc!");
    }

    #[test]
    fn test_limited_and_chain_helpers() {
        let data = b"helloworld";
        let mut lim = limited(&data[..], 5);
        let mut buf = Vec::new();
        lim.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello");

        let p1 = b"abc";
        let p2 = b"xyz";
        let mut ch = chain(&p1[..], &p2[..]);
        let mut ch_buf = Vec::new();
        ch.read_to_end(&mut ch_buf).unwrap();
        assert_eq!(ch_buf, b"abcxyz");
    }

    #[test]
    fn test_multi_reader() {
        // Empty MultiReader
        let mut empty_mr: MultiReader<&[u8]> = multi_reader(vec![]);
        assert!(empty_mr.is_empty());
        assert_eq!(empty_mr.len(), 0);
        assert_eq!(empty_mr.current_index(), 0);
        assert_eq!(empty_mr.remaining_readers(), 0);
        let mut buf = [0u8; 10];
        assert_eq!(empty_mr.read(&mut buf).unwrap(), 0);

        // Multiple parts
        let part1 = b"Hello, ";
        let part2 = b"wonderful ";
        let part3 = b"world!";
        let mut mr = multi_reader(vec![&part1[..], &part2[..], &part3[..]]);
        assert_eq!(mr.len(), 3);
        assert_eq!(mr.remaining_readers(), 3);
        assert_eq!(mr.current_index(), 0);

        let mut output = Vec::new();
        let bytes_read = mr.read_to_end(&mut output).unwrap();
        assert_eq!(bytes_read, 23);
        assert_eq!(output, b"Hello, wonderful world!");
        assert_eq!(mr.current_index(), 3);
        assert_eq!(mr.remaining_readers(), 0);

        // Test with_capacity, add_reader, and into_readers
        let mut mr2: MultiReader<&[u8]> = MultiReader::with_capacity(2);
        mr2.add_reader(b"first\n");
        mr2.add_reader(b"second\n");
        assert_eq!(mr2.len(), 2);
        assert_eq!(mr2.readers().len(), 2);
        assert_eq!(mr2.readers_mut().len(), 2);

        // Test BufRead
        let mut line1 = String::new();
        mr2.read_line(&mut line1).unwrap();
        assert_eq!(line1, "first\n");
        let mut line2 = String::new();
        mr2.read_line(&mut line2).unwrap();
        assert_eq!(line2, "second\n");
        let mut line3 = String::new();
        mr2.read_line(&mut line3).unwrap();
        assert_eq!(line3, "");

        let inner_readers = mr2.into_readers();
        assert_eq!(inner_readers.len(), 2);
    }

    #[test]
    fn test_chunk_reader_and_iter() {
        let data = b"abcdefghijklm"; // 13 bytes
        let mut cr = chunk_reader(&data[..], 4);
        assert_eq!(cr.chunk_size(), 4);
        assert_eq!(*cr.get_ref(), &data[..]);

        // Reading with a larger buffer only returns up to chunk_size
        let mut buf = [0u8; 10];
        let n1 = cr.read(&mut buf).unwrap();
        assert_eq!(n1, 4);
        assert_eq!(&buf[..n1], b"abcd");

        // Next read chunk
        let c2 = cr.read_chunk().unwrap();
        assert_eq!(c2, Some(b"efgh".to_vec()));

        // Next read chunk
        let c3 = cr.read_chunk().unwrap();
        assert_eq!(c3, Some(b"ijkl".to_vec()));

        // Remaining 1 byte
        let c4 = cr.read_chunk().unwrap();
        assert_eq!(c4, Some(b"m".to_vec()));

        // EOF
        let c5 = cr.read_chunk().unwrap();
        assert_eq!(c5, None);

        // Test into_chunks iterator
        let chunk_iter = chunks(&data[..], 5);
        let collected: Vec<Vec<u8>> = chunk_iter.map(|r| r.unwrap()).collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0], b"abcde");
        assert_eq!(collected[1], b"fghij");
        assert_eq!(collected[2], b"klm");

        // Test read_exact_chunk
        let exact_data = b"12345678"; // 8 bytes
        let mut cr_exact = chunk_reader(&exact_data[..], 4);
        assert_eq!(cr_exact.read_exact_chunk().unwrap(), Some(b"1234".to_vec()));
        assert_eq!(cr_exact.read_exact_chunk().unwrap(), Some(b"5678".to_vec()));
        assert_eq!(cr_exact.read_exact_chunk().unwrap(), None);

        // Test read_exact_chunk partial UnexpectedEof
        let partial_data = b"1234567"; // 7 bytes with chunk 4
        let mut cr_part = chunk_reader(&partial_data[..], 4);
        assert_eq!(cr_part.read_exact_chunk().unwrap(), Some(b"1234".to_vec()));
        let err = cr_part.read_exact_chunk().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        // Test set_chunk_size and into_inner
        let mut cr_dynamic = chunk_reader(&data[..], 2);
        cr_dynamic.set_chunk_size(10);
        assert_eq!(cr_dynamic.chunk_size(), 10);
        let inner = cr_dynamic.into_inner();
        assert_eq!(inner, &data[..]);

        // Test BufRead implementation
        let buf_data = b"hello\nworld\n";
        let mut cr_buf = chunk_reader(BufferedReader::new(&buf_data[..]), 3);
        let mut line = String::new();
        cr_buf.read_line(&mut line).unwrap();
        assert_eq!(line, "hello\n");
    }

    #[test]
    fn test_chunk_writer() {
        let mut out = Vec::new();
        {
            let mut cw = chunk_writer(&mut out, 3);
            assert_eq!(cw.chunk_size(), 3);
            assert_eq!(cw.get_ref().len(), 0);

            // Writing 7 bytes should only write 3 bytes
            let n = cw.write(b"abcdefg").unwrap();
            assert_eq!(n, 3);
            cw.flush().unwrap();
        }
        assert_eq!(out, b"abc");

        // Test set_chunk_size, get_mut, into_inner
        let mut cw2 = chunk_writer(Vec::new(), 2);
        cw2.set_chunk_size(5);
        assert_eq!(cw2.chunk_size(), 5);
        cw2.get_mut().extend_from_slice(b"pre");
        let n2 = cw2.write(b"12345678").unwrap();
        assert_eq!(n2, 5);
        cw2.flush().unwrap();
        let inner = cw2.into_inner();
        assert_eq!(inner, b"pre12345");
    }

    #[test]
    fn test_skip_reader() {
        let data = b"hello world from ifa";
        let mut sr = skip_reader(&data[..], 6);
        assert_eq!(sr.remaining_skip(), 6);
        assert!(!sr.is_skipped());
        assert_eq!(sr.get_ref(), &&data[..]);

        let mut output = String::new();
        sr.read_to_string(&mut output).unwrap();
        assert_eq!(output, "world from ifa");
        assert_eq!(sr.remaining_skip(), 0);
        assert!(sr.is_skipped());

        // Test skip_all
        let data2 = b"1234567890abcdef";
        let mut sr2 = skip_reader(&data2[..], 10);
        let skipped = sr2.skip_all().unwrap();
        assert_eq!(skipped, 10);
        assert!(sr2.is_skipped());
        let mut rest = Vec::new();
        sr2.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"abcdef");

        // Test EOF before skipping finishes
        let short_data = b"short";
        let mut sr_short = skip_reader(&short_data[..], 20);
        let skipped_short = sr_short.skip_all().unwrap();
        assert_eq!(skipped_short, 5);
        assert_eq!(sr_short.remaining_skip(), 15);
        assert!(!sr_short.is_skipped());
        let mut empty_buf = [0u8; 10];
        let n = sr_short.read(&mut empty_buf).unwrap();
        assert_eq!(n, 0);

        // Test set_remaining_skip, get_mut, into_inner
        let mut sr3 = skip_reader(&data[..], 100);
        sr3.set_remaining_skip(3);
        assert_eq!(sr3.remaining_skip(), 3);
        let inner = sr3.into_inner();
        assert_eq!(inner, &data[..]);

        // Test BufRead implementation
        let buf_data = b"prefix\nfirst line\nsecond line\n";
        let mut sr_buf = skip_reader(BufferedReader::new(&buf_data[..]), 7);
        let mut line = String::new();
        sr_buf.read_line(&mut line).unwrap();
        assert_eq!(line, "first line\n");
    }

    #[test]
    fn test_pad_writer() {
        let mut out = Vec::new();
        let mut pw = pad_writer(&mut out, 8);
        assert_eq!(pw.block_size(), 8);
        assert_eq!(pw.bytes_written(), 0);
        assert_eq!(pw.padding_needed(), 0);

        // Write 5 bytes
        pw.write_all(b"hello").unwrap();
        assert_eq!(pw.bytes_written(), 5);
        assert_eq!(pw.padding_needed(), 3);

        // Pad with zeros to 8 bytes
        let padded = pw.pad_zero().unwrap();
        assert_eq!(padded, 3);
        assert_eq!(pw.bytes_written(), 8);
        assert_eq!(pw.padding_needed(), 0);

        // Pad when already aligned does nothing
        assert_eq!(pw.pad(b'X').unwrap(), 0);

        // Write 2 bytes and pad with custom byte
        pw.write_all(b"ab").unwrap();
        assert_eq!(pw.bytes_written(), 10);
        assert_eq!(pw.padding_needed(), 6);
        let padded2 = pw.pad(b'#').unwrap();
        assert_eq!(padded2, 6);
        assert_eq!(pw.bytes_written(), 16);

        pw.flush().unwrap();
        assert_eq!(out, b"hello\0\0\0ab######");

        // Test set_block_size, get_ref, get_mut, into_inner
        let mut pw2 = pad_writer(Vec::new(), 4);
        pw2.set_block_size(16);
        assert_eq!(pw2.block_size(), 16);
        pw2.get_mut().extend_from_slice(b"init");
        assert_eq!(pw2.get_ref(), b"init");
        let inner = pw2.into_inner();
        assert_eq!(inner, b"init");
    }

    #[test]
    fn test_pushback_reader() {
        let data = b"hello world";
        let mut pbr = pushback_reader(&data[..]);
        assert_eq!(pbr.unread_len(), 0);
        assert!(!pbr.has_unread());
        assert_eq!(pbr.get_ref(), &&data[..]);

        // Peek byte before consuming
        assert_eq!(pbr.peek_byte().unwrap(), Some(b'h'));
        assert_eq!(pbr.unread_len(), 1);
        assert!(pbr.has_unread());

        // Peek multiple bytes
        let mut peek_buf = [0u8; 4];
        let n_peek = pbr.peek(&mut peek_buf).unwrap();
        assert_eq!(n_peek, 4);
        assert_eq!(&peek_buf, b"hell");

        // Read 3 bytes (should come from the peeked/pushback buffer)
        let mut read_buf = [0u8; 3];
        let n_read = pbr.read(&mut read_buf).unwrap();
        assert_eq!(n_read, 3);
        assert_eq!(&read_buf, b"hel");
        assert_eq!(pbr.unread_len(), 1); // 'l' still unread

        // Unread bytes
        pbr.unread(b"XYZ");
        assert_eq!(pbr.unread_len(), 4); // "XYZl"
        assert!(pbr.has_unread());

        let mut read_all = Vec::new();
        pbr.read_to_end(&mut read_all).unwrap();
        assert_eq!(read_all, b"XYZlo world");
        assert_eq!(pbr.unread_len(), 0);
        assert!(!pbr.has_unread());

        // Test unread_byte and clear_unread
        let mut pbr2 = PushbackReader::with_capacity(&data[..], 16);
        pbr2.unread_byte(b'A');
        pbr2.unread_byte(b'B');
        assert_eq!(pbr2.unread_len(), 2);
        pbr2.clear_unread();
        assert_eq!(pbr2.unread_len(), 0);

        // Test BufRead implementation
        let lines_data = b"first line\nsecond line\n";
        let mut pbr_buf = pushback_reader(BufferedReader::new(&lines_data[..]));
        pbr_buf.unread(b"injected ");
        let mut line = String::new();
        pbr_buf.read_line(&mut line).unwrap();
        assert_eq!(line, "injected first line\n");

        // Test into_inner and get_mut
        pbr2.get_mut();
        let _inner = pbr2.into_inner();
    }

    #[test]
    fn test_prefix_writer() {
        let mut out = Vec::new();
        let mut pw = prefix_writer(&mut out, b"HEADER:".to_vec());
        assert_eq!(pw.prefix(), b"HEADER:");
        assert!(!pw.is_prefix_written());
        assert_eq!(pw.get_ref().len(), 0);

        // First write should write prefix first
        let n = pw.write(b"data").unwrap();
        assert_eq!(n, 4);
        assert!(pw.is_prefix_written());
        pw.flush().unwrap();
        assert_eq!(pw.get_ref().as_slice(), b"HEADER:data");

        // Subsequent write should not write prefix again
        pw.write_all(b"-more").unwrap();
        pw.flush().unwrap();
        assert_eq!(pw.get_ref().as_slice(), b"HEADER:data-more");
        drop(pw);
        assert_eq!(out, b"HEADER:data-more");

        // Test flush without prior write writes prefix
        let mut pw2 = prefix_writer(Vec::new(), b"MAGIC".to_vec());
        pw2.flush().unwrap();
        assert!(pw2.is_prefix_written());
        assert_eq!(pw2.get_ref(), b"MAGIC");

        // Test write_prefix explicit call
        let mut pw3 = prefix_writer(Vec::new(), b"PREFIX".to_vec());
        pw3.write_prefix().unwrap();
        assert!(pw3.is_prefix_written());
        assert_eq!(pw3.get_ref(), b"PREFIX");
        let inner = pw3.into_inner();
        assert_eq!(inner, b"PREFIX");
    }

    #[test]
    fn test_suffixed_reader() {
        let data = b"hello";
        let suffix = b" world!";
        let mut sr = suffixed(&data[..], suffix.to_vec());
        assert_eq!(sr.suffix(), b" world!");
        assert_eq!(sr.suffix_len(), 7);
        assert_eq!(sr.suffix_remaining(), 7);
        assert!(!sr.is_inner_exhausted());
        assert_eq!(sr.get_ref(), &&data[..]);

        let mut out = Vec::new();
        sr.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello world!");
        assert!(sr.is_inner_exhausted());
        assert_eq!(sr.suffix_remaining(), 0);

        // Subsequent read returns 0 (EOF)
        let mut buf = [0u8; 4];
        assert_eq!(sr.read(&mut buf).unwrap(), 0);

        // Chunked read across inner / suffix boundary
        let mut sr2 = suffixed(&b"ABC"[..], b"DEF".to_vec());
        let mut chunk = [0u8; 2];
        assert_eq!(sr2.read(&mut chunk).unwrap(), 2);
        assert_eq!(&chunk, b"AB");
        assert_eq!(sr2.read(&mut chunk).unwrap(), 1);
        assert_eq!(&chunk[..1], b"C");
        assert!(!sr2.is_inner_exhausted());

        // Now inner is exhausted, next read reads from suffix
        assert_eq!(sr2.read(&mut chunk).unwrap(), 2);
        assert_eq!(&chunk, b"DE");
        assert!(sr2.is_inner_exhausted());
        assert_eq!(sr2.suffix_remaining(), 1);
        assert_eq!(sr2.read(&mut chunk).unwrap(), 1);
        assert_eq!(&chunk[..1], b"F");
        assert_eq!(sr2.read(&mut chunk).unwrap(), 0);

        // Empty inner
        let mut sr_empty_inner = suffixed(&b""[..], b"tail".to_vec());
        let mut out2 = Vec::new();
        sr_empty_inner.read_to_end(&mut out2).unwrap();
        assert_eq!(out2, b"tail");

        // Empty suffix
        let mut sr_empty_suffix = suffixed(&b"head"[..], Vec::new());
        let mut out3 = Vec::new();
        sr_empty_suffix.read_to_end(&mut out3).unwrap();
        assert_eq!(out3, b"head");

        // Both empty
        let mut sr_both_empty = suffixed(&b""[..], Vec::new());
        assert_eq!(sr_both_empty.read(&mut chunk).unwrap(), 0);

        // BufRead testing
        let lines_data = b"line 1\nline 2";
        let mut sr_buf = suffixed(BufferedReader::new(&lines_data[..]), b"\nline 3\n".to_vec());
        let mut l1 = String::new();
        sr_buf.read_line(&mut l1).unwrap();
        assert_eq!(l1, "line 1\n");
        let mut l2 = String::new();
        sr_buf.read_line(&mut l2).unwrap();
        assert_eq!(l2, "line 2\n");
        let mut l3 = String::new();
        sr_buf.read_line(&mut l3).unwrap();
        assert_eq!(l3, "line 3\n");
        let mut l4 = String::new();
        let bytes = sr_buf.read_line(&mut l4).unwrap();
        assert_eq!(bytes, 0);

        // Inspect and mut access
        let mut sr3 = suffixed(&b"foo"[..], b"bar".to_vec());
        sr3.get_mut();
        let (inner, sfx, pos) = sr3.into_parts();
        assert_eq!(inner, &b"foo"[..]);
        assert_eq!(sfx, b"bar");
        assert_eq!(pos, 0);

        let sr4 = suffixed(&b"x"[..], b"y".to_vec());
        let _inner = sr4.into_inner();
    }

    #[test]
    fn test_suffix_writer() {
        let mut out = Vec::new();
        let mut sw = suffix_writer(&mut out, b"</root>".to_vec());
        assert_eq!(sw.suffix(), b"</root>");
        assert!(!sw.is_suffix_written());
        assert_eq!(sw.get_ref().len(), 0);

        sw.write_all(b"<root>").unwrap();
        sw.write_all(b"<item/>").unwrap();
        assert!(!sw.is_suffix_written());
        sw.flush().unwrap();
        assert_eq!(sw.get_ref().as_slice(), b"<root><item/>");

        // finish() writes suffix and flushes
        let inner = sw.finish().unwrap();
        assert_eq!(inner.as_slice(), b"<root><item/></root>");

        // Explicit write_suffix() and write-after-suffix prevention
        let mut out2 = Vec::new();
        let mut sw2 = suffix_writer(&mut out2, b"END".to_vec());
        sw2.write_all(b"START:").unwrap();
        sw2.write_suffix().unwrap();
        assert!(sw2.is_suffix_written());
        assert_eq!(sw2.get_ref().as_slice(), b"START:END");

        // Calling write after suffix_written should return an error
        let err = sw2.write(b"extra").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);

        // Multiple calls to write_suffix are idempotent
        sw2.write_suffix().unwrap();
        assert_eq!(sw2.get_ref().as_slice(), b"START:END");

        // Finish after write_suffix already called
        let inner2 = sw2.finish().unwrap();
        assert_eq!(inner2.as_slice(), b"START:END");

        // Empty suffix
        let sw3 = suffix_writer(Vec::new(), Vec::new());
        let inner3 = sw3.finish().unwrap();
        assert!(inner3.is_empty());

        // into_parts & get_mut
        let mut sw4 = suffix_writer(Vec::new(), b"abc".to_vec());
        sw4.get_mut();
        let (buf, sfx, written) = sw4.into_parts();
        assert!(buf.is_empty());
        assert_eq!(sfx, b"abc");
        assert!(!written);

        let sw5 = suffix_writer(Vec::new(), b"xyz".to_vec());
        let _inner5 = sw5.into_inner();
    }

    #[test]
    fn test_length_field_kind_properties_and_encoding() {
        assert_eq!(LengthFieldKind::U8.header_len(), 1);
        assert_eq!(LengthFieldKind::U16Be.header_len(), 2);
        assert_eq!(LengthFieldKind::U16Le.header_len(), 2);
        assert_eq!(LengthFieldKind::U32Be.header_len(), 4);
        assert_eq!(LengthFieldKind::U32Le.header_len(), 4);
        assert_eq!(LengthFieldKind::U64Be.header_len(), 8);
        assert_eq!(LengthFieldKind::U64Le.header_len(), 8);

        assert_eq!(LengthFieldKind::U8.max_length(), 255);
        assert_eq!(LengthFieldKind::U16Be.max_length(), 65535);
        assert_eq!(LengthFieldKind::U16Le.max_length(), 65535);
        assert_eq!(LengthFieldKind::U32Be.max_length(), u32::MAX as usize);

        let mut buf = [0u8; 8];

        // U8 roundtrip
        let n = LengthFieldKind::U8.encode_len(42, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(LengthFieldKind::U8.decode_len(&buf[..1]), 42);

        // U8 overflow
        assert!(LengthFieldKind::U8.encode_len(256, &mut buf).is_err());

        // U16Be & U16Le roundtrip
        let n = LengthFieldKind::U16Be.encode_len(1234, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(LengthFieldKind::U16Be.decode_len(&buf[..2]), 1234);

        let n = LengthFieldKind::U16Le.encode_len(1234, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(LengthFieldKind::U16Le.decode_len(&buf[..2]), 1234);

        // U16 overflow
        assert!(LengthFieldKind::U16Be.encode_len(65536, &mut buf).is_err());
        assert!(LengthFieldKind::U16Le.encode_len(65536, &mut buf).is_err());

        // U32Be & U32Le roundtrip
        let n = LengthFieldKind::U32Be
            .encode_len(100_000, &mut buf)
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(LengthFieldKind::U32Be.decode_len(&buf[..4]), 100_000);

        let n = LengthFieldKind::U32Le
            .encode_len(100_000, &mut buf)
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(LengthFieldKind::U32Le.decode_len(&buf[..4]), 100_000);

        // U64Be & U64Le roundtrip
        let n = LengthFieldKind::U64Be
            .encode_len(999_999_999, &mut buf)
            .unwrap();
        assert_eq!(n, 8);
        assert_eq!(LengthFieldKind::U64Be.decode_len(&buf[..8]), 999_999_999);

        let n = LengthFieldKind::U64Le
            .encode_len(999_999_999, &mut buf)
            .unwrap();
        assert_eq!(n, 8);
        assert_eq!(LengthFieldKind::U64Le.decode_len(&buf[..8]), 999_999_999);

        // Buffer too small error
        let mut small_buf = [0u8; 1];
        assert!(LengthFieldKind::U32Be
            .encode_len(10, &mut small_buf)
            .is_err());
    }

    #[test]
    fn test_framed_writer_reader_roundtrip_default_u32be() {
        let mut wire = Vec::new();
        let mut writer = framed_writer(&mut wire);
        assert_eq!(writer.length_field(), LengthFieldKind::U32Be);
        assert_eq!(writer.frames_written(), 0);
        assert_eq!(writer.bytes_written(), 0);

        writer.write_frame(b"frame 1").unwrap();
        writer.write_frame(b"").unwrap(); // empty payload frame
        writer.write_frame(b"frame three with more data!").unwrap();
        writer.flush().unwrap();

        assert_eq!(writer.frames_written(), 3);
        // Header sizes: 4 bytes each * 3 frames = 12 bytes. Payloads: 7 + 0 + 27 = 34. Total: 46.
        assert_eq!(writer.bytes_written(), 46);
        assert_eq!(wire.len(), 46);

        let mut reader = framed_reader(wire.as_slice());
        assert_eq!(reader.length_field(), LengthFieldKind::U32Be);
        assert_eq!(reader.frames_read(), 0);

        let f1 = reader.read_frame().unwrap();
        assert_eq!(f1, Some(b"frame 1".to_vec()));
        assert_eq!(reader.frames_read(), 1);

        let f2 = reader.read_frame().unwrap();
        assert_eq!(f2, Some(Vec::new()));
        assert_eq!(reader.frames_read(), 2);

        let f3 = reader.read_frame().unwrap();
        assert_eq!(f3, Some(b"frame three with more data!".to_vec()));
        assert_eq!(reader.frames_read(), 3);

        // EOF clean
        let eof = reader.read_frame().unwrap();
        assert_eq!(eof, None);
        assert_eq!(reader.frames_read(), 3);
    }

    #[test]
    fn test_framed_writer_reader_strings_and_other_kinds() {
        // Test U16Le with string frames
        let mut wire = Vec::new();
        let mut writer = FramedWriter::with_length_field(&mut wire, LengthFieldKind::U16Le);
        assert_eq!(writer.length_field(), LengthFieldKind::U16Le);

        writer.write_frame_str("bonjour").unwrap();
        writer.write_frame_str("à bientôt").unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.frames_written(), 2);

        let mut reader = FramedReader::with_options(wire.as_slice(), LengthFieldKind::U16Le, 1024);
        let s1 = reader.read_frame_to_string().unwrap();
        assert_eq!(s1.as_deref(), Some("bonjour"));

        let s2 = reader.read_frame_to_string().unwrap();
        assert_eq!(s2.as_deref(), Some("à bientôt"));

        let s3 = reader.read_frame_to_string().unwrap();
        assert_eq!(s3, None);
    }

    #[test]
    fn test_framed_reader_into_frames_iterator() {
        let mut wire = Vec::new();
        let mut writer = FramedWriter::with_length_field(&mut wire, LengthFieldKind::U8);
        writer.write_frame(b"one").unwrap();
        writer.write_frame(b"two").unwrap();
        writer.write_frame(b"three").unwrap();

        let reader = FramedReader::with_options(wire.as_slice(), LengthFieldKind::U8, 255);
        let mut iter = reader.into_frames();

        let frames: Vec<Vec<u8>> = iter.by_ref().map(|res| res.expect("valid frame")).collect();
        assert_eq!(
            frames,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );

        // Inner reader inspection from iter
        assert_eq!(iter.get_ref().frames_read(), 3);
        iter.get_mut();
        let inner_reader = iter.into_inner();
        assert_eq!(inner_reader.frames_read(), 3);
    }

    #[test]
    fn test_framed_reader_reusable_buffer() {
        let mut wire = Vec::new();
        let mut writer = framed_writer(&mut wire);
        writer.write_frame(b"reusable payload 1").unwrap();
        writer.write_frame(b"p2").unwrap();

        let mut reader = framed_reader(wire.as_slice());
        let mut reusable = Vec::new();

        let n1 = reader.read_frame_buf(&mut reusable).unwrap();
        assert_eq!(n1, Some(18));
        assert_eq!(reusable.as_slice(), b"reusable payload 1");

        let n2 = reader.read_frame_buf(&mut reusable).unwrap();
        assert_eq!(n2, Some(2));
        assert_eq!(reusable.as_slice(), b"p2");

        let n3 = reader.read_frame_buf(&mut reusable).unwrap();
        assert_eq!(n3, None);
    }

    #[test]
    fn test_framed_reader_error_conditions() {
        // 1. Incomplete length prefix
        let incomplete_header = [0x00, 0x00]; // 2 bytes instead of 4 for U32Be
        let mut reader = framed_reader(&incomplete_header[..]);
        let err = reader.read_frame().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        // 2. Incomplete payload
        let mut incomplete_payload = vec![0x00, 0x00, 0x00, 0x10]; // 16 bytes expected
        incomplete_payload.extend_from_slice(b"1234"); // only 4 bytes provided
        let mut reader2 = framed_reader(&incomplete_payload[..]);
        let err2 = reader2.read_frame().unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::UnexpectedEof);

        // 3. Exceeded max frame size
        let mut big_header = vec![0x00, 0x00, 0x00, 0x64]; // 100 bytes length prefix
        big_header.resize(104, 0xAA);
        let mut reader3 = FramedReader::with_options(&big_header[..], LengthFieldKind::U32Be, 50);
        let err3 = reader3.read_frame().unwrap_err();
        assert_eq!(err3.kind(), io::ErrorKind::InvalidData);
        assert!(err3.to_string().contains("exceeds configured maximum"));

        // 4. Invalid UTF-8 in read_frame_to_string
        let mut invalid_utf8_wire = Vec::new();
        let mut writer = framed_writer(&mut invalid_utf8_wire);
        writer.write_frame(&[0xFF, 0xFE, 0xFD]).unwrap();
        let mut reader4 = framed_reader(invalid_utf8_wire.as_slice());
        let err4 = reader4.read_frame_to_string().unwrap_err();
        assert_eq!(err4.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_framed_reader_writer_inspectors_and_into_parts() {
        let mut buf = Vec::new();
        let mut writer = framed_writer(&mut buf);
        writer.write_frame(b"ping").unwrap();
        assert_eq!(writer.get_ref().len(), 8);
        writer.get_mut();
        let (_inner, kind, frames, bytes) = writer.into_parts();
        assert_eq!(kind, LengthFieldKind::U32Be);
        assert_eq!(frames, 1);
        assert_eq!(bytes, 8);

        let mut reader = framed_reader(buf.as_slice());
        assert_eq!(reader.max_frame_size(), DEFAULT_MAX_FRAME_SIZE);
        reader.set_max_frame_size(1024);
        assert_eq!(reader.max_frame_size(), 1024);
        reader.read_frame().unwrap();
        reader.get_mut();
        assert_eq!(reader.get_ref().len(), 0); // all 8 bytes consumed from slice
        let (_inner, kind, max_size, frames) = reader.into_parts();
        assert_eq!(kind, LengthFieldKind::U32Be);
        assert_eq!(max_size, 1024);
        assert_eq!(frames, 1);

        let r2 = framed_reader(buf.as_slice());
        let _inner2 = r2.into_inner();
    }

    #[test]
    fn test_delimited_writer_and_reader_basic() {
        let mut wire = Vec::new();
        let mut writer = delimited_writer(&mut wire, b"\r\n");
        writer.write_record(b"LINE 1").unwrap();
        writer.write_record(b"LINE 2").unwrap();
        writer.write_record(b"LINE 3").unwrap();
        writer.flush().unwrap();

        assert_eq!(writer.records_written(), 3);
        assert_eq!(wire.as_slice(), b"LINE 1\r\nLINE 2\r\nLINE 3\r\n");

        let mut reader = delimited_reader(wire.as_slice(), b"\r\n");
        assert_eq!(reader.delimiter(), b"\r\n");

        let r1 = reader.read_record().unwrap();
        assert_eq!(r1.as_deref(), Some(&b"LINE 1"[..]));

        let r2 = reader.read_record_to_string().unwrap();
        assert_eq!(r2.as_deref(), Some("LINE 2"));

        let r3 = reader.read_record().unwrap();
        assert_eq!(r3.as_deref(), Some(&b"LINE 3"[..]));

        let r4 = reader.read_record().unwrap();
        assert_eq!(r4, None);

        assert_eq!(reader.records_read(), 3);
        assert_eq!(reader.bytes_read(), wire.len());
    }

    #[test]
    fn test_delimited_multi_byte_custom_separator() {
        let mut wire = Vec::new();
        let mut writer = DelimitedWriter::new(&mut wire, b"---SPLIT---");
        writer.write_record_str("first chunk").unwrap();
        writer
            .write_record_str("second chunk with utf8: bénin")
            .unwrap();

        let mut reader = DelimitedReader::new(wire.as_slice(), b"---SPLIT---");
        let mut rec1 = Vec::new();
        let n1 = reader.read_record_buf(&mut rec1).unwrap();
        assert_eq!(n1, Some(11));
        assert_eq!(rec1.as_slice(), b"first chunk");

        let s2 = reader.read_record_to_string().unwrap();
        assert_eq!(s2.as_deref(), Some("second chunk with utf8: bénin"));

        let s3 = reader.read_record().unwrap();
        assert_eq!(s3, None);
    }

    #[test]
    fn test_delimited_reader_into_records_iterator() {
        let data = b"apple;banana;cherry;date;";
        let reader = delimited_reader(&data[..], b";");
        let mut iter = reader.into_records();

        let items: Vec<String> = iter
            .by_ref()
            .map(|res| String::from_utf8(res.expect("valid chunk")).unwrap())
            .collect();
        assert_eq!(items, vec!["apple", "banana", "cherry", "date"]);

        assert_eq!(iter.get_ref().records_read(), 4);
        iter.get_mut();
        let inner = iter.into_inner();
        assert_eq!(inner.records_read(), 4);
    }

    #[test]
    fn test_delimited_reader_keep_delimiter_and_trailing_bytes_at_eof() {
        // Stream without ending delimiter: "one###two###three"
        let data = b"one###two###three";
        let mut reader = delimited_reader(&data[..], b"###");
        reader.set_strip_delimiter(false);
        assert!(!reader.strip_delimiter());

        let r1 = reader.read_record().unwrap();
        assert_eq!(r1.as_deref(), Some(&b"one###"[..]));

        let r2 = reader.read_record().unwrap();
        assert_eq!(r2.as_deref(), Some(&b"two###"[..]));

        // Trailing bytes at EOF has no trailing delimiter
        let r3 = reader.read_record().unwrap();
        assert_eq!(r3.as_deref(), Some(&b"three"[..]));

        let r4 = reader.read_record().unwrap();
        assert_eq!(r4, None);
        assert_eq!(reader.records_read(), 3);
    }

    #[test]
    fn test_delimited_reader_max_record_size_limit() {
        let data = b"short###this_is_a_very_long_chunk_that_exceeds_threshold###end";
        let mut reader = DelimitedReader::with_max_record_size(&data[..], b"###", 10);
        assert_eq!(reader.max_record_size(), 10);

        let r1 = reader.read_record().unwrap();
        assert_eq!(r1.as_deref(), Some(&b"short"[..]));

        let err = reader.read_record().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds configured maximum"));
    }

    #[test]
    fn test_delimited_reader_writer_inspectors_and_into_parts() {
        let mut sink = Vec::new();
        let mut writer = delimited_writer(&mut sink, b"\0");
        writer.write_record(b"cmd1").unwrap();
        assert_eq!(writer.get_ref().len(), 5);
        writer.get_mut();
        let (_inner, delim, records, bytes) = writer.into_parts();
        assert_eq!(delim, b"\0");
        assert_eq!(records, 1);
        assert_eq!(bytes, 5);

        let mut reader = delimited_reader(sink.as_slice(), b"\0");
        reader.set_max_record_size(4096);
        assert_eq!(reader.max_record_size(), 4096);
        let rec = reader.read_record().unwrap();
        assert_eq!(rec.as_deref(), Some(&b"cmd1"[..]));
        assert_eq!(reader.get_ref().len(), 0);
        reader.get_mut();
        let (_inner, delim2, max_size, records_read) = reader.into_parts();
        assert_eq!(delim2, b"\0");
        assert_eq!(max_size, 4096);
        assert_eq!(records_read, 1);
    }

    // -----------------------------------------------------------------------
    // CRC-32 tests
    // -----------------------------------------------------------------------

    /// CRC-32 of "123456789" is the standard check value 0xCBF43926.
    #[test]
    fn test_crc32_known_check_value() {
        assert_eq!(crc32_digest(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_empty() {
        // CRC-32 of empty slice is 0x00000000
        assert_eq!(crc32_digest(b""), 0x0000_0000);
    }

    #[test]
    fn test_crc32_single_byte() {
        // CRC-32 of [0x00] is 0xD202EF8D
        assert_eq!(crc32_digest(&[0x00u8]), 0xD202_EF8D);
    }

    #[test]
    fn test_crc32_hasher_incremental_matches_one_shot() {
        let data = b"hello world";
        let mut h = Crc32Hasher::new();
        h.update(&data[..5]);
        h.update(&data[5..]);
        assert_eq!(h.finalize(), crc32_digest(data));
    }

    #[test]
    fn test_crc32_hasher_reset() {
        let mut h = Crc32Hasher::new();
        h.update(b"garbage");
        h.reset();
        h.update(b"123456789");
        assert_eq!(h.finalize(), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_hasher_clone() {
        let mut h1 = Crc32Hasher::new();
        h1.update(b"hello");
        let mut h2 = h1.clone();
        h1.update(b" world");
        h2.update(b" world");
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_crc32_writer_basic() {
        let mut buf = Vec::new();
        let mut w = Crc32Writer::new(&mut buf);
        w.write_all(b"123456789").unwrap();
        assert_eq!(w.checksum(), 0xCBF4_3926);
        assert_eq!(w.bytes_written(), 9);
        assert_eq!(buf, b"123456789");
    }

    #[test]
    fn test_crc32_writer_incremental() {
        let mut buf = Vec::new();
        let mut w = Crc32Writer::new(&mut buf);
        w.write_all(b"hello").unwrap();
        w.write_all(b" world").unwrap();
        assert_eq!(w.checksum(), crc32_digest(b"hello world"));
        assert_eq!(w.bytes_written(), 11);
    }

    #[test]
    fn test_crc32_writer_into_parts() {
        let mut buf = Vec::new();
        let mut w = Crc32Writer::new(&mut buf);
        w.write_all(b"abc").unwrap();
        let (_, crc, bytes) = w.into_parts();
        assert_eq!(crc, crc32_digest(b"abc"));
        assert_eq!(bytes, 3);
    }

    #[test]
    fn test_crc32_writer_get_ref_mut() {
        let mut buf = Vec::new();
        let mut w = Crc32Writer::new(&mut buf);
        w.write_all(b"x").unwrap();
        let _ = w.get_ref();
        let _ = w.get_mut();
        let inner = w.into_inner();
        assert_eq!(inner, b"x");
    }

    #[test]
    fn test_crc32_writer_flush() {
        let mut buf = Vec::new();
        let mut w = Crc32Writer::new(&mut buf);
        w.write_all(b"flush test").unwrap();
        w.flush().unwrap();
        assert_eq!(w.bytes_written(), 10);
    }

    #[test]
    fn test_crc32_reader_basic() {
        let data = b"123456789";
        let mut r = Crc32Reader::new(data.as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(r.checksum(), 0xCBF4_3926);
        assert_eq!(r.bytes_read(), 9);
        assert_eq!(out, data);
    }

    #[test]
    fn test_crc32_reader_incremental() {
        let data = b"hello world";
        let mut r = Crc32Reader::new(data.as_ref());
        let mut chunk = [0u8; 5];
        r.read_exact(&mut chunk).unwrap();
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(r.checksum(), crc32_digest(b"hello world"));
        assert_eq!(r.bytes_read(), 11);
    }

    #[test]
    fn test_crc32_reader_empty() {
        let mut r = Crc32Reader::new(b"".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(r.checksum(), 0x0000_0000);
        assert_eq!(r.bytes_read(), 0);
    }

    #[test]
    fn test_crc32_reader_into_parts() {
        let data = b"abc";
        let mut r = Crc32Reader::new(data.as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        let (_, crc, bytes) = r.into_parts();
        assert_eq!(crc, crc32_digest(b"abc"));
        assert_eq!(bytes, 3);
    }

    #[test]
    fn test_crc32_reader_get_ref_mut() {
        let data = b"hello";
        let mut r = Crc32Reader::new(data.as_ref());
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).unwrap();
        let _ = r.get_ref();
        let _ = r.get_mut();
        let _ = r.into_inner();
    }

    #[test]
    fn test_crc32_writer_reader_roundtrip() {
        // Write then read back through CRC adapters: both checksums must agree
        let payload = b"The quick brown fox jumps over the lazy dog";
        let mut buf = Vec::new();
        let mut w = Crc32Writer::new(&mut buf);
        w.write_all(payload).unwrap();
        let write_crc = w.checksum();

        let mut r = Crc32Reader::new(buf.as_slice());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        let read_crc = r.checksum();

        assert_eq!(write_crc, read_crc);
        assert_eq!(out, payload);
    }

    #[test]
    fn test_adler32_known_vectors() {
        assert_eq!(adler32_digest(b"Wikipedia"), 300286872);
        assert_eq!(adler32_digest(b"123456789"), 152961502);
        assert_eq!(adler32_digest(b""), 1);
        assert_eq!(adler32_digest(b"a"), 6422626);
    }

    #[test]
    fn test_adler32_large_buffer() {
        let data = vec![b'A'; 10_000];
        assert_eq!(adler32_digest(&data), 2277632920);
    }

    #[test]
    fn test_adler32_hasher_incremental_matches_one_shot() {
        let mut h = Adler32Hasher::new();
        let data = b"The quick brown fox jumps over the lazy dog";
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), adler32_digest(data));
    }

    #[test]
    fn test_adler32_hasher_reset() {
        let mut h = Adler32Hasher::new();
        h.update(b"Wikipedia");
        assert_eq!(h.finalize(), 300286872);
        h.reset();
        assert_eq!(h.finalize(), 1);
        h.update(b"123456789");
        assert_eq!(h.finalize(), 152961502);
    }

    #[test]
    fn test_adler32_hasher_clone() {
        let mut h = Adler32Hasher::new();
        h.update(b"Wiki");
        let mut h2 = h.clone();
        h.update(b"pedia");
        h2.update(b"pedia");
        assert_eq!(h.finalize(), h2.finalize());
    }

    #[test]
    fn test_adler32_writer_basic() {
        let mut buf = Vec::new();
        let mut w = Adler32Writer::new(&mut buf);
        w.write_all(b"Wikipedia").unwrap();
        w.flush().unwrap();
        assert_eq!(w.bytes_written(), 9);
        assert_eq!(w.checksum(), 300286872);
        assert_eq!(buf, b"Wikipedia");
    }

    #[test]
    fn test_adler32_writer_incremental() {
        let mut buf = Vec::new();
        let mut w = Adler32Writer::new(&mut buf);
        w.write_all(b"1234").unwrap();
        w.write_all(b"56789").unwrap();
        assert_eq!(w.bytes_written(), 9);
        assert_eq!(w.checksum(), adler32_digest(b"123456789"));
        assert_eq!(buf, b"123456789");
    }

    #[test]
    fn test_adler32_writer_into_parts() {
        let mut buf = Vec::new();
        let mut w = Adler32Writer::new(&mut buf);
        w.write_all(b"abc").unwrap();
        let (_inner, adler, count) = w.into_parts();
        assert_eq!(count, 3);
        assert_eq!(adler, adler32_digest(b"abc"));
    }

    #[test]
    fn test_adler32_writer_get_ref_mut() {
        let mut buf = Vec::new();
        let mut w = Adler32Writer::new(&mut buf);
        w.write_all(b"hi").unwrap();
        assert_eq!(w.get_ref().len(), 2);
        w.get_mut().clear();
        assert_eq!(w.get_ref().len(), 0);
        let _ = w.into_inner();
    }

    #[test]
    fn test_adler32_reader_basic() {
        let data = b"Wikipedia";
        let mut r = Adler32Reader::new(data.as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(r.bytes_read(), 9);
        assert_eq!(r.checksum(), 300286872);
        assert_eq!(out, b"Wikipedia");
    }

    #[test]
    fn test_adler32_reader_incremental() {
        let data = b"123456789";
        let mut r = Adler32Reader::new(data.as_ref());
        let mut buf = [0u8; 3];
        let n1 = r.read(&mut buf).unwrap();
        let n2 = r.read(&mut buf).unwrap();
        assert_eq!(n1, 3);
        assert_eq!(n2, 3);
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(r.checksum(), adler32_digest(b"123456789"));
        assert_eq!(r.bytes_read(), 9);
    }

    #[test]
    fn test_adler32_reader_empty() {
        let empty: &[u8] = &[];
        let mut r = Adler32Reader::new(empty);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(r.bytes_read(), 0);
        assert_eq!(r.checksum(), 1);
        assert!(out.is_empty());
    }

    #[test]
    fn test_adler32_reader_into_parts() {
        let data = b"abc";
        let mut r = Adler32Reader::new(data.as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        let (_inner, adler, count) = r.into_parts();
        assert_eq!(count, 3);
        assert_eq!(adler, adler32_digest(b"abc"));
    }

    #[test]
    fn test_adler32_reader_get_ref_mut() {
        let data = b"hello";
        let mut r = Adler32Reader::new(data.as_ref());
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).unwrap();
        let _ = r.get_ref();
        let _ = r.get_mut();
        let _ = r.into_inner();
    }

    #[test]
    fn test_adler32_writer_reader_roundtrip() {
        let payload = b"The quick brown fox jumps over the lazy dog";
        let mut buf = Vec::new();
        let mut w = Adler32Writer::new(&mut buf);
        w.write_all(payload).unwrap();
        let write_adler = w.checksum();

        let mut r = Adler32Reader::new(buf.as_slice());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        let read_adler = r.checksum();

        assert_eq!(write_adler, read_adler);
        assert_eq!(out, payload);
    }

    #[test]
    fn test_checksum_shorthands() {
        let mut buf = Vec::new();
        let mut cw = crc32_writer(&mut buf);
        cw.write_all(b"123456789").unwrap();
        assert_eq!(cw.checksum(), 0xCBF4_3926);

        let mut cr = crc32_reader(buf.as_slice());
        let mut out = Vec::new();
        cr.read_to_end(&mut out).unwrap();
        assert_eq!(cr.checksum(), 0xCBF4_3926);

        let mut abuf = Vec::new();
        let mut aw = adler32_writer(&mut abuf);
        aw.write_all(b"Wikipedia").unwrap();
        assert_eq!(aw.checksum(), 300286872);

        let mut ar = adler32_reader(abuf.as_slice());
        let mut aout = Vec::new();
        ar.read_to_end(&mut aout).unwrap();
        assert_eq!(ar.checksum(), 300286872);
    }
}

// ─── Hex encoding / decoding I/O adapters ────────────────────────────────────

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Decodes a nibble (hex digit) to its 4-bit value.
/// Returns `None` for non-hex characters.
#[inline]
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A `Write` adapter that hex-encodes every byte written to it.
///
/// Each input byte is converted into two lowercase hex ASCII characters
/// (`00`–`ff`) and forwarded to the underlying writer.
///
/// # Example
/// ```ignore
/// let mut buf = Vec::new();
/// let mut w = HexWriter::new(&mut buf);
/// w.write_all(b"\xde\xad\xbe\xef").unwrap();
/// assert_eq!(&buf, b"deadbeef");
/// ```
pub struct HexWriter<W: Write> {
    inner: W,
}

impl<W: Write> HexWriter<W> {
    /// Creates a new `HexWriter` wrapping `inner`.
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Consumes the adapter and returns the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns a shared reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

impl<W: Write> Write for HexWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut tmp = [0u8; 2];
        for &byte in buf {
            tmp[0] = HEX_LOWER[(byte >> 4) as usize];
            tmp[1] = HEX_LOWER[(byte & 0x0f) as usize];
            self.inner.write_all(&tmp)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Constructor shorthand for [`HexWriter`].
pub fn hex_writer<W: Write>(writer: W) -> HexWriter<W> {
    HexWriter::new(writer)
}

/// A `Read` adapter that hex-decodes a hex-encoded byte stream on-the-fly.
///
/// The underlying reader must supply an even number of ASCII hex characters.
/// Any non-hex character causes an `InvalidData` error. Whitespace is **not**
/// skipped; use an upstream filter if needed.
///
/// # Example
/// ```ignore
/// let src = b"deadbeef";
/// let mut r = HexReader::new(src.as_ref());
/// let mut out = Vec::new();
/// r.read_to_end(&mut out).unwrap();
/// assert_eq!(out, b"\xde\xad\xbe\xef");
/// ```
pub struct HexReader<R: Read> {
    inner: R,
    /// Buffered nibble from a previous read (high nibble awaiting its pair).
    pending: Option<u8>,
}

impl<R: Read> HexReader<R> {
    /// Creates a new `HexReader` wrapping `inner`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            pending: None,
        }
    }

    /// Consumes the adapter and returns the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Returns a shared reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> Read for HexReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut produced = 0;
        while produced < buf.len() {
            // We need two hex digits to produce one byte.
            let hi = match self.pending.take() {
                Some(v) => v,
                None => {
                    let mut raw = [0u8; 1];
                    match self.inner.read(&mut raw)? {
                        0 => break, // EOF
                        _ => match nibble(raw[0]) {
                            Some(v) => v,
                            None => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "HexReader: invalid hex digit",
                                ))
                            }
                        },
                    }
                }
            };
            // Read the low nibble.
            let mut raw = [0u8; 1];
            match self.inner.read(&mut raw)? {
                0 => {
                    // Odd number of hex digits — store high nibble as pending
                    // and report what we have so far. Next call will error.
                    self.pending = Some(hi);
                    break;
                }
                _ => match nibble(raw[0]) {
                    Some(lo) => {
                        buf[produced] = (hi << 4) | lo;
                        produced += 1;
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "HexReader: invalid hex digit",
                        ))
                    }
                },
            }
        }
        Ok(produced)
    }
}

/// Constructor shorthand for [`HexReader`].
pub fn hex_reader<R: Read>(reader: R) -> HexReader<R> {
    HexReader::new(reader)
}

#[cfg(test)]
mod hex_tests {
    use super::*;

    // ── HexWriter ────────────────────────────────────────────────────────────

    #[test]
    fn hex_writer_empty() {
        let mut buf = Vec::new();
        let mut w = HexWriter::new(&mut buf);
        w.write_all(b"").unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn hex_writer_single_byte() {
        let mut buf = Vec::new();
        let mut w = HexWriter::new(&mut buf);
        w.write_all(b"\xff").unwrap();
        assert_eq!(&buf, b"ff");
    }

    #[test]
    fn hex_writer_known_sequence() {
        let mut buf = Vec::new();
        let mut w = HexWriter::new(&mut buf);
        w.write_all(b"\xde\xad\xbe\xef").unwrap();
        assert_eq!(&buf, b"deadbeef");
    }

    #[test]
    fn hex_writer_all_zero() {
        let mut buf = Vec::new();
        let mut w = HexWriter::new(&mut buf);
        w.write_all(&[0x00; 4]).unwrap();
        assert_eq!(&buf, b"00000000");
    }

    #[test]
    fn hex_writer_ascii_text() {
        let mut buf = Vec::new();
        let mut w = HexWriter::new(&mut buf);
        w.write_all(b"AB").unwrap();
        // 'A' = 0x41, 'B' = 0x42
        assert_eq!(&buf, b"4142");
    }

    #[test]
    fn hex_writer_into_inner() {
        let mut buf = Vec::new();
        {
            let mut w = HexWriter::new(&mut buf);
            w.write_all(b"\x01\x02").unwrap();
        }
        assert_eq!(&buf, b"0102");
    }

    #[test]
    fn hex_writer_multiple_writes() {
        let mut buf = Vec::new();
        let mut w = HexWriter::new(&mut buf);
        w.write_all(b"\x0a").unwrap();
        w.write_all(b"\x0b\x0c").unwrap();
        assert_eq!(&buf, b"0a0b0c");
    }

    // ── HexReader ────────────────────────────────────────────────────────────

    #[test]
    fn hex_reader_empty() {
        let mut r = HexReader::new(b"".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn hex_reader_known_sequence() {
        let mut r = HexReader::new(b"deadbeef".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"\xde\xad\xbe\xef");
    }

    #[test]
    fn hex_reader_uppercase() {
        let mut r = HexReader::new(b"DEADBEEF".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"\xde\xad\xbe\xef");
    }

    #[test]
    fn hex_reader_mixed_case() {
        let mut r = HexReader::new(b"DeAdBeEf".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"\xde\xad\xbe\xef");
    }

    #[test]
    fn hex_reader_all_zeros() {
        let mut r = HexReader::new(b"00000000".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, &[0u8; 4]);
    }

    #[test]
    fn hex_reader_all_ff() {
        let mut r = HexReader::new(b"ffffffff".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, &[0xffu8; 4]);
    }

    #[test]
    fn hex_reader_invalid_char() {
        let mut r = HexReader::new(b"zz".as_ref());
        let mut out = Vec::new();
        let err = r.read_to_end(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn hex_reader_invalid_low_nibble() {
        let mut r = HexReader::new(b"0g".as_ref());
        let mut out = Vec::new();
        let err = r.read_to_end(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ── Round-trip ───────────────────────────────────────────────────────────

    #[test]
    fn hex_roundtrip_arbitrary() {
        let payload: Vec<u8> = (0u8..=255u8).collect();
        let mut encoded = Vec::new();
        HexWriter::new(&mut encoded).write_all(&payload).unwrap();
        assert_eq!(encoded.len(), 512);

        let mut decoded = Vec::new();
        HexReader::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn hex_roundtrip_empty() {
        let mut encoded = Vec::new();
        HexWriter::new(&mut encoded).write_all(b"").unwrap();
        let mut decoded = Vec::new();
        HexReader::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn hex_writer_constructor_shorthand() {
        let mut buf = Vec::new();
        let mut w = hex_writer(&mut buf);
        w.write_all(b"\xca\xfe").unwrap();
        assert_eq!(&buf, b"cafe");
    }

    #[test]
    fn hex_reader_constructor_shorthand() {
        let mut r = hex_reader(b"cafe".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"\xca\xfe");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Base64 streaming adapters
// ════════════════════════════════════════════════════════════════════════════

/// Standard Base64 alphabet (RFC 4648 §4).
const B64_ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode raw bytes as Base64 on-the-fly, writing the encoded characters to
/// the underlying [`Write`] sink.
///
/// Data is buffered in 3-byte groups; call [`flush`][Base64Writer::flush] (or
/// drop the writer) to emit any trailing partial group with the required `=`
/// padding.
///
/// # Example
/// ```ignore
/// let mut buf = Vec::new();
/// let mut w = Base64Writer::new(&mut buf);
/// w.write_all(b"Man").unwrap();
/// w.flush().unwrap();
/// assert_eq!(&buf, b"TWFu");
/// ```
pub struct Base64Writer<W: Write> {
    inner: Option<W>,
    /// Partial 3-byte group accumulated across [`write`] calls.
    pending: [u8; 3],
    pending_len: usize,
}

impl<W: Write> Base64Writer<W> {
    /// Wrap `writer` in a Base64 encoder.
    pub fn new(writer: W) -> Self {
        Self {
            inner: Some(writer),
            pending: [0u8; 3],
            pending_len: 0,
        }
    }

    /// Return a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        self.inner.as_ref().unwrap()
    }

    /// Return a mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        self.inner.as_mut().unwrap()
    }

    /// Flush any pending partial group with `=` padding and return the inner writer.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.flush_pending()?;
        Ok(self.inner.take().unwrap())
    }

    fn encode_chunk(b0: u8, b1: u8, b2: u8) -> [u8; 4] {
        [
            B64_ENC[(b0 >> 2) as usize],
            B64_ENC[(((b0 & 3) << 4) | (b1 >> 4)) as usize],
            B64_ENC[(((b1 & 15) << 2) | (b2 >> 6)) as usize],
            B64_ENC[(b2 & 63) as usize],
        ]
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        let inner = match self.inner.as_mut() {
            Some(w) => w,
            None => return Ok(()),
        };
        match self.pending_len {
            0 => {}
            1 => {
                let b0 = self.pending[0];
                let encoded = [
                    B64_ENC[(b0 >> 2) as usize],
                    B64_ENC[((b0 & 3) << 4) as usize],
                    b'=',
                    b'=',
                ];
                inner.write_all(&encoded)?;
                self.pending_len = 0;
            }
            2 => {
                let b0 = self.pending[0];
                let b1 = self.pending[1];
                let encoded = [
                    B64_ENC[(b0 >> 2) as usize],
                    B64_ENC[(((b0 & 3) << 4) | (b1 >> 4)) as usize],
                    B64_ENC[((b1 & 15) << 2) as usize],
                    b'=',
                ];
                inner.write_all(&encoded)?;
                self.pending_len = 0;
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl<W: Write> Write for Base64Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut pos = 0usize;

        // Fill the pending partial group first.
        while self.pending_len < 3 && pos < buf.len() {
            self.pending[self.pending_len] = buf[pos];
            self.pending_len += 1;
            pos += 1;
        }

        if self.pending_len == 3 {
            let enc = Self::encode_chunk(self.pending[0], self.pending[1], self.pending[2]);
            self.inner.as_mut().unwrap().write_all(&enc)?;
            self.pending_len = 0;
        }

        // Process remaining complete 3-byte groups.
        while pos + 3 <= buf.len() {
            let enc = Self::encode_chunk(buf[pos], buf[pos + 1], buf[pos + 2]);
            self.inner.as_mut().unwrap().write_all(&enc)?;
            pos += 3;
        }

        // Store leftover bytes in pending.
        while pos < buf.len() {
            self.pending[self.pending_len] = buf[pos];
            self.pending_len += 1;
            pos += 1;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()?;
        self.inner.as_mut().unwrap().flush()
    }
}

impl<W: Write> Drop for Base64Writer<W> {
    fn drop(&mut self) {
        let _ = self.flush_pending();
    }
}

/// Convenience constructor — equivalent to [`Base64Writer::new`].
pub fn base64_writer<W: Write>(writer: W) -> Base64Writer<W> {
    Base64Writer::new(writer)
}

// ── Decode table ─────────────────────────────────────────────────────────────

/// 256-entry decode table: maps an ASCII byte to its 6-bit value, or `0xFF`
/// for invalid / padding characters.
const B64_DEC: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0u8;
    // 'A'..='Z' → 0..25
    while i < 26 {
        t[(b'A' + i) as usize] = i;
        i += 1;
    }
    i = 0;
    // 'a'..='z' → 26..51
    while i < 26 {
        t[(b'a' + i) as usize] = 26 + i;
        i += 1;
    }
    i = 0;
    // '0'..='9' → 52..61
    while i < 10 {
        t[(b'0' + i) as usize] = 52 + i;
        i += 1;
    }
    t[b'+' as usize] = 62;
    t[b'/' as usize] = 63;
    t
};

/// Decode Base64-encoded bytes from an underlying [`Read`] source, producing
/// raw binary output on the fly.
///
/// Whitespace in the source is silently skipped (tolerant of line-wrapped
/// encodings). `=` padding characters are consumed but do not produce output.
///
/// # Example
/// ```ignore
/// let mut r = Base64Reader::new(b"TWFu".as_ref());
/// let mut out = Vec::new();
/// r.read_to_end(&mut out).unwrap();
/// assert_eq!(out, b"Man");
/// ```
pub struct Base64Reader<R: Read> {
    inner: R,
    /// Up to 3 decoded bytes ready for the next [`read`] call.
    decoded_buf: [u8; 3],
    decoded_start: usize,
    decoded_end: usize,
    /// Whether the underlying stream is exhausted.
    eof: bool,
}

impl<R: Read> Base64Reader<R> {
    /// Wrap `reader` in a Base64 decoder.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            decoded_buf: [0u8; 3],
            decoded_start: 0,
            decoded_end: 0,
            eof: false,
        }
    }

    /// Return a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Return a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consume the reader and return the inner source.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Read the next 4 Base64 characters (skipping whitespace), decode them,
    /// and store the result in `decoded_buf`.  Returns the number of decoded
    /// bytes (0, 1, 2, or 3), or `None` on clean EOF.
    fn fill_decoded(&mut self) -> io::Result<Option<usize>> {
        if self.eof {
            return Ok(None);
        }

        // Collect exactly 4 non-whitespace, non-null bytes.
        let mut group = [0u8; 4];
        let mut collected = 0usize;

        loop {
            let mut byte = [0u8; 1];
            match self.inner.read(&mut byte) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(_) => {
                    let b = byte[0];
                    if b.is_ascii_whitespace() {
                        continue;
                    }
                    if b == b'=' {
                        // Padding — consume but don't add to group.
                        // Collect remaining padding/whitespace silently.
                        loop {
                            match self.inner.read(&mut byte) {
                                Ok(0) => break,
                                Ok(_) => {
                                    if !byte[0].is_ascii_whitespace() && byte[0] != b'=' {
                                        // Unexpected non-padding character after padding.
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "unexpected data after Base64 padding",
                                        ));
                                    }
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        self.eof = true;
                        break;
                    }
                    group[collected] = b;
                    collected += 1;
                    if collected == 4 {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if collected == 0 {
            return Ok(None);
        }

        // Decode the group.
        let decode = |b: u8| -> io::Result<u8> {
            let v = B64_DEC[b as usize];
            if v == 0xFF {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Base64 character: {}", b as char),
                ))
            } else {
                Ok(v)
            }
        };

        let c0 = decode(group[0])?;
        let decoded_len = match collected {
            4 => {
                let c1 = decode(group[1])?;
                let c2 = decode(group[2])?;
                let c3 = decode(group[3])?;
                self.decoded_buf[0] = (c0 << 2) | (c1 >> 4);
                self.decoded_buf[1] = ((c1 & 15) << 4) | (c2 >> 2);
                self.decoded_buf[2] = ((c2 & 3) << 6) | c3;
                3
            }
            3 => {
                let c1 = decode(group[1])?;
                let c2 = decode(group[2])?;
                self.decoded_buf[0] = (c0 << 2) | (c1 >> 4);
                self.decoded_buf[1] = ((c1 & 15) << 4) | (c2 >> 2);
                2
            }
            2 => {
                let c1 = decode(group[1])?;
                self.decoded_buf[0] = (c0 << 2) | (c1 >> 4);
                1
            }
            1 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete Base64 group (1 character)",
                ));
            }
            _ => unreachable!(),
        };

        self.decoded_start = 0;
        self.decoded_end = decoded_len;
        Ok(Some(decoded_len))
    }
}

impl<R: Read> Read for Base64Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Drain any already-decoded bytes first.
        if self.decoded_start < self.decoded_end {
            let available = self.decoded_end - self.decoded_start;
            let to_copy = available.min(buf.len());
            buf[..to_copy].copy_from_slice(
                &self.decoded_buf[self.decoded_start..self.decoded_start + to_copy],
            );
            self.decoded_start += to_copy;
            return Ok(to_copy);
        }

        // Decode the next group.
        match self.fill_decoded()? {
            None => Ok(0), // EOF
            Some(_) => {
                let available = self.decoded_end - self.decoded_start;
                let to_copy = available.min(buf.len());
                buf[..to_copy].copy_from_slice(
                    &self.decoded_buf[self.decoded_start..self.decoded_start + to_copy],
                );
                self.decoded_start += to_copy;
                Ok(to_copy)
            }
        }
    }
}

/// Convenience constructor — equivalent to [`Base64Reader::new`].
pub fn base64_reader<R: Read>(reader: R) -> Base64Reader<R> {
    Base64Reader::new(reader)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod base64_streaming_tests {
    use super::*;

    // ── Writer ───────────────────────────────────────────────────────────────

    #[test]
    fn b64_writer_empty() {
        let mut buf = Vec::new();
        {
            let mut w = Base64Writer::new(&mut buf);
            w.flush().unwrap();
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn b64_writer_one_byte() {
        let mut buf = Vec::new();
        {
            let mut w = Base64Writer::new(&mut buf);
            w.write_all(b"M").unwrap();
            w.flush().unwrap();
        }
        assert_eq!(&buf, b"TQ==");
    }

    #[test]
    fn b64_writer_two_bytes() {
        let mut buf = Vec::new();
        {
            let mut w = Base64Writer::new(&mut buf);
            w.write_all(b"Ma").unwrap();
            w.flush().unwrap();
        }
        assert_eq!(&buf, b"TWE=");
    }

    #[test]
    fn b64_writer_three_bytes() {
        let mut buf = Vec::new();
        {
            let mut w = Base64Writer::new(&mut buf);
            w.write_all(b"Man").unwrap();
            w.flush().unwrap();
        }
        assert_eq!(&buf, b"TWFu");
    }

    #[test]
    fn b64_writer_longer() {
        // RFC 4648 test vector: "Many hands make light work."
        let mut buf = Vec::new();
        {
            let mut w = Base64Writer::new(&mut buf);
            w.write_all(b"Many hands make light work.").unwrap();
            w.flush().unwrap();
        }
        assert_eq!(&buf, b"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
    }

    #[test]
    fn b64_writer_chunked_writes() {
        let mut buf = Vec::new();
        {
            let mut w = Base64Writer::new(&mut buf);
            // Write byte-by-byte to stress the pending buffer logic.
            for b in b"Man" {
                w.write_all(std::slice::from_ref(b)).unwrap();
            }
            w.flush().unwrap();
        }
        assert_eq!(&buf, b"TWFu");
    }

    #[test]
    fn b64_writer_into_inner() {
        let mut buf = Vec::new();
        {
            let w = Base64Writer::new(&mut buf);
            w.into_inner().unwrap();
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn b64_writer_into_inner_pending() {
        let mut buf = Vec::new();
        {
            let mut w = Base64Writer::new(&mut buf);
            w.write_all(b"M").unwrap();
            w.into_inner().unwrap();
        }
        assert_eq!(&buf, b"TQ==");
    }

    // ── Reader ───────────────────────────────────────────────────────────────

    #[test]
    fn b64_reader_empty() {
        let mut r = Base64Reader::new(b"".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn b64_reader_one_byte() {
        let mut r = Base64Reader::new(b"TQ==".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"M");
    }

    #[test]
    fn b64_reader_two_bytes() {
        let mut r = Base64Reader::new(b"TWE=".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Ma");
    }

    #[test]
    fn b64_reader_three_bytes() {
        let mut r = Base64Reader::new(b"TWFu".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Man");
    }

    #[test]
    fn b64_reader_longer() {
        let mut r = Base64Reader::new(b"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Many hands make light work.");
    }

    #[test]
    fn b64_reader_whitespace_tolerant() {
        // Line-wrapped Base64 (MIME style).
        let encoded = b"TWFu\neSBo\r\nYW5k";
        let mut r = Base64Reader::new(encoded.as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Many hand");
    }

    #[test]
    fn b64_reader_invalid_char() {
        let mut r = Base64Reader::new(b"TW!u".as_ref());
        let mut out = Vec::new();
        let err = r.read_to_end(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ── Round-trip ───────────────────────────────────────────────────────────

    #[test]
    fn b64_roundtrip_all_bytes() {
        let payload: Vec<u8> = (0u8..=255u8).collect();

        let mut encoded = Vec::new();
        {
            let mut w = Base64Writer::new(&mut encoded);
            w.write_all(&payload).unwrap();
            w.flush().unwrap();
        }

        let mut decoded = Vec::new();
        Base64Reader::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn b64_roundtrip_empty() {
        let mut encoded = Vec::new();
        {
            Base64Writer::new(&mut encoded).flush().unwrap();
        }
        let mut decoded = Vec::new();
        Base64Reader::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn b64_writer_constructor_shorthand() {
        let mut buf = Vec::new();
        {
            let mut w = base64_writer(&mut buf);
            w.write_all(b"Man").unwrap();
            w.flush().unwrap();
        }
        assert_eq!(&buf, b"TWFu");
    }

    #[test]
    fn b64_reader_constructor_shorthand() {
        let mut r = base64_reader(b"TWFu".as_ref());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Man");
    }

    #[test]
    fn test_crc_framed_roundtrip_basic() {
        let mut sink = Vec::new();
        {
            let mut writer = CrcFramedWriter::new(&mut sink);
            assert_eq!(writer.frames_written(), 0);
            assert_eq!(writer.bytes_written(), 0);
            assert_eq!(writer.length_field(), LengthFieldKind::U32Be);

            writer.write_frame_str("alpha").unwrap();
            writer.write_frame_str("beta").unwrap();
            writer.write_frame(b"gamma").unwrap();
            writer.flush().unwrap();

            assert_eq!(writer.frames_written(), 3);
            // 3 frames: each has 4-byte len + 4-byte CRC + payload
            // "alpha": 4 + 4 + 5 = 13
            // "beta":  4 + 4 + 4 = 12
            // "gamma": 4 + 4 + 5 = 13
            // Total = 38
            assert_eq!(writer.bytes_written(), 38);
        }

        let mut reader = CrcFramedReader::new(sink.as_slice());
        assert_eq!(reader.frames_read(), 0);
        assert_eq!(reader.length_field(), LengthFieldKind::U32Be);

        assert_eq!(
            reader.read_frame_to_string().unwrap(),
            Some("alpha".to_string())
        );
        assert_eq!(
            reader.read_frame_to_string().unwrap(),
            Some("beta".to_string())
        );
        assert_eq!(reader.read_frame().unwrap(), Some(b"gamma".to_vec()));
        assert_eq!(reader.read_frame().unwrap(), None); // Clean EOF
        assert_eq!(reader.frames_read(), 3);
    }

    #[test]
    fn test_crc_framed_empty_and_binary() {
        let mut sink = Vec::new();
        let payload = vec![0x00, 0xFF, 0x7E, 0x55, 0xAA, 0x12];
        {
            let mut writer = crc_framed_writer(&mut sink);
            writer.write_frame(b"").unwrap();
            writer.write_frame(&payload).unwrap();
            writer.flush().unwrap();
        }

        let mut reader = crc_framed_reader(sink.as_slice());
        assert_eq!(reader.read_frame().unwrap(), Some(Vec::new()));
        assert_eq!(reader.read_frame().unwrap(), Some(payload));
        assert_eq!(reader.read_frame().unwrap(), None);
    }

    #[test]
    fn test_crc_framed_corrupted_payload() {
        let mut sink = Vec::new();
        {
            let mut writer = CrcFramedWriter::new(&mut sink);
            writer.write_frame(b"secure payload").unwrap();
        }

        // Corrupt one byte in the payload
        let last_idx = sink.len() - 1;
        sink[last_idx] ^= 0x01;

        let mut reader = CrcFramedReader::new(sink.as_slice());
        let res = reader.read_frame();
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("CRC-32 checksum mismatch"));
    }

    #[test]
    fn test_crc_framed_corrupted_crc_header() {
        let mut sink = Vec::new();
        {
            let mut writer = CrcFramedWriter::new(&mut sink);
            writer.write_frame(b"another payload").unwrap();
        }

        // Corrupt one byte in the 4-byte CRC header (index 4 to 7 in U32Be)
        sink[5] ^= 0x80;

        let mut reader = CrcFramedReader::new(sink.as_slice());
        let res = reader.read_frame();
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("CRC-32 checksum mismatch"));
    }

    #[test]
    fn test_crc_framed_incomplete_header_and_payload() {
        let mut sink = Vec::new();
        {
            let mut writer = CrcFramedWriter::new(&mut sink);
            writer.write_frame(b"complete frame").unwrap();
        }

        // Truncate inside length header (2 bytes of 4)
        let mut reader_trunc_len = CrcFramedReader::new(&sink[..2]);
        let err1 = reader_trunc_len.read_frame().unwrap_err();
        assert_eq!(err1.kind(), io::ErrorKind::UnexpectedEof);

        // Truncate inside CRC header (4 bytes len + 2 bytes crc)
        let mut reader_trunc_crc = CrcFramedReader::new(&sink[..6]);
        let err2 = reader_trunc_crc.read_frame().unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::UnexpectedEof);

        // Truncate inside payload (4 bytes len + 4 bytes crc + partial payload)
        let mut reader_trunc_pay = CrcFramedReader::new(&sink[..12]);
        let err3 = reader_trunc_pay.read_frame().unwrap_err();
        assert_eq!(err3.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_crc_framed_max_frame_size_exceeded() {
        let mut sink = Vec::new();
        {
            let mut writer = CrcFramedWriter::new(&mut sink);
            writer.write_frame(b"0123456789abcdef").unwrap();
        }

        let mut reader = CrcFramedReader::with_options(sink.as_slice(), LengthFieldKind::U32Be, 10);
        assert_eq!(reader.max_frame_size(), 10);
        reader.set_max_frame_size(8);
        assert_eq!(reader.max_frame_size(), 8);

        let res = reader.read_frame();
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds configured maximum"));
    }

    #[test]
    fn test_crc_framed_into_frames_iterator() {
        let mut sink = Vec::new();
        {
            let mut writer = CrcFramedWriter::new(&mut sink);
            writer.write_frame(b"frame 1").unwrap();
            writer.write_frame(b"frame 2").unwrap();
            writer.write_frame(b"frame 3").unwrap();
        }

        let reader = CrcFramedReader::new(sink.as_slice());
        let iter = reader.into_frames();
        assert_eq!(iter.get_ref().frames_read(), 0);
        let items: Vec<Vec<u8>> = iter.map(|res| res.unwrap()).collect();
        assert_eq!(
            items,
            vec![
                b"frame 1".to_vec(),
                b"frame 2".to_vec(),
                b"frame 3".to_vec()
            ]
        );
    }

    #[test]
    fn test_crc_framed_different_length_kinds() {
        for kind in [
            LengthFieldKind::U16Be,
            LengthFieldKind::U16Le,
            LengthFieldKind::U32Le,
            LengthFieldKind::U64Be,
        ] {
            let mut sink = Vec::new();
            {
                let mut writer = CrcFramedWriter::with_length_field(&mut sink, kind);
                assert_eq!(writer.length_field(), kind);
                writer.write_frame(b"test kind payload").unwrap();
            }

            let mut reader = CrcFramedReader::with_options(sink.as_slice(), kind, 1024);
            assert_eq!(reader.length_field(), kind);
            let frame = reader.read_frame().unwrap().unwrap();
            assert_eq!(frame, b"test kind payload");
        }
    }

    #[test]
    fn test_crc_framed_constructor_shorthands_and_parts() {
        let mut sink = Vec::new();
        let writer = crc_framed_writer(&mut sink);
        let (inner, kind, frames, bytes) = writer.into_parts();
        assert_eq!(kind, LengthFieldKind::U32Be);
        assert_eq!(frames, 0);
        assert_eq!(bytes, 0);

        let reader = crc_framed_reader(inner.as_slice());
        let (_inner_r, kind_r, max_sz, frames_r) = reader.into_parts();
        assert_eq!(kind_r, LengthFieldKind::U32Be);
        assert_eq!(max_sz, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(frames_r, 0);
    }

    #[test]
    fn test_varint_zigzag_bijection() {
        assert_eq!(zigzag_encode(0), 0);
        assert_eq!(zigzag_decode(0), 0);

        assert_eq!(zigzag_encode(-1), 1);
        assert_eq!(zigzag_decode(1), -1);

        assert_eq!(zigzag_encode(1), 2);
        assert_eq!(zigzag_decode(2), 1);

        assert_eq!(zigzag_encode(-2), 3);
        assert_eq!(zigzag_decode(3), -2);

        assert_eq!(zigzag_encode(2), 4);
        assert_eq!(zigzag_decode(4), 2);

        // Edge values
        assert_eq!(zigzag_decode(zigzag_encode(i64::MIN)), i64::MIN);
        assert_eq!(zigzag_decode(zigzag_encode(i64::MAX)), i64::MAX);
        assert_eq!(
            zigzag_decode(zigzag_encode(i32::MIN as i64)),
            i32::MIN as i64
        );
        assert_eq!(
            zigzag_decode(zigzag_encode(i32::MAX as i64)),
            i32::MAX as i64
        );

        for val in -500..=500 {
            assert_eq!(zigzag_decode(zigzag_encode(val)), val);
        }
    }

    #[test]
    fn test_uvarint_encode_decode_known_vectors() {
        let test_cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (300, &[0xAC, 0x02]),
            (16384, &[0x80, 0x80, 0x01]),
            (624485, &[0xE5, 0x8E, 0x26]),
        ];

        let mut buf = [0u8; MAX_VARINT_LEN_U64];
        for &(val, expected_bytes) in test_cases {
            let written = encode_uvarint(val, &mut buf);
            assert_eq!(&buf[..written], expected_bytes);

            let (decoded, consumed) = decode_uvarint(expected_bytes).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, expected_bytes.len());
        }

        // Test u64::MAX
        let written = encode_uvarint(u64::MAX, &mut buf);
        assert_eq!(written, 10);
        let (decoded, consumed) = decode_uvarint(&buf[..written]).unwrap();
        assert_eq!(decoded, u64::MAX);
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_uvarint_vec_helper() {
        let mut out = Vec::new();
        let n1 = encode_uvarint_vec(300, &mut out);
        assert_eq!(n1, 2);
        let n2 = encode_uvarint_vec(127, &mut out);
        assert_eq!(n2, 1);
        assert_eq!(&out, &[0xAC, 0x02, 0x7F]);

        let (v1, len1) = decode_uvarint(&out).unwrap();
        assert_eq!(v1, 300);
        assert_eq!(len1, 2);

        let (v2, len2) = decode_uvarint(&out[len1..]).unwrap();
        assert_eq!(v2, 127);
        assert_eq!(len2, 1);
    }

    #[test]
    fn test_ivarint_encode_decode() {
        let values = [-1000000i64, -128, -64, -1, 0, 1, 63, 127, 255, 1000000];
        let mut buf = [0u8; MAX_VARINT_LEN_U64];

        for &val in &values {
            let n = encode_ivarint(val, &mut buf);
            let (decoded, consumed) = decode_ivarint(&buf[..n]).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, n);
        }
    }

    #[test]
    fn test_varint_decode_error_unexpected_eof() {
        // Empty slice
        let empty_err = decode_uvarint(&[]).unwrap_err();
        assert_eq!(empty_err.kind(), io::ErrorKind::UnexpectedEof);

        // Sequence with continuation bit set but truncated
        let truncated = [0x80u8, 0x80];
        let trunc_err = decode_uvarint(&truncated).unwrap_err();
        assert_eq!(trunc_err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_varint_decode_error_overflow() {
        // 11 continuation bytes -> overflow
        let overflow_11 = [0x80u8; 11];
        let err1 = decode_uvarint(&overflow_11).unwrap_err();
        assert_eq!(err1.kind(), io::ErrorKind::InvalidData);
        assert!(err1.to_string().contains("exceeds 64-bit"));

        // 10th byte with upper bits set (> 1) -> overflow for u64
        let mut overflow_10 = [0x80u8; 10];
        overflow_10[9] = 0x02; // Bit 1 is set -> 2 > 1
        let err2 = decode_uvarint(&overflow_10).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidData);
        assert!(err2
            .to_string()
            .contains("10th byte exceeds 1-bit capacity"));
    }

    #[test]
    fn test_varint_writer_and_reader_streaming() {
        let mut sink = Vec::new();
        {
            let mut writer = VarintWriter::new(&mut sink);
            assert_eq!(writer.values_written(), 0);
            assert_eq!(writer.bytes_written(), 0);

            writer.write_uvarint(0).unwrap();
            writer.write_uvarint(128).unwrap();
            writer.write_ivarint(-42).unwrap();
            writer.write_u32(1000).unwrap();
            writer.write_i32(-999).unwrap();

            // Interleaved raw bytes via Write implementation
            writer.write_all(b"RAW").unwrap();
            writer.flush().unwrap();

            assert_eq!(writer.values_written(), 5);
            assert_eq!(writer.bytes_written(), sink.len() as u64);
        }

        let mut reader = VarintReader::new(sink.as_slice());
        assert_eq!(reader.values_read(), 0);
        assert_eq!(reader.bytes_read(), 0);

        assert_eq!(reader.read_uvarint().unwrap(), 0);
        assert_eq!(reader.read_uvarint().unwrap(), 128);
        assert_eq!(reader.read_ivarint().unwrap(), -42);
        assert_eq!(reader.read_u32().unwrap(), 1000);
        assert_eq!(reader.read_i32().unwrap(), -999);

        // Read the interleaved raw bytes
        let mut raw_buf = [0u8; 3];
        reader.read_exact(&mut raw_buf).unwrap();
        assert_eq!(&raw_buf, b"RAW");

        assert_eq!(reader.values_read(), 5);
        assert_eq!(reader.bytes_read(), sink.len() as u64);

        // At end of stream
        assert_eq!(reader.try_read_uvarint().unwrap(), None);
        let eof_err = reader.read_uvarint().unwrap_err();
        assert_eq!(eof_err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_varint_iterators() {
        let mut sink = Vec::new();
        {
            let mut writer = VarintWriter::new(&mut sink);
            writer.write_uvarint(10).unwrap();
            writer.write_uvarint(20).unwrap();
            writer.write_uvarint(30).unwrap();
        }

        let reader = VarintReader::new(sink.as_slice());
        let u_iter = reader.into_uvarints();
        let u_vals: Vec<u64> = u_iter.map(|r| r.unwrap()).collect();
        assert_eq!(u_vals, vec![10, 20, 30]);

        let mut sink_i = Vec::new();
        {
            let mut writer = VarintWriter::new(&mut sink_i);
            writer.write_ivarint(-10).unwrap();
            writer.write_ivarint(0).unwrap();
            writer.write_ivarint(10).unwrap();
        }

        let reader_i = VarintReader::new(sink_i.as_slice());
        let i_iter = reader_i.into_ivarints();
        let i_vals: Vec<i64> = i_iter.map(|r| r.unwrap()).collect();
        assert_eq!(i_vals, vec![-10, 0, 10]);
    }

    #[test]
    fn test_varint_range_checks() {
        let mut sink = Vec::new();
        {
            let mut writer = VarintWriter::new(&mut sink);
            // Write value exceeding u32
            writer.write_uvarint(u32::MAX as u64 + 1).unwrap();
            // Write value exceeding i32
            writer.write_ivarint(i32::MAX as i64 + 1).unwrap();
        }

        let mut reader = VarintReader::new(sink.as_slice());
        let err_u32 = reader.read_u32().unwrap_err();
        assert_eq!(err_u32.kind(), io::ErrorKind::InvalidData);
        assert!(err_u32.to_string().contains("exceeds u32 range"));

        let err_i32 = reader.read_i32().unwrap_err();
        assert_eq!(err_i32.kind(), io::ErrorKind::InvalidData);
        assert!(err_i32.to_string().contains("exceeds i32 range"));
    }

    #[test]
    fn test_varint_parts_and_shorthand_constructors() {
        let mut sink = Vec::new();
        let writer = varint_writer(&mut sink);
        let (inner, vals_w, bytes_w) = writer.into_parts();
        assert_eq!(vals_w, 0);
        assert_eq!(bytes_w, 0);

        let reader = varint_reader(inner.as_slice());
        let (_inner_r, vals_r, bytes_r) = reader.into_parts();
        assert_eq!(vals_r, 0);
        assert_eq!(bytes_r, 0);
    }

    #[test]
    fn test_sleb128_known_vectors() {
        let test_cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (-1, &[0x7F]),
            (63, &[0x3F]),
            (-64, &[0x40]),
            (64, &[0xC0, 0x00]),
            (-65, &[0xBF, 0x7F]),
            (127, &[0xFF, 0x00]),
            (-128, &[0x80, 0x7F]),
            (128, &[0x80, 0x01]),
            (-129, &[0xFF, 0x7E]),
        ];

        let mut buf = [0u8; MAX_VARINT_LEN_U64];
        for &(val, expected_bytes) in test_cases {
            let written = encode_sleb128(val, &mut buf);
            assert_eq!(&buf[..written], expected_bytes);

            let (decoded, consumed) = decode_sleb128(expected_bytes).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, expected_bytes.len());
        }

        // Test boundary values
        for &val in &[i32::MIN as i64, i32::MAX as i64, i64::MIN, i64::MAX] {
            let n = encode_sleb128(val, &mut buf);
            let (decoded, consumed) = decode_sleb128(&buf[..n]).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, n);
        }

        // Continuous range check
        for val in -1000..=1000 {
            let n = encode_sleb128(val, &mut buf);
            let (decoded, consumed) = decode_sleb128(&buf[..n]).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, n);
        }
    }

    #[test]
    fn test_sleb128_vec_helper() {
        let mut out = Vec::new();
        let n1 = encode_sleb128_vec(-65, &mut out);
        assert_eq!(n1, 2);
        let n2 = encode_sleb128_vec(64, &mut out);
        assert_eq!(n2, 2);
        assert_eq!(&out, &[0xBF, 0x7F, 0xC0, 0x00]);

        let (v1, len1) = decode_sleb128(&out).unwrap();
        assert_eq!(v1, -65);
        assert_eq!(len1, 2);

        let (v2, len2) = decode_sleb128(&out[len1..]).unwrap();
        assert_eq!(v2, 64);
        assert_eq!(len2, 2);
    }

    #[test]
    fn test_sleb128_stream_reader_writer() {
        let mut sink = Vec::new();
        {
            let mut writer = VarintWriter::new(&mut sink);
            assert_eq!(writer.write_sleb128(-1).unwrap(), 1);
            assert_eq!(writer.write_sleb128(64).unwrap(), 2);
            assert_eq!(writer.write_sleb128_i32(-9999).unwrap(), 3);
            assert_eq!(writer.write_sleb128(i64::MIN).unwrap(), 10);
            assert_eq!(writer.write_sleb128(i64::MAX).unwrap(), 10);
            assert_eq!(writer.values_written(), 5);
        }

        let mut reader = VarintReader::new(sink.as_slice());
        assert_eq!(reader.read_sleb128().unwrap(), -1);
        assert_eq!(reader.read_sleb128().unwrap(), 64);
        assert_eq!(reader.read_sleb128_i32().unwrap(), -9999);
        assert_eq!(reader.read_sleb128().unwrap(), i64::MIN);
        assert_eq!(reader.read_sleb128().unwrap(), i64::MAX);
        assert_eq!(reader.values_read(), 5);
        assert_eq!(reader.try_read_sleb128().unwrap(), None);
    }

    #[test]
    fn test_sleb128_iterators() {
        let mut sink = Vec::new();
        {
            let mut writer = VarintWriter::new(&mut sink);
            writer.write_sleb128(-42).unwrap();
            writer.write_sleb128(0).unwrap();
            writer.write_sleb128(42).unwrap();
        }

        let reader = VarintReader::new(sink.as_slice());
        let iter = reader.into_sleb128s();
        let vals: Vec<i64> = iter.map(|r| r.unwrap()).collect();
        assert_eq!(vals, vec![-42, 0, 42]);
    }

    #[test]
    fn test_sleb128_errors() {
        // Unexpected EOF
        let truncated = [0x80, 0x80];
        let err_eof = decode_sleb128(&truncated).unwrap_err();
        assert_eq!(err_eof.kind(), io::ErrorKind::UnexpectedEof);

        // Reader unexpected EOF
        let mut reader = VarintReader::new(&truncated[..]);
        let err_r = reader.read_sleb128().unwrap_err();
        assert_eq!(err_r.kind(), io::ErrorKind::UnexpectedEof);

        // i32 range check
        let mut sink = Vec::new();
        {
            let mut writer = VarintWriter::new(&mut sink);
            writer.write_sleb128(i32::MAX as i64 + 1).unwrap();
        }
        let mut reader_i32 = VarintReader::new(sink.as_slice());
        let err_i32 = reader_i32.read_sleb128_i32().unwrap_err();
        assert_eq!(err_i32.kind(), io::ErrorKind::InvalidData);
        assert!(err_i32.to_string().contains("exceeds i32 range"));

        // Invalid sign bits in 10th byte
        let invalid_10th = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let err_10th = decode_sleb128(&invalid_10th).unwrap_err();
        assert_eq!(err_10th.kind(), io::ErrorKind::InvalidData);
        assert!(err_10th.to_string().contains("invalid sign-extension bits"));
    }

    #[test]
    fn test_varint_framed_basic() {
        let mut sink = Vec::new();
        let payload_300 = vec![0xAB; 300];
        {
            let mut writer = varint_framed_writer(&mut sink);
            writer.write_frame_str("hello").unwrap();
            writer.write_frame(b"").unwrap(); // Empty frame (length 0 = 1 byte varint)
            writer.write_frame_str("world").unwrap();
            writer.write_frame(&payload_300).unwrap(); // 300 bytes -> 2-byte varint: [0xAC, 0x02]
            writer.flush().unwrap();

            assert_eq!(writer.frames_written(), 4);
            // "hello": 1 header + 5 payload = 6
            // "": 1 header + 0 payload = 1
            // "world": 1 header + 5 payload = 6
            // payload_300: 2 header + 300 payload = 302
            // Total = 315
            assert_eq!(writer.bytes_written(), 315);
        }

        let mut reader = varint_framed_reader(sink.as_slice());
        assert_eq!(reader.frames_read(), 0);
        assert_eq!(reader.max_frame_size(), DEFAULT_MAX_FRAME_SIZE);

        assert_eq!(
            reader.read_frame_to_string().unwrap(),
            Some("hello".to_string())
        );
        assert_eq!(reader.read_frame().unwrap(), Some(Vec::new()));
        assert_eq!(
            reader.read_frame_to_string().unwrap(),
            Some("world".to_string())
        );
        assert_eq!(reader.read_frame().unwrap(), Some(payload_300));
        assert_eq!(reader.read_frame().unwrap(), None); // Clean EOF
        assert_eq!(reader.frames_read(), 4);
    }

    #[test]
    fn test_varint_framed_iter_and_buf() {
        let mut sink = Vec::new();
        {
            let mut writer = VarintFramedWriter::new(&mut sink);
            writer.write_frame(b"msg1").unwrap();
            writer.write_frame(b"msg2").unwrap();
            writer.write_frame(b"msg3").unwrap();
        }

        // Test reusable buffer
        {
            let mut reader = VarintFramedReader::new(sink.as_slice());
            let mut buf = Vec::new();
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), Some(4));
            assert_eq!(&buf, b"msg1");
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), Some(4));
            assert_eq!(&buf, b"msg2");
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), Some(4));
            assert_eq!(&buf, b"msg3");
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), None);
        }

        // Test into_frames iterator
        let reader = VarintFramedReader::new(sink.as_slice());
        let frames: Vec<Vec<u8>> = reader.into_frames().map(|r| r.unwrap()).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(&frames[0], b"msg1");
        assert_eq!(&frames[1], b"msg2");
        assert_eq!(&frames[2], b"msg3");
    }

    #[test]
    fn test_varint_framed_errors_and_limits() {
        // Exceeds max frame size
        let mut sink = Vec::new();
        {
            let mut writer = VarintFramedWriter::new(&mut sink);
            writer.write_frame(b"payload too long").unwrap();
        }
        let mut reader = VarintFramedReader::with_max_frame_size(sink.as_slice(), 5);
        assert_eq!(reader.max_frame_size(), 5);
        reader.set_max_frame_size(4);
        assert_eq!(reader.max_frame_size(), 4);
        let res = reader.read_frame();
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds configured maximum"));

        // Premature EOF in payload
        let truncated_payload = [0x05, b'a', b'b']; // header says 5 bytes, only 2 provided
        let mut r_trunc = VarintFramedReader::new(&truncated_payload[..]);
        let err_trunc = r_trunc.read_frame().unwrap_err();
        assert_eq!(err_trunc.kind(), io::ErrorKind::UnexpectedEof);

        // Premature EOF in multi-byte varint header
        let truncated_header = [0x80]; // continuation bit set, but stream ends
        let mut r_trunc_h = VarintFramedReader::new(&truncated_header[..]);
        let err_trunc_h = r_trunc_h.read_frame().unwrap_err();
        assert_eq!(err_trunc_h.kind(), io::ErrorKind::UnexpectedEof);

        // Accessors & unwrapping
        let mut writer = VarintFramedWriter::new(Vec::new());
        writer.write_frame_str("test").unwrap();
        assert_eq!(writer.get_ref().len(), 5);
        assert_eq!(writer.get_mut().len(), 5);
        let (inner_w, fw, bw) = writer.into_parts();
        assert_eq!(inner_w.len(), 5);
        assert_eq!(fw, 1);
        assert_eq!(bw, 5);

        let reader = VarintFramedReader::new(&inner_w[..]);
        assert_eq!(reader.get_ref().len(), 5);
        let (inner_r, mfs, fr) = reader.into_parts();
        assert_eq!(inner_r.len(), 5);
        assert_eq!(mfs, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(fr, 0);
    }

    #[test]
    fn test_adler_framed_basic() {
        let mut sink = Vec::new();
        {
            let mut writer = adler_framed_writer(&mut sink);
            assert_eq!(writer.length_field(), LengthFieldKind::U32Be);
            assert_eq!(writer.frames_written(), 0);
            assert_eq!(writer.bytes_written(), 0);

            writer.write_frame(b"hello").unwrap();
            writer.write_frame_str("world").unwrap();
            writer.write_frame(b"").unwrap(); // empty frame test
            writer.flush().unwrap();

            assert_eq!(writer.frames_written(), 3);
            // frame 1: 4 (len) + 4 (adler) + 5 = 13
            // frame 2: 4 (len) + 4 (adler) + 5 = 13
            // frame 3: 4 (len) + 4 (adler) + 0 = 8
            // total = 34 bytes
            assert_eq!(writer.bytes_written(), 34);
        }

        let mut reader = adler_framed_reader(sink.as_slice());
        assert_eq!(reader.length_field(), LengthFieldKind::U32Be);
        assert_eq!(reader.frames_read(), 0);

        let f1 = reader.read_frame().unwrap().unwrap();
        assert_eq!(f1, b"hello");
        assert_eq!(reader.frames_read(), 1);

        let s2 = reader.read_frame_to_string().unwrap().unwrap();
        assert_eq!(s2, "world");
        assert_eq!(reader.frames_read(), 2);

        let f3 = reader.read_frame().unwrap().unwrap();
        assert!(f3.is_empty());
        assert_eq!(reader.frames_read(), 3);

        // EOF clean
        assert!(reader.read_frame().unwrap().is_none());
        assert!(reader.read_frame_to_string().unwrap().is_none());
    }

    #[test]
    fn test_adler_framed_corruption_detection() {
        let mut sink = Vec::new();
        {
            let mut writer = AdlerFramedWriter::new(&mut sink);
            writer.write_frame(b"critical secure message").unwrap();
        }

        // Corrupt one payload byte
        let last_idx = sink.len() - 1;
        sink[last_idx] ^= 0xFF;

        let mut reader = AdlerFramedReader::new(sink.as_slice());
        let err = reader.read_frame().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Adler-32 checksum mismatch"));
    }

    #[test]
    fn test_adler_framed_iter_and_buf() {
        let mut sink = Vec::new();
        {
            let mut writer = AdlerFramedWriter::new(&mut sink);
            writer.write_frame(b"packet_1").unwrap();
            writer.write_frame(b"packet_2").unwrap();
            writer.write_frame(b"packet_3").unwrap();
        }

        // Test reusable buffer
        {
            let mut reader = AdlerFramedReader::new(sink.as_slice());
            let mut buf = Vec::new();
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), Some(8));
            assert_eq!(&buf, b"packet_1");
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), Some(8));
            assert_eq!(&buf, b"packet_2");
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), Some(8));
            assert_eq!(&buf, b"packet_3");
            assert_eq!(reader.read_frame_buf(&mut buf).unwrap(), None);
        }

        // Test into_frames iterator
        let reader = AdlerFramedReader::new(sink.as_slice());
        let mut iter = reader.into_frames();
        assert_eq!(iter.get_ref().frames_read(), 0);
        assert_eq!(iter.get_mut().frames_read(), 0);
        let frames: Vec<Vec<u8>> = iter.map(|r| r.unwrap()).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(&frames[0], b"packet_1");
        assert_eq!(&frames[1], b"packet_2");
        assert_eq!(&frames[2], b"packet_3");
    }

    #[test]
    fn test_adler_framed_errors_and_options() {
        // Test various LengthFieldKinds
        let kinds = [
            LengthFieldKind::U8,
            LengthFieldKind::U16Le,
            LengthFieldKind::U16Be,
            LengthFieldKind::U32Le,
            LengthFieldKind::U64Be,
            LengthFieldKind::U64Le,
        ];

        for &kind in &kinds {
            let mut sink = Vec::new();
            {
                let mut writer = AdlerFramedWriter::with_length_field(&mut sink, kind);
                writer.write_frame(b"poly-framed").unwrap();
            }
            let mut reader = AdlerFramedReader::with_options(sink.as_slice(), kind, 1024);
            let frame = reader.read_frame().unwrap().unwrap();
            assert_eq!(frame, b"poly-framed");
        }

        // Exceeds max frame size
        let mut sink = Vec::new();
        {
            let mut writer = AdlerFramedWriter::new(&mut sink);
            writer.write_frame(b"excessive frame length").unwrap();
        }
        let mut reader =
            AdlerFramedReader::with_options(sink.as_slice(), LengthFieldKind::U32Be, 10);
        assert_eq!(reader.max_frame_size(), 10);
        reader.set_max_frame_size(5);
        assert_eq!(reader.max_frame_size(), 5);
        let err = reader.read_frame().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds configured maximum"));

        // Truncations: header, adler, and payload
        let mut valid_sink = Vec::new();
        {
            let mut writer = AdlerFramedWriter::new(&mut valid_sink);
            writer.write_frame(b"12345678").unwrap(); // 4 + 4 + 8 = 16 bytes
        }
        assert_eq!(valid_sink.len(), 16);

        // Truncated header (read 2 of 4 bytes)
        let mut r_hdr = AdlerFramedReader::new(&valid_sink[..2]);
        let err_hdr = r_hdr.read_frame().unwrap_err();
        assert_eq!(err_hdr.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err_hdr
            .to_string()
            .contains("incomplete Adler frame length prefix"));

        // Truncated adler (header present, but only 2 of 4 checksum bytes)
        let mut r_adler = AdlerFramedReader::new(&valid_sink[..6]);
        let err_adler = r_adler.read_frame().unwrap_err();
        assert_eq!(err_adler.kind(), io::ErrorKind::UnexpectedEof);

        // Truncated payload (header and adler present, but only 4 of 8 payload bytes)
        let mut r_pay = AdlerFramedReader::new(&valid_sink[..12]);
        let err_pay = r_pay.read_frame().unwrap_err();
        assert_eq!(err_pay.kind(), io::ErrorKind::UnexpectedEof);

        // Accessors & into_parts
        let mut writer = AdlerFramedWriter::new(Vec::new());
        writer.write_frame_str("alpha").unwrap();
        assert_eq!(writer.get_ref().len(), 13);
        assert_eq!(writer.get_mut().len(), 13);
        let (inner_w, fk_w, fw, bw) = writer.into_parts();
        assert_eq!(inner_w.len(), 13);
        assert_eq!(fk_w, LengthFieldKind::U32Be);
        assert_eq!(fw, 1);
        assert_eq!(bw, 13);

        let reader = AdlerFramedReader::new(&inner_w[..]);
        assert_eq!(reader.get_ref().len(), 13);
        let (inner_r, fk_r, mfs, fr) = reader.into_parts();
        assert_eq!(inner_r.len(), 13);
        assert_eq!(fk_r, LengthFieldKind::U32Be);
        assert_eq!(mfs, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(fr, 0);

        // AdlerFramedIter into_inner
        let reader2 = AdlerFramedReader::new(&inner_w[..]);
        let iter2 = reader2.into_frames();
        let _inner_r2 = iter2.into_inner();
    }
}
