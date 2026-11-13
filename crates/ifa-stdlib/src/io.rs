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
}
