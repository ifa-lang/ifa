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
}
