//! Deterministic Cryptographic primitives for IFA standard library.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_INITIAL_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline]
fn sha256_compress_block(h: &mut [u32; 8], chunk: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_val = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h_val
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h_val = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_val);
}

/// Incremental SHA-256 hasher implementing NIST FIPS 180-4.
#[derive(Clone, Debug)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a new SHA-256 hasher initialized to standard initial hash values.
    pub fn new() -> Self {
        Self {
            state: SHA256_INITIAL_H,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Reset internal state to initial values, clearing all processed data.
    pub fn reset(&mut self) {
        self.state = SHA256_INITIAL_H;
        self.buffer = [0u8; 64];
        self.buffer_len = 0;
        self.total_len = 0;
    }

    /// Ingest data slice incrementally.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() < needed {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
            sha256_compress_block(&mut self.state, &self.buffer);
            self.buffer_len = 0;
            data = &data[needed..];
        }

        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().unwrap();
            sha256_compress_block(&mut self.state, block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalize hashing and return the 32-byte digest, resetting internal state.
    pub fn finalize_reset(&mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..64].fill(0);
            sha256_compress_block(&mut self.state, &self.buffer);
            self.buffer[..56].fill(0);
        } else {
            self.buffer[self.buffer_len..56].fill(0);
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress_block(&mut self.state, &self.buffer);

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        self.reset();
        digest
    }

    /// Finalize hashing and consume hasher, returning the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        self.finalize_reset()
    }

    /// Finalize hashing and return digest formatted as lowercase hexadecimal string.
    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }
}

impl std::io::Write for Sha256 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compute standard NIST SHA-256 hash digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute SHA-256 hash and return as lowercase hexadecimal string.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    to_hex(&digest)
}

// ---------------------------------------------------------------------------
// Sha256Writer & Sha256Reader
// ---------------------------------------------------------------------------

/// A [`Write`] adapter that computes the SHA-256 digest of everything written
/// to the wrapped writer, forwarding the data unchanged downstream.
///
/// # Examples
/// ```rust
/// use std::io::Write;
/// use ifa_stdlib::crypto::{Sha256Writer, sha256_hex};
///
/// let mut sink = Vec::new();
/// {
///     let mut writer = Sha256Writer::new(&mut sink);
///     writer.write_all(b"Hello, IFA!").unwrap();
///     assert_eq!(writer.digest_hex(), sha256_hex(b"Hello, IFA!"));
///     assert_eq!(writer.bytes_written(), 11);
/// }
/// assert_eq!(sink, b"Hello, IFA!");
/// ```
#[derive(Clone, Debug)]
pub struct Sha256Writer<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes_written: usize,
}

impl<W: Write> Sha256Writer<W> {
    /// Wrap `writer` and start accumulating a SHA-256 digest.
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            hasher: Sha256::new(),
            bytes_written: 0,
        }
    }

    /// Return the current SHA-256 digest over all bytes written so far.
    pub fn digest(&self) -> [u8; 32] {
        self.hasher.clone().finalize()
    }

    /// Return the current SHA-256 digest formatted as a lowercase hexadecimal string.
    pub fn digest_hex(&self) -> String {
        self.hasher.clone().finalize_hex()
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

    /// Unwrap this adapter, returning `(inner_writer, final_digest, bytes_written)`.
    pub fn into_parts(self) -> (W, [u8; 32], usize) {
        let digest = self.hasher.finalize();
        (self.inner, digest, self.bytes_written)
    }

    /// Unwrap this adapter, returning `(inner_writer, hex_digest, bytes_written)`.
    pub fn into_parts_hex(self) -> (W, String, usize) {
        let (inner, digest, bytes) = self.into_parts();
        (inner, to_hex(&digest), bytes)
    }

    /// Unwrap this adapter, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Sha256Writer<W> {
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

/// A [`Read`] adapter that computes the SHA-256 digest of everything read
/// from the wrapped reader, forwarding the data unchanged to the caller.
///
/// # Examples
/// ```rust
/// use std::io::Read;
/// use ifa_stdlib::crypto::{Sha256Reader, sha256_hex};
///
/// let data = b"Hello, IFA streaming!";
/// let mut reader = Sha256Reader::new(data.as_ref());
/// let mut out = Vec::new();
/// reader.read_to_end(&mut out).unwrap();
///
/// assert_eq!(reader.digest_hex(), sha256_hex(b"Hello, IFA streaming!"));
/// assert_eq!(reader.bytes_read(), data.len());
/// assert_eq!(out, data);
/// ```
#[derive(Clone, Debug)]
pub struct Sha256Reader<R: Read> {
    inner: R,
    hasher: Sha256,
    bytes_read: usize,
}

impl<R: Read> Sha256Reader<R> {
    /// Wrap `reader` and start accumulating a SHA-256 digest.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            hasher: Sha256::new(),
            bytes_read: 0,
        }
    }

    /// Return the current SHA-256 digest over all bytes read so far.
    pub fn digest(&self) -> [u8; 32] {
        self.hasher.clone().finalize()
    }

    /// Return the current SHA-256 digest formatted as a lowercase hexadecimal string.
    pub fn digest_hex(&self) -> String {
        self.hasher.clone().finalize_hex()
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

    /// Unwrap this adapter, returning `(inner_reader, final_digest, bytes_read)`.
    pub fn into_parts(self) -> (R, [u8; 32], usize) {
        let digest = self.hasher.finalize();
        (self.inner, digest, self.bytes_read)
    }

    /// Unwrap this adapter, returning `(inner_reader, hex_digest, bytes_read)`.
    pub fn into_parts_hex(self) -> (R, String, usize) {
        let (inner, digest, bytes) = self.into_parts();
        (inner, to_hex(&digest), bytes)
    }

    /// Unwrap this adapter, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Sha256Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_read += n;
        Ok(n)
    }
}

const SHA1_INITIAL_H: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

#[inline]
fn sha1_compress_block(h: &mut [u32; 5], chunk: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];

    for (i, &w_val) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w_val);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// Incremental SHA-1 hasher implementing FIPS 180-1 / RFC 3174.
#[derive(Clone, Debug)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Create a new SHA-1 hasher initialized to standard initial hash values.
    pub fn new() -> Self {
        Self {
            state: SHA1_INITIAL_H,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Reset internal state to initial values, clearing all processed data.
    pub fn reset(&mut self) {
        self.state = SHA1_INITIAL_H;
        self.buffer = [0u8; 64];
        self.buffer_len = 0;
        self.total_len = 0;
    }

    /// Ingest data slice incrementally.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() < needed {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
            sha1_compress_block(&mut self.state, &self.buffer);
            self.buffer_len = 0;
            data = &data[needed..];
        }

        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().unwrap();
            sha1_compress_block(&mut self.state, block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalize hashing and return the 20-byte digest, resetting internal state.
    pub fn finalize_reset(&mut self) -> [u8; 20] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..64].fill(0);
            sha1_compress_block(&mut self.state, &self.buffer);
            self.buffer[..56].fill(0);
        } else {
            self.buffer[self.buffer_len..56].fill(0);
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha1_compress_block(&mut self.state, &self.buffer);

        let mut digest = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        self.reset();
        digest
    }

    /// Finalize hashing and consume hasher, returning the 20-byte digest.
    pub fn finalize(mut self) -> [u8; 20] {
        self.finalize_reset()
    }

    /// Finalize hashing and return digest formatted as lowercase hexadecimal string.
    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }
}

impl std::io::Write for Sha1 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compute standard SHA-1 hash digest (FIPS 180-1 / RFC 3174).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute SHA-1 hash and return as lowercase hexadecimal string.
pub fn sha1_hex(data: &[u8]) -> String {
    let digest = sha1(data);
    to_hex(&digest)
}

// ---------------------------------------------------------------------------
// Sha1Writer & Sha1Reader
// ---------------------------------------------------------------------------

/// A [`Write`] adapter that computes the SHA-1 digest of everything written
/// to the wrapped writer, forwarding the data unchanged downstream.
///
/// # Examples
/// ```rust
/// use std::io::Write;
/// use ifa_stdlib::crypto::{Sha1Writer, sha1_hex};
///
/// let mut sink = Vec::new();
/// {
///     let mut writer = Sha1Writer::new(&mut sink);
///     writer.write_all(b"Hello, IFA SHA-1!").unwrap();
///     assert_eq!(writer.digest_hex(), sha1_hex(b"Hello, IFA SHA-1!"));
///     assert_eq!(writer.bytes_written(), 17);
/// }
/// assert_eq!(sink, b"Hello, IFA SHA-1!");
/// ```
#[derive(Clone, Debug)]
pub struct Sha1Writer<W: Write> {
    inner: W,
    hasher: Sha1,
    bytes_written: usize,
}

impl<W: Write> Sha1Writer<W> {
    /// Wrap `writer` and start accumulating a SHA-1 digest.
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            hasher: Sha1::new(),
            bytes_written: 0,
        }
    }

    /// Return the current SHA-1 digest over all bytes written so far.
    pub fn digest(&self) -> [u8; 20] {
        self.hasher.clone().finalize()
    }

    /// Return the current SHA-1 digest formatted as a lowercase hexadecimal string.
    pub fn digest_hex(&self) -> String {
        self.hasher.clone().finalize_hex()
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

    /// Unwrap this adapter, returning `(inner_writer, final_digest, bytes_written)`.
    pub fn into_parts(self) -> (W, [u8; 20], usize) {
        let digest = self.hasher.finalize();
        (self.inner, digest, self.bytes_written)
    }

    /// Unwrap this adapter, returning `(inner_writer, hex_digest, bytes_written)`.
    pub fn into_parts_hex(self) -> (W, String, usize) {
        let (inner, digest, bytes) = self.into_parts();
        (inner, to_hex(&digest), bytes)
    }

    /// Unwrap this adapter, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Sha1Writer<W> {
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

/// A [`Read`] adapter that computes the SHA-1 digest of everything read
/// from the wrapped reader, forwarding the data unchanged to the caller.
///
/// # Examples
/// ```rust
/// use std::io::Read;
/// use ifa_stdlib::crypto::{Sha1Reader, sha1_hex};
///
/// let data = b"Hello, IFA SHA-1 streaming!";
/// let mut reader = Sha1Reader::new(data.as_ref());
/// let mut out = Vec::new();
/// reader.read_to_end(&mut out).unwrap();
///
/// assert_eq!(reader.digest_hex(), sha1_hex(b"Hello, IFA SHA-1 streaming!"));
/// assert_eq!(reader.bytes_read(), data.len());
/// assert_eq!(out, data);
/// ```
#[derive(Clone, Debug)]
pub struct Sha1Reader<R: Read> {
    inner: R,
    hasher: Sha1,
    bytes_read: usize,
}

impl<R: Read> Sha1Reader<R> {
    /// Wrap `reader` and start accumulating a SHA-1 digest.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            hasher: Sha1::new(),
            bytes_read: 0,
        }
    }

    /// Return the current SHA-1 digest over all bytes read so far.
    pub fn digest(&self) -> [u8; 20] {
        self.hasher.clone().finalize()
    }

    /// Return the current SHA-1 digest formatted as a lowercase hexadecimal string.
    pub fn digest_hex(&self) -> String {
        self.hasher.clone().finalize_hex()
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

    /// Unwrap this adapter, returning `(inner_reader, final_digest, bytes_read)`.
    pub fn into_parts(self) -> (R, [u8; 20], usize) {
        let digest = self.hasher.finalize();
        (self.inner, digest, self.bytes_read)
    }

    /// Unwrap this adapter, returning `(inner_reader, hex_digest, bytes_read)`.
    pub fn into_parts_hex(self) -> (R, String, usize) {
        let (inner, digest, bytes) = self.into_parts();
        (inner, to_hex(&digest), bytes)
    }

    /// Unwrap this adapter, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Sha1Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_read += n;
        Ok(n)
    }
}

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to Base64 string according to RFC 4648.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, remainder) = data.as_chunks::<3>();

    for chunk in chunks {
        let b0 = chunk[0];
        let b1 = chunk[1];
        let b2 = chunk[2];

        out.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
        out.push(BASE64_CHARS[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        out.push(BASE64_CHARS[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
        out.push(BASE64_CHARS[(b2 & 63) as usize] as char);
    }

    match remainder.len() {
        1 => {
            let b0 = remainder[0];
            out.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
            out.push(BASE64_CHARS[((b0 & 3) << 4) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let b0 = remainder[0];
            let b1 = remainder[1];
            out.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
            out.push(BASE64_CHARS[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            out.push(BASE64_CHARS[((b1 & 15) << 2) as usize] as char);
            out.push('=');
        }
        _ => {}
    }

    out
}

/// Decode Base64 string according to RFC 4648.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err("Invalid Base64 length".to_string());
    }

    let decode_char = |b: u8| -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("Invalid Base64 character: {}", b as char)),
        }
    };

    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.as_chunks::<4>().0 {
        if chunk[0] == b'=' || chunk[1] == b'=' {
            return Err("Invalid padding position".to_string());
        }

        let c0 = decode_char(chunk[0])?;
        let c1 = decode_char(chunk[1])?;

        if chunk[2] == b'=' {
            if chunk[3] != b'=' {
                return Err("Invalid trailing padding".to_string());
            }
            out.push((c0 << 2) | (c1 >> 4));
            break;
        }

        let c2 = decode_char(chunk[2])?;
        out.push((c0 << 2) | (c1 >> 4));

        if chunk[3] == b'=' {
            out.push(((c1 & 15) << 4) | (c2 >> 2));
            break;
        }

        let c3 = decode_char(chunk[3])?;
        out.push(((c1 & 15) << 4) | (c2 >> 2));
        out.push(((c2 & 3) << 6) | c3);
    }

    Ok(out)
}

/// Compare two byte slices in constant time to prevent side-channel timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode a byte slice into a lowercase hexadecimal string.
pub fn hex_encode(data: &[u8]) -> String {
    to_hex(data)
}

/// Decode a hexadecimal string into raw bytes.
pub fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let s = input.trim();
    if !s.len().is_multiple_of(2) {
        return Err("Hex string must have an even length".to_string());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let slice = s.as_bytes();
    for i in (0..slice.len()).step_by(2) {
        let hi = hex_val(slice[i])
            .ok_or_else(|| format!("Invalid hex character '{}'", slice[i] as char))?;
        let lo = hex_val(slice[i + 1])
            .ok_or_else(|| format!("Invalid hex character '{}'", slice[i + 1] as char))?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

#[inline]
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Compare a byte slice with an expected hexadecimal string in constant time.
pub fn constant_time_eq_hex(actual: &[u8], expected_hex: &str) -> bool {
    match hex_decode(expected_hex) {
        Ok(expected) => constant_time_eq(actual, &expected),
        Err(_) => false,
    }
}

/// Encode bytes to URL-safe Base64 without padding according to RFC 4648 / RFC 7515 (JWS).
pub fn base64url_encode(data: &[u8]) -> String {
    let b64 = base64_encode(data);
    b64.replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Decode URL-safe Base64 string (with or without padding) according to RFC 4648 / RFC 7515 (JWS).
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut s = input.trim().replace('-', "+").replace('_', "/");
    match s.len() % 4 {
        2 => s.push_str("=="),
        3 => s.push('='),
        0 => {}
        _ => return Err("Invalid base64url length".to_string()),
    }
    base64_decode(&s)
}

/// Compute Sec-WebSocket-Accept key from client Sec-WebSocket-Key per RFC 6455 section 1.3.
pub fn websocket_accept_key(client_key: &str) -> String {
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let concatenated = format!("{}{}", client_key.trim(), WS_GUID);
    let digest = sha1(concatenated.as_bytes());
    base64_encode(&digest)
}

/// Compute BLAKE3 cryptographic hash digest.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let hash = ::blake3::hash(data);
    *hash.as_bytes()
}

/// Compute BLAKE3 hash and return as lowercase hexadecimal string.
pub fn blake3_hex(data: &[u8]) -> String {
    let digest = blake3(data);
    to_hex(&digest)
}

/// Incremental HMAC-SHA-256 authenticator (RFC 2104).
#[derive(Clone, Debug)]
pub struct HmacSha256 {
    inner: Sha256,
    outer_key_pad: [u8; 64],
    inner_key_pad: [u8; 64],
}

impl HmacSha256 {
    /// Initialize a new HMAC-SHA-256 instance with the provided secret key.
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; 64];
        if key.len() > 64 {
            let digest = sha256(key);
            key_block[..32].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = key_block[i] ^ 0x36;
            opad[i] = key_block[i] ^ 0x5c;
        }

        let mut inner = Sha256::new();
        inner.update(&ipad);

        Self {
            inner,
            outer_key_pad: opad,
            inner_key_pad: ipad,
        }
    }

    /// Reset HMAC state for a new message with the same key.
    pub fn reset(&mut self) {
        self.inner.reset();
        self.inner.update(&self.inner_key_pad);
    }

    /// Feed additional message bytes incrementally into HMAC state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and compute MAC digest, consuming the instance.
    pub fn finalize(self) -> [u8; 32] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Finalize and compute MAC digest, resetting the instance for reuse.
    pub fn finalize_reset(&mut self) -> [u8; 32] {
        let inner_hash = self.inner.finalize_reset();
        let mut outer = Sha256::new();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_hash);
        let digest = outer.finalize();
        self.inner.update(&self.inner_key_pad);
        digest
    }

    /// Finalize and return MAC digest as lowercase hexadecimal string.
    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }

    /// Verify whether the accumulated HMAC matches an expected MAC tag in constant time.
    pub fn verify(&self, expected_tag: &[u8]) -> bool {
        let mac = self.clone().finalize();
        constant_time_eq(&mac, expected_tag)
    }

    /// Verify whether the accumulated HMAC matches an expected lowercase or uppercase hex tag in constant time.
    pub fn verify_hex(&self, expected_hex: &str) -> bool {
        let mac = self.clone().finalize();
        constant_time_eq_hex(&mac, expected_hex)
    }
}

impl std::io::Write for HmacSha256 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compute HMAC-SHA-256 message authentication code (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new(key);
    hmac.update(message);
    hmac.finalize()
}

/// Compute HMAC-SHA-256 and return as lowercase hex string.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let digest = hmac_sha256(key, message);
    to_hex(&digest)
}

/// Verify an HMAC-SHA-256 message authentication code in constant time (RFC 2104).
pub fn hmac_sha256_verify(key: &[u8], message: &[u8], expected_tag: &[u8]) -> bool {
    let mac = hmac_sha256(key, message);
    constant_time_eq(&mac, expected_tag)
}

/// Verify an HMAC-SHA-256 hex string in constant time (RFC 2104).
pub fn hmac_sha256_verify_hex(key: &[u8], message: &[u8], expected_hex: &str) -> bool {
    let mac = hmac_sha256(key, message);
    constant_time_eq_hex(&mac, expected_hex)
}

/// A [`Write`] adapter that computes the HMAC-SHA-256 tag of everything written
/// while forwarding the bytes to the underlying writer.
///
/// # Examples
/// ```rust
/// use std::io::Write;
/// use ifa_stdlib::crypto::{HmacSha256Writer, hmac_sha256_hex};
///
/// let key = b"secret-key";
/// let mut sink = Vec::new();
/// let mut writer = HmacSha256Writer::new(&mut sink, key);
/// writer.write_all(b"hello world").unwrap();
///
/// assert_eq!(writer.mac_hex(), hmac_sha256_hex(key, b"hello world"));
/// assert!(writer.verify_hex(&hmac_sha256_hex(key, b"hello world")));
/// ```
#[derive(Clone, Debug)]
pub struct HmacSha256Writer<W: Write> {
    inner: W,
    hmac: HmacSha256,
    bytes_written: usize,
}

impl<W: Write> HmacSha256Writer<W> {
    /// Wrap `writer` and initialize an HMAC-SHA-256 authenticator with `key`.
    pub fn new(writer: W, key: &[u8]) -> Self {
        Self {
            inner: writer,
            hmac: HmacSha256::new(key),
            bytes_written: 0,
        }
    }

    /// Return the current HMAC-SHA-256 tag over all bytes written so far.
    pub fn mac(&self) -> [u8; 32] {
        self.hmac.clone().finalize()
    }

    /// Return the current HMAC-SHA-256 tag formatted as a lowercase hexadecimal string.
    pub fn mac_hex(&self) -> String {
        self.hmac.clone().finalize_hex()
    }

    /// Verify whether the accumulated HMAC-SHA-256 matches an expected tag in constant time.
    pub fn verify(&self, expected_tag: &[u8]) -> bool {
        self.hmac.verify(expected_tag)
    }

    /// Verify whether the accumulated HMAC-SHA-256 matches an expected hex string in constant time.
    pub fn verify_hex(&self, expected_hex: &str) -> bool {
        self.hmac.verify_hex(expected_hex)
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

    /// Unwrap this adapter, returning `(inner_writer, final_mac, bytes_written)`.
    pub fn into_parts(self) -> (W, [u8; 32], usize) {
        let mac = self.hmac.finalize();
        (self.inner, mac, self.bytes_written)
    }

    /// Unwrap this adapter, returning `(inner_writer, hex_mac, bytes_written)`.
    pub fn into_parts_hex(self) -> (W, String, usize) {
        let (inner, mac, bytes) = self.into_parts();
        (inner, to_hex(&mac), bytes)
    }

    /// Unwrap this adapter, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for HmacSha256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hmac.update(&buf[..n]);
        self.bytes_written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A [`Read`] adapter that computes the HMAC-SHA-256 tag of everything read
/// from the wrapped reader, forwarding data unchanged to the caller.
///
/// # Examples
/// ```rust
/// use std::io::Read;
/// use ifa_stdlib::crypto::{HmacSha256Reader, hmac_sha256_hex};
///
/// let key = b"secret-key";
/// let message = b"authenticated streaming payload";
/// let mut reader = HmacSha256Reader::new(message.as_slice(), key);
/// let mut buf = Vec::new();
/// reader.read_to_end(&mut buf).unwrap();
///
/// assert_eq!(buf, message);
/// assert!(reader.verify_hex(&hmac_sha256_hex(key, message)));
/// ```
#[derive(Clone, Debug)]
pub struct HmacSha256Reader<R: Read> {
    inner: R,
    hmac: HmacSha256,
    bytes_read: usize,
}

impl<R: Read> HmacSha256Reader<R> {
    /// Wrap `reader` and initialize an HMAC-SHA-256 authenticator with `key`.
    pub fn new(reader: R, key: &[u8]) -> Self {
        Self {
            inner: reader,
            hmac: HmacSha256::new(key),
            bytes_read: 0,
        }
    }

    /// Return the current HMAC-SHA-256 tag over all bytes read so far.
    pub fn mac(&self) -> [u8; 32] {
        self.hmac.clone().finalize()
    }

    /// Return the current HMAC-SHA-256 tag formatted as a lowercase hexadecimal string.
    pub fn mac_hex(&self) -> String {
        self.hmac.clone().finalize_hex()
    }

    /// Verify whether the accumulated HMAC-SHA-256 matches an expected tag in constant time.
    pub fn verify(&self, expected_tag: &[u8]) -> bool {
        self.hmac.verify(expected_tag)
    }

    /// Verify whether the accumulated HMAC-SHA-256 matches an expected hex string in constant time.
    pub fn verify_hex(&self, expected_hex: &str) -> bool {
        self.hmac.verify_hex(expected_hex)
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

    /// Unwrap this adapter, returning `(inner_reader, final_mac, bytes_read)`.
    pub fn into_parts(self) -> (R, [u8; 32], usize) {
        let mac = self.hmac.finalize();
        (self.inner, mac, self.bytes_read)
    }

    /// Unwrap this adapter, returning `(inner_reader, hex_mac, bytes_read)`.
    pub fn into_parts_hex(self) -> (R, String, usize) {
        let (inner, mac, bytes) = self.into_parts();
        (inner, to_hex(&mac), bytes)
    }

    /// Unwrap this adapter, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for HmacSha256Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hmac.update(&buf[..n]);
            self.bytes_read += n;
        }
        Ok(n)
    }
}

/// Incremental HMAC-SHA-1 authenticator (RFC 2104).
#[derive(Clone, Debug)]
pub struct HmacSha1 {
    inner: Sha1,
    outer_key_pad: [u8; 64],
    inner_key_pad: [u8; 64],
}

impl HmacSha1 {
    /// Initialize a new HMAC-SHA-1 instance with the provided secret key.
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; 64];
        if key.len() > 64 {
            let digest = sha1(key);
            key_block[..20].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = key_block[i] ^ 0x36;
            opad[i] = key_block[i] ^ 0x5c;
        }

        let mut inner = Sha1::new();
        inner.update(&ipad);

        Self {
            inner,
            outer_key_pad: opad,
            inner_key_pad: ipad,
        }
    }

    /// Reset HMAC state for a new message with the same key.
    pub fn reset(&mut self) {
        self.inner.reset();
        self.inner.update(&self.inner_key_pad);
    }

    /// Feed additional message bytes incrementally into HMAC state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and compute MAC digest, consuming the instance.
    pub fn finalize(self) -> [u8; 20] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha1::new();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Finalize and compute MAC digest, resetting the instance for reuse.
    pub fn finalize_reset(&mut self) -> [u8; 20] {
        let inner_hash = self.inner.finalize_reset();
        let mut outer = Sha1::new();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_hash);
        let digest = outer.finalize();
        self.inner.update(&self.inner_key_pad);
        digest
    }

    /// Finalize and return MAC digest as lowercase hexadecimal string.
    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }

    /// Verify whether the accumulated HMAC matches an expected MAC tag in constant time.
    pub fn verify(&self, expected_tag: &[u8]) -> bool {
        let mac = self.clone().finalize();
        constant_time_eq(&mac, expected_tag)
    }

    /// Verify whether the accumulated HMAC matches an expected lowercase or uppercase hex tag in constant time.
    pub fn verify_hex(&self, expected_hex: &str) -> bool {
        let mac = self.clone().finalize();
        constant_time_eq_hex(&mac, expected_hex)
    }
}

impl std::io::Write for HmacSha1 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compute HMAC-SHA-1 message authentication code (RFC 2104).
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut hmac = HmacSha1::new(key);
    hmac.update(message);
    hmac.finalize()
}

/// Compute HMAC-SHA-1 and return as lowercase hex string.
pub fn hmac_sha1_hex(key: &[u8], message: &[u8]) -> String {
    let digest = hmac_sha1(key, message);
    to_hex(&digest)
}

/// Verify an HMAC-SHA-1 message authentication code in constant time (RFC 2104).
pub fn hmac_sha1_verify(key: &[u8], message: &[u8], expected_tag: &[u8]) -> bool {
    let mac = hmac_sha1(key, message);
    constant_time_eq(&mac, expected_tag)
}

/// Verify an HMAC-SHA-1 hex string in constant time (RFC 2104).
pub fn hmac_sha1_verify_hex(key: &[u8], message: &[u8], expected_hex: &str) -> bool {
    let mac = hmac_sha1(key, message);
    constant_time_eq_hex(&mac, expected_hex)
}

/// A [`Write`] adapter that computes the HMAC-SHA-1 tag of everything written
/// while forwarding the bytes to the underlying writer.
///
/// # Examples
/// ```rust
/// use std::io::Write;
/// use ifa_stdlib::crypto::{HmacSha1Writer, hmac_sha1_hex};
///
/// let key = b"secret-key";
/// let mut sink = Vec::new();
/// let mut writer = HmacSha1Writer::new(&mut sink, key);
/// writer.write_all(b"hello world").unwrap();
///
/// assert_eq!(writer.mac_hex(), hmac_sha1_hex(key, b"hello world"));
/// assert!(writer.verify_hex(&hmac_sha1_hex(key, b"hello world")));
/// ```
#[derive(Clone, Debug)]
pub struct HmacSha1Writer<W: Write> {
    inner: W,
    hmac: HmacSha1,
    bytes_written: usize,
}

impl<W: Write> HmacSha1Writer<W> {
    /// Wrap `writer` and initialize an HMAC-SHA-1 authenticator with `key`.
    pub fn new(writer: W, key: &[u8]) -> Self {
        Self {
            inner: writer,
            hmac: HmacSha1::new(key),
            bytes_written: 0,
        }
    }

    /// Return the current HMAC-SHA-1 tag over all bytes written so far.
    pub fn mac(&self) -> [u8; 20] {
        self.hmac.clone().finalize()
    }

    /// Return the current HMAC-SHA-1 tag formatted as a lowercase hexadecimal string.
    pub fn mac_hex(&self) -> String {
        self.hmac.clone().finalize_hex()
    }

    /// Verify whether the accumulated HMAC-SHA-1 matches an expected tag in constant time.
    pub fn verify(&self, expected_tag: &[u8]) -> bool {
        self.hmac.verify(expected_tag)
    }

    /// Verify whether the accumulated HMAC-SHA-1 matches an expected hex string in constant time.
    pub fn verify_hex(&self, expected_hex: &str) -> bool {
        self.hmac.verify_hex(expected_hex)
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

    /// Unwrap this adapter, returning `(inner_writer, final_mac, bytes_written)`.
    pub fn into_parts(self) -> (W, [u8; 20], usize) {
        let mac = self.hmac.finalize();
        (self.inner, mac, self.bytes_written)
    }

    /// Unwrap this adapter, returning `(inner_writer, hex_mac, bytes_written)`.
    pub fn into_parts_hex(self) -> (W, String, usize) {
        let (inner, mac, bytes) = self.into_parts();
        (inner, to_hex(&mac), bytes)
    }

    /// Unwrap this adapter, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for HmacSha1Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hmac.update(&buf[..n]);
        self.bytes_written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A [`Read`] adapter that computes the HMAC-SHA-1 tag of everything read
/// from the wrapped reader, forwarding data unchanged to the caller.
///
/// # Examples
/// ```rust
/// use std::io::Read;
/// use ifa_stdlib::crypto::{HmacSha1Reader, hmac_sha1_hex};
///
/// let key = b"secret-key";
/// let message = b"authenticated streaming payload";
/// let mut reader = HmacSha1Reader::new(message.as_slice(), key);
/// let mut buf = Vec::new();
/// reader.read_to_end(&mut buf).unwrap();
///
/// assert_eq!(buf, message);
/// assert!(reader.verify_hex(&hmac_sha1_hex(key, message)));
/// ```
#[derive(Clone, Debug)]
pub struct HmacSha1Reader<R: Read> {
    inner: R,
    hmac: HmacSha1,
    bytes_read: usize,
}

impl<R: Read> HmacSha1Reader<R> {
    /// Wrap `reader` and initialize an HMAC-SHA-1 authenticator with `key`.
    pub fn new(reader: R, key: &[u8]) -> Self {
        Self {
            inner: reader,
            hmac: HmacSha1::new(key),
            bytes_read: 0,
        }
    }

    /// Return the current HMAC-SHA-1 tag over all bytes read so far.
    pub fn mac(&self) -> [u8; 20] {
        self.hmac.clone().finalize()
    }

    /// Return the current HMAC-SHA-1 tag formatted as a lowercase hexadecimal string.
    pub fn mac_hex(&self) -> String {
        self.hmac.clone().finalize_hex()
    }

    /// Verify whether the accumulated HMAC-SHA-1 matches an expected tag in constant time.
    pub fn verify(&self, expected_tag: &[u8]) -> bool {
        self.hmac.verify(expected_tag)
    }

    /// Verify whether the accumulated HMAC-SHA-1 matches an expected hex string in constant time.
    pub fn verify_hex(&self, expected_hex: &str) -> bool {
        self.hmac.verify_hex(expected_hex)
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

    /// Unwrap this adapter, returning `(inner_reader, final_mac, bytes_read)`.
    pub fn into_parts(self) -> (R, [u8; 20], usize) {
        let mac = self.hmac.finalize();
        (self.inner, mac, self.bytes_read)
    }

    /// Unwrap this adapter, returning `(inner_reader, hex_mac, bytes_read)`.
    pub fn into_parts_hex(self) -> (R, String, usize) {
        let (inner, mac, bytes) = self.into_parts();
        (inner, to_hex(&mac), bytes)
    }

    /// Unwrap this adapter, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for HmacSha1Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hmac.update(&buf[..n]);
            self.bytes_read += n;
        }
        Ok(n)
    }
}

/// Generate HMAC-Based One-Time Password (HOTP) per RFC 4226.
pub fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let counter_bytes = counter.to_be_bytes();
    let hash = hmac_sha1(key, &counter_bytes);
    let offset = (hash[19] & 0x0f) as usize;
    let binary = ((u32::from(hash[offset] & 0x7f)) << 24)
        | ((u32::from(hash[offset + 1])) << 16)
        | ((u32::from(hash[offset + 2])) << 8)
        | (u32::from(hash[offset + 3]));

    let modulo = 10u32.pow(digits.min(10));
    let token = binary % modulo;
    format!("{:0width$}", token, width = digits as usize)
}

/// Generate Time-Based One-Time Password (TOTP) per RFC 6238.
pub fn totp(key: &[u8], time_seconds: u64, step_seconds: u64, digits: u32) -> String {
    let step = if step_seconds == 0 { 30 } else { step_seconds };
    let counter = time_seconds / step;
    hotp(key, counter, digits)
}

/// Verify a TOTP token against a timestamp with an allowed window of time steps.
pub fn totp_verify(
    key: &[u8],
    code: &str,
    time_seconds: u64,
    step_seconds: u64,
    window_steps: i64,
) -> bool {
    let step = if step_seconds == 0 { 30 } else { step_seconds };
    let current_counter = (time_seconds / step) as i64;
    let clean_code = code.trim();
    let digits = clean_code.len() as u32;
    if digits == 0 {
        return false;
    }

    let win = window_steps.abs();
    for offset in -win..=win {
        let counter = current_counter + offset;
        if counter >= 0 {
            let expected = hotp(key, counter as u64, digits);
            if expected == clean_code {
                return true;
            }
        }
    }
    false
}

/// Compute PBKDF2-HMAC-SHA256 key derivation (RFC 2898 / RFC 8018).
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> Vec<u8> {
    let mut derived = Vec::with_capacity(key_len);
    let mut block_index: u32 = 1;

    while derived.len() < key_len {
        // U_1 = PRF(password, salt || INT_32_BE(block_index))
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac_sha256(password, &msg);
        let mut t = u;

        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for i in 0..32 {
                t[i] ^= u[i];
            }
        }

        let needed = key_len - derived.len();
        if needed < 32 {
            derived.extend_from_slice(&t[..needed]);
        } else {
            derived.extend_from_slice(&t);
        }

        block_index += 1;
    }

    derived
}

/// Compute PBKDF2-HMAC-SHA256 and return lowercase hex string.
pub fn pbkdf2_hmac_sha256_hex(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> String {
    let derived = pbkdf2_hmac_sha256(password, salt, iterations, key_len);
    to_hex(&derived)
}

/// Verify a PBKDF2-HMAC-SHA256 derived key against an expected key in constant time.
pub fn pbkdf2_hmac_sha256_verify(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    expected_key: &[u8],
) -> bool {
    let derived = pbkdf2_hmac_sha256(password, salt, iterations, expected_key.len());
    constant_time_eq(&derived, expected_key)
}

/// Verify a PBKDF2-HMAC-SHA256 derived key against expected hex-encoded key in constant time.
pub fn pbkdf2_hmac_sha256_verify_hex(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    expected_hex: &str,
) -> bool {
    let expected = match hex_decode(expected_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let derived = pbkdf2_hmac_sha256(password, salt, iterations, expected.len());
    constant_time_eq(&derived, &expected)
}

/// Key derivation using PBKDF2 with HMAC-SHA1 according to RFC 2898 / RFC 6070.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    if iterations == 0 || key_len == 0 {
        return Vec::new();
    }
    let mut derived = Vec::with_capacity(key_len);
    let mut block_index: u32 = 1;

    while derived.len() < key_len {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac_sha1(password, &msg);
        let mut t = u;

        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for i in 0..20 {
                t[i] ^= u[i];
            }
        }

        let needed = key_len - derived.len();
        if needed < 20 {
            derived.extend_from_slice(&t[..needed]);
        } else {
            derived.extend_from_slice(&t);
        }

        block_index += 1;
    }

    derived
}

/// Compute PBKDF2-HMAC-SHA1 and return lowercase hex string.
pub fn pbkdf2_hmac_sha1_hex(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> String {
    let derived = pbkdf2_hmac_sha1(password, salt, iterations, key_len);
    to_hex(&derived)
}

/// Verify a PBKDF2-HMAC-SHA1 derived key against an expected key in constant time.
pub fn pbkdf2_hmac_sha1_verify(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    expected_key: &[u8],
) -> bool {
    let derived = pbkdf2_hmac_sha1(password, salt, iterations, expected_key.len());
    constant_time_eq(&derived, expected_key)
}

/// Verify a PBKDF2-HMAC-SHA1 derived key against expected hex-encoded key in constant time.
pub fn pbkdf2_hmac_sha1_verify_hex(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    expected_hex: &str,
) -> bool {
    let expected = match hex_decode(expected_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let derived = pbkdf2_hmac_sha1(password, salt, iterations, expected.len());
    constant_time_eq(&derived, &expected)
}

/// HKDF-Extract step per RFC 5869 using HMAC-SHA256.
///
/// Extracts a pseudorandom key (PRK) of 32 bytes from input key material `ikm` and optional `salt`.
/// If `salt` is `None` or empty, a string of 32 zero bytes is used as specified in RFC 5869.
pub fn hkdf_sha256_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    let zeros = [0u8; 32];
    let actual_salt = match salt {
        Some(s) if !s.is_empty() => s,
        _ => &zeros,
    };
    hmac_sha256(actual_salt, ikm)
}

/// HKDF-Expand step per RFC 5869 using HMAC-SHA256.
///
/// Expands the pseudorandom key `prk` to produce output keying material (OKM) of length `okm_len`.
/// Returns an error if `okm_len > 255 * 32` (8160 bytes).
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>, String> {
    const HASH_LEN: usize = 32;
    if okm_len > 255 * HASH_LEN {
        return Err(format!(
            "Requested length {} exceeds maximum HKDF-SHA256 output length {}",
            okm_len,
            255 * HASH_LEN
        ));
    }
    if okm_len == 0 {
        return Ok(Vec::new());
    }

    let n = okm_len.div_ceil(HASH_LEN);
    let mut okm = Vec::with_capacity(okm_len);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut hmac = HmacSha256::new(prk);
        hmac.update(&t);
        hmac.update(info);
        hmac.update(&[i as u8]);
        let step_mac = hmac.finalize();
        t.clear();
        t.extend_from_slice(&step_mac);

        let to_take = std::cmp::min(HASH_LEN, okm_len - okm.len());
        okm.extend_from_slice(&t[..to_take]);
    }

    Ok(okm)
}

/// Perform HKDF-SHA256 (Extract then Expand) per RFC 5869.
pub fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, String> {
    let prk = hkdf_sha256_extract(salt, ikm);
    hkdf_sha256_expand(&prk, info, okm_len)
}

/// Perform HKDF-SHA256 and return lowercase hex string.
pub fn hkdf_sha256_hex(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<String, String> {
    let okm = hkdf_sha256(salt, ikm, info, okm_len)?;
    Ok(to_hex(&okm))
}

/// HKDF-Extract step per RFC 5869 using HMAC-SHA1.
///
/// Extracts a pseudorandom key (PRK) of 20 bytes from input key material `ikm` and optional `salt`.
/// If `salt` is `None` or empty, a string of 20 zero bytes is used as specified in RFC 5869.
pub fn hkdf_sha1_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 20] {
    let zeros = [0u8; 20];
    let actual_salt = match salt {
        Some(s) if !s.is_empty() => s,
        _ => &zeros,
    };
    hmac_sha1(actual_salt, ikm)
}

/// HKDF-Expand step per RFC 5869 using HMAC-SHA1.
///
/// Expands the pseudorandom key `prk` to produce output keying material (OKM) of length `okm_len`.
/// Returns an error if `okm_len > 255 * 20` (5100 bytes).
pub fn hkdf_sha1_expand(prk: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>, String> {
    const HASH_LEN: usize = 20;
    if okm_len > 255 * HASH_LEN {
        return Err(format!(
            "Requested length {} exceeds maximum HKDF-SHA1 output length {}",
            okm_len,
            255 * HASH_LEN
        ));
    }
    if okm_len == 0 {
        return Ok(Vec::new());
    }

    let n = okm_len.div_ceil(HASH_LEN);
    let mut okm = Vec::with_capacity(okm_len);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut hmac = HmacSha1::new(prk);
        hmac.update(&t);
        hmac.update(info);
        hmac.update(&[i as u8]);
        let step_mac = hmac.finalize();
        t.clear();
        t.extend_from_slice(&step_mac);

        let to_take = std::cmp::min(HASH_LEN, okm_len - okm.len());
        okm.extend_from_slice(&t[..to_take]);
    }

    Ok(okm)
}

/// Perform HKDF-SHA1 (Extract then Expand) per RFC 5869.
pub fn hkdf_sha1(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, String> {
    let prk = hkdf_sha1_extract(salt, ikm);
    hkdf_sha1_expand(&prk, info, okm_len)
}

/// Perform HKDF-SHA1 and return lowercase hex string.
pub fn hkdf_sha1_hex(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<String, String> {
    let okm = hkdf_sha1(salt, ikm, info, okm_len)?;
    Ok(to_hex(&okm))
}

/// JWT claims representing standard RFC 7519 registered claims and arbitrary custom fields.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

impl JwtClaims {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    pub fn with_exp(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    pub fn with_nbf(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    pub fn with_iat(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    pub fn with_iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    pub fn with_aud(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    pub fn with_custom(mut self, key: impl Into<String>, val: serde_json::Value) -> Self {
        self.custom.insert(key.into(), val);
        self
    }

    pub fn get_custom(&self, key: &str) -> Option<&serde_json::Value> {
        self.custom.get(key)
    }
}

/// JWT verification and generation errors (RFC 7519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    InvalidFormat,
    InvalidHeader,
    UnsupportedAlgorithm(String),
    InvalidSignature,
    Expired { expired_at: u64, current_time: u64 },
    NotYetValid { not_before: u64, current_time: u64 },
    SerializationError(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => {
                write!(f, "Invalid JWT format (expected 3 parts separated by dots)")
            }
            Self::InvalidHeader => write!(f, "Invalid JWT header"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "Unsupported JWT algorithm: {}", alg),
            Self::InvalidSignature => write!(f, "Invalid JWT HMAC signature"),
            Self::Expired {
                expired_at,
                current_time,
            } => {
                write!(
                    f,
                    "JWT expired at {} (current time: {})",
                    expired_at, current_time
                )
            }
            Self::NotYetValid {
                not_before,
                current_time,
            } => {
                write!(
                    f,
                    "JWT not valid before {} (current time: {})",
                    not_before, current_time
                )
            }
            Self::SerializationError(msg) => write!(f, "JWT JSON serialization error: {}", msg),
        }
    }
}

impl std::error::Error for JwtError {}

/// JSON Web Token (JWT) HS256 engine according to RFC 7519 and RFC 7515.
pub struct Jwt;

impl Jwt {
    /// Sign claims using HS256 (HMAC-SHA256) and secret key.
    pub fn sign_hs256(secret: &[u8], claims: &JwtClaims) -> Result<String, JwtError> {
        let header_json = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = base64url_encode(header_json.as_bytes());

        let claims_json = serde_json::to_string(claims)
            .map_err(|e| JwtError::SerializationError(e.to_string()))?;
        let claims_b64 = base64url_encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let sig = hmac_sha256(secret, signing_input.as_bytes());
        let sig_b64 = base64url_encode(&sig);

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    /// Verify HS256 token against secret key, checking expiration and validity time windows.
    /// `leeway_secs` allows slight clock drift (e.g. 5 to 60 seconds, or 0).
    pub fn verify_hs256(
        secret: &[u8],
        token: &str,
        current_time_secs: u64,
        leeway_secs: u64,
    ) -> Result<JwtClaims, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }

        let header_b64 = parts[0];
        let claims_b64 = parts[1];
        let sig_b64 = parts[2];

        // 1. Verify header
        let header_bytes = base64url_decode(header_b64).map_err(|_| JwtError::InvalidHeader)?;
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidHeader)?;
        let alg = header_json
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if alg != "HS256" {
            return Err(JwtError::UnsupportedAlgorithm(alg.to_string()));
        }

        // 2. Verify signature in constant time
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let expected_sig = hmac_sha256(secret, signing_input.as_bytes());
        let expected_sig_b64 = base64url_encode(&expected_sig);

        if !constant_time_eq(sig_b64.as_bytes(), expected_sig_b64.as_bytes()) {
            return Err(JwtError::InvalidSignature);
        }

        // 3. Decode claims
        let claims_bytes = base64url_decode(claims_b64).map_err(|_| JwtError::InvalidFormat)?;
        let claims: JwtClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|e| JwtError::SerializationError(e.to_string()))?;

        // 4. Validate exp (Expiration Time)
        if let Some(exp) = claims.exp {
            if current_time_secs > exp.saturating_add(leeway_secs) {
                return Err(JwtError::Expired {
                    expired_at: exp,
                    current_time: current_time_secs,
                });
            }
        }

        // 5. Validate nbf (Not Before)
        if let Some(nbf) = claims.nbf {
            if current_time_secs.saturating_add(leeway_secs) < nbf {
                return Err(JwtError::NotYetValid {
                    not_before: nbf,
                    current_time: current_time_secs,
                });
            }
        }

        Ok(claims)
    }
}

/// Fills `buffer` with cryptographically secure random bytes from the OS entropy source.
pub fn secure_random_fill(buffer: &mut [u8]) -> Result<(), String> {
    if buffer.is_empty() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::fs::File;
        let mut file = File::open("/dev/urandom")
            .map_err(|e| format!("failed to open /dev/urandom: {}", e))?;
        file.read_exact(buffer)
            .map_err(|e| format!("failed to read from /dev/urandom: {}", e))?;
        Ok(())
    }

    #[cfg(windows)]
    {
        #[link(name = "advapi32")]
        extern "system" {
            fn SystemFunction036(pbBuffer: *mut u8, dwLen: u32) -> u8;
        }
        let len = buffer.len();
        let ret = unsafe { SystemFunction036(buffer.as_mut_ptr(), len as u32) };
        if ret != 0 {
            Ok(())
        } else {
            Err("SystemFunction036 (RtlGenRandom) failed".to_string())
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err("Secure entropy source is unsupported on this platform".to_string())
    }
}

/// Generates `len` cryptographically secure random bytes from the OS entropy source.
pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    secure_random_fill(&mut buf)?;
    Ok(buf)
}

/// Generates a cryptographically secure random hex-encoded token of `byte_len` random bytes (producing 2*byte_len characters).
pub fn secure_random_token(byte_len: usize) -> Result<String, String> {
    let bytes = secure_random_bytes(byte_len)?;
    Ok(hex_encode(&bytes))
}

/// Generates a cryptographically secure random URL-safe base64 token of `byte_len` random bytes (unpadded).
pub fn secure_random_token_base64(byte_len: usize) -> Result<String, String> {
    let bytes = secure_random_bytes(byte_len)?;
    Ok(base64url_encode(&bytes).trim_end_matches('=').to_string())
}

/// Error encountered while parsing or generating an RFC 4122 / RFC 9562 UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UuidError {
    InvalidLength(usize),
    InvalidFormat,
    InvalidCharacter(char),
    EntropyError(String),
}

impl std::fmt::Display for UuidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(len) => write!(f, "Invalid UUID string length: {}", len),
            Self::InvalidFormat => write!(f, "Invalid UUID format"),
            Self::InvalidCharacter(c) => write!(f, "Invalid character in UUID string: '{}'", c),
            Self::EntropyError(err) => write!(f, "Failed to gather entropy for UUID: {}", err),
        }
    }
}

impl std::error::Error for UuidError {}

/// RFC 4122 / RFC 9562 Universally Unique Identifier (UUID).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Nil UUID (00000000-0000-0000-0000-000000000000).
    pub const NIL: Self = Self([0u8; 16]);

    /// Returns the Nil UUID.
    pub const fn nil() -> Self {
        Self::NIL
    }

    /// Check if this UUID is the Nil UUID.
    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Creates a UUID directly from raw 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw 16 bytes of the UUID.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Consumes the UUID and returns the raw 16 bytes.
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Returns the UUID version (e.g. 4 for random UUID), or None if nil.
    pub fn version(&self) -> Option<usize> {
        if self.is_nil() {
            None
        } else {
            Some((self.0[6] >> 4) as usize)
        }
    }

    /// Generates a new random Version 4 UUID according to RFC 4122.
    pub fn new_v4() -> Result<Self, UuidError> {
        let mut bytes = [0u8; 16];
        secure_random_fill(&mut bytes).map_err(UuidError::EntropyError)?;
        // Set version 4: bits 4-7 of octet 6 to 0100_2
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        // Set variant RFC 4122: bits 6-7 of octet 8 to 10_2
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(Self(bytes))
    }

    /// Generates a new random Version 4 UUID according to RFC 4122, panicking on entropy failure.
    pub fn v4() -> Self {
        Self::new_v4().expect("Failed to generate secure random UUID v4")
    }

    /// Formats the UUID as a canonical hyphenated string (8-4-4-4-12 lowercase hex characters).
    pub fn to_hyphenated_string(&self) -> String {
        let b = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3],
            b[4], b[5],
            b[6], b[7],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }

    /// Formats the UUID as a simple 32-character lowercase hex string without hyphens.
    pub fn to_simple_string(&self) -> String {
        to_hex(&self.0)
    }

    /// Parses a UUID from string in standard hyphenated, simple hex, braced, or URN format.
    pub fn parse_str(input: &str) -> Result<Self, UuidError> {
        let trimmed = input.trim();
        let s = if let Some(stripped) = trimmed.strip_prefix("urn:uuid:") {
            stripped
        } else if trimmed.starts_with('{') && trimmed.ends_with('}') {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        };

        if s.len() == 36 {
            // Standard hyphenated format: 8-4-4-4-12
            let b = s.as_bytes();
            if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
                return Err(UuidError::InvalidFormat);
            }
            let mut hex_clean = String::with_capacity(32);
            hex_clean.push_str(&s[0..8]);
            hex_clean.push_str(&s[9..13]);
            hex_clean.push_str(&s[14..18]);
            hex_clean.push_str(&s[19..23]);
            hex_clean.push_str(&s[24..36]);
            Self::from_hex_32(&hex_clean)
        } else if s.len() == 32 {
            Self::from_hex_32(s)
        } else {
            Err(UuidError::InvalidLength(s.len()))
        }
    }

    fn from_hex_32(hex: &str) -> Result<Self, UuidError> {
        if hex.len() != 32 {
            return Err(UuidError::InvalidLength(hex.len()));
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let slice = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(slice, 16).map_err(|_| {
                let bad_ch = slice
                    .chars()
                    .find(|c| !c.is_ascii_hexdigit())
                    .unwrap_or('?');
                UuidError::InvalidCharacter(bad_ch)
            })?;
        }
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hyphenated_string())
    }
}

impl std::fmt::Debug for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Uuid({})", self.to_hyphenated_string())
    }
}

impl std::str::FromStr for Uuid {
    type Err = UuidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

impl Serialize for Uuid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hyphenated_string())
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse_str(&s).map_err(serde::de::Error::custom)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_rfc3174_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn test_base64_rfc4648_roundtrip() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");

        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_rfc6455_websocket_accept_key() {
        // Official RFC 6455 section 1.3 test vector
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = websocket_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_hmac_sha1_and_sha256_rfc2202_rfc4231() {
        // RFC 2202 test case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
        let key_20 = [0x0bu8; 20];
        assert_eq!(
            hmac_sha1_hex(&key_20, b"Hi There"),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );

        // RFC 4231 test case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
        assert_eq!(
            hmac_sha256_hex(&key_20, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_rfc4226_hotp_and_rfc6238_totp_vectors() {
        // RFC 4226 Appendix D official test secret
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 0, 6), "755224");
        assert_eq!(hotp(secret, 1, 6), "287082");
        assert_eq!(hotp(secret, 2, 6), "359152");
        assert_eq!(hotp(secret, 3, 6), "969429");
        assert_eq!(hotp(secret, 4, 6), "338314");
        assert_eq!(hotp(secret, 5, 6), "254676");
        assert_eq!(hotp(secret, 6, 6), "287922");
        assert_eq!(hotp(secret, 7, 6), "162583");
        assert_eq!(hotp(secret, 8, 6), "399871");
        assert_eq!(hotp(secret, 9, 6), "520489");

        // TOTP verification at T=59 (counter 1)
        assert_eq!(totp(secret, 59, 30, 6), "287082");
        assert!(totp_verify(secret, "287082", 59, 30, 1));
        assert!(totp_verify(secret, "287082", 60, 30, 1)); // counter 2, window +/- 1 matches counter 1
        assert!(!totp_verify(secret, "000000", 59, 30, 1));
    }

    #[test]
    fn test_rfc6070_pbkdf2_hmac_sha256() {
        let password = b"password";
        let salt = b"salt";

        // c = 1, dkLen = 32
        assert_eq!(
            pbkdf2_hmac_sha256_hex(password, salt, 1, 32),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );

        // c = 2, dkLen = 32
        assert_eq!(
            pbkdf2_hmac_sha256_hex(password, salt, 2, 32),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn test_base64url_and_constant_time_eq() {
        assert!(constant_time_eq(b"hello world", b"hello world"));
        assert!(!constant_time_eq(b"hello world", b"hello word!"));
        assert!(!constant_time_eq(b"short", b"longer string"));

        let payload = b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        let enc = base64url_encode(payload);
        assert_eq!(enc, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let dec = base64url_decode(&enc).unwrap();
        assert_eq!(dec, payload);

        // Test with bytes that produce + and / in standard base64
        let binary_data = vec![251, 255, 254, 253]; // produces standard + and /
        let url_enc = base64url_encode(&binary_data);
        assert!(!url_enc.contains('+'));
        assert!(!url_enc.contains('/'));
        assert!(!url_enc.contains('='));
        let dec_binary = base64url_decode(&url_enc).unwrap();
        assert_eq!(dec_binary, binary_data);
    }

    #[test]
    fn test_jwt_sign_and_verify() {
        let secret = b"super-secret-key-for-ifa-jwt-auth";
        let claims = JwtClaims::new()
            .with_sub("user_123")
            .with_iss("ifa-auth-service")
            .with_iat(1000)
            .with_nbf(1000)
            .with_exp(2000)
            .with_custom("role", serde_json::json!("admin"))
            .with_custom("email", serde_json::json!("alice@ifa.dev"));

        // Sign token
        let token = Jwt::sign_hs256(secret, &claims).expect("Signing must succeed");
        assert_eq!(token.split('.').count(), 3);

        // Verify valid token at t = 1500
        let verified =
            Jwt::verify_hs256(secret, &token, 1500, 0).expect("Verification must succeed");
        assert_eq!(verified.sub.as_deref(), Some("user_123"));
        assert_eq!(verified.iss.as_deref(), Some("ifa-auth-service"));
        assert_eq!(
            verified.get_custom("role"),
            Some(&serde_json::json!("admin"))
        );
        assert_eq!(
            verified.get_custom("email"),
            Some(&serde_json::json!("alice@ifa.dev"))
        );

        // Verification fails with invalid secret
        let wrong_secret = b"wrong-secret-key";
        let err_sig = Jwt::verify_hs256(wrong_secret, &token, 1500, 0).unwrap_err();
        assert_eq!(err_sig, JwtError::InvalidSignature);

        // Verification fails when expired (t = 2500)
        let err_exp = Jwt::verify_hs256(secret, &token, 2500, 0).unwrap_err();
        assert_eq!(
            err_exp,
            JwtError::Expired {
                expired_at: 2000,
                current_time: 2500
            }
        );

        // Verification succeeds with leeway (exp 2000, t = 2050, leeway = 60)
        let verified_leeway = Jwt::verify_hs256(secret, &token, 2050, 60);
        assert!(verified_leeway.is_ok());

        // Verification fails before not_before (t = 500)
        let err_nbf = Jwt::verify_hs256(secret, &token, 500, 0).unwrap_err();
        assert_eq!(
            err_nbf,
            JwtError::NotYetValid {
                not_before: 1000,
                current_time: 500
            }
        );

        // Invalid format
        assert_eq!(
            Jwt::verify_hs256(secret, "invalid.token", 1500, 0).unwrap_err(),
            JwtError::InvalidFormat
        );
    }

    #[test]
    fn test_sha256_incremental_and_streaming() {
        let expected_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_hex(b"abc"), expected_abc);

        // Incremental feeding byte-by-byte
        let mut hasher = Sha256::new();
        hasher.update(b"a");
        hasher.update(b"b");
        hasher.update(b"c");
        assert_eq!(hasher.finalize_hex(), expected_abc);

        // Reset and reuse
        let mut reusable = Sha256::new();
        reusable.update(b"abc");
        assert_eq!(reusable.finalize_reset(), sha256(b"abc"));
        reusable.update(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            reusable.finalize_hex(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );

        // Feeding arbitrary chunk sizes (across 64-byte block boundaries)
        let pattern =
            b"The quick brown fox jumps over the lazy dog. 1234567890! Repeating pattern.".to_vec();
        let mut large_input = Vec::new();
        for _ in 0..10 {
            large_input.extend_from_slice(&pattern);
        }
        let expected_large = sha256_hex(&large_input);

        let mut chunked = Sha256::new();
        for chunk in large_input.chunks(7) {
            chunked.update(chunk);
        }
        assert_eq!(chunked.finalize_hex(), expected_large);
    }

    #[test]
    fn test_sha256_and_sha1_std_io_write() {
        use std::io::Write;

        let input = b"Streaming SHA-256 and SHA-1 through std::io::Write trait.";

        let mut sha256_writer = Sha256::new();
        sha256_writer.write_all(input).unwrap();
        sha256_writer.flush().unwrap();
        assert_eq!(sha256_writer.finalize(), sha256(input));

        let mut sha1_writer = Sha1::new();
        sha1_writer.write_all(input).unwrap();
        sha1_writer.flush().unwrap();
        assert_eq!(sha1_writer.finalize(), sha1(input));
    }

    #[test]
    fn test_sha1_incremental_and_streaming() {
        let text = b"The quick brown fox jumps over the lazy dog";
        let expected = sha1_hex(text);

        let mut hasher = Sha1::new();
        for &byte in text.iter() {
            hasher.update(&[byte]);
        }
        assert_eq!(hasher.finalize_hex(), expected);

        // Reset test
        let mut reusable = Sha1::new();
        reusable.update(b"abc");
        assert_eq!(reusable.finalize_reset(), sha1(b"abc"));
        reusable.update(text);
        assert_eq!(reusable.finalize_hex(), expected);
    }

    #[test]
    fn test_hmac_streaming_and_reset() {
        use std::io::Write;

        let key = b"secret-streaming-key";
        let message = b"Streaming HMAC payload broken into multiple packets.";

        // HMAC-SHA256 streaming
        let mut hmac256 = HmacSha256::new(key);
        for chunk in message.chunks(5) {
            hmac256.write_all(chunk).unwrap();
        }
        assert_eq!(hmac256.finalize(), hmac_sha256(key, message));

        // HMAC-SHA256 reset & reuse
        let mut hmac256_reuse = HmacSha256::new(key);
        hmac256_reuse.update(b"first message");
        let _ = hmac256_reuse.finalize_reset();
        hmac256_reuse.update(message);
        assert_eq!(hmac256_reuse.finalize(), hmac_sha256(key, message));

        // HMAC-SHA1 streaming
        let mut hmac1 = HmacSha1::new(key);
        for chunk in message.chunks(9) {
            hmac1.write_all(chunk).unwrap();
        }
        assert_eq!(hmac1.finalize(), hmac_sha1(key, message));

        // HMAC-SHA1 reset & reuse
        let mut hmac1_reuse = HmacSha1::new(key);
        hmac1_reuse.update(b"first message");
        let _ = hmac1_reuse.finalize_reset();
        hmac1_reuse.update(message);
        assert_eq!(hmac1_reuse.finalize(), hmac_sha1(key, message));
    }

    #[test]
    fn test_sha256_streaming_writer_and_reader() {
        use std::io::{Read, Write};

        let message = b"Deterministic IFA cryptographic streaming hash verification.";
        let expected_digest = sha256(message);
        let expected_hex = sha256_hex(message);

        // Test Sha256Writer
        let mut sink = Vec::new();
        let mut writer = Sha256Writer::new(&mut sink);
        assert_eq!(writer.bytes_written(), 0);
        assert_eq!(writer.get_ref().len(), 0);
        writer.get_mut().reserve(64);

        for chunk in message.chunks(7) {
            let n = writer.write(chunk).unwrap();
            assert_eq!(n, chunk.len());
        }
        writer.flush().unwrap();

        assert_eq!(writer.bytes_written(), message.len());
        assert_eq!(writer.digest(), expected_digest);
        assert_eq!(writer.digest_hex(), expected_hex);
        assert_eq!(sink.as_slice(), message);

        // Test into_parts & into_parts_hex & into_inner
        let sink2 = Vec::new();
        let mut writer2 = Sha256Writer::new(sink2);
        writer2.write_all(message).unwrap();
        let (out_sink, out_digest, bytes) = writer2.into_parts();
        assert_eq!(out_sink.as_slice(), message);
        assert_eq!(out_digest, expected_digest);
        assert_eq!(bytes, message.len());

        let sink3 = Vec::new();
        let mut writer3 = Sha256Writer::new(sink3);
        writer3.write_all(message).unwrap();
        let (_out_sink3, hex, _) = writer3.into_parts_hex();
        assert_eq!(hex, expected_hex);

        let writer4 = Sha256Writer::new(Vec::new());
        let _inner = writer4.into_inner();

        // Test Sha256Reader
        let mut reader = Sha256Reader::new(message.as_slice());
        assert_eq!(reader.bytes_read(), 0);
        assert_eq!(reader.get_ref().len(), message.len());
        let _ = reader.get_mut();

        let mut read_buf = Vec::new();
        let mut temp = [0u8; 9];
        loop {
            let n = reader.read(&mut temp).unwrap();
            if n == 0 {
                break;
            }
            read_buf.extend_from_slice(&temp[..n]);
        }

        assert_eq!(read_buf.as_slice(), message);
        assert_eq!(reader.bytes_read(), message.len());
        assert_eq!(reader.digest(), expected_digest);
        assert_eq!(reader.digest_hex(), expected_hex);

        // Test reader into_parts & into_parts_hex & into_inner
        let reader2 = Sha256Reader::new(message.as_slice());
        let mut drain = Vec::new();
        let mut reader2 = reader2;
        reader2.read_to_end(&mut drain).unwrap();
        let (inner_r, dig, n_read) = reader2.into_parts();
        assert_eq!(inner_r.len(), 0);
        assert_eq!(dig, expected_digest);
        assert_eq!(n_read, message.len());

        let mut reader3 = Sha256Reader::new(message.as_slice());
        reader3.read_to_end(&mut drain).unwrap();
        let (_, hex_r, _) = reader3.into_parts_hex();
        assert_eq!(hex_r, expected_hex);

        let reader4 = Sha256Reader::new(message.as_slice());
        let _ = reader4.into_inner();
    }

    #[test]
    fn test_sha1_streaming_writer_and_reader() {
        use std::io::{Read, Write};

        let message = b"The quick brown fox jumps over the lazy dog";
        let expected_digest = sha1(message);
        let expected_hex = sha1_hex(message);

        // Test Sha1Writer
        let mut sink = Vec::new();
        let mut writer = Sha1Writer::new(&mut sink);
        assert_eq!(writer.bytes_written(), 0);
        assert_eq!(writer.get_ref().len(), 0);
        writer.get_mut().reserve(32);

        for chunk in message.chunks(5) {
            let n = writer.write(chunk).unwrap();
            assert_eq!(n, chunk.len());
        }
        writer.flush().unwrap();

        assert_eq!(writer.bytes_written(), message.len());
        assert_eq!(writer.digest(), expected_digest);
        assert_eq!(writer.digest_hex(), expected_hex);
        assert_eq!(sink.as_slice(), message);

        // Test into_parts & into_parts_hex & into_inner
        let sink2 = Vec::new();
        let mut writer2 = Sha1Writer::new(sink2);
        writer2.write_all(message).unwrap();
        let (out_sink, out_digest, bytes) = writer2.into_parts();
        assert_eq!(out_sink.as_slice(), message);
        assert_eq!(out_digest, expected_digest);
        assert_eq!(bytes, message.len());

        let sink3 = Vec::new();
        let mut writer3 = Sha1Writer::new(sink3);
        writer3.write_all(message).unwrap();
        let (_out_sink3, hex, _) = writer3.into_parts_hex();
        assert_eq!(hex, expected_hex);

        let writer4 = Sha1Writer::new(Vec::new());
        let _inner = writer4.into_inner();

        // Test Sha1Reader
        let mut reader = Sha1Reader::new(message.as_slice());
        assert_eq!(reader.bytes_read(), 0);
        assert_eq!(reader.get_ref().len(), message.len());
        let _ = reader.get_mut();

        let mut read_buf = Vec::new();
        let mut temp = [0u8; 8];
        loop {
            let n = reader.read(&mut temp).unwrap();
            if n == 0 {
                break;
            }
            read_buf.extend_from_slice(&temp[..n]);
        }

        assert_eq!(read_buf.as_slice(), message);
        assert_eq!(reader.bytes_read(), message.len());
        assert_eq!(reader.digest(), expected_digest);
        assert_eq!(reader.digest_hex(), expected_hex);

        // Test reader into_parts & into_parts_hex & into_inner
        let reader2 = Sha1Reader::new(message.as_slice());
        let mut drain = Vec::new();
        let mut reader2 = reader2;
        reader2.read_to_end(&mut drain).unwrap();
        let (inner_r, dig, n_read) = reader2.into_parts();
        assert_eq!(inner_r.len(), 0);
        assert_eq!(dig, expected_digest);
        assert_eq!(n_read, message.len());

        let mut reader3 = Sha1Reader::new(message.as_slice());
        reader3.read_to_end(&mut drain).unwrap();
        let (_, hex_r, _) = reader3.into_parts_hex();
        assert_eq!(hex_r, expected_hex);

        let reader4 = Sha1Reader::new(message.as_slice());
        let _ = reader4.into_inner();
    }

    #[test]
    fn test_hex_codecs_and_constant_time_eq_hex() {
        let original = b"Hello, IFA Cryptography & Hex!";
        let encoded = hex_encode(original);
        assert_eq!(
            encoded,
            "48656c6c6f2c204946412043727970746f67726170687920262048657821"
        );

        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), original);

        // Uppercase decode
        let upper_encoded = encoded.to_ascii_uppercase();
        let decoded_upper = hex_decode(&upper_encoded).unwrap();
        assert_eq!(decoded_upper.as_slice(), original);

        // Constant time eq hex
        assert!(constant_time_eq_hex(original, &encoded));
        assert!(constant_time_eq_hex(original, &upper_encoded));
        assert!(!constant_time_eq_hex(original, "1234"));
        assert!(!constant_time_eq_hex(original, "invalid hex string!"));

        // Invalid length
        assert!(hex_decode("123").is_err());
        // Invalid chars
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn test_hmac_sha256_verification_and_streaming() {
        use std::io::{Read, Write};

        let key = b"super-secret-key-for-hmac";
        let message = b"The quick brown fox jumps over the lazy dog";
        let expected_mac = hmac_sha256(key, message);
        let expected_hex = hmac_sha256_hex(key, message);

        // Verification helpers
        assert!(hmac_sha256_verify(key, message, &expected_mac));
        assert!(hmac_sha256_verify_hex(key, message, &expected_hex));
        assert!(hmac_sha256_verify_hex(
            key,
            message,
            &expected_hex.to_ascii_uppercase()
        ));
        assert!(!hmac_sha256_verify(key, message, &[0u8; 32]));
        assert!(!hmac_sha256_verify_hex(
            key,
            message,
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        // HmacSha256 instance verify
        let mut hmac = HmacSha256::new(key);
        hmac.update(message);
        assert!(hmac.verify(&expected_mac));
        assert!(hmac.verify_hex(&expected_hex));

        // HmacSha256Writer
        let mut sink = Vec::new();
        let mut writer = HmacSha256Writer::new(&mut sink, key);
        assert_eq!(writer.bytes_written(), 0);
        assert_eq!(writer.get_ref().len(), 0);
        writer.get_mut().reserve(16);

        for chunk in message.chunks(7) {
            let n = writer.write(chunk).unwrap();
            assert_eq!(n, chunk.len());
        }
        writer.flush().unwrap();

        assert_eq!(writer.bytes_written(), message.len());
        assert_eq!(writer.mac(), expected_mac);
        assert_eq!(writer.mac_hex(), expected_hex);
        assert!(writer.verify(&expected_mac));
        assert!(writer.verify_hex(&expected_hex));
        assert_eq!(sink.as_slice(), message);

        // into_parts & into_parts_hex & into_inner
        let sink2 = Vec::new();
        let mut writer2 = HmacSha256Writer::new(sink2, key);
        writer2.write_all(message).unwrap();
        let (out_sink, out_mac, n_written) = writer2.into_parts();
        assert_eq!(out_sink.as_slice(), message);
        assert_eq!(out_mac, expected_mac);
        assert_eq!(n_written, message.len());

        let sink3 = Vec::new();
        let mut writer3 = HmacSha256Writer::new(sink3, key);
        writer3.write_all(message).unwrap();
        let (_, hex_out, _) = writer3.into_parts_hex();
        assert_eq!(hex_out, expected_hex);

        let writer4 = HmacSha256Writer::new(Vec::new(), key);
        let _ = writer4.into_inner();

        // HmacSha256Reader
        let mut reader = HmacSha256Reader::new(message.as_slice(), key);
        assert_eq!(reader.bytes_read(), 0);
        assert_eq!(reader.get_ref().len(), message.len());
        let _ = reader.get_mut();

        let mut read_buf = Vec::new();
        let mut temp = [0u8; 9];
        loop {
            let n = reader.read(&mut temp).unwrap();
            if n == 0 {
                break;
            }
            read_buf.extend_from_slice(&temp[..n]);
        }

        assert_eq!(read_buf.as_slice(), message);
        assert_eq!(reader.bytes_read(), message.len());
        assert_eq!(reader.mac(), expected_mac);
        assert_eq!(reader.mac_hex(), expected_hex);
        assert!(reader.verify(&expected_mac));
        assert!(reader.verify_hex(&expected_hex));

        // reader into_parts & into_parts_hex & into_inner
        let reader2 = HmacSha256Reader::new(message.as_slice(), key);
        let mut drain = Vec::new();
        let mut reader2 = reader2;
        reader2.read_to_end(&mut drain).unwrap();
        let (inner_r, mac_r, n_read) = reader2.into_parts();
        assert_eq!(inner_r.len(), 0);
        assert_eq!(mac_r, expected_mac);
        assert_eq!(n_read, message.len());

        let mut reader3 = HmacSha256Reader::new(message.as_slice(), key);
        reader3.read_to_end(&mut drain).unwrap();
        let (_, hex_r, _) = reader3.into_parts_hex();
        assert_eq!(hex_r, expected_hex);

        let reader4 = HmacSha256Reader::new(message.as_slice(), key);
        let _ = reader4.into_inner();
    }

    #[test]
    fn test_hmac_sha1_verification_and_streaming() {
        use std::io::{Read, Write};

        let key = b"super-secret-key-for-hmac-sha1";
        let message = b"The quick brown fox jumps over the lazy dog";
        let expected_mac = hmac_sha1(key, message);
        let expected_hex = hmac_sha1_hex(key, message);

        // Verification helpers
        assert!(hmac_sha1_verify(key, message, &expected_mac));
        assert!(hmac_sha1_verify_hex(key, message, &expected_hex));
        assert!(hmac_sha1_verify_hex(
            key,
            message,
            &expected_hex.to_ascii_uppercase()
        ));
        assert!(!hmac_sha1_verify(key, message, &[0u8; 20]));
        assert!(!hmac_sha1_verify_hex(
            key,
            message,
            "0000000000000000000000000000000000000000"
        ));

        // HmacSha1 instance verify
        let mut hmac = HmacSha1::new(key);
        hmac.update(message);
        assert!(hmac.verify(&expected_mac));
        assert!(hmac.verify_hex(&expected_hex));

        // HmacSha1Writer
        let mut sink = Vec::new();
        let mut writer = HmacSha1Writer::new(&mut sink, key);
        assert_eq!(writer.bytes_written(), 0);
        assert_eq!(writer.get_ref().len(), 0);
        writer.get_mut().reserve(16);

        for chunk in message.chunks(7) {
            let n = writer.write(chunk).unwrap();
            assert_eq!(n, chunk.len());
        }
        writer.flush().unwrap();

        assert_eq!(writer.bytes_written(), message.len());
        assert_eq!(writer.mac(), expected_mac);
        assert_eq!(writer.mac_hex(), expected_hex);
        assert!(writer.verify(&expected_mac));
        assert!(writer.verify_hex(&expected_hex));
        assert_eq!(sink.as_slice(), message);

        // into_parts & into_parts_hex & into_inner
        let sink2 = Vec::new();
        let mut writer2 = HmacSha1Writer::new(sink2, key);
        writer2.write_all(message).unwrap();
        let (out_sink, out_mac, n_written) = writer2.into_parts();
        assert_eq!(out_sink.as_slice(), message);
        assert_eq!(out_mac, expected_mac);
        assert_eq!(n_written, message.len());

        let sink3 = Vec::new();
        let mut writer3 = HmacSha1Writer::new(sink3, key);
        writer3.write_all(message).unwrap();
        let (_, hex_out, _) = writer3.into_parts_hex();
        assert_eq!(hex_out, expected_hex);

        let writer4 = HmacSha1Writer::new(Vec::new(), key);
        let _ = writer4.into_inner();

        // HmacSha1Reader
        let mut reader = HmacSha1Reader::new(message.as_slice(), key);
        assert_eq!(reader.bytes_read(), 0);
        assert_eq!(reader.get_ref().len(), message.len());
        let _ = reader.get_mut();

        let mut read_buf = Vec::new();
        let mut temp = [0u8; 8];
        loop {
            let n = reader.read(&mut temp).unwrap();
            if n == 0 {
                break;
            }
            read_buf.extend_from_slice(&temp[..n]);
        }

        assert_eq!(read_buf.as_slice(), message);
        assert_eq!(reader.bytes_read(), message.len());
        assert_eq!(reader.mac(), expected_mac);
        assert_eq!(reader.mac_hex(), expected_hex);
        assert!(reader.verify(&expected_mac));
        assert!(reader.verify_hex(&expected_hex));

        // reader into_parts & into_parts_hex & into_inner
        let reader2 = HmacSha1Reader::new(message.as_slice(), key);
        let mut drain = Vec::new();
        let mut reader2 = reader2;
        reader2.read_to_end(&mut drain).unwrap();
        let (inner_r, mac_r, n_read) = reader2.into_parts();
        assert_eq!(inner_r.len(), 0);
        assert_eq!(mac_r, expected_mac);
        assert_eq!(n_read, message.len());

        let mut reader3 = HmacSha1Reader::new(message.as_slice(), key);
        reader3.read_to_end(&mut drain).unwrap();
        let (_, hex_r, _) = reader3.into_parts_hex();
        assert_eq!(hex_r, expected_hex);

        let reader4 = HmacSha1Reader::new(message.as_slice(), key);
        let _ = reader4.into_inner();
    }

    #[test]
    fn test_pbkdf2_hmac_sha256_verification() {
        let password = b"my-secret-password";
        let salt = b"salt1234";
        let iterations = 100;
        let derived = pbkdf2_hmac_sha256(password, salt, iterations, 32);
        let derived_hex = pbkdf2_hmac_sha256_hex(password, salt, iterations, 32);

        assert!(pbkdf2_hmac_sha256_verify(
            password, salt, iterations, &derived
        ));
        assert!(pbkdf2_hmac_sha256_verify_hex(
            password,
            salt,
            iterations,
            &derived_hex
        ));

        // Wrong password / wrong salt / wrong iterations
        assert!(!pbkdf2_hmac_sha256_verify(
            b"wrong", salt, iterations, &derived
        ));
        assert!(!pbkdf2_hmac_sha256_verify(
            password,
            b"wrong_salt",
            iterations,
            &derived
        ));
        assert!(!pbkdf2_hmac_sha256_verify(password, salt, 99, &derived));
        assert!(!pbkdf2_hmac_sha256_verify_hex(
            password, salt, iterations, "deadbeef"
        ));
        assert!(!pbkdf2_hmac_sha256_verify_hex(
            password, salt, iterations, "not-hex!"
        ));
    }

    #[test]
    fn test_rfc6070_pbkdf2_hmac_sha1() {
        // RFC 6070 Test 1
        let p = b"password";
        let s = b"salt";
        assert_eq!(
            pbkdf2_hmac_sha1_hex(p, s, 1, 20),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        assert!(pbkdf2_hmac_sha1_verify_hex(
            p,
            s,
            1,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        ));

        // RFC 6070 Test 2
        assert_eq!(
            pbkdf2_hmac_sha1_hex(p, s, 2, 20),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
        assert!(pbkdf2_hmac_sha1_verify_hex(
            p,
            s,
            2,
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        ));

        // RFC 6070 Test 3 (4096 iterations)
        assert_eq!(
            pbkdf2_hmac_sha1_hex(p, s, 4096, 20),
            "4b007901b765489abead49d926f721d065a429c1"
        );

        // RFC 6070 Test 4
        let p4 = b"passwordPASSWORDpassword";
        let s4 = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        assert_eq!(
            pbkdf2_hmac_sha1_hex(p4, s4, 4096, 25),
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
        );

        // Edge cases
        assert_eq!(pbkdf2_hmac_sha1(p, s, 0, 20), Vec::<u8>::new());
        assert_eq!(pbkdf2_hmac_sha1(p, s, 1, 0), Vec::<u8>::new());
        assert!(!pbkdf2_hmac_sha1_verify(
            b"bad",
            s,
            1,
            &hex_decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap()
        ));
        assert!(!pbkdf2_hmac_sha1_verify_hex(p, s, 1, "invalid_hex!"));
    }

    #[test]
    fn test_rfc5869_hkdf_sha256_vectors() {
        // RFC 5869 Test Case 1
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_sha256_extract(Some(&salt), &ikm);
        assert_eq!(
            hex_encode(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let okm = hkdf_sha256_expand(&prk, &info, 42).unwrap();
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        let direct = hkdf_sha256(Some(&salt), &ikm, &info, 42).unwrap();
        assert_eq!(okm, direct);
        assert_eq!(
            hkdf_sha256_hex(Some(&salt), &ikm, &info, 42).unwrap(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // RFC 5869 Test Case 2 (80 bytes IKM, 80 bytes salt, 80 bytes info, L=82)
        let ikm2: Vec<u8> = (0x00..=0x4f).collect();
        let salt2: Vec<u8> = (0x60..=0xaf).collect();
        let info2: Vec<u8> = (0xb0..=0xff).collect();
        let prk2 = hkdf_sha256_extract(Some(&salt2), &ikm2);
        assert_eq!(
            hex_encode(&prk2),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        );
        let okm2 = hkdf_sha256_expand(&prk2, &info2, 82).unwrap();
        assert_eq!(
            hex_encode(&okm2),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );

        // RFC 5869 Test Case 3 (zero-length salt and info)
        let ikm3 = [0x0bu8; 22];
        let prk3_none = hkdf_sha256_extract(None, &ikm3);
        let prk3_empty = hkdf_sha256_extract(Some(&[]), &ikm3);
        assert_eq!(
            hex_encode(&prk3_none),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        assert_eq!(prk3_none, prk3_empty);

        let okm3 = hkdf_sha256_expand(&prk3_none, &[], 42).unwrap();
        assert_eq!(
            hex_encode(&okm3),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );

        // Error cases: length exceeding 255 * HashLen
        assert!(hkdf_sha256_expand(&prk, &info, 255 * 32 + 1).is_err());
        assert_eq!(
            hkdf_sha256_expand(&prk, &info, 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn test_rfc5869_hkdf_sha1_vectors() {
        // RFC 5869 Test Case 4
        let ikm = [0x0bu8; 11];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_sha1_extract(Some(&salt), &ikm);
        assert_eq!(hex_encode(&prk), "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243");

        let okm = hkdf_sha1_expand(&prk, &info, 42).unwrap();
        assert_eq!(
            hex_encode(&okm),
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        );

        let direct = hkdf_sha1(Some(&salt), &ikm, &info, 42).unwrap();
        assert_eq!(okm, direct);
        assert_eq!(
            hkdf_sha1_hex(Some(&salt), &ikm, &info, 42).unwrap(),
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        );

        // RFC 5869 Test Case 7 (zero-length salt and info)
        let ikm7 = [0x0cu8; 22];
        let prk7_none = hkdf_sha1_extract(None, &ikm7);
        let prk7_empty = hkdf_sha1_extract(Some(&[]), &ikm7);
        assert_eq!(
            hex_encode(&prk7_none),
            "2adccada18779e7c2077ad2eb19d3f3e731385dd"
        );
        assert_eq!(prk7_none, prk7_empty);

        let okm7 = hkdf_sha1_expand(&prk7_none, &[], 42).unwrap();
        assert_eq!(
            hex_encode(&okm7),
            "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"
        );

        // Error cases: length exceeding 255 * HashLen
        assert!(hkdf_sha1_expand(&prk, &info, 255 * 20 + 1).is_err());
        assert_eq!(hkdf_sha1_expand(&prk, &info, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_secure_random_and_tokens() {
        let empty: Result<Vec<u8>, String> = secure_random_bytes(0);
        assert_eq!(empty.unwrap(), Vec::<u8>::new());

        let bytes = secure_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        // Check tokens
        let hex_tok = secure_random_token(16).unwrap();
        assert_eq!(hex_tok.len(), 32);
        assert!(hex_tok.chars().all(|c| c.is_ascii_hexdigit()));

        let b64_tok = secure_random_token_base64(32).unwrap();
        assert!(!b64_tok.is_empty());
        assert!(!b64_tok.contains('='));
        assert!(!b64_tok.contains('+'));
        assert!(!b64_tok.contains('/'));
    }

    #[test]
    fn test_uuid_nil() {
        let nil = Uuid::nil();
        assert!(nil.is_nil());
        assert_eq!(nil.version(), None);
        assert_eq!(nil.to_string(), "00000000-0000-0000-0000-000000000000");
        assert_eq!(nil.to_simple_string(), "00000000000000000000000000000000");
        assert_eq!(nil.as_bytes(), &[0u8; 16]);

        let parsed = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
        assert_eq!(parsed, nil);
    }

    #[test]
    fn test_uuid_v4_generation_and_properties() {
        let u1 = Uuid::new_v4().unwrap();
        let u2 = Uuid::v4();
        assert_ne!(u1, u2);
        assert!(!u1.is_nil());
        assert_eq!(u1.version(), Some(4));
        assert_eq!(u2.version(), Some(4));

        let s1 = u1.to_string();
        assert_eq!(s1.len(), 36);
        // Byte 6 high nibble must be 4
        assert_eq!(&s1[14..15], "4");
        // Byte 8 high nibble must be 8, 9, a, or b
        let var_ch = s1.chars().nth(19).unwrap();
        assert!(matches!(var_ch, '8' | '9' | 'a' | 'b'));

        let simple = u1.to_simple_string();
        assert_eq!(simple.len(), 32);
        assert_eq!(simple, s1.replace('-', ""));
    }

    #[test]
    fn test_uuid_parse_all_formats_and_serde() {
        let raw = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let u_hyphenated = Uuid::parse_str(raw).unwrap();
        assert_eq!(u_hyphenated.to_string(), raw);
        assert_eq!(u_hyphenated.version(), Some(1));

        // Simple 32-hex
        let u_simple = Uuid::parse_str("6ba7b8109dad11d180b400c04fd430c8").unwrap();
        assert_eq!(u_simple, u_hyphenated);

        // Braced format
        let u_braced = Uuid::parse_str("{6ba7b810-9dad-11d1-80b4-00c04fd430c8}").unwrap();
        assert_eq!(u_braced, u_hyphenated);

        // URN format
        let u_urn = Uuid::parse_str("urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
        assert_eq!(u_urn, u_hyphenated);

        // FromStr trait
        let u_from_str: Uuid = raw.parse().unwrap();
        assert_eq!(u_from_str, u_hyphenated);

        // Serde JSON round-trip
        let json = serde_json::to_string(&u_hyphenated).unwrap();
        assert_eq!(json, format!("\"{}\"", raw));
        let decoded: Uuid = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, u_hyphenated);

        // Error cases
        assert!(matches!(
            Uuid::parse_str("short"),
            Err(UuidError::InvalidLength(5))
        ));
        assert!(matches!(
            Uuid::parse_str("6ba7b810_9dad_11d1_80b4_00c04fd430c8"),
            Err(UuidError::InvalidFormat)
        ));
        assert!(matches!(
            Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430cz"),
            Err(UuidError::InvalidCharacter('z'))
        ));
    }
}
