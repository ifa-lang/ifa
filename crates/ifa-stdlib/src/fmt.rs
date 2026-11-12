//! Advanced text formatting, streaming encoders, and numeric specifiers for IFA standard library.
//!
//! Supports decimal precision, field padding, alignment (left, right, center),
//! hexadecimal/octal/binary streaming representations, hex dumps, and string escaping.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    Left,
    Right,
    Center,
}

/// Format options specifying minimum field width, precision, alignment, and fill character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatSpecifier {
    pub width: usize,
    pub precision: Option<usize>,
    pub alignment: Alignment,
    pub pad_char: char,
}

impl Default for FormatSpecifier {
    fn default() -> Self {
        Self {
            width: 0,
            precision: None,
            alignment: Alignment::Left,
            pad_char: ' ',
        }
    }
}

impl FormatSpecifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_width(mut self, width: usize) -> Self {
        self.width = width;
        self
    }

    pub fn with_precision(mut self, precision: usize) -> Self {
        self.precision = Some(precision);
        self
    }

    pub fn with_alignment(mut self, alignment: Alignment) -> Self {
        self.alignment = alignment;
        self
    }

    pub fn with_pad_char(mut self, pad_char: char) -> Self {
        self.pad_char = pad_char;
        self
    }

    /// Format a string with the configured width and alignment.
    pub fn format_str(&self, s: &str) -> String {
        align_string(s, self.width, self.alignment, self.pad_char)
    }

    /// Format a 64-bit signed integer.
    pub fn format_i64(&self, val: i64) -> String {
        let raw = val.to_string();
        align_string(&raw, self.width, self.alignment, self.pad_char)
    }

    /// Format a 64-bit float with optional precision.
    pub fn format_f64(&self, val: f64) -> String {
        let raw = if let Some(prec) = self.precision {
            format!("{:.1$}", val, prec)
        } else {
            val.to_string()
        };
        align_string(&raw, self.width, self.alignment, self.pad_char)
    }
}

/// Format an integer in hexadecimal representation.
pub fn format_hex(val: i64, prefix: bool, uppercase: bool) -> String {
    let hex_part = if uppercase {
        format!("{:X}", val)
    } else {
        format!("{:x}", val)
    };
    if prefix {
        if uppercase {
            format!("0X{}", hex_part)
        } else {
            format!("0x{}", hex_part)
        }
    } else {
        hex_part
    }
}

/// Format an integer in octal representation.
pub fn format_octal(val: i64, prefix: bool) -> String {
    let oct_part = format!("{:o}", val);
    if prefix {
        format!("0o{}", oct_part)
    } else {
        oct_part
    }
}

/// Format an integer in binary representation.
pub fn format_binary(val: i64, prefix: bool) -> String {
    let bin_part = format!("{:b}", val);
    if prefix {
        format!("0b{}", bin_part)
    } else {
        bin_part
    }
}

/// Format a float with fixed decimal precision.
pub fn format_float(val: f64, precision: usize) -> String {
    format!("{:.1$}", val, precision)
}

/// Pad a string to `width` aligning to the left (padding on right).
pub fn pad_left(s: &str, width: usize, pad_char: char) -> String {
    let count = s.chars().count();
    if count >= width {
        s.to_string()
    } else {
        let mut out = s.to_string();
        for _ in 0..(width - count) {
            out.push(pad_char);
        }
        out
    }
}

/// Pad a string to `width` aligning to the right (padding on left).
pub fn pad_right(s: &str, width: usize, pad_char: char) -> String {
    let count = s.chars().count();
    if count >= width {
        s.to_string()
    } else {
        let mut out = String::with_capacity(width);
        for _ in 0..(width - count) {
            out.push(pad_char);
        }
        out.push_str(s);
        out
    }
}

/// Pad a string to `width` aligning in the center.
pub fn pad_center(s: &str, width: usize, pad_char: char) -> String {
    let count = s.chars().count();
    if count >= width {
        s.to_string()
    } else {
        let total_pad = width - count;
        let left_pad = total_pad / 2;
        let right_pad = total_pad - left_pad;

        let mut out = String::with_capacity(width);
        for _ in 0..left_pad {
            out.push(pad_char);
        }
        out.push_str(s);
        for _ in 0..right_pad {
            out.push(pad_char);
        }
        out
    }
}

fn align_string(s: &str, width: usize, alignment: Alignment, pad_char: char) -> String {
    match alignment {
        Alignment::Left => pad_left(s, width, pad_char),
        Alignment::Right => pad_right(s, width, pad_char),
        Alignment::Center => pad_center(s, width, pad_char),
    }
}

/// Write aligned text directly to any `fmt::Write` destination without intermediate allocations.
pub fn write_aligned<W: fmt::Write>(
    w: &mut W,
    s: &str,
    width: usize,
    alignment: Alignment,
    pad_char: char,
) -> fmt::Result {
    let count = s.chars().count();
    if count >= width {
        w.write_str(s)
    } else {
        let pad = width - count;
        match alignment {
            Alignment::Left => {
                w.write_str(s)?;
                for _ in 0..pad {
                    w.write_char(pad_char)?;
                }
                Ok(())
            }
            Alignment::Right => {
                for _ in 0..pad {
                    w.write_char(pad_char)?;
                }
                w.write_str(s)
            }
            Alignment::Center => {
                let left_pad = pad / 2;
                let right_pad = pad - left_pad;
                for _ in 0..left_pad {
                    w.write_char(pad_char)?;
                }
                w.write_str(s)?;
                for _ in 0..right_pad {
                    w.write_char(pad_char)?;
                }
                Ok(())
            }
        }
    }
}

/// Stream formatted integer with width alignment into any `fmt::Write`.
pub fn write_int_aligned<W: fmt::Write>(
    w: &mut W,
    val: i64,
    width: usize,
    alignment: Alignment,
    pad_char: char,
) -> fmt::Result {
    let s = val.to_string();
    write_aligned(w, &s, width, alignment, pad_char)
}

/// Stream hexadecimal representation directly to a writer.
pub fn write_hex<W: fmt::Write>(w: &mut W, val: u64, prefix: bool, uppercase: bool) -> fmt::Result {
    if prefix {
        if uppercase {
            w.write_str("0X")?;
        } else {
            w.write_str("0x")?;
        }
    }
    if uppercase {
        write!(w, "{:X}", val)
    } else {
        write!(w, "{:x}", val)
    }
}

/// Stream octal representation directly to a writer.
pub fn write_octal<W: fmt::Write>(w: &mut W, val: u64, prefix: bool) -> fmt::Result {
    if prefix {
        w.write_str("0o")?;
    }
    write!(w, "{:o}", val)
}

/// Stream binary representation directly to a writer.
pub fn write_binary<W: fmt::Write>(w: &mut W, val: u64, prefix: bool) -> fmt::Result {
    if prefix {
        w.write_str("0b")?;
    }
    write!(w, "{:b}", val)
}

/// Stream float formatting with decimal precision directly to a writer.
pub fn write_float_prec<W: fmt::Write>(w: &mut W, val: f64, precision: usize) -> fmt::Result {
    write!(w, "{:.1$}", val, precision)
}

/// Stream raw bytes as continuous hex characters into a writer.
pub fn write_hex_bytes<W: fmt::Write>(w: &mut W, bytes: &[u8], uppercase: bool) -> fmt::Result {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let table = if uppercase { HEX_UPPER } else { HEX_LOWER };
    for &b in bytes {
        let hi = table[(b >> 4) as usize] as char;
        let lo = table[(b & 0x0f) as usize] as char;
        w.write_char(hi)?;
        w.write_char(lo)?;
    }
    Ok(())
}

/// Encode byte slice into hexadecimal string.
pub fn encode_hex(bytes: &[u8], uppercase: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    let _ = write_hex_bytes(&mut out, bytes, uppercase);
    out
}

/// Error type for hexadecimal decoding failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    #[error("hex string has an odd length: {0}")]
    OddLength(usize),
    #[error("invalid hex character '{ch}' at index {index}")]
    InvalidChar { ch: char, index: usize },
}

/// Decode hexadecimal string into raw bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.trim();
    let s = if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        stripped
    } else {
        s
    };
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength(s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let h = hex_val(bytes[i]).ok_or_else(|| HexError::InvalidChar {
            ch: bytes[i] as char,
            index: i,
        })?;
        let l = hex_val(bytes[i + 1]).ok_or_else(|| HexError::InvalidChar {
            ch: bytes[i + 1] as char,
            index: i + 1,
        })?;
        out.push((h << 4) | l);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Stream canonical hexdump format into a writer.
pub fn write_hexdump<W: fmt::Write>(w: &mut W, data: &[u8], bytes_per_line: usize) -> fmt::Result {
    let bpl = if bytes_per_line == 0 {
        16
    } else {
        bytes_per_line
    };
    for (line_idx, chunk) in data.chunks(bpl).enumerate() {
        let offset = line_idx * bpl;
        write!(w, "{:08x}  ", offset)?;

        for (i, &b) in chunk.iter().enumerate() {
            if i > 0 && bpl == 16 && i == 8 {
                w.write_str(" ")?;
            }
            write!(w, "{:02x} ", b)?;
        }

        if chunk.len() < bpl {
            for i in chunk.len()..bpl {
                if bpl == 16 && i == 8 {
                    w.write_str(" ")?;
                }
                w.write_str("   ")?;
            }
        }

        w.write_str(" |")?;
        for &b in chunk {
            if (0x20..=0x7e).contains(&b) {
                w.write_char(b as char)?;
            } else {
                w.write_char('.')?;
            }
        }
        w.write_str("|\n")?;
    }
    Ok(())
}

/// Format byte slice into canonical hexdump string.
pub fn format_hexdump(data: &[u8]) -> String {
    let mut s = String::new();
    let _ = write_hexdump(&mut s, data, 16);
    s
}

/// Zero-allocation streaming `Display` adapter for byte slices formatted as canonical hexdump.
#[derive(Debug, Clone, Copy)]
pub struct HexDump<'a> {
    pub data: &'a [u8],
    pub bytes_per_line: usize,
}

impl<'a> HexDump<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bytes_per_line: 16,
        }
    }

    pub fn with_bytes_per_line(data: &'a [u8], bytes_per_line: usize) -> Self {
        Self {
            data,
            bytes_per_line,
        }
    }
}

impl<'a> fmt::Display for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hexdump(f, self.data, self.bytes_per_line)
    }
}

/// Errors occurring during text unescaping.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnescapeError {
    #[error("incomplete escape sequence ending with backslash")]
    TrailingBackslash,
    #[error("invalid escape character '{0}'")]
    InvalidEscape(char),
    #[error("incomplete hex escape: expected 2 hex digits")]
    IncompleteHexEscape,
    #[error("invalid hex digit in escape sequence: '{0}'")]
    InvalidHexDigit(char),
    #[error("invalid unicode escape format")]
    InvalidUnicodeEscape,
}

/// Stream escaped string representation into writer.
pub fn write_escaped_str<W: fmt::Write>(w: &mut W, s: &str) -> fmt::Result {
    for c in s.chars() {
        match c {
            '\\' => w.write_str(r"\\")?,
            '"' => w.write_str(r#"\""#)?,
            '\n' => w.write_str(r"\n")?,
            '\r' => w.write_str(r"\r")?,
            '\t' => w.write_str(r"\t")?,
            '\0' => w.write_str(r"\0")?,
            c if c.is_control() => {
                write!(w, r"\x{:02x}", c as u32)?;
            }
            c => w.write_char(c)?,
        }
    }
    Ok(())
}

/// Escape string for debug/code representation.
pub fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let _ = write_escaped_str(&mut out, s);
    out
}

/// Unescape string containing backslash escape sequences (`\n`, `\t`, `\xHH`, `\u{HHHH}`).
pub fn unescape_str(s: &str) -> Result<String, UnescapeError> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('0') => out.push('\0'),
                Some('x') => {
                    let d1 = chars.next().ok_or(UnescapeError::IncompleteHexEscape)?;
                    let d2 = chars.next().ok_or(UnescapeError::IncompleteHexEscape)?;
                    let h1 = hex_val(d1 as u8).ok_or(UnescapeError::InvalidHexDigit(d1))?;
                    let h2 = hex_val(d2 as u8).ok_or(UnescapeError::InvalidHexDigit(d2))?;
                    out.push(((h1 << 4) | h2) as char);
                }
                Some('u') => {
                    if chars.next() != Some('{') {
                        return Err(UnescapeError::InvalidUnicodeEscape);
                    }
                    let mut hex_val_accum: u32 = 0;
                    let mut count = 0;
                    loop {
                        match chars.next() {
                            Some('}') => break,
                            Some(ch) => {
                                let v =
                                    hex_val(ch as u8).ok_or(UnescapeError::InvalidHexDigit(ch))?;
                                hex_val_accum = (hex_val_accum << 4) | (v as u32);
                                count += 1;
                                if count > 6 {
                                    return Err(UnescapeError::InvalidUnicodeEscape);
                                }
                            }
                            None => return Err(UnescapeError::InvalidUnicodeEscape),
                        }
                    }
                    if count == 0 {
                        return Err(UnescapeError::InvalidUnicodeEscape);
                    }
                    let unicode_char =
                        char::from_u32(hex_val_accum).ok_or(UnescapeError::InvalidUnicodeEscape)?;
                    out.push(unicode_char);
                }
                Some(other) => return Err(UnescapeError::InvalidEscape(other)),
                None => return Err(UnescapeError::TrailingBackslash),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hex_octal_binary() {
        assert_eq!(format_hex(255, true, false), "0xff");
        assert_eq!(format_hex(255, true, true), "0XFF");
        assert_eq!(format_hex(255, false, false), "ff");

        assert_eq!(format_octal(64, true), "0o100");
        assert_eq!(format_octal(64, false), "100");

        assert_eq!(format_binary(10, true), "0b1010");
        assert_eq!(format_binary(10, false), "1010");
    }

    #[test]
    fn test_streaming_writers() {
        let mut buf = String::new();
        write_hex(&mut buf, 0xcafe, true, true).unwrap();
        assert_eq!(buf, "0XCAFE");

        buf.clear();
        write_octal(&mut buf, 0o755, true).unwrap();
        assert_eq!(buf, "0o755");

        buf.clear();
        write_binary(&mut buf, 0b101100, true).unwrap();
        assert_eq!(buf, "0b101100");

        buf.clear();
        write_float_prec(&mut buf, 3.14159, 2).unwrap();
        assert_eq!(buf, "3.14");

        buf.clear();
        write_int_aligned(&mut buf, 42, 6, Alignment::Right, '0').unwrap();
        assert_eq!(buf, "000042");
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = b"Hello, IFA!";
        let encoded = encode_hex(data, false);
        assert_eq!(encoded, "48656c6c6f2c2049464121");

        let decoded = decode_hex(&encoded).unwrap();
        assert_eq!(decoded, data);

        let prefixed = format!("0x{}", encoded);
        assert_eq!(decode_hex(&prefixed).unwrap(), data);

        assert!(matches!(decode_hex("abc"), Err(HexError::OddLength(3))));
        assert!(matches!(
            decode_hex("0xzz"),
            Err(HexError::InvalidChar { .. })
        ));
    }

    #[test]
    fn test_hexdump() {
        let data = b"Hello World!\x00\x01\x02\xff";
        let dump = format_hexdump(data);
        assert!(dump.starts_with("00000000  48 65 6c 6c 6f 20 57 6f"));
        assert!(dump.contains("|Hello World!....|"));

        let display_dump = format!("{}", HexDump::new(data));
        assert_eq!(display_dump, dump);
    }

    #[test]
    fn test_string_escape_unescape() {
        let s = "Hello \"IFA\"\n\t\\Line2\0";
        let escaped = escape_str(s);
        assert_eq!(escaped, r#"Hello \"IFA\"\n\t\\Line2\0"#);

        let unescaped = unescape_str(&escaped).unwrap();
        assert_eq!(unescaped, s);

        let unicode_test = r"Unicode: \u{1f600} \x41";
        let unescaped_unicode = unescape_str(unicode_test).unwrap();
        assert_eq!(unescaped_unicode, "Unicode: 😀 A");
    }

    #[test]
    fn test_format_float_precision() {
        assert_eq!(format_float(std::f64::consts::PI, 2), "3.14");
        assert_eq!(format_float(std::f64::consts::PI, 4), "3.1416");
        assert_eq!(format_float(42.0, 3), "42.000");
    }

    #[test]
    fn test_padding_and_alignment() {
        assert_eq!(pad_left("hello", 10, ' '), "hello     ");
        assert_eq!(pad_right("hello", 10, '0'), "00000hello");
        assert_eq!(pad_center("test", 10, '-'), "---test---");

        let spec = FormatSpecifier::new()
            .with_width(8)
            .with_alignment(Alignment::Right)
            .with_pad_char(' ');
        assert_eq!(spec.format_i64(42), "      42");

        let f_spec = FormatSpecifier::new()
            .with_width(10)
            .with_precision(2)
            .with_alignment(Alignment::Right);
        assert_eq!(f_spec.format_f64(12.3456), "     12.35");
    }
}
