/// Advanced text formatting and numeric specifiers for IFA standard library.
///
/// Supports decimal precision, field padding, alignment (left, right, center),
/// and hexadecimal, octal, and binary representations.

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
