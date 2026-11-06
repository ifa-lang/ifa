use std::collections::BTreeMap;
use std::fmt;

/// In-memory representation of any JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut JsonValue> {
        match self {
            JsonValue::Object(map) => map.get_mut(key),
            _ => None,
        }
    }

    pub fn index(&self, idx: usize) -> Option<&JsonValue> {
        match self {
            JsonValue::Array(arr) => arr.get(idx),
            _ => None,
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encode(self))
    }
}

/// Parse a JSON string into a `JsonValue`.
pub fn decode(src: &str) -> Result<JsonValue, String> {
    let mut parser = JsonParser::new(src);
    let val = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.cursor < parser.chars.len() {
        return Err(format!(
            "Trailing unexpected characters at index {}",
            parser.cursor
        ));
    }
    Ok(val)
}

/// Serialize a `JsonValue` into a compact JSON string.
pub fn encode(val: &JsonValue) -> String {
    let mut out = String::new();
    encode_to(&mut out, val);
    out
}

/// Serialize a `JsonValue` into an indented, human-readable JSON string.
pub fn encode_pretty(val: &JsonValue) -> String {
    let mut out = String::new();
    encode_pretty_to(&mut out, val, 0);
    out
}

fn encode_to(out: &mut String, val: &JsonValue) {
    match val {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => {
            if n.fract() == 0.0 && !n.is_nan() && !n.is_infinite() {
                out.push_str(&format!("{:.0}", n));
            } else {
                out.push_str(&format!("{}", n));
            }
        }
        JsonValue::String(s) => escape_string_to(out, s),
        JsonValue::Array(arr) => {
            out.push('[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_to(out, elem);
            }
            out.push(']');
        }
        JsonValue::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_string_to(out, k);
                out.push(':');
                encode_to(out, v);
            }
            out.push('}');
        }
    }
}

fn encode_pretty_to(out: &mut String, val: &JsonValue, indent: usize) {
    let spaces = "  ".repeat(indent);
    let inner_spaces = "  ".repeat(indent + 1);

    match val {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
            encode_to(out, val);
        }
        JsonValue::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&inner_spaces);
                encode_pretty_to(out, elem, indent + 1);
            }
            out.push('\n');
            out.push_str(&spaces);
            out.push(']');
        }
        JsonValue::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&inner_spaces);
                escape_string_to(out, k);
                out.push_str(": ");
                encode_pretty_to(out, v, indent + 1);
            }
            out.push('\n');
            out.push_str(&spaces);
            out.push('}');
        }
    }
}

fn escape_string_to(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push(c),
        }
    }
    out.push('"');
}

struct JsonParser<'a> {
    chars: Vec<char>,
    cursor: usize,
    _marker: std::marker::PhantomData<&'a str>,
}

impl<'a> JsonParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            chars: src.chars().collect(),
            cursor: 0,
            _marker: std::marker::PhantomData,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.cursor).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.chars.get(self.cursor).copied();
        if ch.is_some() {
            self.cursor += 1;
        }
        ch
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        let ch = self
            .peek()
            .ok_or_else(|| "Unexpected end of JSON input".to_string())?;

        match ch {
            'n' => self.parse_null(),
            't' | 'f' => self.parse_bool(),
            '"' => self.parse_string().map(JsonValue::String),
            '[' => self.parse_array(),
            '{' => self.parse_object(),
            '-' | '0'..='9' => self.parse_number(),
            _ => Err(format!(
                "Unexpected character '{}' at offset {}",
                ch, self.cursor
            )),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, String> {
        self.expect_str("null")?;
        Ok(JsonValue::Null)
    }

    fn parse_bool(&mut self) -> Result<JsonValue, String> {
        if self.expect_str("true").is_ok() {
            Ok(JsonValue::Bool(true))
        } else if self.expect_str("false").is_ok() {
            Ok(JsonValue::Bool(false))
        } else {
            Err(format!("Expected boolean at offset {}", self.cursor))
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.cursor;
        if self.peek() == Some('-') {
            self.advance();
        }

        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() || ch == '.' || ch == 'e' || ch == 'E' || ch == '+' || ch == '-'
            {
                self.advance();
            } else {
                break;
            }
        }

        let num_str: String = self.chars[start..self.cursor].iter().collect();
        let val: f64 = num_str
            .parse()
            .map_err(|_| format!("Invalid number literal '{}'", num_str))?;
        Ok(JsonValue::Number(val))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_char('"')?;
        let mut s = String::new();

        while let Some(ch) = self.advance() {
            match ch {
                '"' => return Ok(s),
                '\\' => {
                    let esc = self
                        .advance()
                        .ok_or_else(|| "Unexpected EOF in escape sequence".to_string())?;
                    match esc {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'u' => {
                            let mut hex = String::with_capacity(4);
                            for _ in 0..4 {
                                hex.push(
                                    self.advance().ok_or_else(|| {
                                        "Incomplete \\u unicode escape".to_string()
                                    })?,
                                );
                            }
                            let codepoint = u32::from_str_radix(&hex, 16)
                                .map_err(|_| "Invalid hex in \\u escape")?;
                            let unicode_char =
                                char::from_u32(codepoint).ok_or("Invalid unicode codepoint")?;
                            s.push(unicode_char);
                        }
                        _ => return Err(format!("Invalid escape sequence '\\{}'", esc)),
                    }
                }
                _ => s.push(ch),
            }
        }

        Err("Unterminated string literal".to_string())
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.expect_char('[')?;
        let mut items = Vec::new();

        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.advance();
            return Ok(JsonValue::Array(items));
        }

        loop {
            let elem = self.parse_value()?;
            items.push(elem);

            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.advance();
                }
                Some(']') => {
                    self.advance();
                    break;
                }
                Some(other) => {
                    return Err(format!("Expected ',' or ']' in array, found '{}'", other))
                }
                None => return Err("Unexpected EOF in array".to_string()),
            }
        }

        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.expect_char('{')?;
        let mut map = BTreeMap::new();

        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.advance();
            return Ok(JsonValue::Object(map));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;

            self.skip_whitespace();
            self.expect_char(':')?;

            let value = self.parse_value()?;
            map.insert(key, value);

            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.advance();
                }
                Some('}') => {
                    self.advance();
                    break;
                }
                Some(other) => {
                    return Err(format!("Expected ',' or '}}' in object, found '{}'", other))
                }
                None => return Err("Unexpected EOF in object".to_string()),
            }
        }

        Ok(JsonValue::Object(map))
    }

    fn expect_char(&mut self, expected: char) -> Result<(), String> {
        let ch = self.advance();
        if ch == Some(expected) {
            Ok(())
        } else {
            Err(format!(
                "Expected '{}', found {:?}",
                expected,
                ch.map(|c| c.to_string())
                    .unwrap_or_else(|| "EOF".to_string())
            ))
        }
    }

    fn expect_str(&mut self, expected: &str) -> Result<(), String> {
        for exp_ch in expected.chars() {
            let ch = self.advance();
            if ch != Some(exp_ch) {
                return Err(format!("Expected literal '{}'", expected));
            }
        }
        Ok(())
    }
}
