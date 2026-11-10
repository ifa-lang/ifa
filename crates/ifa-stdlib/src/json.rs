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

    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, JsonValue::Bool(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, JsonValue::Number(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, JsonValue::String(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, JsonValue::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, JsonValue::Object(_))
    }

    pub fn array_len(&self) -> usize {
        match self {
            JsonValue::Array(arr) => arr.len(),
            _ => 0,
        }
    }

    pub fn array_push(&mut self, val: JsonValue) -> bool {
        match self {
            JsonValue::Array(arr) => {
                arr.push(val);
                true
            }
            _ => false,
        }
    }

    pub fn array_pop(&mut self) -> Option<JsonValue> {
        match self {
            JsonValue::Array(arr) => arr.pop(),
            _ => None,
        }
    }

    pub fn array_insert(&mut self, idx: usize, val: JsonValue) -> bool {
        match self {
            JsonValue::Array(arr) if idx <= arr.len() => {
                arr.insert(idx, val);
                true
            }
            _ => false,
        }
    }

    pub fn array_remove(&mut self, idx: usize) -> Option<JsonValue> {
        match self {
            JsonValue::Array(arr) if idx < arr.len() => Some(arr.remove(idx)),
            _ => None,
        }
    }

    /// Recursively merge another JSON tree into this one deterministically.
    pub fn deep_merge(&mut self, other: JsonValue) {
        match (self, other) {
            (JsonValue::Object(target_map), JsonValue::Object(source_map)) => {
                for (k, v) in source_map {
                    if let Some(target_child) = target_map.get_mut(&k) {
                        target_child.deep_merge(v);
                    } else {
                        target_map.insert(k, v);
                    }
                }
            }
            (this, other) => {
                *this = other;
            }
        }
    }

    /// Flatten nested JSON structure into dot-separated key-value pairs deterministically.
    pub fn flatten(&self, prefix: &str) -> BTreeMap<String, JsonValue> {
        let mut map = BTreeMap::new();
        self.flatten_recursive(prefix, &mut map);
        map
    }

    fn flatten_recursive(&self, prefix: &str, out: &mut BTreeMap<String, JsonValue>) {
        match self {
            JsonValue::Object(obj) => {
                for (k, v) in obj {
                    let next_key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{}.{}", prefix, k)
                    };
                    v.flatten_recursive(&next_key, out);
                }
            }
            JsonValue::Array(arr) => {
                for (idx, elem) in arr.iter().enumerate() {
                    let next_key = if prefix.is_empty() {
                        format!("{}", idx)
                    } else {
                        format!("{}.{}", prefix, idx)
                    };
                    elem.flatten_recursive(&next_key, out);
                }
            }
            primitive => {
                if !prefix.is_empty() {
                    out.insert(prefix.to_string(), primitive.clone());
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heterogeneous_arrays_and_mutation() {
        let raw = r#"[42, "ifa", true, null, {"key": "val"}]"#;
        let mut val = decode(raw).expect("decode heterogeneous array");
        assert!(val.is_array());
        assert_eq!(val.array_len(), 5);

        assert_eq!(val.index(0).unwrap().as_i64(), Some(42));
        assert_eq!(val.index(1).unwrap().as_str(), Some("ifa"));
        assert_eq!(val.index(2).unwrap().as_bool(), Some(true));
        assert!(val.index(3).unwrap().is_null());
        assert!(val.index(4).unwrap().is_object());

        // Array pop
        let popped = val.array_pop().expect("pop item");
        assert!(popped.is_object());
        assert_eq!(val.array_len(), 4);

        // Array insert
        assert!(val.array_insert(1, JsonValue::String("inserted".to_string())));
        assert_eq!(val.array_len(), 5);
        assert_eq!(val.index(1).unwrap().as_str(), Some("inserted"));

        // Array remove
        let removed = val.array_remove(1).expect("remove item");
        assert_eq!(removed.as_str(), Some("inserted"));
        assert_eq!(val.array_len(), 4);
    }

    #[test]
    fn test_deep_merge_and_flatten() {
        let base_raw = r#"{"server":{"host":"127.0.0.1","port":8080},"env":"dev"}"#;
        let ext_raw = r#"{"server":{"port":9000,"tls":true},"debug":true}"#;

        let mut base = decode(base_raw).unwrap();
        let ext = decode(ext_raw).unwrap();

        base.deep_merge(ext);

        let server_obj = base.get("server").unwrap().as_object().unwrap();
        assert_eq!(server_obj.get("host").unwrap().as_str(), Some("127.0.0.1"));
        assert_eq!(server_obj.get("port").unwrap().as_i64(), Some(9000));
        assert_eq!(server_obj.get("tls").unwrap().as_bool(), Some(true));
        assert_eq!(base.get("env").unwrap().as_str(), Some("dev"));
        assert_eq!(base.get("debug").unwrap().as_bool(), Some(true));

        let flattened = base.flatten("");
        assert_eq!(
            flattened.get("server.host").unwrap().as_str(),
            Some("127.0.0.1")
        );
        assert_eq!(flattened.get("server.port").unwrap().as_i64(), Some(9000));
        assert_eq!(flattened.get("server.tls").unwrap().as_bool(), Some(true));
        assert_eq!(flattened.get("env").unwrap().as_str(), Some("dev"));
        assert_eq!(flattened.get("debug").unwrap().as_bool(), Some(true));
    }
}
