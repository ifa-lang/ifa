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

    /// Retrieve a reference to the value at the given RFC 6901 JSON Pointer.
    pub fn pointer(&self, ptr: &str) -> Option<&JsonValue> {
        let tokens = split_pointer(ptr).ok()?;
        let mut curr = self;
        for token in tokens {
            match curr {
                JsonValue::Object(map) => {
                    curr = map.get(&token)?;
                }
                JsonValue::Array(arr) => {
                    if token.len() > 1 && token.starts_with('0') {
                        return None;
                    }
                    let idx: usize = token.parse().ok()?;
                    curr = arr.get(idx)?;
                }
                _ => return None,
            }
        }
        Some(curr)
    }

    /// Retrieve a mutable reference to the value at the given RFC 6901 JSON Pointer.
    pub fn pointer_mut(&mut self, ptr: &str) -> Option<&mut JsonValue> {
        let tokens = split_pointer(ptr).ok()?;
        let mut curr = self;
        for token in tokens {
            match curr {
                JsonValue::Object(map) => {
                    curr = map.get_mut(&token)?;
                }
                JsonValue::Array(arr) => {
                    if token.len() > 1 && token.starts_with('0') {
                        return None;
                    }
                    let idx: usize = token.parse().ok()?;
                    curr = arr.get_mut(idx)?;
                }
                _ => return None,
            }
        }
        Some(curr)
    }

    /// Set or insert a value at the specified RFC 6901 JSON Pointer.
    pub fn set_pointer(&mut self, ptr: &str, val: JsonValue) -> Result<(), String> {
        let tokens = split_pointer(ptr)?;
        if tokens.is_empty() {
            *self = val;
            return Ok(());
        }

        let (last_token, parent_tokens) = tokens.split_last().unwrap();
        let mut curr = self;
        for (i, token) in parent_tokens.iter().enumerate() {
            curr = match curr {
                JsonValue::Object(map) => map
                    .get_mut(token)
                    .ok_or_else(|| format!("Segment '{}' not found at step {}", token, i))?,
                JsonValue::Array(arr) => {
                    if token.len() > 1 && token.starts_with('0') {
                        return Err(format!("Invalid array index '{}' with leading zero", token));
                    }
                    let idx: usize = token
                        .parse()
                        .map_err(|_| format!("Invalid array index '{}'", token))?;
                    let len = arr.len();
                    arr.get_mut(idx)
                        .ok_or_else(|| format!("Array index {} out of bounds (len {})", idx, len))?
                }
                _ => return Err(format!("Cannot traverse non-container at step {}", i)),
            };
        }

        match curr {
            JsonValue::Object(map) => {
                map.insert(last_token.clone(), val);
                Ok(())
            }
            JsonValue::Array(arr) => {
                if last_token == "-" {
                    arr.push(val);
                    Ok(())
                } else {
                    if last_token.len() > 1 && last_token.starts_with('0') {
                        return Err(format!(
                            "Invalid array index '{}' with leading zero",
                            last_token
                        ));
                    }
                    let idx: usize = last_token
                        .parse()
                        .map_err(|_| format!("Invalid array index '{}'", last_token))?;
                    if idx < arr.len() {
                        arr[idx] = val;
                        Ok(())
                    } else if idx == arr.len() {
                        arr.push(val);
                        Ok(())
                    } else {
                        Err(format!(
                            "Array index {} out of bounds for insertion (len {})",
                            idx,
                            arr.len()
                        ))
                    }
                }
            }
            _ => Err("Target parent is not an Object or Array".to_string()),
        }
    }

    /// Remove a value at the specified RFC 6901 JSON Pointer, returning the removed value if present.
    pub fn delete_pointer(&mut self, ptr: &str) -> Result<Option<JsonValue>, String> {
        let tokens = split_pointer(ptr)?;
        if tokens.is_empty() {
            let old = std::mem::replace(self, JsonValue::Null);
            return Ok(Some(old));
        }

        let (last_token, parent_tokens) = tokens.split_last().unwrap();
        let mut curr = self;
        for (i, token) in parent_tokens.iter().enumerate() {
            curr = match curr {
                JsonValue::Object(map) => map
                    .get_mut(token)
                    .ok_or_else(|| format!("Segment '{}' not found at step {}", token, i))?,
                JsonValue::Array(arr) => {
                    if token.len() > 1 && token.starts_with('0') {
                        return Err(format!("Invalid array index '{}' with leading zero", token));
                    }
                    let idx: usize = token
                        .parse()
                        .map_err(|_| format!("Invalid array index '{}'", token))?;
                    let len = arr.len();
                    arr.get_mut(idx)
                        .ok_or_else(|| format!("Array index {} out of bounds (len {})", idx, len))?
                }
                _ => return Err(format!("Cannot traverse non-container at step {}", i)),
            };
        }

        match curr {
            JsonValue::Object(map) => Ok(map.remove(last_token)),
            JsonValue::Array(arr) => {
                if last_token.len() > 1 && last_token.starts_with('0') {
                    return Err(format!(
                        "Invalid array index '{}' with leading zero",
                        last_token
                    ));
                }
                let idx: usize = last_token
                    .parse()
                    .map_err(|_| format!("Invalid array index '{}'", last_token))?;
                if idx < arr.len() {
                    Ok(Some(arr.remove(idx)))
                } else {
                    Ok(None)
                }
            }
            _ => Err("Target parent is not an Object or Array".to_string()),
        }
    }

    /// Apply an RFC 7396 JSON Merge Patch to this value.
    pub fn merge_patch(&mut self, patch: &JsonValue) {
        match patch {
            JsonValue::Object(patch_obj) => {
                if !self.is_object() {
                    *self = JsonValue::Object(BTreeMap::new());
                }
                if let JsonValue::Object(target_map) = self {
                    for (k, v) in patch_obj {
                        if v.is_null() {
                            target_map.remove(k);
                        } else {
                            target_map
                                .entry(k.clone())
                                .or_insert(JsonValue::Null)
                                .merge_patch(v);
                        }
                    }
                }
            }
            other => {
                *self = other.clone();
            }
        }
    }

    /// Apply a sequence of RFC 6902 JSON Patch operations atomically.
    /// If any operation fails, the original document remains unmodified.
    pub fn apply_patch(&mut self, ops: &[PatchOperation]) -> Result<(), String> {
        let mut draft = self.clone();
        for op in ops {
            match op {
                PatchOperation::Add { path, value } => {
                    apply_add(&mut draft, path, value.clone())?;
                }
                PatchOperation::Remove { path } => {
                    apply_remove(&mut draft, path)?;
                }
                PatchOperation::Replace { path, value } => {
                    apply_replace(&mut draft, path, value.clone())?;
                }
                PatchOperation::Move { from, path } => {
                    if path.starts_with(from)
                        && (path.len() == from.len()
                            || path.as_bytes().get(from.len()) == Some(&b'/'))
                        && path != from
                    {
                        return Err(format!(
                            "Cannot move '{}' into its own child location '{}'",
                            from, path
                        ));
                    }
                    if from == path {
                        if draft.pointer(from).is_none() {
                            return Err(format!("Path '{}' does not exist for move", from));
                        }
                    } else {
                        let val = apply_remove(&mut draft, from)?;
                        apply_add(&mut draft, path, val)?;
                    }
                }
                PatchOperation::Copy { from, path } => {
                    let val = draft
                        .pointer(from)
                        .ok_or_else(|| {
                            format!("Source location '{}' does not exist for copy", from)
                        })?
                        .clone();
                    apply_add(&mut draft, path, val)?;
                }
                PatchOperation::Test { path, value } => {
                    let existing = draft
                        .pointer(path)
                        .ok_or_else(|| format!("Location '{}' does not exist for test", path))?;
                    if existing != value {
                        return Err(format!(
                            "Test operation failed at '{}': expected {}, found {}",
                            path, value, existing
                        ));
                    }
                }
            }
        }
        *self = draft;
        Ok(())
    }

    /// Parse and apply an RFC 6902 JSON Patch document atomically.
    pub fn apply_json_patch(&mut self, patch_doc: &JsonValue) -> Result<(), String> {
        let ops = parse_patch(patch_doc)?;
        self.apply_patch(&ops)
    }
}

/// Decode a JSON Pointer reference token according to RFC 6901 (`~1` -> `/`, `~0` -> `~`).
pub fn decode_pointer_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// Encode a string as a JSON Pointer reference token according to RFC 6901 (`~` -> `~0`, `/` -> `~1`).
pub fn encode_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn split_pointer(ptr: &str) -> Result<Vec<String>, String> {
    if ptr.is_empty() {
        return Ok(Vec::new());
    }
    if !ptr.starts_with('/') {
        return Err(format!(
            "Invalid JSON Pointer '{}': must start with '/'",
            ptr
        ));
    }
    Ok(ptr[1..].split('/').map(decode_pointer_token).collect())
}

/// An operation in an RFC 6902 JSON Patch document.
#[derive(Debug, Clone, PartialEq)]
pub enum PatchOperation {
    Add { path: String, value: JsonValue },
    Remove { path: String },
    Replace { path: String, value: JsonValue },
    Move { from: String, path: String },
    Copy { from: String, path: String },
    Test { path: String, value: JsonValue },
}

impl PatchOperation {
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        match self {
            PatchOperation::Add { path, value } => {
                map.insert("op".to_string(), JsonValue::String("add".to_string()));
                map.insert("path".to_string(), JsonValue::String(path.clone()));
                map.insert("value".to_string(), value.clone());
            }
            PatchOperation::Remove { path } => {
                map.insert("op".to_string(), JsonValue::String("remove".to_string()));
                map.insert("path".to_string(), JsonValue::String(path.clone()));
            }
            PatchOperation::Replace { path, value } => {
                map.insert("op".to_string(), JsonValue::String("replace".to_string()));
                map.insert("path".to_string(), JsonValue::String(path.clone()));
                map.insert("value".to_string(), value.clone());
            }
            PatchOperation::Move { from, path } => {
                map.insert("op".to_string(), JsonValue::String("move".to_string()));
                map.insert("from".to_string(), JsonValue::String(from.clone()));
                map.insert("path".to_string(), JsonValue::String(path.clone()));
            }
            PatchOperation::Copy { from, path } => {
                map.insert("op".to_string(), JsonValue::String("copy".to_string()));
                map.insert("from".to_string(), JsonValue::String(from.clone()));
                map.insert("path".to_string(), JsonValue::String(path.clone()));
            }
            PatchOperation::Test { path, value } => {
                map.insert("op".to_string(), JsonValue::String("test".to_string()));
                map.insert("path".to_string(), JsonValue::String(path.clone()));
                map.insert("value".to_string(), value.clone());
            }
        }
        JsonValue::Object(map)
    }
}

/// Parse an RFC 6902 JSON Patch array document into structured operations.
pub fn parse_patch(patch_json: &JsonValue) -> Result<Vec<PatchOperation>, String> {
    let arr = patch_json
        .as_array()
        .ok_or_else(|| "JSON Patch document must be an array of operation objects".to_string())?;

    let mut ops = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| format!("Patch operation at index {} must be an object", idx))?;

        let op = obj
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Missing or non-string 'op' field at index {}", idx))?;

        let path = obj
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Missing or non-string 'path' field at index {}", idx))?
            .to_string();

        let operation = match op {
            "add" => {
                let value = obj
                    .get("value")
                    .ok_or_else(|| {
                        format!("Missing 'value' field for 'add' operation at index {}", idx)
                    })?
                    .clone();
                PatchOperation::Add { path, value }
            }
            "remove" => PatchOperation::Remove { path },
            "replace" => {
                let value = obj
                    .get("value")
                    .ok_or_else(|| {
                        format!(
                            "Missing 'value' field for 'replace' operation at index {}",
                            idx
                        )
                    })?
                    .clone();
                PatchOperation::Replace { path, value }
            }
            "move" => {
                let from = obj
                    .get("from")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        format!(
                            "Missing or non-string 'from' field for 'move' operation at index {}",
                            idx
                        )
                    })?
                    .to_string();
                PatchOperation::Move { from, path }
            }
            "copy" => {
                let from = obj
                    .get("from")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        format!(
                            "Missing or non-string 'from' field for 'copy' operation at index {}",
                            idx
                        )
                    })?
                    .to_string();
                PatchOperation::Copy { from, path }
            }
            "test" => {
                let value = obj
                    .get("value")
                    .ok_or_else(|| {
                        format!(
                            "Missing 'value' field for 'test' operation at index {}",
                            idx
                        )
                    })?
                    .clone();
                PatchOperation::Test { path, value }
            }
            unknown => {
                return Err(format!(
                    "Unsupported JSON Patch operation '{}' at index {}",
                    unknown, idx
                ))
            }
        };

        ops.push(operation);
    }

    Ok(ops)
}

/// Compute an RFC 7396 JSON Merge Patch document representing the minimal differences to transform `source` into `target`.
pub fn create_merge_patch(source: &JsonValue, target: &JsonValue) -> JsonValue {
    match (source, target) {
        (JsonValue::Object(s_map), JsonValue::Object(t_map)) => {
            let mut patch = BTreeMap::new();
            for k in s_map.keys() {
                if !t_map.contains_key(k) {
                    patch.insert(k.clone(), JsonValue::Null);
                }
            }
            for (k, v) in t_map {
                match s_map.get(k) {
                    Some(s_val) => {
                        if s_val != v {
                            if s_val.is_object() && v.is_object() {
                                let sub_patch = create_merge_patch(s_val, v);
                                if sub_patch != JsonValue::Object(BTreeMap::new()) {
                                    patch.insert(k.clone(), sub_patch);
                                }
                            } else {
                                patch.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    None => {
                        patch.insert(k.clone(), v.clone());
                    }
                }
            }
            JsonValue::Object(patch)
        }
        _ => {
            if source == target {
                JsonValue::Null
            } else {
                target.clone()
            }
        }
    }
}

fn navigate_parent_mut<'a>(
    root: &'a mut JsonValue,
    parent_tokens: &[String],
) -> Result<&'a mut JsonValue, String> {
    let mut curr = root;
    for (i, token) in parent_tokens.iter().enumerate() {
        curr = match curr {
            JsonValue::Object(map) => map
                .get_mut(token)
                .ok_or_else(|| format!("Segment '{}' not found at step {}", token, i))?,
            JsonValue::Array(arr) => {
                if token.len() > 1 && token.starts_with('0') {
                    return Err(format!("Invalid array index '{}' with leading zero", token));
                }
                let idx: usize = token
                    .parse()
                    .map_err(|_| format!("Invalid array index '{}'", token))?;
                let len = arr.len();
                arr.get_mut(idx)
                    .ok_or_else(|| format!("Array index {} out of bounds (len {})", idx, len))?
            }
            _ => return Err(format!("Cannot traverse non-container at step {}", i)),
        };
    }
    Ok(curr)
}

fn apply_add(root: &mut JsonValue, path: &str, value: JsonValue) -> Result<(), String> {
    let tokens = split_pointer(path)?;
    if tokens.is_empty() {
        *root = value;
        return Ok(());
    }
    let (last_token, parent_tokens) = tokens.split_last().unwrap();
    let parent = navigate_parent_mut(root, parent_tokens)?;
    match parent {
        JsonValue::Object(map) => {
            map.insert(last_token.clone(), value);
            Ok(())
        }
        JsonValue::Array(arr) => {
            if last_token == "-" {
                arr.push(value);
                Ok(())
            } else {
                if last_token.len() > 1 && last_token.starts_with('0') {
                    return Err(format!(
                        "Invalid array index '{}' with leading zero",
                        last_token
                    ));
                }
                let idx: usize = last_token
                    .parse()
                    .map_err(|_| format!("Invalid array index '{}'", last_token))?;
                if idx <= arr.len() {
                    arr.insert(idx, value);
                    Ok(())
                } else {
                    Err(format!(
                        "Array index {} out of bounds for add (len {})",
                        idx,
                        arr.len()
                    ))
                }
            }
        }
        _ => Err("Parent container is neither an object nor an array".to_string()),
    }
}

fn apply_remove(root: &mut JsonValue, path: &str) -> Result<JsonValue, String> {
    let tokens = split_pointer(path)?;
    if tokens.is_empty() {
        return Err("Cannot remove root JSON element".to_string());
    }
    let (last_token, parent_tokens) = tokens.split_last().unwrap();
    let parent = navigate_parent_mut(root, parent_tokens)?;
    match parent {
        JsonValue::Object(map) => map
            .remove(last_token)
            .ok_or_else(|| format!("Path '{}' does not exist in object", path)),
        JsonValue::Array(arr) => {
            if last_token.len() > 1 && last_token.starts_with('0') {
                return Err(format!(
                    "Invalid array index '{}' with leading zero",
                    last_token
                ));
            }
            let idx: usize = last_token
                .parse()
                .map_err(|_| format!("Invalid array index '{}'", last_token))?;
            if idx < arr.len() {
                Ok(arr.remove(idx))
            } else {
                Err(format!(
                    "Array index {} out of bounds for remove (len {})",
                    idx,
                    arr.len()
                ))
            }
        }
        _ => Err("Parent container is neither an object nor an array".to_string()),
    }
}

fn apply_replace(root: &mut JsonValue, path: &str, value: JsonValue) -> Result<(), String> {
    let tokens = split_pointer(path)?;
    if tokens.is_empty() {
        *root = value;
        return Ok(());
    }
    let (last_token, parent_tokens) = tokens.split_last().unwrap();
    let parent = navigate_parent_mut(root, parent_tokens)?;
    match parent {
        JsonValue::Object(map) => {
            if map.contains_key(last_token) {
                map.insert(last_token.clone(), value);
                Ok(())
            } else {
                Err(format!(
                    "Property '{}' does not exist for replace",
                    last_token
                ))
            }
        }
        JsonValue::Array(arr) => {
            if last_token.len() > 1 && last_token.starts_with('0') {
                return Err(format!(
                    "Invalid array index '{}' with leading zero",
                    last_token
                ));
            }
            let idx: usize = last_token
                .parse()
                .map_err(|_| format!("Invalid array index '{}'", last_token))?;
            if idx < arr.len() {
                arr[idx] = value;
                Ok(())
            } else {
                Err(format!(
                    "Array index {} out of bounds for replace (len {})",
                    idx,
                    arr.len()
                ))
            }
        }
        _ => Err("Parent container is neither an object nor an array".to_string()),
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

    #[test]
    fn test_json_pointer_rfc6901() {
        let raw = r#"{
            "foo": ["bar", "baz"],
            "": 0,
            "a/b": 1,
            "c%d": 2,
            "e^f": 3,
            "g|h": 4,
            "i\\j": 5,
            "k\"l": 6,
            " ": 7,
            "m~n": 8
        }"#;

        let mut doc = decode(raw).expect("decode rfc sample");

        // Pointer lookup tests
        assert_eq!(doc.pointer("").unwrap(), &doc);
        assert_eq!(doc.pointer("/foo").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(doc.pointer("/foo/0").unwrap().as_str(), Some("bar"));
        assert_eq!(doc.pointer("/foo/1").unwrap().as_str(), Some("baz"));
        assert_eq!(doc.pointer("/foo/2"), None);
        assert_eq!(doc.pointer("/").unwrap().as_i64(), Some(0));
        assert_eq!(doc.pointer("/a~1b").unwrap().as_i64(), Some(1));
        assert_eq!(doc.pointer("/c%d").unwrap().as_i64(), Some(2));
        assert_eq!(doc.pointer("/m~0n").unwrap().as_i64(), Some(8));

        // pointer_mut
        if let Some(val) = doc.pointer_mut("/foo/0") {
            *val = JsonValue::String("qux".to_string());
        }
        assert_eq!(doc.pointer("/foo/0").unwrap().as_str(), Some("qux"));

        // set_pointer on array end with '-'
        assert!(doc
            .set_pointer("/foo/-", JsonValue::String("tail".to_string()))
            .is_ok());
        assert_eq!(doc.pointer("/foo/2").unwrap().as_str(), Some("tail"));

        // set_pointer in object
        assert!(doc
            .set_pointer("/nested/child", JsonValue::Bool(true))
            .is_err()); // non-existing parent
        assert!(doc.set_pointer("/foo/new_key", JsonValue::Null).is_err()); // not an object

        // delete_pointer
        let deleted = doc.delete_pointer("/foo/1").unwrap();
        assert_eq!(deleted.unwrap().as_str(), Some("baz"));
        assert_eq!(doc.pointer("/foo/1").unwrap().as_str(), Some("tail"));
    }

    #[test]
    fn test_json_merge_patch_rfc7396() {
        let original_raw = r#"{"a":"b","c":{"d":"e","f":"g"},"h":1}"#;
        let patch_raw = r#"{"a":"z","c":{"f":null},"h":null,"new_field":true}"#;

        let mut original = decode(original_raw).expect("decode original");
        let patch = decode(patch_raw).expect("decode patch");

        original.merge_patch(&patch);

        assert_eq!(original.get("a").unwrap().as_str(), Some("z"));
        let c_obj = original.get("c").unwrap().as_object().unwrap();
        assert_eq!(c_obj.get("d").unwrap().as_str(), Some("e"));
        assert_eq!(c_obj.get("f"), None); // removed via null
        assert_eq!(original.get("h"), None); // removed via null
        assert_eq!(original.get("new_field").unwrap().as_bool(), Some(true));

        // Test non-object target replaced completely
        let mut primitive = JsonValue::Number(42.0);
        primitive.merge_patch(&JsonValue::String("hello".to_string()));
        assert_eq!(primitive.as_str(), Some("hello"));

        // Test create_merge_patch
        let s_val = decode(r#"{"title":"IFA Book","author":"John","tags":["code"]}"#).unwrap();
        let t_val = decode(r#"{"title":"IFA Guide","tags":["code","system"]}"#).unwrap();

        let generated_patch = create_merge_patch(&s_val, &t_val);
        let mut applied = s_val.clone();
        applied.merge_patch(&generated_patch);
        assert_eq!(applied, t_val);
    }

    #[test]
    fn test_json_patch_rfc6902() {
        let doc_raw = r#"{
            "title": "Old Title",
            "numbers": [10, 20, 30],
            "details": {
                "author": "Alice"
            }
        }"#;

        let patch_doc_raw = r#"[
            {"op": "test", "path": "/title", "value": "Old Title"},
            {"op": "replace", "path": "/title", "value": "New Title"},
            {"op": "add", "path": "/details/year", "value": 2026},
            {"op": "add", "path": "/numbers/1", "value": 15},
            {"op": "add", "path": "/numbers/-", "value": 40},
            {"op": "remove", "path": "/numbers/0"},
            {"op": "copy", "from": "/details/author", "path": "/editor"},
            {"op": "move", "from": "/editor", "path": "/creator"}
        ]"#;

        let mut doc = decode(doc_raw).expect("decode initial document");
        let patch_json = decode(patch_doc_raw).expect("decode patch document");

        let res = doc.apply_json_patch(&patch_json);
        assert!(res.is_ok(), "apply_json_patch failed: {:?}", res);

        assert_eq!(doc.pointer("/title").unwrap().as_str(), Some("New Title"));
        assert_eq!(doc.pointer("/details/year").unwrap().as_i64(), Some(2026));
        assert_eq!(doc.pointer("/creator").unwrap().as_str(), Some("Alice"));
        assert_eq!(doc.pointer("/editor"), None);

        // numbers was: [10, 20, 30]
        // add at 1 -> [10, 15, 20, 30]
        // add at '-' -> [10, 15, 20, 30, 40]
        // remove 0 -> [15, 20, 30, 40]
        let arr = doc.pointer("/numbers").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0].as_i64(), Some(15));
        assert_eq!(arr[1].as_i64(), Some(20));
        assert_eq!(arr[2].as_i64(), Some(30));
        assert_eq!(arr[3].as_i64(), Some(40));

        // Test atomicity on failure
        let backup = doc.clone();
        let bad_patch_raw = r#"[
            {"op": "replace", "path": "/title", "value": "Failing Title"},
            {"op": "test", "path": "/title", "value": "Does Not Match"}
        ]"#;
        let bad_patch = decode(bad_patch_raw).unwrap();
        let fail_res = doc.apply_json_patch(&bad_patch);
        assert!(fail_res.is_err());
        assert_eq!(
            doc, backup,
            "Document must remain unchanged after failed patch"
        );
    }
}
