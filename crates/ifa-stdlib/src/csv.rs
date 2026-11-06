/// In-memory tabular representation of CSV data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CsvTable {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl CsvTable {
    pub fn new(headers: Vec<String>) -> Self {
        Self {
            headers,
            rows: Vec::new(),
        }
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub fn col_count(&self) -> usize {
        self.headers.len()
    }

    pub fn get_value(&self, row_idx: usize, col_name: &str) -> Option<&str> {
        let col_idx = self.headers.iter().position(|h| h == col_name)?;
        self.rows.get(row_idx)?.get(col_idx).map(|s| s.as_str())
    }
}

/// Parse RFC 4180 compliant CSV string into a `CsvTable`.
pub fn decode(src: &str, has_headers: bool, delimiter: char) -> Result<CsvTable, String> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Vec<String> = Vec::new();
    let mut current_field = String::new();
    let mut inside_quotes = false;

    let chars: Vec<char> = src.chars().collect();
    let mut idx = 0;

    while idx < chars.len() {
        let ch = chars[idx];

        if inside_quotes {
            if ch == '"' {
                // Check for escaped double quote `""`
                if idx + 1 < chars.len() && chars[idx + 1] == '"' {
                    current_field.push('"');
                    idx += 2;
                    continue;
                } else {
                    inside_quotes = false;
                    idx += 1;
                    continue;
                }
            } else {
                current_field.push(ch);
                idx += 1;
                continue;
            }
        }

        if ch == '"' {
            inside_quotes = true;
            idx += 1;
        } else if ch == delimiter {
            current_row.push(std::mem::take(&mut current_field));
            idx += 1;
        } else if ch == '\n' || (ch == '\r' && idx + 1 < chars.len() && chars[idx + 1] == '\n') {
            if ch == '\r' {
                idx += 1; // skip '\r'
            }
            current_row.push(std::mem::take(&mut current_field));
            rows.push(std::mem::take(&mut current_row));
            idx += 1;
        } else {
            current_field.push(ch);
            idx += 1;
        }
    }

    // Push trailing field/row if any
    if !current_field.is_empty() || !current_row.is_empty() {
        current_row.push(current_field);
        rows.push(current_row);
    }

    if rows.is_empty() {
        return Ok(CsvTable::default());
    }

    if has_headers {
        let headers = rows.remove(0);
        Ok(CsvTable { headers, rows })
    } else {
        let col_count = rows.first().map(|r| r.len()).unwrap_or(0);
        let headers = (0..col_count).map(|i| format!("col_{}", i)).collect();
        Ok(CsvTable { headers, rows })
    }
}

/// Serialize a `CsvTable` into an RFC 4180 compliant CSV string.
pub fn encode(table: &CsvTable, delimiter: char) -> String {
    let mut out = String::new();

    // Write headers
    if !table.headers.is_empty() {
        for (i, h) in table.headers.iter().enumerate() {
            if i > 0 {
                out.push(delimiter);
            }
            write_field(&mut out, h, delimiter);
        }
        out.push('\n');
    }

    // Write rows
    for row in &table.rows {
        for (i, field) in row.iter().enumerate() {
            if i > 0 {
                out.push(delimiter);
            }
            write_field(&mut out, field, delimiter);
        }
        out.push('\n');
    }

    out
}

fn write_field(out: &mut String, field: &str, delimiter: char) {
    let needs_quotes = field.contains(delimiter)
        || field.contains('"')
        || field.contains('\n')
        || field.contains('\r');

    if !needs_quotes {
        out.push_str(field);
    } else {
        out.push('"');
        for c in field.chars() {
            if c == '"' {
                out.push_str("\"\"");
            } else {
                out.push(c);
            }
        }
        out.push('"');
    }
}
