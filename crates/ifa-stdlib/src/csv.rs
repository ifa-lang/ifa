use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use thiserror::Error;

/// Error types occurring during CSV parsing, encoding, or tabular manipulation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CsvError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Unterminated quote at row {row}, col {col}")]
    UnterminatedQuote { row: usize, col: usize },
    #[error("Column count mismatch at row {row}: expected {expected}, got {actual}")]
    ColumnCountMismatch {
        row: usize,
        expected: usize,
        actual: usize,
    },
    #[error("Column '{0}' not found in table headers")]
    ColumnNotFound(String),
    #[error("Invalid CSV syntax: {0}")]
    SyntaxError(String),
}

impl From<io::Error> for CsvError {
    fn from(err: io::Error) -> Self {
        CsvError::Io(err.to_string())
    }
}

/// Parsing and serialization options for CSV processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvOptions {
    pub delimiter: char,
    pub quote: char,
    pub comment: Option<char>,
    pub has_headers: bool,
    pub flexible_columns: bool,
    pub trim: bool,
}

impl Default for CsvOptions {
    fn default() -> Self {
        Self {
            delimiter: ',',
            quote: '"',
            comment: None,
            has_headers: true,
            flexible_columns: false,
            trim: false,
        }
    }
}

impl CsvOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn delimiter(mut self, delimiter: char) -> Self {
        self.delimiter = delimiter;
        self
    }

    pub fn quote(mut self, quote: char) -> Self {
        self.quote = quote;
        self
    }

    pub fn comment(mut self, comment: char) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn has_headers(mut self, has_headers: bool) -> Self {
        self.has_headers = has_headers;
        self
    }

    pub fn flexible_columns(mut self, flexible: bool) -> Self {
        self.flexible_columns = flexible;
        self
    }

    pub fn trim(mut self, trim: bool) -> Self {
        self.trim = trim;
        self
    }
}

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

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn get_value(&self, row_idx: usize, col_name: &str) -> Option<&str> {
        let col_idx = self.headers.iter().position(|h| h == col_name)?;
        self.rows.get(row_idx)?.get(col_idx).map(|s| s.as_str())
    }

    pub fn column(&self, col_name: &str) -> Option<Vec<&str>> {
        let col_idx = self.headers.iter().position(|h| h == col_name)?;
        Some(
            self.rows
                .iter()
                .filter_map(|r| r.get(col_idx).map(|s| s.as_str()))
                .collect(),
        )
    }

    pub fn filter_rows<F>(&self, predicate: F) -> Self
    where
        F: Fn(&[String]) -> bool,
    {
        let filtered_rows = self.rows.iter().filter(|r| predicate(r)).cloned().collect();
        Self {
            headers: self.headers.clone(),
            rows: filtered_rows,
        }
    }

    pub fn select_columns(&self, col_names: &[&str]) -> Result<Self, CsvError> {
        let mut indices = Vec::with_capacity(col_names.len());
        for &name in col_names {
            match self.headers.iter().position(|h| h == name) {
                Some(idx) => indices.push(idx),
                None => return Err(CsvError::ColumnNotFound(name.to_string())),
            }
        }

        let new_headers = col_names.iter().map(|&s| s.to_string()).collect();
        let mut new_rows = Vec::with_capacity(self.rows.len());

        for row in &self.rows {
            let mut new_row = Vec::with_capacity(indices.len());
            for &idx in &indices {
                new_row.push(row.get(idx).cloned().unwrap_or_default());
            }
            new_rows.push(new_row);
        }

        Ok(Self {
            headers: new_headers,
            rows: new_rows,
        })
    }

    pub fn sort_by_column(&mut self, col_name: &str, ascending: bool) -> Result<(), CsvError> {
        let col_idx = self
            .headers
            .iter()
            .position(|h| h == col_name)
            .ok_or_else(|| CsvError::ColumnNotFound(col_name.to_string()))?;

        self.rows.sort_by(|a, b| {
            let val_a = a.get(col_idx).map(|s| s.as_str()).unwrap_or("");
            let val_b = b.get(col_idx).map(|s| s.as_str()).unwrap_or("");
            if ascending {
                val_a.cmp(val_b)
            } else {
                val_b.cmp(val_a)
            }
        });

        Ok(())
    }

    pub fn to_maps(&self) -> Vec<HashMap<String, String>> {
        let mut result = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let mut map = HashMap::with_capacity(self.headers.len());
            for (idx, header) in self.headers.iter().enumerate() {
                if let Some(val) = row.get(idx) {
                    map.insert(header.clone(), val.clone());
                }
            }
            result.push(map);
        }
        result
    }

    pub fn from_maps(maps: &[HashMap<String, String>]) -> Self {
        if maps.is_empty() {
            return Self::default();
        }
        let mut headers_set = std::collections::BTreeSet::new();
        for map in maps {
            for k in map.keys() {
                headers_set.insert(k.clone());
            }
        }
        let headers: Vec<String> = headers_set.into_iter().collect();
        let mut rows = Vec::with_capacity(maps.len());
        for map in maps {
            let mut row = Vec::with_capacity(headers.len());
            for h in &headers {
                row.push(map.get(h).cloned().unwrap_or_default());
            }
            rows.push(row);
        }
        Self { headers, rows }
    }
}

/// Streaming reader for CSV streams.
pub struct CsvReader<R> {
    reader: R,
    options: CsvOptions,
    line_number: usize,
    reached_eof: bool,
}

impl<R: Read> CsvReader<BufReader<R>> {
    pub fn new(reader: R) -> Self {
        Self::with_options(reader, CsvOptions::default())
    }

    pub fn with_options(reader: R, options: CsvOptions) -> Self {
        Self {
            reader: BufReader::new(reader),
            options,
            line_number: 0,
            reached_eof: false,
        }
    }
}

impl<R: BufRead> CsvReader<R> {
    pub fn from_buf_read(reader: R, options: CsvOptions) -> Self {
        Self {
            reader,
            options,
            line_number: 0,
            reached_eof: false,
        }
    }

    pub fn line_number(&self) -> usize {
        self.line_number
    }

    pub fn read_record(&mut self) -> Result<Option<Vec<String>>, CsvError> {
        if self.reached_eof {
            return Ok(None);
        }

        let mut line_buf = String::new();
        let mut in_quotes = false;

        loop {
            let prev_len = line_buf.len();
            let bytes_read = self.reader.read_line(&mut line_buf)?;
            if bytes_read == 0 {
                self.reached_eof = true;
                if in_quotes {
                    return Err(CsvError::UnterminatedQuote {
                        row: self.line_number + 1,
                        col: line_buf.len(),
                    });
                }
                if line_buf.trim().is_empty() {
                    return Ok(None);
                }
                break;
            }

            self.line_number += 1;

            // Handle comments on non-quoted lines
            if !in_quotes && prev_len == 0 {
                if let Some(comm) = self.options.comment {
                    let trimmed = line_buf.trim_start();
                    if trimmed.starts_with(comm) {
                        line_buf.clear();
                        continue;
                    }
                }
            }

            let slice = &line_buf[prev_len..];
            for ch in slice.chars() {
                if ch == self.options.quote {
                    in_quotes = !in_quotes;
                }
            }

            if !in_quotes {
                break;
            }
        }

        if line_buf.trim().is_empty() {
            return Ok(None);
        }

        let record = parse_record_line(&line_buf, &self.options)?;
        Ok(Some(record))
    }
}

fn parse_record_line(src: &str, options: &CsvOptions) -> Result<Vec<String>, CsvError> {
    let mut record = Vec::new();
    let mut current_field = String::new();
    let mut inside_quotes = false;

    let chars: Vec<char> = src.chars().collect();
    let mut idx = 0;
    let n = chars.len();

    let mut end = n;
    while end > 0 && (chars[end - 1] == '\n' || chars[end - 1] == '\r') {
        end -= 1;
    }

    while idx < end {
        let ch = chars[idx];

        if inside_quotes {
            if ch == options.quote {
                if idx + 1 < end && chars[idx + 1] == options.quote {
                    current_field.push(options.quote);
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

        if ch == options.quote {
            inside_quotes = true;
            idx += 1;
        } else if ch == options.delimiter {
            let field = std::mem::take(&mut current_field);
            let val = if options.trim {
                field.trim().to_string()
            } else {
                field
            };
            record.push(val);
            idx += 1;
        } else {
            current_field.push(ch);
            idx += 1;
        }
    }

    if inside_quotes {
        return Err(CsvError::UnterminatedQuote {
            row: 0,
            col: current_field.len(),
        });
    }

    let val = if options.trim {
        current_field.trim().to_string()
    } else {
        current_field
    };
    record.push(val);

    Ok(record)
}

/// Streaming writer for CSV formatted data.
pub struct CsvWriter<W> {
    writer: W,
    delimiter: char,
    quote: char,
}

impl<W: Write> CsvWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            delimiter: ',',
            quote: '"',
        }
    }

    pub fn with_delimiter(mut self, delimiter: char) -> Self {
        self.delimiter = delimiter;
        self
    }

    pub fn with_quote(mut self, quote: char) -> Self {
        self.quote = quote;
        self
    }

    pub fn write_record<I, S>(&mut self, record: I) -> Result<(), CsvError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut first = true;
        for field in record {
            if !first {
                write!(self.writer, "{}", self.delimiter)?;
            }
            first = false;
            self.write_field(field.as_ref())?;
        }
        writeln!(self.writer)?;
        Ok(())
    }

    fn write_field(&mut self, field: &str) -> Result<(), CsvError> {
        let needs_quotes = field.contains(self.delimiter)
            || field.contains(self.quote)
            || field.contains('\n')
            || field.contains('\r');

        if !needs_quotes {
            write!(self.writer, "{}", field)?;
        } else {
            write!(self.writer, "{}", self.quote)?;
            for c in field.chars() {
                if c == self.quote {
                    write!(self.writer, "{}{}", self.quote, self.quote)?;
                } else {
                    write!(self.writer, "{}", c)?;
                }
            }
            write!(self.writer, "{}", self.quote)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), CsvError> {
        self.writer.flush()?;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

/// Parse CSV source into `CsvTable` using fine-grained options.
pub fn decode_with_options(src: &str, options: &CsvOptions) -> Result<CsvTable, CsvError> {
    if src.trim().is_empty() {
        return Ok(CsvTable::default());
    }

    let mut reader = CsvReader::from_buf_read(src.as_bytes(), options.clone());
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut expected_cols: Option<usize> = None;

    while let Some(row) = reader.read_record()? {
        if let Some(exp) = expected_cols {
            if !options.flexible_columns && row.len() != exp {
                return Err(CsvError::ColumnCountMismatch {
                    row: reader.line_number(),
                    expected: exp,
                    actual: row.len(),
                });
            }
        } else {
            expected_cols = Some(row.len());
        }
        rows.push(row);
    }

    if rows.is_empty() {
        return Ok(CsvTable::default());
    }

    if options.has_headers {
        let headers = rows.remove(0);
        Ok(CsvTable { headers, rows })
    } else {
        let col_count = rows.first().map(|r| r.len()).unwrap_or(0);
        let headers = (0..col_count).map(|i| format!("col_{}", i)).collect();
        Ok(CsvTable { headers, rows })
    }
}

/// Serialize a `CsvTable` into CSV string format using options.
pub fn encode_with_options(table: &CsvTable, options: &CsvOptions) -> String {
    let mut buf = Vec::new();
    {
        let mut writer = CsvWriter::new(&mut buf)
            .with_delimiter(options.delimiter)
            .with_quote(options.quote);

        if !table.headers.is_empty() {
            let _ = writer.write_record(&table.headers);
        }
        for row in &table.rows {
            let _ = writer.write_record(row);
        }
        let _ = writer.flush();
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// Parse RFC 4180 compliant CSV string into a `CsvTable`.
pub fn decode(src: &str, has_headers: bool, delimiter: char) -> Result<CsvTable, String> {
    let options = CsvOptions::new()
        .has_headers(has_headers)
        .delimiter(delimiter);
    decode_with_options(src, &options).map_err(|e| e.to_string())
}

/// Serialize a `CsvTable` into an RFC 4180 compliant CSV string.
pub fn encode(table: &CsvTable, delimiter: char) -> String {
    let options = CsvOptions::new().delimiter(delimiter);
    encode_with_options(table, &options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_table_columns_and_filter() {
        let mut table = CsvTable::new(vec![
            "id".to_string(),
            "name".to_string(),
            "role".to_string(),
        ]);
        table.add_row(vec![
            "1".to_string(),
            "Alice".to_string(),
            "Admin".to_string(),
        ]);
        table.add_row(vec![
            "2".to_string(),
            "Bob".to_string(),
            "Developer".to_string(),
        ]);
        table.add_row(vec![
            "3".to_string(),
            "Charlie".to_string(),
            "Admin".to_string(),
        ]);

        assert_eq!(table.row_count(), 3);
        assert_eq!(table.col_count(), 3);
        assert_eq!(table.column("name"), Some(vec!["Alice", "Bob", "Charlie"]));
        assert_eq!(table.column("invalid"), None);

        let admins = table.filter_rows(|r| r.get(2).map(|s| s.as_str()) == Some("Admin"));
        assert_eq!(admins.row_count(), 2);
        assert_eq!(admins.column("name"), Some(vec!["Alice", "Charlie"]));
    }

    #[test]
    fn test_csv_table_select_columns_and_sort() {
        let mut table = CsvTable::new(vec![
            "id".to_string(),
            "dept".to_string(),
            "salary".to_string(),
        ]);
        table.add_row(vec!["1".to_string(), "Ops".to_string(), "5000".to_string()]);
        table.add_row(vec!["2".to_string(), "Dev".to_string(), "7000".to_string()]);
        table.add_row(vec!["3".to_string(), "Dev".to_string(), "6000".to_string()]);

        let projected = table.select_columns(&["salary", "dept"]).unwrap();
        assert_eq!(projected.headers, vec!["salary", "dept"]);
        assert_eq!(projected.rows[0], vec!["5000", "Ops"]);

        table.sort_by_column("salary", true).unwrap();
        assert_eq!(table.column("id"), Some(vec!["1", "3", "2"]));

        table.sort_by_column("salary", false).unwrap();
        assert_eq!(table.column("id"), Some(vec!["2", "3", "1"]));
    }

    #[test]
    fn test_csv_table_maps_conversion() {
        let mut table = CsvTable::new(vec!["city".to_string(), "temp".to_string()]);
        table.add_row(vec!["Cotonou".to_string(), "31".to_string()]);
        table.add_row(vec!["Paris".to_string(), "15".to_string()]);

        let maps = table.to_maps();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].get("city").unwrap(), "Cotonou");
        assert_eq!(maps[0].get("temp").unwrap(), "31");

        let reconstructed = CsvTable::from_maps(&maps);
        assert_eq!(reconstructed.row_count(), 2);
        assert_eq!(reconstructed.headers, vec!["city", "temp"]);
    }

    #[test]
    fn test_csv_streaming_reader_with_comments_and_trim() {
        let raw = "\
# comment header
name , age , role
# comment middle
 Alice , 30 , Engineer 
Bob, 25, \"Systems, Architect\"
";
        let options = CsvOptions::new().comment('#').trim(true).has_headers(true);

        let table = decode_with_options(raw, &options).unwrap();
        assert_eq!(table.headers, vec!["name", "age", "role"]);
        assert_eq!(table.row_count(), 2);
        assert_eq!(table.rows[0], vec!["Alice", "30", "Engineer"]);
        assert_eq!(table.rows[1], vec!["Bob", "25", "Systems, Architect"]);
    }

    #[test]
    fn test_csv_streaming_writer() {
        let mut buffer = Vec::new();
        {
            let mut writer = CsvWriter::new(&mut buffer)
                .with_delimiter(';')
                .with_quote('"');
            writer.write_record(["id", "note", "status"]).unwrap();
            writer
                .write_record(["1", "Line with ; inside", "OK"])
                .unwrap();
            writer
                .write_record(["2", "Line with \"quote\"", "PENDING"])
                .unwrap();
            writer.flush().unwrap();
        }

        let written = String::from_utf8(buffer).unwrap();
        assert_eq!(
            written,
            "id;note;status\n1;\"Line with ; inside\";OK\n2;\"Line with \"\"quote\"\"\";PENDING\n"
        );
    }

    #[test]
    fn test_csv_mismatched_column_count_error() {
        let raw = "col1,col2\nval1,val2,val3\n";
        let options = CsvOptions::new().flexible_columns(false);
        let result = decode_with_options(raw, &options);
        assert!(matches!(result, Err(CsvError::ColumnCountMismatch { .. })));

        let options_flex = CsvOptions::new().flexible_columns(true);
        assert!(decode_with_options(raw, &options_flex).is_ok());
    }
}
