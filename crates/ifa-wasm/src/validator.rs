use thiserror::Error;

pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // \0asm
pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // version 1

#[derive(Debug, Error)]
pub enum WasmValidationError {
    #[error("File is smaller than minimum 8-byte WebAssembly header")]
    FileTooSmall,
    #[error("Invalid WebAssembly magic number: expected \\0asm")]
    InvalidMagic,
    #[error("Unsupported WebAssembly version: expected 1")]
    UnsupportedVersion,
    #[error("Malformed section at byte offset {0}: {1}")]
    MalformedSection(usize, String),
}

/// Description of a section inside a WebAssembly binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmSection {
    pub id: u8,
    pub name: &'static str,
    pub offset: usize,
    pub size: usize,
}

/// Exported entity in WebAssembly binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExport {
    pub name: String,
    pub kind: u8, // 0 = func, 1 = table, 2 = mem, 3 = global
    pub index: u32,
}

/// WebAssembly table definition from the Table section (ID 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmTableDef {
    /// Element reference type (0x70 = funcref / anyfunc).
    pub elem_type: u8,
    /// Minimum declared size.
    pub min_size: u32,
    /// Maximum declared size if specified.
    pub max_size: Option<u32>,
}

/// WebAssembly element segment from the Element section (ID 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmElementSegment {
    /// Target table index (typically 0).
    pub table_index: u32,
    /// Offset where elements are loaded into the table.
    pub offset: usize,
    /// Function indices referenced by this segment.
    pub func_indices: Vec<u32>,
}

/// WebAssembly function type signature from the Type section (ID 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmFuncType {
    /// Parameter types (0x7F = i32, 0x7E = i64, 0x7D = f32, 0x7C = f64).
    pub params: Vec<u8>,
    /// Result types.
    pub results: Vec<u8>,
}

/// WebAssembly binary inspector and validator.
pub struct WasmModuleInspector<'a> {
    bytes: &'a [u8],
}

impl<'a> WasmModuleInspector<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Validate header and parse sections.
    pub fn inspect(&self) -> Result<Vec<WasmSection>, WasmValidationError> {
        if self.bytes.len() < 8 {
            return Err(WasmValidationError::FileTooSmall);
        }

        if self.bytes[0..4] != WASM_MAGIC {
            return Err(WasmValidationError::InvalidMagic);
        }

        if self.bytes[4..8] != WASM_VERSION {
            return Err(WasmValidationError::UnsupportedVersion);
        }

        let mut sections = Vec::new();
        let mut offset = 8;

        while offset < self.bytes.len() {
            let section_id = self.bytes[offset];
            offset += 1;

            let (section_len, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            let section_data_offset = offset;
            offset += section_len as usize;

            if offset > self.bytes.len() {
                return Err(WasmValidationError::MalformedSection(
                    section_data_offset,
                    "Section length exceeds file size".to_string(),
                ));
            }

            let section_name = match section_id {
                0 => "custom",
                1 => "type",
                2 => "import",
                3 => "function",
                4 => "table",
                5 => "memory",
                6 => "global",
                7 => "export",
                8 => "start",
                9 => "element",
                10 => "code",
                11 => "data",
                12 => "data_count",
                _ => "unknown",
            };

            sections.push(WasmSection {
                id: section_id,
                name: section_name,
                offset: section_data_offset,
                size: section_len as usize,
            });
        }

        Ok(sections)
    }

    /// Extract exported symbols from the Export section (ID 7).
    pub fn extract_exports(&self) -> Result<Vec<WasmExport>, WasmValidationError> {
        let sections = self.inspect()?;
        let export_sec = match sections.iter().find(|s| s.id == 7) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let mut offset = export_sec.offset;
        let (count, leb_len) = self
            .read_leb128_u32(offset)
            .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
        offset += leb_len;

        let mut exports = Vec::new();
        for _ in 0..count {
            let (name_len, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            let name_bytes = &self.bytes[offset..offset + name_len as usize];
            let name = std::str::from_utf8(name_bytes)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e.to_string()))?
                .to_string();
            offset += name_len as usize;

            let kind = self.bytes[offset];
            offset += 1;

            let (index, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            exports.push(WasmExport { name, kind, index });
        }

        Ok(exports)
    }

    /// Extract table definitions from the Table section (ID 4).
    pub fn extract_tables(&self) -> Result<Vec<WasmTableDef>, WasmValidationError> {
        let sections = self.inspect()?;
        let table_sec = match sections.iter().find(|s| s.id == 4) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let mut offset = table_sec.offset;
        let (count, leb_len) = self
            .read_leb128_u32(offset)
            .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
        offset += leb_len;

        let mut tables = Vec::new();
        for _ in 0..count {
            if offset >= self.bytes.len() {
                return Err(WasmValidationError::MalformedSection(
                    offset,
                    "Unexpected EOF reading table".to_string(),
                ));
            }
            let elem_type = self.bytes[offset];
            offset += 1;

            let flag = self.bytes[offset];
            offset += 1;

            let (min_size, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            let max_size = if (flag & 1) != 0 {
                let (max, leb_len) = self
                    .read_leb128_u32(offset)
                    .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
                offset += leb_len;
                Some(max)
            } else {
                None
            };

            tables.push(WasmTableDef {
                elem_type,
                min_size,
                max_size,
            });
        }

        Ok(tables)
    }

    /// Extract element segments from the Element section (ID 9).
    pub fn extract_elements(&self) -> Result<Vec<WasmElementSegment>, WasmValidationError> {
        let sections = self.inspect()?;
        let elem_sec = match sections.iter().find(|s| s.id == 9) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let mut offset = elem_sec.offset;
        let (count, leb_len) = self
            .read_leb128_u32(offset)
            .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
        offset += leb_len;

        let mut segments = Vec::new();
        for _ in 0..count {
            let (kind, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            let (table_index, elem_offset) = match kind {
                0 => {
                    let (expr_offset, consumed) = self.parse_offset_expr(offset)?;
                    offset += consumed;
                    (0, expr_offset)
                }
                2 => {
                    let (t_idx, leb_len) = self
                        .read_leb128_u32(offset)
                        .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
                    offset += leb_len;
                    let (expr_offset, consumed) = self.parse_offset_expr(offset)?;
                    offset += consumed;
                    offset += 1; // skip elemkind
                    (t_idx, expr_offset)
                }
                _ => (0, 0),
            };

            let (num_elems, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            let mut func_indices = Vec::new();
            for _ in 0..num_elems {
                let (f_idx, leb_len) = self
                    .read_leb128_u32(offset)
                    .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
                offset += leb_len;
                func_indices.push(f_idx);
            }

            segments.push(WasmElementSegment {
                table_index,
                offset: elem_offset,
                func_indices,
            });
        }

        Ok(segments)
    }

    /// Extract function type signatures from the Type section (ID 1).
    pub fn extract_types(&self) -> Result<Vec<WasmFuncType>, WasmValidationError> {
        let sections = self.inspect()?;
        let type_sec = match sections.iter().find(|s| s.id == 1) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let mut offset = type_sec.offset;
        let (count, leb_len) = self
            .read_leb128_u32(offset)
            .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
        offset += leb_len;

        let mut types = Vec::new();
        for _ in 0..count {
            if offset >= self.bytes.len() || self.bytes[offset] != 0x60 {
                return Err(WasmValidationError::MalformedSection(
                    offset,
                    "Expected 0x60 func type tag".to_string(),
                ));
            }
            offset += 1;

            let (num_params, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            let params = self.bytes[offset..offset + num_params as usize].to_vec();
            offset += num_params as usize;

            let (num_results, leb_len) = self
                .read_leb128_u32(offset)
                .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
            offset += leb_len;

            let results = self.bytes[offset..offset + num_results as usize].to_vec();
            offset += num_results as usize;

            types.push(WasmFuncType { params, results });
        }

        Ok(types)
    }

    /// Check whether the WebAssembly Code section contains `call_indirect` instructions (opcode 0x11).
    pub fn has_indirect_calls(&self) -> Result<bool, WasmValidationError> {
        let sections = self.inspect()?;
        let code_sec = match sections.iter().find(|s| s.id == 10) {
            Some(s) => s,
            None => return Ok(false),
        };

        let code_bytes = &self.bytes[code_sec.offset..code_sec.offset + code_sec.size];
        Ok(code_bytes.contains(&0x11))
    }

    fn parse_offset_expr(&self, mut offset: usize) -> Result<(usize, usize), WasmValidationError> {
        let start = offset;
        let mut computed_offset = 0;
        while offset < self.bytes.len() {
            let op = self.bytes[offset];
            offset += 1;
            if op == 0x41 {
                let (val, leb_len) = self
                    .read_leb128_u32(offset)
                    .map_err(|e| WasmValidationError::MalformedSection(offset, e))?;
                offset += leb_len;
                computed_offset = val as usize;
            } else if op == 0x0B {
                break;
            }
        }
        Ok((computed_offset, offset - start))
    }

    fn read_leb128_u32(&self, mut offset: usize) -> Result<(u32, usize), String> {
        let mut result = 0u32;
        let mut shift = 0;
        let mut count = 0;

        loop {
            if offset >= self.bytes.len() {
                return Err("Unexpected EOF while reading LEB128".to_string());
            }
            let byte = self.bytes[offset];
            offset += 1;
            count += 1;

            result |= ((byte & 0x7F) as u32) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                return Err("LEB128 integer overflow".to_string());
            }
        }

        Ok((result, count))
    }
}
