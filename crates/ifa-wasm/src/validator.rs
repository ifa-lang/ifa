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
