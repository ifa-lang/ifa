//! WebAssembly Component Model (Wasm 3.0 / WASI 0.2) binary encoder and inspector.
//!
//! Encapsulates core WebAssembly modules into structured WebAssembly Components
//! according to the W3C Component Model Specification (Layer 1).

use thiserror::Error;

pub const WASM_COMPONENT_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // \0asm
pub const WASM_COMPONENT_VERSION: [u8; 4] = [0x0d, 0x00, 0x01, 0x00]; // version 0x0001000d

#[derive(Debug, Error)]
pub enum ComponentError {
    #[error("Component binary is smaller than 8-byte header")]
    TooSmall,
    #[error("Invalid component magic number: expected \\0asm")]
    InvalidMagic,
    #[error("Invalid component layer version: expected [0x0d, 0x00, 0x01, 0x00]")]
    InvalidVersion,
    #[error("Malformed component section at offset {0}: {1}")]
    MalformedSection(usize, String),
    #[error("Missing required core module")]
    MissingCoreModule,
}

/// Identifiers for Component Model Binary Sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComponentSectionId {
    Custom = 0,
    CoreModule = 1,
    CoreInstance = 2,
    CoreType = 3,
    Component = 4,
    ComponentInstance = 5,
    ComponentAlias = 6,
    ComponentType = 7,
    ComponentCanonical = 8,
    ComponentStart = 9,
    ComponentImport = 10,
    ComponentExport = 11,
}

impl ComponentSectionId {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(ComponentSectionId::Custom),
            1 => Some(ComponentSectionId::CoreModule),
            2 => Some(ComponentSectionId::CoreInstance),
            3 => Some(ComponentSectionId::CoreType),
            4 => Some(ComponentSectionId::Component),
            5 => Some(ComponentSectionId::ComponentInstance),
            6 => Some(ComponentSectionId::ComponentAlias),
            7 => Some(ComponentSectionId::ComponentType),
            8 => Some(ComponentSectionId::ComponentCanonical),
            9 => Some(ComponentSectionId::ComponentStart),
            10 => Some(ComponentSectionId::ComponentImport),
            11 => Some(ComponentSectionId::ComponentExport),
            _ => None,
        }
    }
}

/// Information about a section parsed inside a Component binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentSectionHeader {
    pub id: ComponentSectionId,
    pub offset: usize,
    pub payload_offset: usize,
    pub payload_size: usize,
}

/// Canonical ABI function lift/lower options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonLift {
    pub core_func_index: u32,
    pub type_index: u32,
    pub memory_index: Option<u32>,
    pub realloc_index: Option<u32>,
    pub string_encoding: StringEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StringEncoding {
    Utf8 = 0,
    Utf16 = 1,
    CompactUtf16 = 2,
}

/// Exported item in a Component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentExport {
    pub name: String,
    pub sort: u8, // 0x00 = core module, 0x01 = func, 0x02 = val, 0x03 = type, 0x04 = instance, 0x05 = component
    pub index: u32,
}

/// Imported item in a Component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentImport {
    pub name: String,
    pub type_index: u32,
}

/// WebAssembly Component Builder.
pub struct ComponentBuilder {
    core_modules: Vec<Vec<u8>>,
    imports: Vec<ComponentImport>,
    exports: Vec<ComponentExport>,
    canonical_lifts: Vec<CanonLift>,
    custom_sections: Vec<(String, Vec<u8>)>,
}

impl Default for ComponentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ComponentBuilder {
    pub fn new() -> Self {
        Self {
            core_modules: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            canonical_lifts: Vec::new(),
            custom_sections: Vec::new(),
        }
    }

    /// Embed a compiled core WebAssembly module (`\0asm\x01\x00\x00\x00`).
    pub fn add_core_module(&mut self, wasm_bytes: Vec<u8>) -> &mut Self {
        self.core_modules.push(wasm_bytes);
        self
    }

    /// Add a component import (e.g. `wasi:cli/stdout@0.2.0`).
    pub fn add_import(&mut self, name: impl Into<String>, type_index: u32) -> &mut Self {
        self.imports.push(ComponentImport {
            name: name.into(),
            type_index,
        });
        self
    }

    /// Add a canonical lift wrapping a core function into a component function.
    pub fn add_canon_lift(&mut self, lift: CanonLift) -> &mut Self {
        self.canonical_lifts.push(lift);
        self
    }

    /// Add a component export.
    pub fn add_export(&mut self, name: impl Into<String>, sort: u8, index: u32) -> &mut Self {
        self.exports.push(ComponentExport {
            name: name.into(),
            sort,
            index,
        });
        self
    }

    /// Add custom metadata section.
    pub fn add_custom_section(&mut self, name: impl Into<String>, payload: Vec<u8>) -> &mut Self {
        self.custom_sections.push((name.into(), payload));
        self
    }

    /// Serialize the WebAssembly Component into binary format.
    pub fn finish(&self) -> Result<Vec<u8>, ComponentError> {
        let mut out = Vec::new();

        // 1. Component Header: \0asm [0x0d, 0x00, 0x01, 0x00]
        out.extend_from_slice(&WASM_COMPONENT_MAGIC);
        out.extend_from_slice(&WASM_COMPONENT_VERSION);

        // 2. Custom sections (e.g. metadata or producers)
        for (name, payload) in &self.custom_sections {
            let mut sec_buf = Vec::new();
            encode_leb128_u32(&mut sec_buf, name.len() as u32);
            sec_buf.extend_from_slice(name.as_bytes());
            sec_buf.extend_from_slice(payload);
            write_section(&mut out, ComponentSectionId::Custom, &sec_buf);
        }

        // 3. Core Modules (Section 1)
        for core in &self.core_modules {
            write_section(&mut out, ComponentSectionId::CoreModule, core);
        }

        // 4. Canonical Lifts (Section 8: Component Canonical)
        if !self.canonical_lifts.is_empty() {
            let mut sec_buf = Vec::new();
            encode_leb128_u32(&mut sec_buf, self.canonical_lifts.len() as u32);
            for lift in &self.canonical_lifts {
                // 0x00 = canon lift
                sec_buf.push(0x00);
                // flags: bit 0 = string_encoding, bit 1 = memory, bit 2 = realloc
                let mut flags = lift.string_encoding as u8;
                if lift.memory_index.is_some() {
                    flags |= 0x04;
                }
                if lift.realloc_index.is_some() {
                    flags |= 0x08;
                }
                sec_buf.push(flags);

                encode_leb128_u32(&mut sec_buf, lift.core_func_index);
                encode_leb128_u32(&mut sec_buf, lift.type_index);
                if let Some(mem) = lift.memory_index {
                    encode_leb128_u32(&mut sec_buf, mem);
                }
                if let Some(realloc) = lift.realloc_index {
                    encode_leb128_u32(&mut sec_buf, realloc);
                }
            }
            write_section(&mut out, ComponentSectionId::ComponentCanonical, &sec_buf);
        }

        // 5. Component Imports (Section 10)
        if !self.imports.is_empty() {
            let mut sec_buf = Vec::new();
            encode_leb128_u32(&mut sec_buf, self.imports.len() as u32);
            for imp in &self.imports {
                encode_leb128_u32(&mut sec_buf, imp.name.len() as u32);
                sec_buf.extend_from_slice(imp.name.as_bytes());
                // Import target sort: 0x03 = type
                sec_buf.push(0x03);
                encode_leb128_u32(&mut sec_buf, imp.type_index);
            }
            write_section(&mut out, ComponentSectionId::ComponentImport, &sec_buf);
        }

        // 6. Component Exports (Section 11)
        if !self.exports.is_empty() {
            let mut sec_buf = Vec::new();
            encode_leb128_u32(&mut sec_buf, self.exports.len() as u32);
            for exp in &self.exports {
                encode_leb128_u32(&mut sec_buf, exp.name.len() as u32);
                sec_buf.extend_from_slice(exp.name.as_bytes());
                sec_buf.push(exp.sort);
                encode_leb128_u32(&mut sec_buf, exp.index);
            }
            write_section(&mut out, ComponentSectionId::ComponentExport, &sec_buf);
        }

        Ok(out)
    }
}

/// Inspector and validator for WebAssembly Components.
pub struct ComponentInspector<'a> {
    bytes: &'a [u8],
}

impl<'a> ComponentInspector<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Verify binary header and parse all section headers.
    pub fn inspect(&self) -> Result<Vec<ComponentSectionHeader>, ComponentError> {
        if self.bytes.len() < 8 {
            return Err(ComponentError::TooSmall);
        }

        if self.bytes[0..4] != WASM_COMPONENT_MAGIC {
            return Err(ComponentError::InvalidMagic);
        }

        if self.bytes[4..8] != WASM_COMPONENT_VERSION {
            return Err(ComponentError::InvalidVersion);
        }

        let mut offset = 8;
        let mut sections = Vec::new();

        while offset < self.bytes.len() {
            let sec_start = offset;
            let sec_id_byte = self.bytes[offset];
            offset += 1;

            let sec_id = ComponentSectionId::from_u8(sec_id_byte).ok_or_else(|| {
                ComponentError::MalformedSection(
                    sec_start,
                    format!("Unknown component section ID: {}", sec_id_byte),
                )
            })?;

            let (sec_len, leb_bytes) = read_leb128_u32(&self.bytes[offset..]).map_err(|e| {
                ComponentError::MalformedSection(
                    offset,
                    format!("Invalid section length LEB128: {}", e),
                )
            })?;
            offset += leb_bytes;

            let payload_offset = offset;
            let payload_size = sec_len as usize;

            if payload_offset + payload_size > self.bytes.len() {
                return Err(ComponentError::MalformedSection(
                    payload_offset,
                    "Component section payload extends beyond EOF".to_string(),
                ));
            }

            offset += payload_size;

            sections.push(ComponentSectionHeader {
                id: sec_id,
                offset: sec_start,
                payload_offset,
                payload_size,
            });
        }

        Ok(sections)
    }

    /// Extract embedded core modules.
    pub fn extract_core_modules(&self) -> Result<Vec<&'a [u8]>, ComponentError> {
        let sections = self.inspect()?;
        let mut modules = Vec::new();
        for sec in sections {
            if sec.id == ComponentSectionId::CoreModule {
                let bytes = &self.bytes[sec.payload_offset..sec.payload_offset + sec.payload_size];
                modules.push(bytes);
            }
        }
        Ok(modules)
    }
}

fn write_section(out: &mut Vec<u8>, id: ComponentSectionId, payload: &[u8]) {
    out.push(id as u8);
    encode_leb128_u32(out, payload.len() as u32);
    out.extend_from_slice(payload);
}

fn encode_leb128_u32(out: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
}

fn read_leb128_u32(slice: &[u8]) -> Result<(u32, usize), &'static str> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &byte in slice {
        bytes_read += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, bytes_read));
        }
        shift += 7;
        if shift >= 35 {
            return Err("LEB128 integer overflow");
        }
    }
    Err("Unexpected end of LEB128 slice")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_binary_generation_and_inspection() {
        let dummy_core_module = vec![
            0x00, 0x61, 0x73, 0x6D, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ];

        let mut builder = ComponentBuilder::new();
        builder.add_core_module(dummy_core_module.clone());
        builder.add_import("wasi:cli/stdout@0.2.0", 0);
        builder.add_canon_lift(CanonLift {
            core_func_index: 0,
            type_index: 1,
            memory_index: Some(0),
            realloc_index: Some(1),
            string_encoding: StringEncoding::Utf8,
        });
        builder.add_export("greet", 0x01, 0);

        let component_bytes = builder.finish().expect("Failed to build component");

        // Verify Header
        assert_eq!(&component_bytes[0..4], &WASM_COMPONENT_MAGIC);
        assert_eq!(&component_bytes[4..8], &WASM_COMPONENT_VERSION);

        // Inspect Sections
        let inspector = ComponentInspector::new(&component_bytes);
        let sections = inspector.inspect().expect("Failed to inspect component");

        assert_eq!(sections.len(), 4);
        assert_eq!(sections[0].id, ComponentSectionId::CoreModule);
        assert_eq!(sections[1].id, ComponentSectionId::ComponentCanonical);
        assert_eq!(sections[2].id, ComponentSectionId::ComponentImport);
        assert_eq!(sections[3].id, ComponentSectionId::ComponentExport);

        // Extract core module
        let modules = inspector.extract_core_modules().expect("Failed to extract");
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0], &dummy_core_module);
    }
}
