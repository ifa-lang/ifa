pub mod bindings;
pub mod bundler;
pub mod component;
pub mod runner;
pub mod runtime;
pub mod validator;
pub mod wit;

pub use bindings::{TypeScriptBindingsGenerator, WasmExportFunction, WasmType};
pub use bundler::{WasmBundleResult, WasmBundler};
pub use component::{
    CanonLift, ComponentBuilder, ComponentError, ComponentExport, ComponentImport,
    ComponentInspector, ComponentSectionHeader, ComponentSectionId, StringEncoding,
    WASM_COMPONENT_MAGIC, WASM_COMPONENT_VERSION,
};
pub use runner::{WasmEngine, WasmEngineRunner, WasmExecutionResult, WasmRunnerError};
pub use runtime::{WasiHostEnvironment, WasmFunctionTable, WasmLinearMemory, WASM_PAGE_SIZE};
pub use validator::{
    WasmElementSegment, WasmExport, WasmFuncType, WasmModuleInspector, WasmSection, WasmTableDef,
    WasmValidationError,
};
pub use wit::{
    WitField, WitFunction, WitInterface, WitPackage, WitPackageId, WitType, WitVariantCase,
    WitWorld, WitWorldItem,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_linear_memory_allocation() {
        let mut mem = WasmLinearMemory::new(1, 10);
        assert_eq!(mem.page_count(), 1);

        let (ptr, len) = mem.write_str("Hello IFA WebAssembly!");
        let read_back = mem.read_str(ptr, len).unwrap();
        assert_eq!(read_back, "Hello IFA WebAssembly!");

        // Deallocate and reuse same size class
        mem.dealloc(ptr, len + 1);
        let ptr2 = mem.alloc(len + 1);
        assert_eq!(ptr, ptr2);
    }

    #[test]
    fn test_wasi_fd_write_simulation() {
        let mut mem = WasmLinearMemory::new(1, 4);
        let mut host = WasiHostEnvironment::new();

        // Write message to memory at offset 2000
        let msg = b"Testing WASI stdout buffer";
        mem.write_bytes(2000, msg).unwrap();

        // Setup iovec struct at offset 3000: [ptr: u32, len: u32]
        let mut iovec = Vec::new();
        iovec.extend_from_slice(&(2000u32).to_le_bytes());
        iovec.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        mem.write_bytes(3000, &iovec).unwrap();

        // Call fd_write (fd = 1 for stdout)
        let nwritten_ptr = 4000;
        let ret = host.fd_write(&mut mem, 1, 3000, 1, nwritten_ptr);
        assert_eq!(ret, 0);

        let nwritten =
            u32::from_le_bytes(mem.read_bytes(nwritten_ptr, 4).unwrap().try_into().unwrap());
        assert_eq!(nwritten as usize, msg.len());
        assert_eq!(host.stdout_buffer, msg);
    }

    #[test]
    fn test_wasm_binary_inspection() {
        // Construct minimal valid WebAssembly binary: \0asm, version 1
        let mut wasm_bytes = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // Add export section: ID 7, length 7
        // 1 export: name "add", kind 0 (func), index 0
        wasm_bytes.extend_from_slice(&[
            0x07, // Section ID: Export
            0x07, // Section size: 7 bytes (1 + 4 + 1 + 1)
            0x01, // 1 export entry
            0x03, b'a', b'd', b'd', // name "add" (length 3)
            0x00, // Export kind: function
            0x00, // Function index: 0
        ]);

        let inspector = WasmModuleInspector::new(&wasm_bytes);
        let sections = inspector.inspect().unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].name, "export");

        let exports = inspector.extract_exports().unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "add");
        assert_eq!(exports[0].kind, 0);
        assert_eq!(exports[0].index, 0);
    }

    #[test]
    fn test_typescript_bindings_generation() {
        let mut gen = TypeScriptBindingsGenerator::new("math_engine");
        gen.add_function(WasmExportFunction {
            name: "add".to_string(),
            params: vec![
                ("a".to_string(), WasmType::I32),
                ("b".to_string(), WasmType::I32),
            ],
            ret_ty: WasmType::I32,
            doc: Some("Adds two 32-bit integers deterministically.".to_string()),
        });
        gen.add_function(WasmExportFunction {
            name: "format_message".to_string(),
            params: vec![("name".to_string(), WasmType::String)],
            ret_ty: WasmType::String,
            doc: Some("Format greeting message.".to_string()),
        });

        let dts = gen.generate_dts();
        assert!(dts.contains("add(a: number, b: number): number;"));
        assert!(dts.contains("format_message(name: string): string;"));
        assert!(dts.contains("export declare function init"));

        let esm = gen.generate_esm();
        assert!(esm.contains("export async function init"));
        assert!(esm.contains("export function add(a, b)"));
        assert!(esm.contains("export function format_message(name)"));
        assert!(esm.contains("textEncoder.encode(name)"));
    }

    #[test]
    fn test_wasm_bundler() {
        let wasm_bytes = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let bundler =
            WasmBundler::new("ifa_core", wasm_bytes).with_functions(vec![WasmExportFunction {
                name: "compute".to_string(),
                params: vec![("x".to_string(), WasmType::I32)],
                ret_ty: WasmType::I32,
                doc: None,
            }]);

        let tmp_dir = std::env::temp_dir().join("ifa_wasm_test_bundle");
        let result = bundler.bundle(&tmp_dir).unwrap();

        assert!(result.wasm_file.exists());
        assert!(result.js_file.exists());
        assert!(result.dts_file.exists());
        assert!(result.react_file.exists());
        assert!(result.react_dts_file.exists());
        assert!(result.web_os_file.exists());
        assert!(result.web_os_dts_file.exists());
        assert!(result.package_json_file.exists());

        let react_js = std::fs::read_to_string(&result.react_file).unwrap();
        assert!(react_js.contains("export function useIfaModule"));

        let web_os_js = std::fs::read_to_string(&result.web_os_file).unwrap();
        assert!(web_os_js.contains("export class WebOsProcess"));

        let pkg = std::fs::read_to_string(&result.package_json_file).unwrap();
        assert!(pkg.contains("\"./react\""));
        assert!(pkg.contains("\"./web-os\""));

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_wasm_function_table_and_indirect_dispatch() {
        let mut table = WasmFunctionTable::new(4, Some(16));
        assert_eq!(table.len(), 4);
        assert_eq!(table.get(0), None);

        // Load elements into table slots
        table.load_elements(1, &[101, 102, 103]).unwrap();
        assert_eq!(table.get(0), None);
        assert_eq!(table.get(1), Some(101));
        assert_eq!(table.get(2), Some(102));
        assert_eq!(table.get(3), Some(103));

        // Grow table dynamically
        table.set(5, 105).unwrap();
        assert_eq!(table.len(), 6);
        assert_eq!(table.get(5), Some(105));

        // Host environment indirect dispatch
        let mut host = WasiHostEnvironment::new();
        host.table = table;
        let dispatched = host.dispatch_indirect(2, &[]).unwrap();
        assert_eq!(dispatched, Some(102));

        // Uninitialized slot returns error
        let err = host.dispatch_indirect(0, &[]);
        assert!(err.is_err());
    }

    #[test]
    fn test_wasm_table_and_element_inspection() {
        // Construct minimal WebAssembly binary with Table (ID 4) and Element (ID 9)
        let mut wasm_bytes = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

        // 1. Table section (ID 4): 1 table, funcref (0x70), min=5, max=10
        // Payload: 1 table, 0x70, flag=1 (min and max), min=5, max=10
        let table_payload = vec![0x01, 0x70, 0x01, 0x05, 0x0A];
        wasm_bytes.push(0x04);
        wasm_bytes.push(table_payload.len() as u8);
        wasm_bytes.extend_from_slice(&table_payload);

        // 2. Element section (ID 9): 1 active segment on table 0 at offset 2, 2 func indices [7, 8]
        // Payload: 1 segment, kind=0 (table 0 active), 0x41, 0x02, 0x0B (offset expr), 2 funcs, 7, 8
        let elem_payload = vec![0x01, 0x00, 0x41, 0x02, 0x0B, 0x02, 0x07, 0x08];
        wasm_bytes.push(0x09);
        wasm_bytes.push(elem_payload.len() as u8);
        wasm_bytes.extend_from_slice(&elem_payload);

        // 3. Code section (ID 10): containing call_indirect (0x11)
        let code_payload = vec![0x01, 0x04, 0x00, 0x11, 0x00, 0x0B];
        wasm_bytes.push(0x0A);
        wasm_bytes.push(code_payload.len() as u8);
        wasm_bytes.extend_from_slice(&code_payload);

        let inspector = WasmModuleInspector::new(&wasm_bytes);
        let tables = inspector.extract_tables().unwrap();
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].elem_type, 0x70);
        assert_eq!(tables[0].min_size, 5);
        assert_eq!(tables[0].max_size, Some(10));

        let elements = inspector.extract_elements().unwrap();
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].table_index, 0);
        assert_eq!(elements[0].offset, 2);
        assert_eq!(elements[0].func_indices, vec![7, 8]);

        let has_indirect = inspector.has_indirect_calls().unwrap();
        assert!(
            has_indirect,
            "Expected call_indirect opcode 0x11 to be detected"
        );
    }

    #[test]
    fn test_typescript_bindings_higher_order_callback() {
        let mut gen = TypeScriptBindingsGenerator::new("hof_engine");
        gen.add_function(WasmExportFunction {
            name: "apply".to_string(),
            params: vec![
                (
                    "callback".to_string(),
                    WasmType::Function(vec![WasmType::I64], Box::new(WasmType::I64)),
                ),
                ("val".to_string(), WasmType::I64),
            ],
            ret_ty: WasmType::I64,
            doc: Some("Higher-order function applying callback to value.".to_string()),
        });

        let dts = gen.generate_dts();
        assert!(dts.contains("callback: (arg0: bigint) => bigint"));
        assert!(dts.contains("val: bigint"));
    }

    #[test]
    fn test_wasm_typed_array_slices_and_tensor_bindings() {
        let mut gen = TypeScriptBindingsGenerator::new("tensor_engine");
        gen.add_function(WasmExportFunction {
            name: "matrix_vector_mult".to_string(),
            params: vec![
                ("matrix".to_string(), WasmType::SliceF64),
                ("vector".to_string(), WasmType::SliceF64),
                ("out".to_string(), WasmType::SliceF64),
                ("dim".to_string(), WasmType::I32),
            ],
            ret_ty: WasmType::SliceF64,
            doc: Some("Compute matrix-vector multiplication returning result vector".to_string()),
        });

        let dts = gen.generate_dts();
        assert!(dts.contains("matrix: Float64Array"));
        assert!(dts.contains("vector: Float64Array"));
        assert!(dts.contains("out: Float64Array"));
        assert!(dts.contains("dim: number"));
        assert!(dts.contains("): Float64Array"));

        let esm = gen.generate_esm();
        assert!(esm.contains("const matrixBytes = new Uint8Array(matrix.buffer, matrix.byteOffset, matrix.byteLength)"));
        assert!(esm.contains("const matrixPtr = wasmInstance.exports.ifa_alloc ? wasmInstance.exports.ifa_alloc(matrixBytes.length) : 0"));
        assert!(esm.contains("matrixPtr, matrix.length"));
        assert!(esm.contains("new Float64Array(wasmInstance.exports.memory.buffer.slice(retPtr, retPtr + retLen * 8))"));
    }

    #[test]
    fn test_web_os_sandbox_memory_and_slice_views() {
        let gen = TypeScriptBindingsGenerator::new("web_os_sandbox_test");
        let web_os_js = gen.generate_web_os_js();
        assert!(web_os_js.contains("getMemoryBuffer()"));
        assert!(web_os_js.contains("getMemoryView(offset, length)"));
        assert!(web_os_js.contains("getSliceView(offset, length, type = 'u8')"));
        assert!(web_os_js.contains("case 'i64': return new BigInt64Array(buf, offset, length)"));
        assert!(web_os_js.contains("case 'f64': return new Float64Array(buf, offset, length)"));

        let web_os_dts = gen.generate_web_os_dts();
        assert!(web_os_dts.contains("getMemoryBuffer(): ArrayBuffer | null"));
        assert!(
            web_os_dts.contains("getMemoryView(offset: number, length: number): Uint8Array | null")
        );
        assert!(web_os_dts.contains("getSliceView(offset: number, length: number, type?: 'u8' | 'i32' | 'i64' | 'f64'): ArrayBufferView | null"));
    }

    #[test]
    fn test_bundler_from_fir_module_inference() {
        use ifa_fir::{BasicBlock, BlockId, FirFunction, FirModule, FirParam, FirType, ParamMode};
        use ifa_sema::types::IntType;
        use ifa_span::{Span, INTERNER};

        let mut func = FirFunction::new(
            INTERNER.intern("gemm_kernel"),
            vec![
                FirParam::new(
                    INTERNER.intern("a"),
                    ifa_fir::ValueId(0),
                    FirType::Slice(Box::new(FirType::Int(IntType::I64))),
                    ParamMode::In,
                ),
                FirParam::new(
                    INTERNER.intern("dim"),
                    ifa_fir::ValueId(1),
                    FirType::Int(IntType::I64),
                    ParamMode::In,
                ),
            ],
            FirType::Int(IntType::I64),
            true, // is_strict
            true, // is_pub
            false,
            None,
            Span::DUMMY,
        );
        let mut bb = BasicBlock::new(BlockId(0));
        bb.terminator = Some(ifa_fir::Terminator::Return(Some(ifa_fir::ValueId(1))));
        func.blocks.push(bb);

        let fir_module = FirModule {
            name: INTERNER.intern("gemm_wasm_mod"),
            functions: vec![func],
            structs: Vec::new(),
            enums: Vec::new(),
            constants: Vec::new(),
        };

        let bundler = WasmBundler::from_fir_module(
            "gemm_pkg",
            vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00],
            &fir_module,
        );
        assert_eq!(bundler.functions().len(), 1);
        assert_eq!(bundler.functions()[0].name, "gemm_kernel");
        assert_eq!(bundler.functions()[0].params[0].1, WasmType::SliceI64);
        assert_eq!(bundler.functions()[0].params[1].1, WasmType::I64);
        assert_eq!(bundler.functions()[0].ret_ty, WasmType::I64);
    }
}
