pub mod bindings;
pub mod bundler;
pub mod runner;
pub mod runtime;
pub mod validator;

pub use bindings::{TypeScriptBindingsGenerator, WasmExportFunction, WasmType};
pub use bundler::{WasmBundleResult, WasmBundler};
pub use runner::{WasmEngine, WasmEngineRunner, WasmExecutionResult, WasmRunnerError};
pub use runtime::{WasiHostEnvironment, WasmLinearMemory, WASM_PAGE_SIZE};
pub use validator::{WasmExport, WasmModuleInspector, WasmSection, WasmValidationError};

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
        assert!(result.package_json_file.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
