use serde::{Deserialize, Serialize};

/// Data type mapping for WebAssembly exported functions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmType {
    I32,
    I64,
    F32,
    F64,
    Bool,
    String,
    Void,
}

impl WasmType {
    pub fn to_typescript(&self) -> &'static str {
        match self {
            WasmType::I32 | WasmType::F32 | WasmType::F64 => "number",
            WasmType::I64 => "bigint",
            WasmType::Bool => "boolean",
            WasmType::String => "string",
            WasmType::Void => "void",
        }
    }
}

/// Description of an exported WebAssembly function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmExportFunction {
    pub name: String,
    pub params: Vec<(String, WasmType)>,
    pub ret_ty: WasmType,
    pub doc: Option<String>,
}

/// Generator for modern TypeScript declarations and ES Module wrappers.
pub struct TypeScriptBindingsGenerator {
    module_name: String,
    exports: Vec<WasmExportFunction>,
}

impl TypeScriptBindingsGenerator {
    pub fn new(module_name: impl Into<String>) -> Self {
        Self {
            module_name: module_name.into(),
            exports: Vec::new(),
        }
    }

    pub fn add_function(&mut self, func: WasmExportFunction) {
        self.exports.push(func);
    }

    /// Generate complete TypeScript declaration file (`index.d.ts`).
    pub fn generate_dts(&self) -> String {
        let mut dts = String::new();
        dts.push_str("// IFA WebAssembly Type Definitions\n");
        dts.push_str("// Generated automatically by the IFA WebAssembly toolchain\n\n");

        dts.push_str("export interface IfaWasmInstance {\n");
        for func in &self.exports {
            if let Some(doc) = &func.doc {
                dts.push_str(&format!("  /** {} */\n", doc));
            }
            let params = func
                .params
                .iter()
                .map(|(name, ty)| format!("{}: {}", name, ty.to_typescript()))
                .collect::<Vec<_>>()
                .join(", ");
            dts.push_str(&format!(
                "  {}({}): {};\n",
                func.name,
                params,
                func.ret_ty.to_typescript()
            ));
        }
        dts.push_str("}\n\n");

        dts.push_str("/** Initialize and load the WebAssembly module in browser or Node.js */\n");
        dts.push_str("export declare function init(input?: RequestInfo | BufferSource | WebAssembly.Module): Promise<IfaWasmInstance>;\n\n");

        for func in &self.exports {
            let params = func
                .params
                .iter()
                .map(|(name, ty)| format!("{}: {}", name, ty.to_typescript()))
                .collect::<Vec<_>>()
                .join(", ");
            dts.push_str(&format!(
                "export declare function {}({}): {};\n",
                func.name,
                params,
                func.ret_ty.to_typescript()
            ));
        }

        dts
    }

    /// Generate JavaScript ES Module wrapper (`index.js`).
    pub fn generate_esm(&self) -> String {
        let mut js = String::new();
        js.push_str("// IFA WebAssembly ES Module Runtime Wrapper\n");
        js.push_str("let wasmInstance = null;\n");
        js.push_str("const textEncoder = new TextEncoder();\n");
        js.push_str("const textDecoder = new TextDecoder();\n\n");

        js.push_str("export async function init(input) {\n");
        js.push_str("  if (wasmInstance) return wasmInstance.exports;\n");
        js.push_str("  let module;\n");
        js.push_str("  if (!input) {\n");
        js.push_str("    if (typeof fetch === 'function' && typeof window !== 'undefined') {\n");
        js.push_str(&format!(
            "      input = await fetch('{}.wasm');\n",
            self.module_name
        ));
        js.push_str("    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {\n");
        js.push_str("      const fs = await import('node:fs');\n");
        js.push_str("      const path = await import('node:path');\n");
        js.push_str(&format!("      input = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '{}.wasm'));\n", self.module_name));
        js.push_str("    }\n");
        js.push_str("  }\n");
        js.push_str("  if (typeof Response !== 'undefined' && input instanceof Response) {\n");
        js.push_str("    const result = await WebAssembly.instantiateStreaming(input, { wasi_snapshot_preview1: createWasiStubs() });\n");
        js.push_str("    wasmInstance = result.instance;\n");
        js.push_str("  } else {\n");
        js.push_str("    const bytes = input instanceof ArrayBuffer ? input : await input;\n");
        js.push_str("    const result = await WebAssembly.instantiate(bytes, { wasi_snapshot_preview1: createWasiStubs() });\n");
        js.push_str("    wasmInstance = result.instance;\n");
        js.push_str("  }\n");
        js.push_str("  return wasmInstance.exports;\n");
        js.push_str("}\n\n");

        js.push_str("function createWasiStubs() {\n");
        js.push_str("  return {\n");
        js.push_str("    fd_write: (fd, iovs, iovs_len, nwritten) => 0,\n");
        js.push_str(
            "    proc_exit: (code) => { console.warn(`IFA Wasm exited with code ${code}`); },\n",
        );
        js.push_str("    clock_time_get: () => 0,\n");
        js.push_str("    random_get: (buf, len) => 0\n");
        js.push_str("  };\n");
        js.push_str("}\n\n");

        for func in &self.exports {
            let has_string_param = func.params.iter().any(|(_, t)| *t == WasmType::String);
            let returns_string = func.ret_ty == WasmType::String;
            let param_names = func
                .params
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            js.push_str(&format!(
                "export function {}({}) {{\n",
                func.name, param_names
            ));
            js.push_str("  if (!wasmInstance) throw new Error(\"IFA Wasm module not initialized. Call 'await init()' first.\");\n");

            if !has_string_param && !returns_string {
                js.push_str(&format!(
                    "  return wasmInstance.exports.{}({});\n",
                    func.name, param_names
                ));
            } else {
                // String marshalling logic
                for (p_name, p_ty) in &func.params {
                    if *p_ty == WasmType::String {
                        js.push_str(&format!(
                            "  const {}Encoded = textEncoder.encode({});\n",
                            p_name, p_name
                        ));
                        js.push_str(&format!(
                            "  const {}Ptr = wasmInstance.exports.ifa_alloc({}Encoded.length);\n",
                            p_name, p_name
                        ));
                        js.push_str(&format!("  new Uint8Array(wasmInstance.exports.memory.buffer, {}Ptr, {}Encoded.length).set({}Encoded);\n", p_name, p_name, p_name));
                    }
                }
                let call_args = func
                    .params
                    .iter()
                    .map(|(p_name, p_ty)| {
                        if *p_ty == WasmType::String {
                            format!("{}Ptr, {}Encoded.length", p_name, p_name)
                        } else {
                            p_name.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                if returns_string {
                    js.push_str(&format!(
                        "  const retPtr = wasmInstance.exports.{}({});\n",
                        func.name, call_args
                    ));
                    js.push_str("  const retLen = wasmInstance.exports.ifa_str_len(retPtr);\n");
                    js.push_str("  return textDecoder.decode(new Uint8Array(wasmInstance.exports.memory.buffer, retPtr, retLen));\n");
                } else {
                    js.push_str(&format!(
                        "  return wasmInstance.exports.{}({});\n",
                        func.name, call_args
                    ));
                }
            }
            js.push_str("}\n\n");
        }

        js
    }
}
