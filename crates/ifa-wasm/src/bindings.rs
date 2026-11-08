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
    SliceI64,
    SliceF64,
    SliceU8,
    SliceI32,
    Function(Vec<WasmType>, Box<WasmType>),
}

impl WasmType {
    pub fn is_slice(&self) -> bool {
        matches!(
            self,
            WasmType::SliceI64 | WasmType::SliceF64 | WasmType::SliceU8 | WasmType::SliceI32
        )
    }

    pub fn typed_array_constructor(&self) -> &'static str {
        match self {
            WasmType::SliceI64 => "BigInt64Array",
            WasmType::SliceF64 => "Float64Array",
            WasmType::SliceU8 => "Uint8Array",
            WasmType::SliceI32 => "Int32Array",
            _ => "Uint8Array",
        }
    }

    pub fn slice_elem_size(&self) -> usize {
        match self {
            WasmType::SliceI64 | WasmType::SliceF64 => 8,
            WasmType::SliceI32 => 4,
            WasmType::SliceU8 => 1,
            _ => 1,
        }
    }

    pub fn to_typescript(&self) -> String {
        match self {
            WasmType::I32 | WasmType::F32 | WasmType::F64 => "number".to_string(),
            WasmType::I64 => "bigint".to_string(),
            WasmType::Bool => "boolean".to_string(),
            WasmType::String => "string".to_string(),
            WasmType::Void => "void".to_string(),
            WasmType::SliceI64 => "BigInt64Array".to_string(),
            WasmType::SliceF64 => "Float64Array".to_string(),
            WasmType::SliceU8 => "Uint8Array".to_string(),
            WasmType::SliceI32 => "Int32Array".to_string(),
            WasmType::Function(params, ret) => {
                let p_str = params
                    .iter()
                    .enumerate()
                    .map(|(i, p)| format!("arg{}: {}", i, p.to_typescript()))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("({}) => {}", p_str, ret.to_typescript())
            }
        }
    }

    pub fn from_fir_type(ty: &ifa_fir::FirType) -> Self {
        use ifa_sema::types::{FloatType, IntType};
        match ty {
            ifa_fir::FirType::Int(IntType::I64 | IntType::U64) => WasmType::I64,
            ifa_fir::FirType::Int(_) => WasmType::I32,
            ifa_fir::FirType::Float(FloatType::F64) => WasmType::F64,
            ifa_fir::FirType::Float(FloatType::F32) => WasmType::F32,
            ifa_fir::FirType::Bool => WasmType::Bool,
            ifa_fir::FirType::String | ifa_fir::FirType::Str => WasmType::String,
            ifa_fir::FirType::Unit => WasmType::Void,
            ifa_fir::FirType::Slice(inner) => match inner.as_ref() {
                ifa_fir::FirType::Int(IntType::I64 | IntType::U64) => WasmType::SliceI64,
                ifa_fir::FirType::Float(FloatType::F64) => WasmType::SliceF64,
                ifa_fir::FirType::Int(IntType::I32 | IntType::U32) => WasmType::SliceI32,
                _ => WasmType::SliceU8,
            },
            ifa_fir::FirType::Array(inner, _) => match inner.as_ref() {
                ifa_fir::FirType::Int(IntType::I64 | IntType::U64) => WasmType::SliceI64,
                ifa_fir::FirType::Float(FloatType::F64) => WasmType::SliceF64,
                ifa_fir::FirType::Int(IntType::I32 | IntType::U32) => WasmType::SliceI32,
                _ => WasmType::SliceU8,
            },
            ifa_fir::FirType::Function { params, ret } => {
                let p = params.iter().map(Self::from_fir_type).collect();
                let r = Box::new(Self::from_fir_type(ret));
                WasmType::Function(p, r)
            }
            _ => WasmType::I32,
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
        js.push_str("    fd_write: (fd, iovs, iovs_len, nwritten) => {\n");
        js.push_str("      if (!wasmInstance) return 0;\n");
        js.push_str("      const mem = new DataView(wasmInstance.exports.memory.buffer);\n");
        js.push_str("      let written = 0;\n");
        js.push_str("      let text = '';\n");
        js.push_str("      for (let i = 0; i < iovs_len; i++) {\n");
        js.push_str("        const ptr = mem.getUint32(iovs + i * 8, true);\n");
        js.push_str("        const len = mem.getUint32(iovs + i * 8 + 4, true);\n");
        js.push_str(
            "        const bytes = new Uint8Array(wasmInstance.exports.memory.buffer, ptr, len);\n",
        );
        js.push_str("        text += textDecoder.decode(bytes);\n");
        js.push_str("        written += len;\n");
        js.push_str("      }\n");
        js.push_str("      if (nwritten) {\n");
        js.push_str("        mem.setUint32(nwritten, written, true);\n");
        js.push_str("      }\n");
        js.push_str("      if (fd === 1) {\n");
        js.push_str("        console.log(text.endsWith('\\n') ? text.slice(0, -1) : text);\n");
        js.push_str("      } else if (fd === 2) {\n");
        js.push_str("        console.error(text.endsWith('\\n') ? text.slice(0, -1) : text);\n");
        js.push_str("      }\n");
        js.push_str("      return 0;\n");
        js.push_str("    },\n");
        js.push_str("    proc_exit: (code) => {\n");
        js.push_str("      console.warn(`[IFA WASI] Process exited with code ${code}`);\n");
        js.push_str("    },\n");
        js.push_str("    clock_time_get: (_clock_id, _precision, time_ptr) => {\n");
        js.push_str("      if (!wasmInstance) return 0;\n");
        js.push_str("      const mem = new DataView(wasmInstance.exports.memory.buffer);\n");
        js.push_str("      const nowNanos = BigInt(Date.now()) * 1000000n;\n");
        js.push_str("      mem.setBigUint64(time_ptr, nowNanos, true);\n");
        js.push_str("      return 0;\n");
        js.push_str("    },\n");
        js.push_str("    random_get: (buf, len) => {\n");
        js.push_str("      if (!wasmInstance) return 0;\n");
        js.push_str(
            "      const slice = new Uint8Array(wasmInstance.exports.memory.buffer, buf, len);\n",
        );
        js.push_str("      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {\n");
        js.push_str("        crypto.getRandomValues(slice);\n");
        js.push_str("      }\n");
        js.push_str("      return 0;\n");
        js.push_str("    }\n");
        js.push_str("  };\n");
        js.push_str("}\n\n");

        for func in &self.exports {
            let has_string_param = func.params.iter().any(|(_, t)| *t == WasmType::String);
            let returns_string = func.ret_ty == WasmType::String;
            let has_slice_param = func.params.iter().any(|(_, t)| t.is_slice());
            let returns_slice = func.ret_ty.is_slice();
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

            if !has_string_param && !returns_string && !has_slice_param && !returns_slice {
                js.push_str(&format!(
                    "  return wasmInstance.exports.{}({});\n",
                    func.name, param_names
                ));
            } else {
                // Parameter marshalling logic
                for (p_name, p_ty) in &func.params {
                    if *p_ty == WasmType::String {
                        js.push_str(&format!(
                            "  const {}Encoded = textEncoder.encode({});\n",
                            p_name, p_name
                        ));
                        js.push_str(&format!(
                            "  const {}Ptr = wasmInstance.exports.ifa_alloc ? wasmInstance.exports.ifa_alloc({}Encoded.length) : 0;\n",
                            p_name, p_name
                        ));
                        js.push_str(&format!("  new Uint8Array(wasmInstance.exports.memory.buffer, {}Ptr, {}Encoded.length).set({}Encoded);\n", p_name, p_name, p_name));
                    } else if p_ty.is_slice() {
                        js.push_str(&format!(
                            "  const {}Bytes = new Uint8Array({}.buffer, {}.byteOffset, {}.byteLength);\n",
                            p_name, p_name, p_name, p_name
                        ));
                        js.push_str(&format!(
                            "  const {}Ptr = wasmInstance.exports.ifa_alloc ? wasmInstance.exports.ifa_alloc({}Bytes.length) : 0;\n",
                            p_name, p_name
                        ));
                        js.push_str(&format!(
                            "  new Uint8Array(wasmInstance.exports.memory.buffer, {}Ptr, {}Bytes.length).set({}Bytes);\n",
                            p_name, p_name, p_name
                        ));
                    }
                }
                let call_args = func
                    .params
                    .iter()
                    .map(|(p_name, p_ty)| {
                        if *p_ty == WasmType::String {
                            format!("{}Ptr, {}Encoded.length", p_name, p_name)
                        } else if p_ty.is_slice() {
                            format!("{}Ptr, {}.length", p_name, p_name)
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
                    js.push_str("  const retLen = wasmInstance.exports.ifa_str_len ? wasmInstance.exports.ifa_str_len(retPtr) : 0;\n");
                    js.push_str("  return textDecoder.decode(new Uint8Array(wasmInstance.exports.memory.buffer, retPtr, retLen));\n");
                } else if returns_slice {
                    let typed_arr = func.ret_ty.typed_array_constructor();
                    let elem_size = func.ret_ty.slice_elem_size();
                    js.push_str(&format!(
                        "  const retPtr = wasmInstance.exports.{}({});\n",
                        func.name, call_args
                    ));
                    js.push_str("  const retLen = wasmInstance.exports.ifa_slice_len ? wasmInstance.exports.ifa_slice_len(retPtr) : 0;\n");
                    js.push_str(&format!(
                        "  return new {}(wasmInstance.exports.memory.buffer.slice(retPtr, retPtr + retLen * {}));\n",
                        typed_arr, elem_size
                    ));
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

    /// Generate React Hook JavaScript code (`react.js`).
    pub fn generate_react_hook_js(&self) -> String {
        let mut js = String::new();
        js.push_str("// IFA React Hook for WebAssembly execution\n");
        js.push_str("import { useState, useEffect } from 'react';\n");
        js.push_str("import { init } from './index.js';\n\n");
        js.push_str("export function useIfaModule(wasmSource) {\n");
        js.push_str("  const [instance, setInstance] = useState(null);\n");
        js.push_str("  const [loading, setLoading] = useState(true);\n");
        js.push_str("  const [error, setError] = useState(null);\n\n");
        js.push_str("  useEffect(() => {\n");
        js.push_str("    let active = true;\n");
        js.push_str("    init(wasmSource)\n");
        js.push_str("      .then((exports) => {\n");
        js.push_str("        if (active) {\n");
        js.push_str("          setInstance(exports);\n");
        js.push_str("          setLoading(false);\n");
        js.push_str("        }\n");
        js.push_str("      })\n");
        js.push_str("      .catch((err) => {\n");
        js.push_str("        if (active) {\n");
        js.push_str("          setError(err);\n");
        js.push_str("          setLoading(false);\n");
        js.push_str("        }\n");
        js.push_str("      });\n");
        js.push_str("    return () => {\n");
        js.push_str("      active = false;\n");
        js.push_str("    };\n");
        js.push_str("  }, [wasmSource]);\n\n");
        js.push_str("  return {\n");
        js.push_str("    instance,\n");
        js.push_str("    loading,\n");
        js.push_str("    error,\n");
        js.push_str("    ready: !loading && !error && !!instance,\n");
        js.push_str("  };\n");
        js.push_str("}\n");
        js
    }

    /// Generate React Hook TypeScript definitions (`react.d.ts`).
    pub fn generate_react_hook_dts(&self) -> String {
        let mut dts = String::new();
        dts.push_str("// IFA React Hook Type Definitions\n");
        dts.push_str("import type { IfaWasmInstance } from './index.js';\n\n");
        dts.push_str("export interface UseIfaModuleResult {\n");
        dts.push_str("  instance: IfaWasmInstance | null;\n");
        dts.push_str("  loading: boolean;\n");
        dts.push_str("  error: Error | null;\n");
        dts.push_str("  ready: boolean;\n");
        dts.push_str("}\n\n");
        dts.push_str(
            "/** React hook to load and execute the IFA WebAssembly module asynchronously */\n",
        );
        dts.push_str("export declare function useIfaModule(wasmSource?: RequestInfo | BufferSource | WebAssembly.Module): UseIfaModuleResult;\n");
        dts
    }

    /// Generate Web OS Process Sandbox runner (`web_os.js`).
    pub fn generate_web_os_js(&self) -> String {
        let mut js = String::new();
        js.push_str("// IFA Web OS Process Sandbox & Isolation Runner\n");
        js.push_str("import { init } from './index.js';\n\n");
        js.push_str("export class WebOsProcess {\n");
        js.push_str("  constructor(options = {}) {\n");
        js.push_str("    this.pid = Math.floor(Math.random() * 90000) + 10000;\n");
        js.push_str("    this.name = options.name || 'ifa-process';\n");
        js.push_str("    this.env = options.env || {};\n");
        js.push_str("    this.stdoutCallbacks = [];\n");
        js.push_str("    this.stderrCallbacks = [];\n");
        js.push_str("    this.exitCode = null;\n");
        js.push_str("    this.instance = null;\n");
        js.push_str("    this.isRunning = false;\n");
        js.push_str("  }\n\n");
        js.push_str("  onStdout(callback) {\n");
        js.push_str("    this.stdoutCallbacks.push(callback);\n");
        js.push_str("    return this;\n");
        js.push_str("  }\n\n");
        js.push_str("  onStderr(callback) {\n");
        js.push_str("    this.stderrCallbacks.push(callback);\n");
        js.push_str("    return this;\n");
        js.push_str("  }\n\n");
        js.push_str("  emitStdout(text) {\n");
        js.push_str("    for (const cb of this.stdoutCallbacks) cb(text);\n");
        js.push_str("  }\n\n");
        js.push_str("  emitStderr(text) {\n");
        js.push_str("    for (const cb of this.stderrCallbacks) cb(text);\n");
        js.push_str("  }\n\n");
        js.push_str("  async spawn(wasmSource) {\n");
        js.push_str("    this.isRunning = true;\n");
        js.push_str("    try {\n");
        js.push_str("      this.instance = await init(wasmSource);\n");
        js.push_str("      if (typeof this.instance._start === 'function') {\n");
        js.push_str("        this.instance._start();\n");
        js.push_str("      } else if (typeof this.instance.main === 'function') {\n");
        js.push_str("        this.exitCode = this.instance.main();\n");
        js.push_str("      }\n");
        js.push_str("      this.isRunning = false;\n");
        js.push_str("      return this.exitCode ?? 0;\n");
        js.push_str("    } catch (err) {\n");
        js.push_str("      this.isRunning = false;\n");
        js.push_str("      this.emitStderr(String(err));\n");
        js.push_str("      throw err;\n");
        js.push_str("    }\n");
        js.push_str("  }\n\n");
        js.push_str("  kill(signal = 15) {\n");
        js.push_str("    this.isRunning = false;\n");
        js.push_str("    this.exitCode = 128 + signal;\n");
        js.push_str("    this.emitStderr(`Process ${this.pid} terminated by signal ${signal}`);\n");
        js.push_str("  }\n\n");
        js.push_str("  getMemoryBuffer() {\n");
        js.push_str("    if (!this.instance || !this.instance.memory) return null;\n");
        js.push_str("    return this.instance.memory.buffer;\n");
        js.push_str("  }\n\n");
        js.push_str("  getMemoryView(offset, length) {\n");
        js.push_str("    const buf = this.getMemoryBuffer();\n");
        js.push_str("    if (!buf) return null;\n");
        js.push_str("    return new Uint8Array(buf, offset, length);\n");
        js.push_str("  }\n\n");
        js.push_str("  getSliceView(offset, length, type = 'u8') {\n");
        js.push_str("    const buf = this.getMemoryBuffer();\n");
        js.push_str("    if (!buf) return null;\n");
        js.push_str("    switch (type) {\n");
        js.push_str("      case 'i64': return new BigInt64Array(buf, offset, length);\n");
        js.push_str("      case 'f64': return new Float64Array(buf, offset, length);\n");
        js.push_str("      case 'i32': return new Int32Array(buf, offset, length);\n");
        js.push_str("      default: return new Uint8Array(buf, offset, length);\n");
        js.push_str("    }\n");
        js.push_str("  }\n");
        js.push_str("}\n");
        js
    }

    /// Generate Web OS Process Sandbox TypeScript definitions (`web_os.d.ts`).
    pub fn generate_web_os_dts(&self) -> String {
        let mut dts = String::new();
        dts.push_str("// IFA Web OS Process Sandbox Type Definitions\n");
        dts.push_str("import type { IfaWasmInstance } from './index.js';\n\n");
        dts.push_str("export interface WebOsProcessOptions {\n");
        dts.push_str("  name?: string;\n");
        dts.push_str("  env?: Record<string, string>;\n");
        dts.push_str("}\n\n");
        dts.push_str("export declare class WebOsProcess {\n");
        dts.push_str("  pid: number;\n");
        dts.push_str("  name: string;\n");
        dts.push_str("  env: Record<string, string>;\n");
        dts.push_str("  exitCode: number | null;\n");
        dts.push_str("  instance: IfaWasmInstance | null;\n");
        dts.push_str("  isRunning: boolean;\n\n");
        dts.push_str("  constructor(options?: WebOsProcessOptions);\n");
        dts.push_str("  onStdout(callback: (text: string) => void): this;\n");
        dts.push_str("  onStderr(callback: (text: string) => void): this;\n");
        dts.push_str("  spawn(wasmSource?: RequestInfo | BufferSource | WebAssembly.Module): Promise<number>;\n");
        dts.push_str("  kill(signal?: number): void;\n");
        dts.push_str("  getMemoryBuffer(): ArrayBuffer | null;\n");
        dts.push_str("  getMemoryView(offset: number, length: number): Uint8Array | null;\n");
        dts.push_str("  getSliceView(offset: number, length: number, type?: 'u8' | 'i32' | 'i64' | 'f64'): ArrayBufferView | null;\n");
        dts.push_str("}\n");
        dts
    }
}
