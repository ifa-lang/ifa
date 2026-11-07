use crate::bindings::{TypeScriptBindingsGenerator, WasmExportFunction, WasmType};
use crate::validator::WasmModuleInspector;
use std::fs;
use std::path::{Path, PathBuf};

/// Package structure produced by the IFA WebAssembly Bundler.
#[derive(Debug, Clone)]
pub struct WasmBundleResult {
    pub output_dir: PathBuf,
    pub wasm_file: PathBuf,
    pub js_file: PathBuf,
    pub dts_file: PathBuf,
    pub react_file: PathBuf,
    pub react_dts_file: PathBuf,
    pub web_os_file: PathBuf,
    pub web_os_dts_file: PathBuf,
    pub package_json_file: PathBuf,
}

pub struct WasmBundler {
    module_name: String,
    wasm_bytes: Vec<u8>,
    functions: Vec<WasmExportFunction>,
}

impl WasmBundler {
    pub fn new(module_name: impl Into<String>, wasm_bytes: Vec<u8>) -> Self {
        Self {
            module_name: module_name.into(),
            wasm_bytes,
            functions: Vec::new(),
        }
    }

    pub fn with_functions(mut self, functions: Vec<WasmExportFunction>) -> Self {
        self.functions = functions;
        self
    }

    /// Package the WebAssembly module and bindings into output directory.
    pub fn bundle(&self, output_dir: &Path) -> std::io::Result<WasmBundleResult> {
        fs::create_dir_all(output_dir)?;

        // Validate WASM binary header
        let inspector = WasmModuleInspector::new(&self.wasm_bytes);
        let _ = inspector.inspect();

        // Write .wasm file
        let wasm_file = output_dir.join(format!("{}.wasm", self.module_name));
        fs::write(&wasm_file, &self.wasm_bytes)?;

        // Build TS/JS bindings
        let mut gen = TypeScriptBindingsGenerator::new(&self.module_name);
        for func in &self.functions {
            gen.add_function(func.clone());
        }

        // If no explicit functions provided, extract exported function names
        if self.functions.is_empty() {
            if let Ok(exports) = inspector.extract_exports() {
                for exp in exports {
                    if exp.kind == 0 && exp.name != "memory" {
                        gen.add_function(WasmExportFunction {
                            name: exp.name,
                            params: Vec::new(),
                            ret_ty: WasmType::I32,
                            doc: Some("Exported WebAssembly function".to_string()),
                        });
                    }
                }
            }
        }

        let js_file = output_dir.join("index.js");
        let dts_file = output_dir.join("index.d.ts");
        let react_file = output_dir.join("react.js");
        let react_dts_file = output_dir.join("react.d.ts");
        let web_os_file = output_dir.join("web_os.js");
        let web_os_dts_file = output_dir.join("web_os.d.ts");
        let package_json_file = output_dir.join("package.json");
        let readme_file = output_dir.join("README.md");

        fs::write(&js_file, gen.generate_esm())?;
        fs::write(&dts_file, gen.generate_dts())?;
        fs::write(&react_file, gen.generate_react_hook_js())?;
        fs::write(&react_dts_file, gen.generate_react_hook_dts())?;
        fs::write(&web_os_file, gen.generate_web_os_js())?;
        fs::write(&web_os_dts_file, gen.generate_web_os_dts())?;

        let package_json = format!(
            r#"{{
  "name": "@{name}/wasm",
  "version": "0.1.0",
  "description": "Deterministic WebAssembly module compiled with IFA",
  "type": "module",
  "main": "index.js",
  "types": "index.d.ts",
  "exports": {{
    ".": {{
      "import": "./index.js",
      "types": "./index.d.ts"
    }},
    "./react": {{
      "import": "./react.js",
      "types": "./react.d.ts"
    }},
    "./web-os": {{
      "import": "./web_os.js",
      "types": "./web_os.d.ts"
    }}
  }},
  "files": [
    "index.js",
    "index.d.ts",
    "react.js",
    "react.d.ts",
    "web_os.js",
    "web_os.d.ts",
    "{name}.wasm"
  ]
}}
"#,
            name = self.module_name
        );
        fs::write(&package_json_file, package_json)?;

        let readme = format!(
            r#"# @{name}/wasm

Deterministic, zero-GC WebAssembly module powered by the IFA programming language.

## Quickstart in React & Web OS

### 1. Vanilla TypeScript / ES Module
```typescript
import {{ init, {example_fn} }} from '@{name}/wasm';

async function run() {{
  await init();
  const result = {example_fn}();
  console.log("IFA Wasm Result:", result);
}}
run();
```

### 2. React Hook
```tsx
import {{ useIfaModule }} from '@{name}/wasm/react';

export function IfaWasmComponent() {{
  const {{ ready, error }} = useIfaModule();
  if (error) return <div>Failed to load module: {{error.message}}</div>;
  if (!ready) return <div>Loading IFA WebAssembly...</div>;
  return <div>IFA WebAssembly ready!</div>;
}}
```

### 3. Web OS Process Sandbox
```typescript
import {{ WebOsProcess }} from '@{name}/wasm/web-os';

const proc = new WebOsProcess({{ name: '{name}-task' }});
proc.onStdout((msg) => console.log('[STDOUT]', msg));
await proc.spawn();
```
"#,
            name = self.module_name,
            example_fn = self
                .functions
                .first()
                .map(|f| f.name.as_str())
                .unwrap_or("run")
        );
        fs::write(&readme_file, readme)?;

        Ok(WasmBundleResult {
            output_dir: output_dir.to_path_buf(),
            wasm_file,
            js_file,
            dts_file,
            react_file,
            react_dts_file,
            web_os_file,
            web_os_dts_file,
            package_json_file,
        })
    }
}
