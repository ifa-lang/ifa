use crate::cache::BuildCache;
use crate::error::KoriError;
use crate::ffi_gen::FfiBridgeGenerator;
use crate::lockfile::Lockfile;
use crate::manifest::{BackendKind, BinTarget, CrateType, LibTarget, Manifest, ProfileConfig};
use crate::module_metadata::ModuleMetadata;
use crate::resolver::{DependencyResolver, ResolvedPackage};
use ifa_ast::Item;
use ifa_codegen_cranelift::AotCompiler;
use ifa_codegen_llvm::{LlvmCompiler, LlvmTargetConfig};
use ifa_fir::compile_to_fir;
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::{analyze, analyze_with_symbols, symbol_table::ModuleSymbol, SymbolTable};
use ifa_span::{SourceMap, Symbol, INTERNER};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Type of artifact built by Kori.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactKind {
    Executable,
    SharedLibrary,
    StaticLibrary,
    WebAssemblyModule,
    WebAssemblyBundle,
    CHeader,
    PhpBridge,
    PreloadScript,
    ServiceConfig,
    IfaArchive,
}

/// Metadata for a single compiled artifact.
#[derive(Debug, Clone)]
pub struct BuiltArtifact {
    pub name: String,
    pub path: PathBuf,
    pub kind: ArtifactKind,
    pub cached: bool,
}

/// Compilation and orchestration execution report.
#[derive(Debug, Clone)]
pub struct BuildReport {
    pub packages_resolved: usize,
    pub artifacts: Vec<BuiltArtifact>,
    pub duration: std::time::Duration,
}

/// Multi-target build orchestrator coordinating parsing, FIR lowering, codegen, and FFI bridging.
pub struct BuildOrchestrator {
    root_dir: PathBuf,
    target_dir: PathBuf,
    manifest: Manifest,
}

impl BuildOrchestrator {
    /// Create a build orchestrator rooted at the specified project directory.
    pub fn new(root_dir: PathBuf) -> Result<Self, KoriError> {
        let manifest_path = root_dir.join("kori.toml");
        let mut manifest = Manifest::from_file(&manifest_path)?;
        manifest.resolve_targets(&root_dir);

        let target_dir = root_dir.join("target");
        Ok(Self {
            root_dir,
            target_dir,
            manifest,
        })
    }

    /// Build all targets under the specified profile (dev or release).
    pub fn build(
        &self,
        release: bool,
        backend_override: Option<BackendKind>,
        force: bool,
    ) -> Result<BuildReport, KoriError> {
        let start_time = Instant::now();
        let profile_dir_name = if release { "release" } else { "dev" };
        let out_dir = self.target_dir.join(profile_dir_name);
        fs::create_dir_all(&out_dir)?;

        let mut profile = if release {
            self.manifest.profiles.release.clone()
        } else {
            self.manifest.profiles.dev.clone()
        };

        if let Some(backend) = backend_override {
            profile.backend = backend;
        }

        // 1. Dependency resolution and lockfile synchronization
        let lock_path = self.root_dir.join("kori.lock");
        let existing_lock = if lock_path.exists() {
            Lockfile::from_file(&lock_path).ok()
        } else {
            None
        };

        let resolver = DependencyResolver::new(self.root_dir.clone());
        let (build_order, mut updated_lock) =
            resolver.resolve(&self.manifest, existing_lock.as_ref())?;

        // Save updated lockfile
        updated_lock.save(&lock_path)?;

        // 2. Build cache initialization
        let mut cache = BuildCache::new(&self.target_dir)?;

        let mut all_artifacts = Vec::new();

        // 3. Compile resolved packages in topological order
        for pkg in &build_order {
            let pkg_artifacts = self.compile_package(pkg, &profile, &out_dir, &mut cache, force)?;
            all_artifacts.extend(pkg_artifacts);
        }

        Ok(BuildReport {
            packages_resolved: build_order.len(),
            artifacts: all_artifacts,
            duration: start_time.elapsed(),
        })
    }

    fn compile_package(
        &self,
        pkg: &ResolvedPackage,
        profile: &ProfileConfig,
        out_dir: &Path,
        cache: &mut BuildCache,
        force: bool,
    ) -> Result<Vec<BuiltArtifact>, KoriError> {
        let mut manifest = pkg.manifest.clone();
        manifest.resolve_targets(&pkg.root_dir);

        let mut artifacts = Vec::new();

        // Build binary targets
        for bin in &manifest.targets.bin {
            let art = self.build_bin_target(pkg, bin, profile, out_dir, cache, force)?;
            artifacts.push(art);
        }

        // Build library targets
        if let Some(lib) = &manifest.targets.lib {
            let lib_arts = self.build_lib_target(pkg, lib, profile, out_dir, cache, force)?;
            artifacts.extend(lib_arts);
        }

        Ok(artifacts)
    }

    fn build_bin_target(
        &self,
        pkg: &ResolvedPackage,
        bin: &BinTarget,
        profile: &ProfileConfig,
        out_dir: &Path,
        cache: &mut BuildCache,
        force: bool,
    ) -> Result<BuiltArtifact, KoriError> {
        let target_key = format!("{}:bin:{}", pkg.name, bin.name);
        let output_bin = out_dir.join(&bin.name);
        let expected_outputs = [&output_bin as &Path];

        let fingerprint = cache.compute_target_fingerprint(pkg, profile, &[]);

        if !force && cache.is_up_to_date(&target_key, &fingerprint, &expected_outputs) {
            return Ok(BuiltArtifact {
                name: bin.name.clone(),
                path: output_bin,
                kind: ArtifactKind::Executable,
                cached: true,
            });
        }

        // Compile pipeline
        let src_path = pkg.root_dir.join(&bin.path);
        let fir_module = self.compile_source_to_fir(&src_path, &pkg.name, cache)?;

        let obj_path = out_dir.join(format!("{}.o", bin.name));

        match profile.backend {
            BackendKind::Llvm => {
                let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::host());
                llvm_comp
                    .opt_level(profile.opt_level)
                    .lto(&profile.lto)
                    .strip_symbols(profile.strip_symbols);
                llvm_comp
                    .compile_to_object(&fir_module, &obj_path)
                    .map_err(|e| {
                        KoriError::Codegen(format!("LLVM compile to object failed: {}", e))
                    })?;
                LlvmCompiler::link_executable_with_lto(&obj_path, &output_bin, &profile.lto)
                    .map_err(|e| {
                        KoriError::Codegen(format!("Failed to link binary `{}`: {}", bin.name, e))
                    })?;
            }
            BackendKind::Cranelift => {
                let compiler = AotCompiler::new().map_err(|e| {
                    KoriError::Codegen(format!("AOT compiler initialization failed: {}", e))
                })?;

                compiler
                    .compile_to_object(&fir_module, &obj_path)
                    .map_err(|e| {
                        KoriError::Codegen(format!("Failed to compile to object: {}", e))
                    })?;

                AotCompiler::link_executable(&obj_path, &output_bin).map_err(|e| {
                    KoriError::Codegen(format!("Failed to link binary `{}`: {}", bin.name, e))
                })?;
            }
        }

        cache.record_success(&target_key, fingerprint, vec![output_bin.clone()])?;

        Ok(BuiltArtifact {
            name: bin.name.clone(),
            path: output_bin,
            kind: ArtifactKind::Executable,
            cached: false,
        })
    }

    fn build_lib_target(
        &self,
        pkg: &ResolvedPackage,
        lib: &LibTarget,
        profile: &ProfileConfig,
        out_dir: &Path,
        cache: &mut BuildCache,
        force: bool,
    ) -> Result<Vec<BuiltArtifact>, KoriError> {
        let mut artifacts = Vec::new();
        let src_path = pkg.root_dir.join(&lib.path);
        let fir_module = self.compile_source_to_fir(&src_path, &pkg.name, cache)?;

        for crate_type in &lib.crate_types {
            match crate_type {
                CrateType::Cdylib => {
                    let so_filename = format!("lib{}.so", lib.name);
                    let so_path = out_dir.join(&so_filename);
                    let target_key = format!("{}:cdylib:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, profile, &[]);

                    if !force && cache.is_up_to_date(&target_key, &fingerprint, &[&so_path]) {
                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: so_path.clone(),
                            kind: ArtifactKind::SharedLibrary,
                            cached: true,
                        });
                    } else {
                        let obj_path = out_dir.join(format!("{}_cdylib.o", lib.name));

                        match profile.backend {
                            BackendKind::Llvm => {
                                let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::host());
                                llvm_comp
                                    .opt_level(profile.opt_level)
                                    .lto(&profile.lto)
                                    .strip_symbols(profile.strip_symbols);
                                llvm_comp
                                    .compile_to_object(&fir_module, &obj_path)
                                    .map_err(|e| {
                                        KoriError::Codegen(format!(
                                            "LLVM compile shared object failed: {}",
                                            e
                                        ))
                                    })?;
                            }
                            BackendKind::Cranelift => {
                                let compiler = AotCompiler::new().map_err(|e| {
                                    KoriError::Codegen(format!(
                                        "AOT compiler initialization failed: {}",
                                        e
                                    ))
                                })?;

                                compiler.compile_to_object(&fir_module, &obj_path).map_err(
                                    |e| {
                                        KoriError::Codegen(format!(
                                            "Failed to compile shared object: {}",
                                            e
                                        ))
                                    },
                                )?;
                            }
                        }

                        Self::link_shared_library(&obj_path, &so_path)?;

                        cache.record_success(&target_key, fingerprint, vec![so_path.clone()])?;

                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: so_path.clone(),
                            kind: ArtifactKind::SharedLibrary,
                            cached: false,
                        });
                    }

                    // Automatic FFI generation for PHP 8.4+ and C header
                    let ffi_config = pkg.manifest.ffi.clone().unwrap_or_default();
                    let ffi_gen = FfiBridgeGenerator::new(&pkg.name, ffi_config);
                    let exported_fns = FfiBridgeGenerator::extract_exported_functions(&fir_module);

                    let ffi_artifacts =
                        ffi_gen.emit_bindings(&exported_fns, out_dir, &so_filename)?;

                    artifacts.push(BuiltArtifact {
                        name: format!("{}.h", pkg.name),
                        path: ffi_artifacts.header_path,
                        kind: ArtifactKind::CHeader,
                        cached: false,
                    });

                    artifacts.push(BuiltArtifact {
                        name: format!("{}.php", ffi_artifacts.class_name),
                        path: ffi_artifacts.php_path,
                        kind: ArtifactKind::PhpBridge,
                        cached: false,
                    });

                    if let Some(preload_path) = ffi_artifacts.preload_path {
                        artifacts.push(BuiltArtifact {
                            name: "preload.php".to_string(),
                            path: preload_path,
                            kind: ArtifactKind::PreloadScript,
                            cached: false,
                        });
                    }

                    if let Some(service_path) = ffi_artifacts.service_config_path {
                        artifacts.push(BuiltArtifact {
                            name: "services.yaml".to_string(),
                            path: service_path,
                            kind: ArtifactKind::ServiceConfig,
                            cached: false,
                        });
                    }
                }
                CrateType::Staticlib => {
                    let a_filename = format!("lib{}.a", lib.name);
                    let a_path = out_dir.join(&a_filename);
                    let target_key = format!("{}:staticlib:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, profile, &[]);

                    if !force && cache.is_up_to_date(&target_key, &fingerprint, &[&a_path]) {
                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: a_path.clone(),
                            kind: ArtifactKind::StaticLibrary,
                            cached: true,
                        });
                    } else {
                        let obj_path = out_dir.join(format!("{}_static.o", lib.name));

                        match profile.backend {
                            BackendKind::Llvm => {
                                let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::host());
                                llvm_comp
                                    .opt_level(profile.opt_level)
                                    .lto(&profile.lto)
                                    .strip_symbols(profile.strip_symbols);
                                llvm_comp
                                    .compile_to_object(&fir_module, &obj_path)
                                    .map_err(|e| {
                                        KoriError::Codegen(format!(
                                            "LLVM compile static object failed: {}",
                                            e
                                        ))
                                    })?;
                            }
                            BackendKind::Cranelift => {
                                let compiler = AotCompiler::new().map_err(|e| {
                                    KoriError::Codegen(format!(
                                        "AOT compiler initialization failed: {}",
                                        e
                                    ))
                                })?;

                                compiler.compile_to_object(&fir_module, &obj_path).map_err(
                                    |e| {
                                        KoriError::Codegen(format!(
                                            "Failed to compile static object: {}",
                                            e
                                        ))
                                    },
                                )?;
                            }
                        }

                        Self::create_static_library(&obj_path, &a_path)?;

                        cache.record_success(&target_key, fingerprint, vec![a_path.clone()])?;

                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: a_path.clone(),
                            kind: ArtifactKind::StaticLibrary,
                            cached: false,
                        });
                    }
                }
                CrateType::Wasm => {
                    let wasm_filename = format!("{}.wasm", lib.name);
                    let wasm_path = out_dir.join(&wasm_filename);
                    let target_key = format!("{}:wasm:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, profile, &[]);

                    if !force && cache.is_up_to_date(&target_key, &fingerprint, &[&wasm_path]) {
                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: wasm_path.clone(),
                            kind: ArtifactKind::WebAssemblyModule,
                            cached: true,
                        });
                    } else {
                        let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::wasm32_wasi());
                        llvm_comp
                            .opt_level(profile.opt_level)
                            .lto(&profile.lto)
                            .strip_symbols(profile.strip_symbols);
                        llvm_comp
                            .compile_to_wasm(&fir_module, &wasm_path)
                            .map_err(|e| {
                                KoriError::Codegen(format!(
                                    "LLVM compile WebAssembly failed: {}",
                                    e
                                ))
                            })?;

                        cache.record_success(&target_key, fingerprint, vec![wasm_path.clone()])?;

                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: wasm_path.clone(),
                            kind: ArtifactKind::WebAssemblyModule,
                            cached: false,
                        });

                        // Bundle WebAssembly package with TypeScript and JavaScript glue
                        if let Ok(wasm_bytes) = fs::read(&wasm_path) {
                            let bundle_dir = out_dir.join(format!("{}_wasm_bundle", lib.name));
                            let bundler = ifa_wasm::WasmBundler::new(&lib.name, wasm_bytes);
                            if bundler.bundle(&bundle_dir).is_ok() {
                                artifacts.push(BuiltArtifact {
                                    name: format!("{}_wasm_bundle", lib.name),
                                    path: bundle_dir,
                                    kind: ArtifactKind::WebAssemblyBundle,
                                    cached: false,
                                });
                            }
                        }
                    }
                }
                CrateType::IfaLib => {
                    let ifalib_filename = format!("{}.ifalib", lib.name);
                    let ifalib_path = out_dir.join(&ifalib_filename);
                    let target_key = format!("{}:ifalib:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, profile, &[]);

                    if !force && cache.is_up_to_date(&target_key, &fingerprint, &[&ifalib_path]) {
                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: ifalib_path,
                            kind: ArtifactKind::IfaArchive,
                            cached: true,
                        });
                    } else {
                        let meta = ModuleMetadata::from_symbols_and_fir(
                            &lib.name,
                            &pkg.name,
                            &fingerprint,
                            &SymbolTable::new(),
                            &fir_module,
                        );
                        let binary_data = meta.serialize_to_binary()?;
                        fs::write(&ifalib_path, binary_data)?;
                        cache.record_success(
                            &target_key,
                            fingerprint,
                            vec![ifalib_path.clone()],
                        )?;

                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: ifalib_path,
                            kind: ArtifactKind::IfaArchive,
                            cached: false,
                        });
                    }
                }
            }
        }

        Ok(artifacts)
    }

    /// Resolve a module import path to its corresponding `.ifa` file on disk.
    pub fn resolve_module_file(base_dir: &Path, module_path: &[Symbol]) -> Option<PathBuf> {
        if module_path.is_empty() {
            return None;
        }
        let parts: Vec<String> = module_path.iter().map(|s| INTERNER.resolve(s)).collect();

        // 1. Check direct file: base_dir/part1/.../partN.ifa
        let mut file_path = base_dir.to_path_buf();
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                file_path.push(format!("{}.ifa", part));
            } else {
                file_path.push(part);
            }
        }
        if file_path.is_file() {
            return Some(file_path);
        }

        // 2. Check directory module: base_dir/part1/.../partN/mod.ifa
        let mut dir_path = base_dir.to_path_buf();
        for part in &parts {
            dir_path.push(part);
        }
        dir_path.push("mod.ifa");
        if dir_path.is_file() {
            return Some(dir_path);
        }

        None
    }

    fn compile_source_to_fir(
        &self,
        source_path: &Path,
        pkg_name: &str,
        cache: &BuildCache,
    ) -> Result<ifa_fir::FirModule, KoriError> {
        let source_text =
            fs::read_to_string(source_path).map_err(|e| KoriError::CompilationError {
                package: pkg_name.to_string(),
                message: format!(
                    "Failed to read source file `{}`: {}",
                    source_path.display(),
                    e
                ),
            })?;

        let mut sm = SourceMap::new();
        let file_id = sm.add_file(source_path.to_string_lossy(), &source_text);

        let tokens = tokenize(file_id, &source_text);

        let (ast_prog, parse_diags) = parse(file_id, tokens);
        if !parse_diags.is_empty() {
            let mut msg = String::new();
            for diag in &parse_diags {
                msg.push_str(&diag.render_to_string(&sm));
            }
            return Err(KoriError::CompilationError {
                package: pkg_name.to_string(),
                message: msg,
            });
        }

        let base_dir = source_path.parent().unwrap_or_else(|| Path::new("."));

        let mut symbols = SymbolTable::new();
        let mut sub_fir_modules = Vec::new();

        // Detect and resolve local submodules imported in the root program
        for item in &ast_prog.items {
            if let Item::Import(im) = item {
                if let Some(sub_path) = Self::resolve_module_file(base_dir, &im.path) {
                    let sub_fingerprint = BuildCache::compute_file_fingerprint(&sub_path)?;
                    let path_str = im
                        .path
                        .iter()
                        .map(|s| INTERNER.resolve(s))
                        .collect::<Vec<_>>()
                        .join("::");
                    let mod_key = format!("{}:{}", pkg_name, path_str);
                    let local_alias = im.alias.unwrap_or_else(|| *im.path.last().unwrap());

                    let sub_source =
                        fs::read_to_string(&sub_path).map_err(|e| KoriError::CompilationError {
                            package: pkg_name.to_string(),
                            message: format!(
                                "Failed to read module `{}`: {}",
                                sub_path.display(),
                                e
                            ),
                        })?;

                    let sub_file_id = sm.add_file(sub_path.to_string_lossy(), &sub_source);
                    let sub_tokens = tokenize(sub_file_id, &sub_source);
                    let (sub_prog, sub_parse_diags) = parse(sub_file_id, sub_tokens);
                    if !sub_parse_diags.is_empty() {
                        let mut msg = String::new();
                        for diag in &sub_parse_diags {
                            msg.push_str(&diag.render_to_string(&sm));
                        }
                        return Err(KoriError::CompilationError {
                            package: pkg_name.to_string(),
                            message: msg,
                        });
                    }

                    let sub_analysis = analyze(&sm, &sub_prog);
                    if sub_analysis.has_errors() {
                        let mut msg = String::new();
                        for diag in &sub_analysis.diagnostics {
                            msg.push_str(&diag.render_to_string(&sm));
                        }
                        return Err(KoriError::CompilationError {
                            package: pkg_name.to_string(),
                            message: msg,
                        });
                    }

                    // Lower submodule to FIR and collect
                    let sub_fir = compile_to_fir(&sub_prog, &sub_analysis.symbols, true, true)
                        .map_err(|errors| {
                            let mut msg = String::new();
                            for diag in &errors {
                                msg.push_str(&diag.render_to_string(&sm));
                            }
                            KoriError::CompilationError {
                                package: pkg_name.to_string(),
                                message: msg,
                            }
                        })?;

                    // Store binary module metadata into cache
                    let meta = ModuleMetadata::from_symbols_and_fir(
                        &path_str,
                        pkg_name,
                        &sub_fingerprint,
                        &sub_analysis.symbols,
                        &sub_fir,
                    );
                    let _ = cache.store_module_metadata(&mod_key, &meta);

                    sub_fir_modules.push(sub_fir);

                    // Build ModuleSymbol containing exported (is_pub) definitions
                    let mut mod_sym =
                        ModuleSymbol::new(local_alias, im.path.clone(), true, im.span);
                    for f in sub_analysis.symbols.functions.values() {
                        mod_sym.add_function(f.clone());
                    }
                    for s in sub_analysis.symbols.structs.values() {
                        mod_sym.add_struct(s.clone());
                    }
                    for e in sub_analysis.symbols.enums.values() {
                        mod_sym.add_enum(e.clone());
                    }
                    for c in sub_analysis.symbols.consts.values() {
                        mod_sym.add_const(c.clone());
                    }

                    let path_sym = INTERNER.intern(&path_str);
                    symbols.modules.insert(local_alias, mod_sym.clone());
                    symbols.modules.insert(path_sym, mod_sym.clone());
                    if let Some(last) = im.path.last() {
                        symbols.modules.insert(*last, mod_sym);
                    }
                }
            }
        }

        let analysis = analyze_with_symbols(&sm, &ast_prog, symbols);
        if analysis.has_errors() {
            let mut msg = String::new();
            for diag in &analysis.diagnostics {
                msg.push_str(&diag.render_to_string(&sm));
            }
            return Err(KoriError::CompilationError {
                package: pkg_name.to_string(),
                message: msg,
            });
        }

        let mut fir_module =
            compile_to_fir(&ast_prog, &analysis.symbols, true, true).map_err(|errors| {
                let mut msg = String::new();
                for diag in &errors {
                    msg.push_str(&diag.render_to_string(&sm));
                }
                KoriError::CompilationError {
                    package: pkg_name.to_string(),
                    message: msg,
                }
            })?;

        // Merge all compiled submodule FIR definitions into the unified root FIR module
        for sub_fir in sub_fir_modules {
            fir_module.merge(sub_fir);
        }

        Ok(fir_module)
    }

    /// Link an object file into a C-ABI compatible dynamic shared library (.so) using host toolchain.
    pub fn link_shared_library(object_path: &Path, output_so: &Path) -> Result<(), KoriError> {
        let compilers = ["clang", "gcc", "cc"];
        let mut last_err = String::new();

        static STUB_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stub_id = STUB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let rt_stub = ifa_codegen_cranelift::RUNTIME_STUB_C;
        let rt_path = std::env::temp_dir().join(format!(
            "ifa_runtime_stub_so_{}_{}_{}.c",
            std::process::id(),
            stub_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::write(&rt_path, rt_stub)?;

        for compiler in &compilers {
            let status = Command::new(compiler)
                .arg("-shared")
                .arg("-fPIC")
                .arg(object_path)
                .arg(&rt_path)
                .arg("-o")
                .arg(output_so)
                .status();

            match status {
                Ok(s) if s.success() => {
                    let _ = fs::remove_file(&rt_path);
                    return Ok(());
                }
                Ok(s) => {
                    last_err = format!("Compiler `{}` failed with exit status {}", compiler, s);
                }
                Err(e) => {
                    last_err = format!("Failed to execute `{}`: {}", compiler, e);
                }
            }
        }

        let _ = fs::remove_file(&rt_path);
        Err(KoriError::Codegen(format!(
            "Failed to link shared library `{}`: {}",
            output_so.display(),
            last_err
        )))
    }

    /// Create a static library (.a) from an object file using the host archiver (`ar` or `llvm-ar`).
    pub fn create_static_library(object_path: &Path, output_a: &Path) -> Result<(), KoriError> {
        let archivers = ["ar", "llvm-ar"];
        let mut last_err = String::new();

        for archiver in &archivers {
            let status = Command::new(archiver)
                .arg("crs")
                .arg(output_a)
                .arg(object_path)
                .status();

            match status {
                Ok(s) if s.success() => return Ok(()),
                Ok(s) => {
                    last_err = format!("Archiver `{}` failed with exit status {}", archiver, s);
                }
                Err(e) => {
                    last_err = format!("Failed to execute `{}`: {}", archiver, e);
                }
            }
        }

        Err(KoriError::Codegen(format!(
            "Failed to create static library `{}`: {}",
            output_a.display(),
            last_err
        )))
    }
}
