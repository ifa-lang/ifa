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
use ifa_fir::{compile_to_fir, compile_to_fir_with_opts, CacheLayoutPass, SroaPass};
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

/// Static analysis and semantic check execution report.
#[derive(Debug, Clone)]
pub struct CheckReport {
    pub package: String,
    pub targets_checked: usize,
    pub duration: std::time::Duration,
}

/// Multi-target build orchestrator coordinating parsing, FIR lowering, codegen, and FFI bridging.
pub struct BuildOrchestrator {
    root_dir: PathBuf,
    target_dir: PathBuf,
    manifest: Manifest,
}

struct BuildContext<'a> {
    profile: &'a ProfileConfig,
    out_dir: &'a Path,
    target_filter: Option<&'a str>,
    force: bool,
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
        self.build_with_target(release, backend_override, None, force)
    }

    /// Build package targets under the specified profile, with optional target architecture filtering.
    pub fn build_with_target(
        &self,
        release: bool,
        backend_override: Option<BackendKind>,
        target_filter: Option<&str>,
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
            let pkg_artifacts =
                self.compile_package(pkg, &profile, &out_dir, &mut cache, target_filter, force)?;
            all_artifacts.extend(pkg_artifacts);
        }

        Ok(BuildReport {
            packages_resolved: build_order.len(),
            artifacts: all_artifacts,
            duration: start_time.elapsed(),
        })
    }

    /// Check syntax and semantics for all package targets and imported local modules without code generation.
    pub fn check(&self) -> Result<CheckReport, KoriError> {
        let start_time = Instant::now();
        let mut manifest = self.manifest.clone();
        manifest.resolve_targets(&self.root_dir);

        let mut targets_checked = 0;
        let mut all_errors = Vec::new();

        let mut target_paths = Vec::new();
        for bin in &manifest.targets.bin {
            target_paths.push((format!("bin:{}", bin.name), self.root_dir.join(&bin.path)));
        }
        if let Some(lib) = &manifest.targets.lib {
            target_paths.push((format!("lib:{}", lib.name), self.root_dir.join(&lib.path)));
        }

        for (target_name, src_path) in target_paths {
            targets_checked += 1;
            let src = fs::read_to_string(&src_path).map_err(|e| KoriError::CompilationError {
                package: self.manifest.package.name.clone(),
                message: format!(
                    "Failed to read target `{}` at `{}`: {}",
                    target_name,
                    src_path.display(),
                    e
                ),
            })?;

            let mut source_map = SourceMap::new();
            let fid = source_map.add_file(src_path.to_string_lossy(), &src);
            let tokens = tokenize(fid, &src);
            let (prog, parse_diags) = parse(fid, tokens);

            let mut target_has_errors = false;
            let mut diag_msg = String::new();
            for diag in &parse_diags {
                diag_msg.push_str(&diag.render_to_string(&source_map));
                target_has_errors = true;
            }

            if !target_has_errors {
                let base_dir = src_path.parent().unwrap_or_else(|| Path::new("."));
                let (analysis, _) =
                    Self::analyze_with_local_modules(&mut source_map, base_dir, &prog);
                for diag in &analysis.diagnostics {
                    diag_msg.push_str(&diag.render_to_string(&source_map));
                }
                if analysis.has_errors() {
                    target_has_errors = true;
                }
            }

            if target_has_errors {
                all_errors.push(format!("In target `{}`:\n{}", target_name, diag_msg));
            }
        }

        if !all_errors.is_empty() {
            return Err(KoriError::CompilationError {
                package: self.manifest.package.name.clone(),
                message: all_errors.join("\n"),
            });
        }

        Ok(CheckReport {
            package: self.manifest.package.name.clone(),
            targets_checked,
            duration: start_time.elapsed(),
        })
    }

    fn compile_package(
        &self,
        pkg: &ResolvedPackage,
        profile: &ProfileConfig,
        out_dir: &Path,
        cache: &mut BuildCache,
        target_filter: Option<&str>,
        force: bool,
    ) -> Result<Vec<BuiltArtifact>, KoriError> {
        let mut manifest = pkg.manifest.clone();
        manifest.resolve_targets(&pkg.root_dir);

        let mut artifacts = Vec::new();

        let is_wasm_only = target_filter.map(|t| t.contains("wasm")).unwrap_or(false);
        let is_native_only = target_filter
            .map(|t| t == "native" || t == "host")
            .unwrap_or(false);

        let ctx = BuildContext {
            profile,
            out_dir,
            target_filter,
            force,
        };

        // Build binary targets
        for bin in &manifest.targets.bin {
            let bin_is_wasm = bin.is_wasm();
            if is_wasm_only && !bin_is_wasm {
                let has_wasm_lib = manifest.targets.lib.as_ref().is_some_and(|l| l.has_wasm());
                if has_wasm_lib {
                    continue;
                }
            } else if is_native_only && bin_is_wasm {
                continue;
            }

            let art = self.build_bin_target(pkg, bin, &ctx, cache)?;
            artifacts.push(art);
        }

        // Build library targets
        if let Some(lib) = &manifest.targets.lib {
            let lib_arts = self.build_lib_target(pkg, lib, &ctx, cache)?;
            artifacts.extend(lib_arts);
        }

        Ok(artifacts)
    }

    fn build_bin_target(
        &self,
        pkg: &ResolvedPackage,
        bin: &BinTarget,
        ctx: &BuildContext<'_>,
        cache: &mut BuildCache,
    ) -> Result<BuiltArtifact, KoriError> {
        let is_wasm = bin.is_wasm()
            || ctx
                .target_filter
                .map(|t| t.contains("wasm"))
                .unwrap_or(false);

        let bin_stem = bin.name.strip_suffix(".wasm").unwrap_or(&bin.name);
        let output_bin = if is_wasm {
            ctx.out_dir.join(format!("{}.wasm", bin_stem))
        } else {
            ctx.out_dir.join(&bin.name)
        };
        let target_arch = if is_wasm { "wasm32-wasi" } else { "native" };
        let target_key = format!("{}:bin:{}:{}", pkg.name, bin.name, target_arch);
        let expected_outputs = [&output_bin as &Path];

        let fingerprint = cache.compute_target_fingerprint(pkg, ctx.profile, &[]);

        if !ctx.force && cache.is_up_to_date(&target_key, &fingerprint, &expected_outputs) {
            return Ok(BuiltArtifact {
                name: output_bin
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                path: output_bin,
                kind: if is_wasm {
                    ArtifactKind::WebAssemblyModule
                } else {
                    ArtifactKind::Executable
                },
                cached: true,
            });
        }

        // Compile pipeline
        let src_path = pkg.root_dir.join(&bin.path);
        let fir_module = self.compile_source_to_fir(&src_path, &pkg.name, cache)?;

        if is_wasm {
            let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::wasm32_wasi());
            llvm_comp
                .opt_level(ctx.profile.opt_level)
                .lto(&ctx.profile.lto)
                .strip_symbols(ctx.profile.strip_symbols);
            llvm_comp
                .compile_to_wasm(&fir_module, &output_bin)
                .map_err(|e| {
                    KoriError::Codegen(format!("LLVM compile WebAssembly binary failed: {}", e))
                })?;

            cache.record_success(&target_key, fingerprint, vec![output_bin.clone()])?;

            return Ok(BuiltArtifact {
                name: output_bin
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                path: output_bin,
                kind: ArtifactKind::WebAssemblyModule,
                cached: false,
            });
        }

        let obj_path = ctx.out_dir.join(format!("{}.o", bin.name));

        match ctx.profile.backend {
            BackendKind::Llvm => {
                let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::host());
                llvm_comp
                    .opt_level(ctx.profile.opt_level)
                    .lto(&ctx.profile.lto)
                    .strip_symbols(ctx.profile.strip_symbols);
                llvm_comp
                    .compile_to_object(&fir_module, &obj_path)
                    .map_err(|e| {
                        KoriError::Codegen(format!("LLVM compile to object failed: {}", e))
                    })?;
                LlvmCompiler::link_executable_with_lto(&obj_path, &output_bin, &ctx.profile.lto)
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
        ctx: &BuildContext<'_>,
        cache: &mut BuildCache,
    ) -> Result<Vec<BuiltArtifact>, KoriError> {
        let mut artifacts = Vec::new();
        let src_path = pkg.root_dir.join(&lib.path);
        let fir_module = self.compile_source_to_fir(&src_path, &pkg.name, cache)?;

        let is_wasm_only = ctx
            .target_filter
            .map(|t| t.contains("wasm"))
            .unwrap_or(false);
        let is_native_only = ctx
            .target_filter
            .map(|t| t == "native" || t == "host")
            .unwrap_or(false);

        let crate_types_to_build: Vec<CrateType> = if is_wasm_only {
            vec![CrateType::Wasm]
        } else if is_native_only {
            lib.crate_types
                .iter()
                .copied()
                .filter(|ct| *ct != CrateType::Wasm)
                .collect()
        } else {
            lib.crate_types.clone()
        };

        for crate_type in &crate_types_to_build {
            match crate_type {
                CrateType::Cdylib => {
                    let so_filename = format!("lib{}.so", lib.name);
                    let so_path = ctx.out_dir.join(&so_filename);
                    let target_key = format!("{}:cdylib:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, ctx.profile, &[]);

                    if !ctx.force && cache.is_up_to_date(&target_key, &fingerprint, &[&so_path]) {
                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: so_path.clone(),
                            kind: ArtifactKind::SharedLibrary,
                            cached: true,
                        });
                    } else {
                        let obj_path = ctx.out_dir.join(format!("{}_cdylib.o", lib.name));

                        match ctx.profile.backend {
                            BackendKind::Llvm => {
                                let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::host());
                                llvm_comp
                                    .opt_level(ctx.profile.opt_level)
                                    .lto(&ctx.profile.lto)
                                    .strip_symbols(ctx.profile.strip_symbols);
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
                        ffi_gen.emit_bindings(&exported_fns, ctx.out_dir, &so_filename)?;

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
                    let a_path = ctx.out_dir.join(&a_filename);
                    let target_key = format!("{}:staticlib:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, ctx.profile, &[]);

                    if !ctx.force && cache.is_up_to_date(&target_key, &fingerprint, &[&a_path]) {
                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: a_path.clone(),
                            kind: ArtifactKind::StaticLibrary,
                            cached: true,
                        });
                    } else {
                        let obj_path = ctx.out_dir.join(format!("{}_static.o", lib.name));

                        match ctx.profile.backend {
                            BackendKind::Llvm => {
                                let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::host());
                                llvm_comp
                                    .opt_level(ctx.profile.opt_level)
                                    .lto(&ctx.profile.lto)
                                    .strip_symbols(ctx.profile.strip_symbols);
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
                    let wasm_path = ctx.out_dir.join(&wasm_filename);
                    let target_key = format!("{}:wasm:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, ctx.profile, &[]);
                    let bundle_dir = ctx.out_dir.join(format!("{}_wasm_bundle", lib.name));

                    if !ctx.force && cache.is_up_to_date(&target_key, &fingerprint, &[&wasm_path]) {
                        artifacts.push(BuiltArtifact {
                            name: lib.name.clone(),
                            path: wasm_path.clone(),
                            kind: ArtifactKind::WebAssemblyModule,
                            cached: true,
                        });
                        if bundle_dir.exists() {
                            artifacts.push(BuiltArtifact {
                                name: format!("{}_wasm_bundle", lib.name),
                                path: bundle_dir,
                                kind: ArtifactKind::WebAssemblyBundle,
                                cached: true,
                            });
                        }
                    } else {
                        let mut llvm_comp = LlvmCompiler::new(LlvmTargetConfig::wasm32_wasi());
                        llvm_comp
                            .opt_level(ctx.profile.opt_level)
                            .lto(&ctx.profile.lto)
                            .strip_symbols(ctx.profile.strip_symbols);
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
                            let bundler = ifa_wasm::WasmBundler::from_fir_module(
                                &lib.name,
                                wasm_bytes,
                                &fir_module,
                            );
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
                    let ifalib_path = ctx.out_dir.join(&ifalib_filename);
                    let target_key = format!("{}:ifalib:{}", pkg.name, lib.name);
                    let fingerprint = cache.compute_target_fingerprint(pkg, ctx.profile, &[]);

                    if !ctx.force && cache.is_up_to_date(&target_key, &fingerprint, &[&ifalib_path])
                    {
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

        // Check candidate directories:
        // 1. base_dir (e.g. src/ or tests/)
        // 2. base_dir sibling src/ (e.g. tests/../src -> src/)
        // 3. base_dir child src/ (e.g. project_root/src)
        // 4. Current working directory "src"
        let mut candidate_dirs: Vec<PathBuf> = vec![base_dir.to_path_buf()];
        if let Some(parent) = base_dir.parent() {
            let sibling_src = parent.join("src");
            if sibling_src != base_dir && sibling_src.is_dir() {
                candidate_dirs.push(sibling_src);
            }
        }
        let child_src = base_dir.join("src");
        if child_src.is_dir() && !candidate_dirs.contains(&child_src) {
            candidate_dirs.push(child_src);
        }
        let cwd_src = PathBuf::from("src");
        if cwd_src.is_dir() && !candidate_dirs.contains(&cwd_src) {
            candidate_dirs.push(cwd_src);
        }

        let check_in_dir = |dir: &Path, slice: &[String]| -> Option<PathBuf> {
            if slice.is_empty() {
                return None;
            }
            // 1. Direct file: dir/part1/.../partN.ifa
            let mut file_path = dir.to_path_buf();
            for (i, part) in slice.iter().enumerate() {
                if i == slice.len() - 1 {
                    file_path.push(format!("{}.ifa", part));
                } else {
                    file_path.push(part);
                }
            }
            if file_path.is_file() {
                return Some(file_path);
            }

            // 2. Directory module: dir/part1/.../partN/mod.ifa
            let mut dir_path = dir.to_path_buf();
            for part in slice {
                dir_path.push(part);
            }
            dir_path.push("mod.ifa");
            if dir_path.is_file() {
                return Some(dir_path);
            }
            None
        };

        for dir in &candidate_dirs {
            if let Some(found) = check_in_dir(dir, &parts) {
                return Some(found);
            }
            if parts.len() > 1 {
                if let Some(found) = check_in_dir(dir, &parts[1..]) {
                    return Some(found);
                }
            }
        }

        None
    }

    /// Analyzes an IFA AST program, automatically resolving imported local submodules
    /// located relative to `base_dir` and lowering them to FIR modules.
    pub fn analyze_with_local_modules(
        source_map: &mut SourceMap,
        base_dir: &Path,
        prog: &ifa_ast::Program,
    ) -> (ifa_sema::AnalysisResult, Vec<ifa_fir::FirModule>) {
        let mut symbols = SymbolTable::new();
        let mut sub_firs = Vec::new();
        let mut loaded_modules = std::collections::HashSet::new();
        let mut extra_diagnostics = Vec::new();

        // Multi-pass resolution: retry unresolved modules if earlier modules had forward dependencies
        let mut resolved_any = true;
        let mut attempts = 0;
        while resolved_any && attempts < 4 {
            resolved_any = false;
            attempts += 1;

            for item in &prog.items {
                if let Item::Import(im) = item {
                    let local_alias = im.alias.unwrap_or_else(|| *im.path.last().unwrap());
                    if loaded_modules.contains(&local_alias) {
                        continue;
                    }

                    if let Some(sub_path) = Self::resolve_module_file(base_dir, &im.path) {
                        if let Ok(sub_src) = fs::read_to_string(&sub_path) {
                            let sub_fid = source_map.add_file(sub_path.to_string_lossy(), &sub_src);
                            let sub_toks = tokenize(sub_fid, &sub_src);
                            let (sub_prog, sub_diags) = parse(sub_fid, sub_toks);
                            if !sub_diags.is_empty() {
                                extra_diagnostics.extend(sub_diags);
                            } else {
                                let sub_res =
                                    analyze_with_symbols(source_map, &sub_prog, symbols.clone());
                                if sub_res.has_errors() {
                                    extra_diagnostics.extend(sub_res.diagnostics);
                                } else {
                                    if let Ok(sub_fir) =
                                        compile_to_fir(&sub_prog, &sub_res.symbols, true, true)
                                    {
                                        sub_firs.push(sub_fir);
                                    }
                                    let path_str = im
                                        .path
                                        .iter()
                                        .map(|s| INTERNER.resolve(s))
                                        .collect::<Vec<_>>()
                                        .join("::");
                                    let path_sym = INTERNER.intern(&path_str);
                                    let mut mod_sym =
                                        symbols.modules.remove(&local_alias).unwrap_or_else(|| {
                                            ModuleSymbol::new(
                                                local_alias,
                                                im.path.clone(),
                                                true,
                                                im.span,
                                            )
                                        });
                                    for f in sub_res.symbols.functions.values() {
                                        mod_sym.add_function(f.clone());
                                    }
                                    for s in sub_res.symbols.structs.values() {
                                        mod_sym.add_struct(s.clone());
                                    }
                                    for e in sub_res.symbols.enums.values() {
                                        mod_sym.add_enum(e.clone());
                                    }
                                    for c in sub_res.symbols.consts.values() {
                                        mod_sym.add_const(c.clone());
                                    }
                                    symbols.modules.insert(local_alias, mod_sym.clone());
                                    symbols.modules.insert(path_sym, mod_sym.clone());
                                    if let Some(last) = im.path.last() {
                                        symbols.modules.insert(*last, mod_sym);
                                    }
                                    loaded_modules.insert(local_alias);
                                    resolved_any = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut analysis = analyze_with_symbols(source_map, prog, symbols);
        analysis.diagnostics.extend(extra_diagnostics);
        (analysis, sub_firs)
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
                    let sub_fir = compile_to_fir_with_opts(
                        &sub_prog,
                        &sub_analysis.symbols,
                        true,
                        true,
                        false,
                        true,
                    )
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
            compile_to_fir_with_opts(&ast_prog, &analysis.symbols, true, true, false, true)
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

        // Merge all compiled submodule FIR definitions into the unified root FIR module
        for sub_fir in sub_fir_modules {
            fir_module.merge(sub_fir);
        }

        // Run whole-module cache layout packing and SROA on the fully unified FIR module
        let mut layout_pass = CacheLayoutPass::new();
        layout_pass.run_on_module(&mut fir_module);

        let mut sroa_pass = SroaPass::new();
        sroa_pass.run_on_module(&mut fir_module);

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
        let _ = fs::remove_file(output_so);

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
