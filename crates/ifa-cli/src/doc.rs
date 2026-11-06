//! Canonical documentation generator for IFA programs and packages (ifa doc).
//! Extracts triple-slash (`///`) docstrings and AST item signatures, producing
//! publication-grade Markdown and standalone responsive HTML documentation.

use ifa_ast::{Enum, Function, Item, Program, Struct};
use ifa_span::{SourceMap, Span, INTERNER};
use std::fs;
use std::path::{Path, PathBuf};

/// Documentation metadata for a single item.
#[derive(Debug, Clone)]
pub struct ItemDoc {
    pub kind: String,
    pub name: String,
    pub signature: String,
    pub docstring: String,
    pub is_pub: bool,
    pub details: Vec<String>,
}

/// Extracted documentation for an IFA program or module.
#[derive(Debug, Clone)]
pub struct ModuleDoc {
    pub module_name: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub overview: String,
    pub functions: Vec<ItemDoc>,
    pub structs: Vec<ItemDoc>,
    pub enums: Vec<ItemDoc>,
    pub constants: Vec<ItemDoc>,
}

impl ModuleDoc {
    pub fn new(module_name: &str) -> Self {
        Self {
            module_name: module_name.to_string(),
            package_name: None,
            package_version: None,
            overview: String::new(),
            functions: Vec::new(),
            structs: Vec::new(),
            enums: Vec::new(),
            constants: Vec::new(),
        }
    }
}

/// Format an AST type into its canonical source-code representation.
pub fn format_ast_type(ty: &ifa_ast::Type) -> String {
    match &ty.kind {
        ifa_ast::TypeKind::Named(s) => INTERNER.resolve(s),
        ifa_ast::TypeKind::Path(p) => {
            let parts: Vec<String> = p.iter().map(|s| INTERNER.resolve(s)).collect();
            parts.join("::")
        }
        ifa_ast::TypeKind::Generic(name, args) => {
            let name_str = INTERNER.resolve(name);
            let args_str: Vec<String> = args.iter().map(format_ast_type).collect();
            format!("{}<{}>", name_str, args_str.join(", "))
        }
        ifa_ast::TypeKind::Ref(inner) => format!("ref {}", format_ast_type(inner)),
        ifa_ast::TypeKind::Optional(inner) => format!("?{}", format_ast_type(inner)),
        ifa_ast::TypeKind::Slice(inner) => format!("Slice<{}>", format_ast_type(inner)),
        ifa_ast::TypeKind::Array(inner, n) => format!("[{}; {}]", format_ast_type(inner), n),
        ifa_ast::TypeKind::ErrorUnion(err, ok) => {
            format!("{}!{}", format_ast_type(err), format_ast_type(ok))
        }
        ifa_ast::TypeKind::Tuple(types) => {
            let parts: Vec<String> = types.iter().map(format_ast_type).collect();
            format!("({})", parts.join(", "))
        }
        ifa_ast::TypeKind::Unit => "()".to_string(),
    }
}

/// Extract documentation from source text and parsed AST.
pub fn extract_module_docs(
    program: &Program,
    source_text: &str,
    source_map: &SourceMap,
    module_name: &str,
) -> ModuleDoc {
    let mut module_doc = ModuleDoc::new(module_name);

    // Extract module-level docstring at the beginning of the file (//!)
    let mut module_lines = Vec::new();
    for line in source_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//!") {
            module_lines.push(trimmed.trim_start_matches("//!").trim());
        } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
            break;
        }
    }
    module_doc.overview = module_lines.join("\n");

    let lines: Vec<&str> = source_text.lines().collect();

    for item in &program.items {
        match item {
            Item::Function(f) => {
                let docstring = extract_preceding_docstrings(f.span, source_map, &lines);
                let sig = format_function_signature(f);
                let name = INTERNER.resolve(&f.name);
                let mut details = Vec::new();
                for p in &f.params {
                    let p_name = INTERNER.resolve(&p.name);
                    details.push(format!(
                        "`{} {}: {}`",
                        p.mode,
                        p_name,
                        format_ast_type(&p.ty)
                    ));
                }

                module_doc.functions.push(ItemDoc {
                    kind: "Function".to_string(),
                    name,
                    signature: sig,
                    docstring,
                    is_pub: f.is_pub,
                    details,
                });
            }
            Item::Struct(s) => {
                let docstring = extract_preceding_docstrings(s.span, source_map, &lines);
                let sig = format_struct_signature(s);
                let name = INTERNER.resolve(&s.name);
                let mut details = Vec::new();
                for fld in &s.fields {
                    let f_name = INTERNER.resolve(&fld.name);
                    let pub_str = if fld.is_pub { "pub " } else { "" };
                    details.push(format!("{pub_str}{f_name}: {}", format_ast_type(&fld.ty)));
                }

                module_doc.structs.push(ItemDoc {
                    kind: "Struct".to_string(),
                    name,
                    signature: sig,
                    docstring,
                    is_pub: s.is_pub,
                    details,
                });
            }
            Item::Enum(e) => {
                let docstring = extract_preceding_docstrings(e.span, source_map, &lines);
                let sig = format_enum_signature(e);
                let name = INTERNER.resolve(&e.name);
                let mut details = Vec::new();
                for v in &e.variants {
                    let v_name = INTERNER.resolve(&v.name);
                    if let Some(payload) = &v.payload {
                        details.push(format!("{v_name}({})", format_ast_type(payload)));
                    } else {
                        details.push(v_name);
                    }
                }

                module_doc.enums.push(ItemDoc {
                    kind: "Enum".to_string(),
                    name,
                    signature: sig,
                    docstring,
                    is_pub: e.is_pub,
                    details,
                });
            }
            Item::Const(c) => {
                let docstring = extract_preceding_docstrings(c.span, source_map, &lines);
                let name = INTERNER.resolve(&c.name);
                let pub_prefix = if c.is_pub { "pub " } else { "" };
                let ty_str =
                    c.ty.as_ref()
                        .map(|t| format!(": {}", format_ast_type(t)))
                        .unwrap_or_default();
                let sig = format!("{pub_prefix}const {name}{ty_str}");

                module_doc.constants.push(ItemDoc {
                    kind: "Constant".to_string(),
                    name,
                    signature: sig,
                    docstring,
                    is_pub: c.is_pub,
                    details: Vec::new(),
                });
            }
            _ => {}
        }
    }

    module_doc
}

fn extract_preceding_docstrings(span: Span, source_map: &SourceMap, lines: &[&str]) -> String {
    let line_idx = if let Some((line, _)) = source_map.lookup_line_col(span) {
        line.saturating_sub(1)
    } else {
        return String::new();
    };

    let mut doc_lines = Vec::new();
    let mut cur = line_idx.saturating_sub(1);
    while cur < lines.len() {
        let trimmed = lines[cur].trim();
        if trimmed.starts_with("///") {
            doc_lines.push(trimmed.trim_start_matches("///").trim());
            if cur == 0 {
                break;
            }
            cur -= 1;
        } else {
            break;
        }
    }

    doc_lines.reverse();
    doc_lines.join("\n")
}

fn format_function_signature(f: &Function) -> String {
    let pub_str = if f.is_pub { "pub " } else { "" };
    let strict_str = if f.is_strict { "strict " } else { "" };
    let comptime_str = if f.is_comptime { "comptime " } else { "" };
    let name = INTERNER.resolve(&f.name);

    let params: Vec<String> = f
        .params
        .iter()
        .map(|p| {
            let p_name = INTERNER.resolve(&p.name);
            format!("{} {}: {}", p.mode, p_name, format_ast_type(&p.ty))
        })
        .collect();

    let ret_str = f
        .ret_ty
        .as_ref()
        .map(|t| format!(" -> {}", format_ast_type(t)))
        .unwrap_or_default();

    format!(
        "{pub_str}{strict_str}{comptime_str}fn {name}({}){ret_str}",
        params.join(", ")
    )
}

fn format_struct_signature(s: &Struct) -> String {
    let pub_str = if s.is_pub { "pub " } else { "" };
    let name = INTERNER.resolve(&s.name);
    format!("{pub_str}struct {name}")
}

fn format_enum_signature(e: &Enum) -> String {
    let pub_str = if e.is_pub { "pub " } else { "" };
    let name = INTERNER.resolve(&e.name);
    format!("{pub_str}enum {name}")
}

/// Render module documentation into standard Markdown format.
pub fn render_markdown(doc: &ModuleDoc) -> String {
    let mut md = String::new();

    md.push_str(&format!("# Module `{}`\n\n", doc.module_name));

    if let (Some(pkg), Some(ver)) = (&doc.package_name, &doc.package_version) {
        md.push_str(&format!("**Package:** `{pkg}` v{ver}  \n\n"));
    }

    if !doc.overview.is_empty() {
        md.push_str("## Overview\n\n");
        md.push_str(&doc.overview);
        md.push_str("\n\n");
    }

    if !doc.functions.is_empty() {
        md.push_str("## Functions\n\n");
        for f in &doc.functions {
            md.push_str(&format!("### `{}`\n\n", f.name));
            md.push_str(&format!("```ifa\n{}\n```\n\n", f.signature));
            if !f.docstring.is_empty() {
                md.push_str(&f.docstring);
                md.push_str("\n\n");
            }
            if !f.details.is_empty() {
                md.push_str("**Parameters:**\n\n");
                for p in &f.details {
                    md.push_str(&format!("- {p}\n"));
                }
                md.push('\n');
            }
        }
    }

    if !doc.structs.is_empty() {
        md.push_str("## Structs\n\n");
        for s in &doc.structs {
            md.push_str(&format!("### `{}`\n\n", s.name));
            md.push_str(&format!("```ifa\n{}\n```\n\n", s.signature));
            if !s.docstring.is_empty() {
                md.push_str(&s.docstring);
                md.push_str("\n\n");
            }
            if !s.details.is_empty() {
                md.push_str("**Fields:**\n\n");
                for f in &s.details {
                    md.push_str(&format!("- `{f}`\n"));
                }
                md.push('\n');
            }
        }
    }

    if !doc.enums.is_empty() {
        md.push_str("## Enums\n\n");
        for e in &doc.enums {
            md.push_str(&format!("### `{}`\n\n", e.name));
            md.push_str(&format!("```ifa\n{}\n```\n\n", e.signature));
            if !e.docstring.is_empty() {
                md.push_str(&e.docstring);
                md.push_str("\n\n");
            }
            if !e.details.is_empty() {
                md.push_str("**Variants:**\n\n");
                for v in &e.details {
                    md.push_str(&format!("- `{v}`\n"));
                }
                md.push('\n');
            }
        }
    }

    if !doc.constants.is_empty() {
        md.push_str("## Constants\n\n");
        for c in &doc.constants {
            md.push_str(&format!("### `{}`\n\n", c.name));
            md.push_str(&format!("```ifa\n{}\n```\n\n", c.signature));
            if !c.docstring.is_empty() {
                md.push_str(&c.docstring);
                md.push_str("\n\n");
            }
        }
    }

    md
}

pub const HTML_CSS_STYLES: &str = r#"
        :root {
            --bg: #0f141c;
            --surface: #18202c;
            --border: #283548;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --primary: #38bdf8;
            --code-bg: #1e293b;
            --accent: #22c55e;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        header {
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }
        h1 { color: #f8fafc; margin-bottom: 0.5rem; font-size: 2.25rem; }
        h2 { color: var(--primary); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-top: 2rem; }
        h3 { color: #f1f5f9; margin-top: 1.5rem; }
        pre {
            background: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.95rem;
            color: #38bdf8;
        }
        code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            background: var(--surface);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
        }
        .item-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1.5rem;
        }
        .badge {
            display: inline-block;
            font-size: 0.75rem;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            background: #0369a1;
            color: #e0f2fe;
            margin-right: 0.5rem;
            text-transform: uppercase;
            font-weight: 600;
        }
        .badge-pub { background: #15803d; color: #dcfce7; }
        ul { padding-left: 1.5rem; }
        li { margin-bottom: 0.25rem; }
        footer {
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-size: 0.875rem;
            text-align: center;
        }
    "#;

/// Render module documentation into a standalone HTML page.
pub fn render_html(doc: &ModuleDoc) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!(
        "<title>Module {} - IFA Documentation</title>\n",
        doc.module_name
    ));
    html.push_str("<style>\n");
    html.push_str(HTML_CSS_STYLES);
    html.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    html.push_str("<header>\n");
    html.push_str(&format!(
        "<h1>Module <code>{}</code></h1>\n",
        doc.module_name
    ));
    if let (Some(pkg), Some(ver)) = (&doc.package_name, &doc.package_version) {
        html.push_str(&format!(
            "<p>Package: <strong>{}</strong> v{}</p>\n",
            pkg, ver
        ));
    }
    html.push_str("</header>\n");

    if !doc.overview.is_empty() {
        html.push_str("<section>\n<h2>Overview</h2>\n");
        html.push_str(&format!("<p>{}</p>\n", doc.overview.replace('\n', "<br>")));
        html.push_str("</section>\n");
    }

    if !doc.functions.is_empty() {
        html.push_str("<section>\n<h2>Functions</h2>\n");
        for f in &doc.functions {
            html.push_str("<div class=\"item-card\">\n");
            let pub_badge = if f.is_pub {
                "<span class=\"badge badge-pub\">public</span>"
            } else {
                ""
            };
            let kind_badge = format!("<span class=\"badge\">{}</span>", f.kind.to_lowercase());
            html.push_str(&format!(
                "<h3>{pub_badge}{kind_badge}<code>{}</code></h3>\n",
                f.name
            ));
            html.push_str(&format!("<pre><code>{}</code></pre>\n", f.signature));
            if !f.docstring.is_empty() {
                html.push_str(&format!("<p>{}</p>\n", f.docstring.replace('\n', "<br>")));
            }
            if !f.details.is_empty() {
                html.push_str("<p><strong>Parameters:</strong></p>\n<ul>\n");
                for p in &f.details {
                    html.push_str(&format!("<li>{}</li>\n", p));
                }
                html.push_str("</ul>\n");
            }
            html.push_str("</div>\n");
        }
        html.push_str("</section>\n");
    }

    if !doc.structs.is_empty() {
        html.push_str("<section>\n<h2>Structs</h2>\n");
        for s in &doc.structs {
            html.push_str("<div class=\"item-card\">\n");
            let pub_badge = if s.is_pub {
                "<span class=\"badge badge-pub\">public</span>"
            } else {
                ""
            };
            let kind_badge = format!("<span class=\"badge\">{}</span>", s.kind.to_lowercase());
            html.push_str(&format!(
                "<h3>{pub_badge}{kind_badge}<code>{}</code></h3>\n",
                s.name
            ));
            html.push_str(&format!("<pre><code>{}</code></pre>\n", s.signature));
            if !s.docstring.is_empty() {
                html.push_str(&format!("<p>{}</p>\n", s.docstring.replace('\n', "<br>")));
            }
            if !s.details.is_empty() {
                html.push_str("<p><strong>Fields:</strong></p>\n<ul>\n");
                for fld in &s.details {
                    html.push_str(&format!("<li><code>{}</code></li>\n", fld));
                }
                html.push_str("</ul>\n");
            }
            html.push_str("</div>\n");
        }
        html.push_str("</section>\n");
    }

    if !doc.enums.is_empty() {
        html.push_str("<section>\n<h2>Enums</h2>\n");
        for e in &doc.enums {
            html.push_str("<div class=\"item-card\">\n");
            let pub_badge = if e.is_pub {
                "<span class=\"badge badge-pub\">public</span>"
            } else {
                ""
            };
            let kind_badge = format!("<span class=\"badge\">{}</span>", e.kind.to_lowercase());
            html.push_str(&format!(
                "<h3>{pub_badge}{kind_badge}<code>{}</code></h3>\n",
                e.name
            ));
            html.push_str(&format!("<pre><code>{}</code></pre>\n", e.signature));
            if !e.docstring.is_empty() {
                html.push_str(&format!("<p>{}</p>\n", e.docstring.replace('\n', "<br>")));
            }
            if !e.details.is_empty() {
                html.push_str("<p><strong>Variants:</strong></p>\n<ul>\n");
                for v in &e.details {
                    html.push_str(&format!("<li><code>{}</code></li>\n", v));
                }
                html.push_str("</ul>\n");
            }
            html.push_str("</div>\n");
        }
        html.push_str("</section>\n");
    }

    if !doc.constants.is_empty() {
        html.push_str("<section>\n<h2>Constants</h2>\n");
        for c in &doc.constants {
            html.push_str("<div class=\"item-card\">\n");
            let pub_badge = if c.is_pub {
                "<span class=\"badge badge-pub\">public</span>"
            } else {
                ""
            };
            let kind_badge = format!("<span class=\"badge\">{}</span>", c.kind.to_lowercase());
            html.push_str(&format!(
                "<h3>{pub_badge}{kind_badge}<code>{}</code></h3>\n",
                c.name
            ));
            html.push_str(&format!("<pre><code>{}</code></pre>\n", c.signature));
            if !c.docstring.is_empty() {
                html.push_str(&format!("<p>{}</p>\n", c.docstring.replace('\n', "<br>")));
            }
            html.push_str("</div>\n");
        }
        html.push_str("</section>\n");
    }

    html.push_str("<footer>\nGenerated canonically by <code>ifa doc</code> — Deterministic Language Ecosystem\n</footer>\n");
    html.push_str("</div>\n</body>\n</html>\n");

    html
}

/// Render a canonical index page in Markdown listing all modules of a package.
pub fn render_package_index_markdown(
    package_name: &str,
    package_version: Option<&str>,
    modules: &[ModuleDoc],
) -> String {
    let mut md = String::new();
    let version_str = package_version
        .map(|v| format!(" v{v}"))
        .unwrap_or_default();
    md.push_str(&format!("# Package `{package_name}`{version_str}\n\n"));
    md.push_str("IFA Language Package Reference Book\n\n");
    md.push_str("## Modules\n\n");
    for m in modules {
        md.push_str(&format!(
            "### [{}]({}.md)\n\n",
            m.module_name, m.module_name
        ));
        if !m.overview.is_empty() {
            md.push_str(&format!("{}\n\n", m.overview));
        }
        let total_items = m.functions.len() + m.structs.len() + m.enums.len() + m.constants.len();
        md.push_str(&format!(
            "- **Exported items**: {} ({} functions, {} structs, {} enums, {} constants)\n\n",
            total_items,
            m.functions.len(),
            m.structs.len(),
            m.enums.len(),
            m.constants.len()
        ));
    }
    md
}

/// Render a canonical standalone index page in responsive HTML listing all modules of a package.
pub fn render_package_index_html(
    package_name: &str,
    package_version: Option<&str>,
    modules: &[ModuleDoc],
) -> String {
    let mut html = String::new();
    let version_str = package_version
        .map(|v| format!(" v{v}"))
        .unwrap_or_default();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!(
        "<title>{} — Package Documentation</title>\n",
        package_name
    ));
    html.push_str("<style>\n");
    html.push_str(HTML_CSS_STYLES);
    html.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    html.push_str("<header>\n");
    html.push_str(&format!(
        "<h1>Package <code>{}</code>{}</h1>\n",
        package_name, version_str
    ));
    html.push_str("<p>IFA Language Package Reference Book & Architecture Specifications</p>\n");
    html.push_str("</header>\n");

    html.push_str("<section>\n<h2>Modules</h2>\n");
    for m in modules {
        html.push_str("<div class=\"item-card\">\n");
        html.push_str(&format!(
            "<h3><a href=\"{}.html\" style=\"color: #38bdf8; text-decoration: none;\"><code>{}</code></a></h3>\n",
            m.module_name, m.module_name
        ));
        if !m.overview.is_empty() {
            html.push_str(&format!("<p>{}</p>\n", m.overview.replace('\n', "<br>")));
        }
        html.push_str(&format!(
            "<p><span class=\"badge\">{} functions</span> <span class=\"badge\">{} structs</span> <span class=\"badge\">{} enums</span> <span class=\"badge\">{} constants</span></p>\n",
            m.functions.len(), m.structs.len(), m.enums.len(), m.constants.len()
        ));
        html.push_str("</div>\n");
    }
    html.push_str("</section>\n");

    html.push_str("<footer>\nGenerated canonically by <code>ifa doc</code> — Deterministic Language Ecosystem\n</footer>\n");
    html.push_str("</div>\n</body>\n</html>\n");
    html
}

/// Generate documentation files on disk for a given source file or package.
pub fn generate_docs(
    input_path: &Path,
    output_dir: Option<&Path>,
    format: &str,
) -> Result<PathBuf, String> {
    if input_path.is_dir() {
        generate_package_docs(input_path, output_dir, format)
    } else {
        generate_single_file_docs(input_path, output_dir, format)
    }
}

fn generate_single_file_docs(
    source_path: &Path,
    output_dir: Option<&Path>,
    format: &str,
) -> Result<PathBuf, String> {
    let source_text = fs::read_to_string(source_path).map_err(|e| {
        format!(
            "Failed to read source file {}: {}",
            source_path.display(),
            e
        )
    })?;

    let module_name = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("main");

    let mut sm = SourceMap::new();
    let fid = sm.add_file(source_path.to_string_lossy().as_ref(), &source_text);
    let tokens = ifa_lexer::tokenize(fid, &source_text);
    let (program, diags) = ifa_parser::parse(fid, tokens);

    if !diags.is_empty() {
        return Err(format!(
            "Parsing failed with {} syntax errors; cannot generate documentation",
            diags.len()
        ));
    }

    let mut doc = extract_module_docs(&program, &source_text, &sm, module_name);

    let root_dir = source_path.parent().unwrap_or(Path::new("."));
    let manifest_path = root_dir.join("kori.toml");
    if manifest_path.exists() {
        if let Ok(manifest) = kori::manifest::Manifest::from_file(&manifest_path) {
            doc.package_name = Some(manifest.package.name);
            doc.package_version = Some(manifest.package.version);
        }
    }

    let out_dir = match output_dir {
        Some(d) => d.to_path_buf(),
        None => root_dir.join("docs"),
    };
    fs::create_dir_all(&out_dir).map_err(|e| {
        format!(
            "Failed to create documentation directory {}: {}",
            out_dir.display(),
            e
        )
    })?;

    if format == "all" || format == "markdown" {
        let md = render_markdown(&doc);
        let md_path = out_dir.join(format!("{module_name}.md"));
        fs::write(&md_path, md)
            .map_err(|e| format!("Failed to write Markdown documentation: {}", e))?;
    }

    if format == "all" || format == "html" {
        let html = render_html(&doc);
        let html_path = out_dir.join(format!("{module_name}.html"));
        fs::write(&html_path, html)
            .map_err(|e| format!("Failed to write HTML documentation: {}", e))?;
    }

    Ok(out_dir)
}

fn generate_package_docs(
    package_dir: &Path,
    output_dir: Option<&Path>,
    format: &str,
) -> Result<PathBuf, String> {
    let src_dir = package_dir.join("src");
    let search_dir = if src_dir.is_dir() {
        &src_dir
    } else {
        package_dir
    };

    let mut ifa_files = Vec::new();
    let entries = fs::read_dir(search_dir).map_err(|e| {
        format!(
            "Failed to read package directory {}: {}",
            search_dir.display(),
            e
        )
    })?;

    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("ifa") {
            ifa_files.push(p);
        }
    }

    ifa_files.sort();

    if ifa_files.is_empty() {
        return Err(format!(
            "No `.ifa` source files found in package directory: {}",
            search_dir.display()
        ));
    }

    let out_dir = match output_dir {
        Some(d) => d.to_path_buf(),
        None => package_dir.join("docs"),
    };
    fs::create_dir_all(&out_dir).map_err(|e| {
        format!(
            "Failed to create documentation directory {}: {}",
            out_dir.display(),
            e
        )
    })?;

    let mut pkg_name = package_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("package")
        .to_string();
    let mut pkg_version = None;

    let manifest_path = package_dir.join("kori.toml");
    if manifest_path.exists() {
        if let Ok(manifest) = kori::manifest::Manifest::from_file(&manifest_path) {
            pkg_name = manifest.package.name;
            pkg_version = Some(manifest.package.version);
        }
    }

    let mut modules = Vec::new();

    for file_path in &ifa_files {
        let source_text = fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read source file {}: {}", file_path.display(), e))?;

        let module_name = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("module");

        let mut sm = SourceMap::new();
        let fid = sm.add_file(file_path.to_string_lossy().as_ref(), &source_text);
        let tokens = ifa_lexer::tokenize(fid, &source_text);
        let (program, diags) = ifa_parser::parse(fid, tokens);

        if !diags.is_empty() {
            return Err(format!(
                "Parsing failed for `{}` with {} syntax errors",
                file_path.display(),
                diags.len()
            ));
        }

        let mut doc = extract_module_docs(&program, &source_text, &sm, module_name);
        doc.package_name = Some(pkg_name.clone());
        doc.package_version = pkg_version.clone();

        if format == "all" || format == "markdown" {
            let md = render_markdown(&doc);
            let md_path = out_dir.join(format!("{module_name}.md"));
            fs::write(&md_path, md)
                .map_err(|e| format!("Failed to write Markdown documentation: {}", e))?;
        }

        if format == "all" || format == "html" {
            let html = render_html(&doc);
            let html_path = out_dir.join(format!("{module_name}.html"));
            fs::write(&html_path, html)
                .map_err(|e| format!("Failed to write HTML documentation: {}", e))?;
        }

        modules.push(doc);
    }

    // Generate canonical package index book
    if format == "all" || format == "markdown" {
        let index_md = render_package_index_markdown(&pkg_name, pkg_version.as_deref(), &modules);
        let index_md_path = out_dir.join("index.md");
        fs::write(&index_md_path, index_md)
            .map_err(|e| format!("Failed to write package index Markdown: {}", e))?;
    }

    if format == "all" || format == "html" {
        let index_html = render_package_index_html(&pkg_name, pkg_version.as_deref(), &modules);
        let index_html_path = out_dir.join("index.html");
        fs::write(&index_html_path, index_html)
            .map_err(|e| format!("Failed to write package index HTML: {}", e))?;
    }

    Ok(out_dir)
}
