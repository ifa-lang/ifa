use crate::document::DocumentStore;
use crate::handlers::{
    code_actions, completion, definition, formatting, hover, inlay_hints, references, rename,
    semantic_tokens, signature_help, symbols, workspace_symbols,
};
use crate::protocol::*;
use std::io::{self, BufRead, Read, Write};

/// IFA Language Server Protocol engine instance.
pub struct LanguageServer {
    documents: DocumentStore,
    is_shutdown: bool,
}

impl Default for LanguageServer {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageServer {
    pub fn new() -> Self {
        Self {
            documents: DocumentStore::new(),
            is_shutdown: false,
        }
    }

    /// Run the server loop processing standard input/output until `exit` is received.
    pub fn run_stdio(&mut self) -> io::Result<()> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let stdout = io::stdout();
        let mut writer = stdout.lock();

        loop {
            let mut line = String::new();
            let mut content_length: Option<usize> = None;

            // Read headers
            loop {
                line.clear();
                let bytes_read = reader.read_line(&mut line)?;
                if bytes_read == 0 {
                    return Ok(()); // EOF
                }

                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break; // Header/content delimiter reached
                }

                if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
                    if let Ok(len) = rest.trim().parse::<usize>() {
                        content_length = Some(len);
                    }
                }
            }

            let len = match content_length {
                Some(l) => l,
                None => continue,
            };

            let mut body = vec![0u8; len];
            reader.read_exact(&mut body)?;

            let msg_str = match std::str::from_utf8(&body) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let (response, notif) = self.handle_message(msg_str);

            if let Some(resp_json) = response {
                write_message(&mut writer, &resp_json)?;
            }

            if let Some(notif_json) = notif {
                write_message(&mut writer, &notif_json)?;
            }

            if self.is_shutdown {
                break;
            }
        }

        Ok(())
    }

    /// Process a raw JSON-RPC string message and return optional response and notification payloads.
    pub fn handle_message(&mut self, raw: &str) -> (Option<String>, Option<String>) {
        // Try parsing as Request
        if let Ok(req) = serde_json::from_str::<Request>(raw) {
            let (resp, notif) = self.dispatch_request(req);
            let resp_str = resp.and_then(|r| serde_json::to_string(&r).ok());
            let notif_str = notif.and_then(|n| serde_json::to_string(&n).ok());
            return (resp_str, notif_str);
        }

        // Try parsing as Notification
        if let Ok(notif) = serde_json::from_str::<Notification>(raw) {
            let outgoing_notif = self.dispatch_notification(notif);
            let notif_str = outgoing_notif.and_then(|n| serde_json::to_string(&n).ok());
            return (None, notif_str);
        }

        (
            Some(
                serde_json::to_string(&Response::err(
                    serde_json::Value::Null,
                    PARSE_ERROR,
                    "Failed to parse JSON-RPC message",
                ))
                .unwrap(),
            ),
            None,
        )
    }

    fn dispatch_request(&mut self, req: Request) -> (Option<Response>, Option<Notification>) {
        match req.method.as_str() {
            "initialize" => {
                let caps = ServerCapabilities {
                    text_document_sync: 1, // Full sync
                    hover_provider: true,
                    completion_provider: CompletionOptions {
                        trigger_characters: vec![".".to_string(), ":".to_string(), "@".to_string()],
                    },
                    definition_provider: true,
                    references_provider: true,
                    rename_provider: true,
                    document_symbol_provider: true,
                    workspace_symbol_provider: true,
                    document_formatting_provider: true,
                    semantic_tokens_provider: Some(SemanticTokensOptionsWithLegend {
                        legend: semantic_tokens::get_semantic_tokens_legend(),
                        full: Some(true),
                    }),
                    inlay_hint_provider: Some(true),
                    code_action_provider: Some(true),
                    signature_help_provider: Some(SignatureHelpOptions {
                        trigger_characters: vec!["(".to_string(), ",".to_string()],
                    }),
                };
                let result = InitializeResult {
                    capabilities: caps,
                    server_info: ServerInfo {
                        name: "ifa-lsp".to_string(),
                        version: "0.1.0".to_string(),
                    },
                };
                (
                    Some(Response::ok(req.id, serde_json::to_value(result).unwrap())),
                    None,
                )
            }

            "shutdown" => {
                self.is_shutdown = true;
                (Some(Response::ok(req.id, serde_json::Value::Null)), None)
            }

            "textDocument/completion" => {
                let params: CompletionParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid CompletionParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => {
                        return (
                            Some(Response::ok(
                                req.id,
                                serde_json::to_value(CompletionList {
                                    is_incomplete: false,
                                    items: Vec::new(),
                                })
                                .unwrap(),
                            )),
                            None,
                        )
                    }
                };
                let list = completion::handle_completion(doc, params.position);
                (
                    Some(Response::ok(req.id, serde_json::to_value(list).unwrap())),
                    None,
                )
            }

            "textDocument/hover" => {
                let params: HoverParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(req.id, INVALID_PARAMS, "Invalid HoverParams")),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => return (Some(Response::ok(req.id, serde_json::Value::Null)), None),
                };
                let hover_res = hover::handle_hover(doc, params.position);
                (
                    Some(Response::ok(
                        req.id,
                        serde_json::to_value(hover_res).unwrap_or(serde_json::Value::Null),
                    )),
                    None,
                )
            }

            "textDocument/definition" => {
                let params: DefinitionParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid DefinitionParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => return (Some(Response::ok(req.id, serde_json::Value::Null)), None),
                };
                let loc = definition::handle_definition(doc, params.position);
                (
                    Some(Response::ok(
                        req.id,
                        serde_json::to_value(loc).unwrap_or(serde_json::Value::Null),
                    )),
                    None,
                )
            }

            "textDocument/references" => {
                let params: ReferenceParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid ReferenceParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => {
                        return (
                            Some(Response::ok(req.id, serde_json::Value::Array(Vec::new()))),
                            None,
                        )
                    }
                };
                let locs = references::handle_workspace_references(&self.documents, doc, params);
                (
                    Some(Response::ok(req.id, serde_json::to_value(locs).unwrap())),
                    None,
                )
            }

            "textDocument/prepareRename" => {
                let params: PrepareRenameParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid PrepareRenameParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => return (Some(Response::ok(req.id, serde_json::Value::Null)), None),
                };
                let range = rename::handle_prepare_rename(doc, params.position);
                (
                    Some(Response::ok(
                        req.id,
                        serde_json::to_value(range).unwrap_or(serde_json::Value::Null),
                    )),
                    None,
                )
            }

            "textDocument/rename" => {
                let params: RenameParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid RenameParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => return (Some(Response::ok(req.id, serde_json::Value::Null)), None),
                };
                let edit = rename::handle_workspace_rename(&self.documents, doc, params);
                (
                    Some(Response::ok(
                        req.id,
                        serde_json::to_value(edit).unwrap_or(serde_json::Value::Null),
                    )),
                    None,
                )
            }

            "textDocument/semanticTokens/full" => {
                let params: SemanticTokensParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid SemanticTokensParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => {
                        return (
                            Some(Response::ok(
                                req.id,
                                serde_json::to_value(SemanticTokens::default()).unwrap(),
                            )),
                            None,
                        )
                    }
                };
                let tokens = semantic_tokens::handle_semantic_tokens(doc);
                (
                    Some(Response::ok(req.id, serde_json::to_value(tokens).unwrap())),
                    None,
                )
            }

            "textDocument/inlayHint" => {
                let params: InlayHintParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid InlayHintParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => {
                        return (
                            Some(Response::ok(req.id, serde_json::Value::Array(Vec::new()))),
                            None,
                        )
                    }
                };
                let hints = inlay_hints::handle_inlay_hints(doc, params.range);
                (
                    Some(Response::ok(req.id, serde_json::to_value(hints).unwrap())),
                    None,
                )
            }

            "textDocument/codeAction" => {
                let params: CodeActionParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid CodeActionParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => {
                        return (
                            Some(Response::ok(req.id, serde_json::Value::Array(Vec::new()))),
                            None,
                        )
                    }
                };
                let actions = code_actions::handle_code_actions(doc, params);
                (
                    Some(Response::ok(req.id, serde_json::to_value(actions).unwrap())),
                    None,
                )
            }

            "textDocument/signatureHelp" => {
                let params: SignatureHelpParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid SignatureHelpParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => return (Some(Response::ok(req.id, serde_json::Value::Null)), None),
                };
                let sig = signature_help::handle_signature_help(doc, params.position);
                (
                    Some(Response::ok(
                        req.id,
                        serde_json::to_value(sig).unwrap_or(serde_json::Value::Null),
                    )),
                    None,
                )
            }

            "textDocument/documentSymbol" => {
                let params: DocumentSymbolParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid DocumentSymbolParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => {
                        return (
                            Some(Response::ok(req.id, serde_json::Value::Array(Vec::new()))),
                            None,
                        )
                    }
                };
                let syms = symbols::handle_document_symbols(doc);
                (
                    Some(Response::ok(req.id, serde_json::to_value(syms).unwrap())),
                    None,
                )
            }

            "workspace/symbol" => {
                let params: WorkspaceSymbolParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid WorkspaceSymbolParams",
                                )),
                                None,
                            )
                        }
                    };
                let syms =
                    workspace_symbols::handle_workspace_symbols(&self.documents, &params.query);
                (
                    Some(Response::ok(req.id, serde_json::to_value(syms).unwrap())),
                    None,
                )
            }

            "textDocument/formatting" => {
                let params: DocumentFormattingParams =
                    match req.params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return (
                                Some(Response::err(
                                    req.id,
                                    INVALID_PARAMS,
                                    "Invalid DocumentFormattingParams",
                                )),
                                None,
                            )
                        }
                    };
                let doc = match self.documents.get(&params.text_document.uri) {
                    Some(d) => d,
                    None => {
                        return (
                            Some(Response::ok(req.id, serde_json::Value::Array(Vec::new()))),
                            None,
                        )
                    }
                };
                let edits = formatting::handle_formatting(doc);
                (
                    Some(Response::ok(req.id, serde_json::to_value(edits).unwrap())),
                    None,
                )
            }

            _ => (
                Some(Response::err(
                    req.id,
                    METHOD_NOT_FOUND,
                    format!("Method `{}` not found", req.method),
                )),
                None,
            ),
        }
    }

    fn dispatch_notification(&mut self, notif: Notification) -> Option<Notification> {
        match notif.method.as_str() {
            "initialized" => None,

            "textDocument/didOpen" => {
                let params: DidOpenTextDocumentParams =
                    notif.params.and_then(|p| serde_json::from_value(p).ok())?;
                let doc = self.documents.open(
                    params.text_document.uri.clone(),
                    params.text_document.version,
                    params.text_document.text,
                );
                let diag_params = PublishDiagnosticsParams {
                    uri: doc.uri.clone(),
                    diagnostics: doc.diagnostics.clone(),
                    version: Some(doc.version),
                };
                Some(Notification::new(
                    "textDocument/publishDiagnostics",
                    serde_json::to_value(diag_params).unwrap(),
                ))
            }

            "textDocument/didChange" => {
                let params: DidChangeTextDocumentParams =
                    notif.params.and_then(|p| serde_json::from_value(p).ok())?;
                let new_text = params.content_changes.last()?.text.clone();
                let doc = self.documents.update(
                    &params.text_document.uri,
                    params.text_document.version,
                    new_text,
                )?;
                let diag_params = PublishDiagnosticsParams {
                    uri: doc.uri.clone(),
                    diagnostics: doc.diagnostics.clone(),
                    version: Some(doc.version),
                };
                Some(Notification::new(
                    "textDocument/publishDiagnostics",
                    serde_json::to_value(diag_params).unwrap(),
                ))
            }

            "textDocument/didClose" => {
                let params: DidCloseTextDocumentParams =
                    notif.params.and_then(|p| serde_json::from_value(p).ok())?;
                self.documents.close(&params.text_document.uri);
                None
            }

            "textDocument/didSave" => {
                let params: DidSaveTextDocumentParams =
                    notif.params.and_then(|p| serde_json::from_value(p).ok())?;
                let doc = self.documents.get_mut(&params.text_document.uri)?;
                doc.reparse_and_analyze();
                let diag_params = PublishDiagnosticsParams {
                    uri: doc.uri.clone(),
                    diagnostics: doc.diagnostics.clone(),
                    version: Some(doc.version),
                };
                Some(Notification::new(
                    "textDocument/publishDiagnostics",
                    serde_json::to_value(diag_params).unwrap(),
                ))
            }

            _ => None,
        }
    }
}

fn write_message<W: Write>(writer: &mut W, body: &str) -> io::Result<()> {
    write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
    writer.flush()
}
