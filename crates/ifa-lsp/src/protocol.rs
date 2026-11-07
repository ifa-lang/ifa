use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 Request Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 Response Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// JSON-RPC 2.0 Notification Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl Notification {
    pub fn new(method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params: Some(params),
        }
    }
}

/// JSON-RPC Error specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// Zero-based position in a text document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

impl Position {
    pub fn new(line: u32, character: u32) -> Self {
        Self { line, character }
    }
}

/// Range in a text document expressed as (start, end) positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }
}

/// Location in a text document (URI + Range).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub uri: String,
    pub range: Range,
}

/// Text document identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextDocumentIdentifier {
    pub uri: String,
}

/// Versioned text document identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedTextDocumentIdentifier {
    pub uri: String,
    pub version: i64,
}

/// Text document item sent on didOpen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextDocumentItem {
    pub uri: String,
    #[serde(rename = "languageId")]
    pub language_id: String,
    pub version: i64,
    pub text: String,
}

/// DidOpenTextDocument notification parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidOpenTextDocumentParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentItem,
}

/// Content change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextDocumentContentChangeEvent {
    pub text: String,
}

/// DidChangeTextDocument notification parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidChangeTextDocumentParams {
    #[serde(rename = "textDocument")]
    pub text_document: VersionedTextDocumentIdentifier,
    #[serde(rename = "contentChanges")]
    pub content_changes: Vec<TextDocumentContentChangeEvent>,
}

/// DidCloseTextDocument notification parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidCloseTextDocumentParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
}

/// DidSaveTextDocument notification parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidSaveTextDocumentParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
}

/// Diagnostic severity matching LSP 3.17.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum DiagnosticSeverity {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4,
}

/// Diagnostic item reported to the editor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub range: Range,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub message: String,
}

/// Parameters for publishDiagnostics notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishDiagnosticsParams {
    pub uri: String,
    pub diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

/// Markup content for Hover and documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkupContent {
    pub kind: String,
    pub value: String,
}

impl MarkupContent {
    pub fn markdown(value: impl Into<String>) -> Self {
        Self {
            kind: "markdown".to_string(),
            value: value.into(),
        }
    }

    pub fn plaintext(value: impl Into<String>) -> Self {
        Self {
            kind: "plaintext".to_string(),
            value: value.into(),
        }
    }
}

/// Parameters for Hover request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoverParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

/// Hover result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hover {
    pub contents: MarkupContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<Range>,
}

/// Completion trigger kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum CompletionItemKind {
    Text = 1,
    Method = 2,
    Function = 3,
    Constructor = 4,
    Field = 5,
    Variable = 6,
    Class = 7,
    Interface = 8,
    Module = 9,
    Property = 10,
    Unit = 11,
    Value = 12,
    Enum = 13,
    Keyword = 14,
    Snippet = 15,
    Color = 16,
    File = 17,
    Reference = 18,
    Folder = 19,
    EnumMember = 20,
    Constant = 21,
    Struct = 22,
    Event = 23,
    Operator = 24,
    TypeParameter = 25,
}

/// Completion item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionItem {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<MarkupContent>,
    #[serde(rename = "insertText", skip_serializing_if = "Option::is_none")]
    pub insert_text: Option<String>,
}

impl CompletionItem {
    pub fn new(label: impl Into<String>, kind: CompletionItemKind) -> Self {
        Self {
            label: label.into(),
            kind: Some(kind as u32),
            detail: None,
            documentation: None,
            insert_text: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_doc(mut self, doc: impl Into<String>) -> Self {
        self.documentation = Some(MarkupContent::markdown(doc));
        self
    }
}

/// Parameters for Completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

/// Completion list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionList {
    #[serde(rename = "isIncomplete")]
    pub is_incomplete: bool,
    pub items: Vec<CompletionItem>,
}

/// Parameters for Definition request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

/// Symbol kind for document symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum SymbolKind {
    File = 1,
    Module = 2,
    Namespace = 3,
    Package = 4,
    Class = 5,
    Method = 6,
    Property = 7,
    Field = 8,
    Constructor = 9,
    Enum = 10,
    Interface = 11,
    Function = 12,
    Variable = 13,
    Constant = 14,
    String = 15,
    Number = 16,
    Boolean = 17,
    Array = 18,
    Object = 19,
    Key = 20,
    Null = 21,
    EnumMember = 22,
    Struct = 23,
    Event = 24,
    Operator = 25,
    TypeParameter = 26,
}

/// Hierarchical document symbol for outline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSymbol {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub kind: u32,
    pub range: Range,
    #[serde(rename = "selectionRange")]
    pub selection_range: Range,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<DocumentSymbol>>,
}

/// Parameters for DocumentSymbol request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSymbolParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
}

/// TextEdit for formatting or refactoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEdit {
    pub range: Range,
    #[serde(rename = "newText")]
    pub new_text: String,
}

/// Parameters for DocumentFormatting request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentFormattingParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
}

/// Parameters for Find References request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceContext {
    #[serde(rename = "includeDeclaration")]
    pub include_declaration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
    pub context: ReferenceContext,
}

/// Parameters for Prepare Rename request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareRenameParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

/// Parameters for Rename request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
    #[serde(rename = "newName")]
    pub new_name: String,
}

/// WorkspaceEdit represents changes to many resources managed in the workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WorkspaceEdit {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<std::collections::HashMap<String, Vec<TextEdit>>>,
}

/// Legend of token types and token modifiers supported by Semantic Tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTokensLegend {
    #[serde(rename = "tokenTypes")]
    pub token_types: Vec<String>,
    #[serde(rename = "tokenModifiers")]
    pub token_modifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTokensOptionsWithLegend {
    pub legend: SemanticTokensLegend,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
}

/// Parameters for SemanticTokens request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTokensParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
}

/// SemanticTokens data response encoded as relative delta integers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SemanticTokens {
    #[serde(rename = "resultId", skip_serializing_if = "Option::is_none")]
    pub result_id: Option<String>,
    pub data: Vec<u32>,
}

/// Parameters for Inlay Hints request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlayHintParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum InlayHintKind {
    Type = 1,
    Parameter = 2,
}

/// Inlay hint display item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlayHint {
    pub position: Position,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<u32>,
    #[serde(rename = "paddingLeft", skip_serializing_if = "Option::is_none")]
    pub padding_left: Option<bool>,
    #[serde(rename = "paddingRight", skip_serializing_if = "Option::is_none")]
    pub padding_right: Option<bool>,
}

/// Parameters for CodeAction request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeActionContext {
    pub diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeActionParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub range: Range,
    pub context: CodeActionContext,
}

/// Code action response item (e.g. quickfix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAction {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Vec<Diagnostic>>,
    #[serde(rename = "isPreferred", skip_serializing_if = "Option::is_none")]
    pub is_preferred: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edit: Option<WorkspaceEdit>,
}

/// Parameters for Signature Help request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureHelpParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInformation {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<MarkupContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInformation {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<MarkupContent>,
    pub parameters: Vec<ParameterInformation>,
    #[serde(rename = "activeParameter", skip_serializing_if = "Option::is_none")]
    pub active_parameter: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureHelp {
    pub signatures: Vec<SignatureInformation>,
    #[serde(rename = "activeSignature", skip_serializing_if = "Option::is_none")]
    pub active_signature: Option<u32>,
    #[serde(rename = "activeParameter", skip_serializing_if = "Option::is_none")]
    pub active_parameter: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureHelpOptions {
    #[serde(rename = "triggerCharacters")]
    pub trigger_characters: Vec<String>,
}

/// Parameters for Workspace Symbol search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSymbolParams {
    pub query: String,
}

/// Workspace symbol information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInformation {
    pub name: String,
    pub kind: u32,
    pub location: Location,
    #[serde(rename = "containerName", skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
}

/// Server capabilities declared during initialize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(rename = "textDocumentSync")]
    pub text_document_sync: u32, // 1 = Full
    #[serde(rename = "hoverProvider")]
    pub hover_provider: bool,
    #[serde(rename = "completionProvider")]
    pub completion_provider: CompletionOptions,
    #[serde(rename = "definitionProvider")]
    pub definition_provider: bool,
    #[serde(rename = "referencesProvider")]
    pub references_provider: bool,
    #[serde(rename = "renameProvider")]
    pub rename_provider: bool,
    #[serde(rename = "documentSymbolProvider")]
    pub document_symbol_provider: bool,
    #[serde(rename = "workspaceSymbolProvider")]
    pub workspace_symbol_provider: bool,
    #[serde(rename = "documentFormattingProvider")]
    pub document_formatting_provider: bool,
    #[serde(
        rename = "semanticTokensProvider",
        skip_serializing_if = "Option::is_none"
    )]
    pub semantic_tokens_provider: Option<SemanticTokensOptionsWithLegend>,
    #[serde(rename = "inlayHintProvider", skip_serializing_if = "Option::is_none")]
    pub inlay_hint_provider: Option<bool>,
    #[serde(rename = "codeActionProvider", skip_serializing_if = "Option::is_none")]
    pub code_action_provider: Option<bool>,
    #[serde(
        rename = "signatureHelpProvider",
        skip_serializing_if = "Option::is_none"
    )]
    pub signature_help_provider: Option<SignatureHelpOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionOptions {
    #[serde(rename = "triggerCharacters")]
    pub trigger_characters: Vec<String>,
}

/// Initialize result returned to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}
