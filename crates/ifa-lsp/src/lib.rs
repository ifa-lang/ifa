pub mod document;
pub mod handlers;
pub mod protocol;
pub mod server;

pub use document::{Document, DocumentStore};
pub use protocol::*;
pub use server::LanguageServer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsp_initialize() {
        let mut server = LanguageServer::new();
        let init_req = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }"#;

        let (resp, notif) = server.handle_message(init_req);
        assert!(notif.is_none());
        assert!(resp.is_some());

        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        assert_eq!(resp_val["id"], 1);
        assert_eq!(resp_val["result"]["serverInfo"]["name"], "ifa-lsp");
        assert_eq!(resp_val["result"]["capabilities"]["textDocumentSync"], 1);
        assert!(resp_val["result"]["capabilities"]["hoverProvider"]
            .as_bool()
            .unwrap());
        assert!(
            resp_val["result"]["capabilities"]["completionProvider"]["triggerCharacters"]
                .is_array()
        );
    }

    #[test]
    fn test_lsp_did_open_and_diagnostics() {
        let mut server = LanguageServer::new();
        let code = r#"
            pub fn compute(x: int) -> int {
                let y: int = "incompatible";
                return x;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/test.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        let (resp, notif) = server.handle_message(&open_notif);
        assert!(resp.is_none());
        assert!(notif.is_some());

        let notif_val: serde_json::Value = serde_json::from_str(&notif.unwrap()).unwrap();
        assert_eq!(notif_val["method"], "textDocument/publishDiagnostics");
        assert_eq!(notif_val["params"]["uri"], "file:///workspace/test.ifa");
        // Must contain semantic type mismatch error
        let diags = notif_val["params"]["diagnostics"].as_array().unwrap();
        assert!(!diags.is_empty());
    }

    #[test]
    fn test_lsp_completion() {
        let mut server = LanguageServer::new();
        let code = r#"
            struct User {
                id: int,
                name: string,
            }

            pub fn main() -> () {
                let u: User = User { id: 1, name: "Alice" };
                u.
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/main.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        // Completion right after `u.`
        let completion_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/main.ifa"
                },
                "position": {
                    "line": 8,
                    "character": 18
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&completion_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let items = resp_val["result"]["items"].as_array().unwrap();
        assert!(!items.is_empty());
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
        assert!(labels.contains(&"id") || labels.contains(&"name") || labels.contains(&"fn"));
    }

    #[test]
    fn test_lsp_hover() {
        let mut server = LanguageServer::new();
        let code = r#"
            pub fn add_numbers(a: int, inout b: int) -> int {
                return a + b;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/math.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        // Hover over `add_numbers`
        let hover_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/math.ifa"
                },
                "position": {
                    "line": 1,
                    "character": 22
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&hover_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let hover_text = resp_val["result"]["contents"]["value"].as_str().unwrap();
        assert!(hover_text.contains("add_numbers"));
        assert!(hover_text.contains("int"));
    }

    #[test]
    fn test_lsp_formatting() {
        let mut server = LanguageServer::new();
        let unformatted = "pub fn test() -> () {\nlet a = 10;\nreturn a;\n}\n";

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/fmt.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": unformatted
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let fmt_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "textDocument/formatting",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/fmt.ifa"
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&fmt_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let edits = resp_val["result"].as_array().unwrap();
        assert_eq!(edits.len(), 1);
        let formatted_text = edits[0]["newText"].as_str().unwrap();
        assert!(formatted_text.contains("    let a = 10;"));
    }

    #[test]
    fn test_lsp_document_symbols() {
        let mut server = LanguageServer::new();
        let code = r#"
            struct Point {
                x: int,
                y: int,
            }

            pub fn calc() -> int {
                return 42;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/symbols.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let sym_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "textDocument/documentSymbol",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/symbols.ifa"
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&sym_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let syms = resp_val["result"].as_array().unwrap();
        assert!(syms.len() >= 2);
    }
}
