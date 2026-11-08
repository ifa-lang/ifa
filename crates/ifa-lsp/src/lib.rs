pub mod analysis_ext;
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
    fn test_lsp_safe_navigation_completion() {
        let mut server = LanguageServer::new();
        let code = r#"
            struct Node {
                val: i64,
                next: ?ref Node,
            }

            pub fn main() -> () {
                let n: ?ref Node = null;
                n?.
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/node.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let completion_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/node.ifa"
                },
                "position": {
                    "line": 8,
                    "character": 19
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&completion_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let items = resp_val["result"]["items"].as_array().unwrap();
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
        assert!(labels.contains(&"val"));
        assert!(labels.contains(&"next"));
    }

    #[test]
    fn test_lsp_colon_colon_namespace_completion() {
        let mut server = LanguageServer::new();
        let code = r#"
            import math;

            pub fn main() {
                let x = math::
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/math_test.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        // Completion right after `math::` (line 4, column 30)
        let completion_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "textDocument/completion",
            "params": {
                "textDocument": { "uri": "file:///workspace/math_test.ifa" },
                "position": { "line": 4, "character": 30 }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&completion_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let items = resp_val["result"]["items"].as_array().unwrap();
        assert!(
            !items.is_empty(),
            "Completion items after math:: must not be empty"
        );
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
        assert!(
            labels.contains(&"sqrt"),
            "Completion after math:: must propose `sqrt`"
        );
        assert!(
            labels.contains(&"abs"),
            "Completion after math:: must propose `abs`"
        );
        assert!(
            labels.contains(&"PI"),
            "Completion after math:: must propose `PI`"
        );
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

    #[test]
    fn test_lsp_references() {
        let mut server = LanguageServer::new();
        let code = r#"
            pub fn compute(x: int) -> int {
                return x * 2;
            }

            pub fn run() -> int {
                let a = compute(5);
                let b = compute(a);
                return b;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/refs.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        // Find references to `compute`
        let ref_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "textDocument/references",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/refs.ifa"
                },
                "position": {
                    "line": 1,
                    "character": 22
                },
                "context": {
                    "includeDeclaration": true
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&ref_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let locs = resp_val["result"].as_array().unwrap();
        // Should find declaration + 2 calls = 3 locations
        assert_eq!(locs.len(), 3);
    }

    #[test]
    fn test_lsp_prepare_rename_and_rename() {
        let mut server = LanguageServer::new();
        let code = r#"
            pub fn multiply(factor: int, val: int) -> int {
                let factor_val = factor * val;
                return factor_val;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/rename.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        // 1. Prepare rename on `multiply`
        let prep_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "textDocument/prepareRename",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/rename.ifa"
                },
                "position": {
                    "line": 1,
                    "character": 22
                }
            }
        })
        .to_string();

        let (resp_prep, _) = server.handle_message(&prep_req);
        assert!(resp_prep.is_some());
        let prep_val: serde_json::Value = serde_json::from_str(&resp_prep.unwrap()).unwrap();
        assert!(!prep_val["result"].is_null());

        // 2. Perform rename to `scale`
        let rename_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "textDocument/rename",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/rename.ifa"
                },
                "position": {
                    "line": 1,
                    "character": 22
                },
                "newName": "scale"
            }
        })
        .to_string();

        let (resp_rename, _) = server.handle_message(&rename_req);
        assert!(resp_rename.is_some());
        let rename_val: serde_json::Value = serde_json::from_str(&resp_rename.unwrap()).unwrap();
        let changes = &rename_val["result"]["changes"]["file:///workspace/rename.ifa"];
        assert!(changes.is_array());
        let edits = changes.as_array().unwrap();
        assert!(!edits.is_empty());
        assert_eq!(edits[0]["newText"], "scale");
    }

    #[test]
    fn test_lsp_semantic_tokens() {
        let mut server = LanguageServer::new();
        let code = r#"
            struct Config {
                port: int,
            }

            pub fn serve(c: Config) -> int {
                let active = true;
                return c.port;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/sem.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let sem_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "textDocument/semanticTokens/full",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/sem.ifa"
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&sem_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let data = resp_val["result"]["data"].as_array().unwrap();
        assert!(!data.is_empty());
        // Delta-encoded array length must be multiple of 5
        assert_eq!(data.len() % 5, 0);
    }

    #[test]
    fn test_lsp_inlay_hints() {
        let mut server = LanguageServer::new();
        let code = r#"
            pub fn add_two(x: int, y: int) -> int {
                let sum = x + y;
                return sum;
            }

            pub fn run() -> int {
                return add_two(10, 20);
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/inlay.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let hint_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "textDocument/inlayHint",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/inlay.ifa"
                },
                "range": {
                    "start": { "line": 0, "character": 0 },
                    "end": { "line": 10, "character": 0 }
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&hint_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let hints = resp_val["result"].as_array().unwrap();
        assert!(!hints.is_empty());
        let labels: Vec<&str> = hints.iter().filter_map(|h| h["label"].as_str()).collect();
        // Should contain type inlay hint for sum and parameter hints for add_two(10, 20)
        assert!(labels
            .iter()
            .any(|l| l.contains("int") || l.contains("x: ") || l.contains("y: ")));
    }

    #[test]
    fn test_lsp_inlay_hints_for_ranges_and_slices() {
        let mut server = LanguageServer::new();
        let code = r#"
            pub fn process_data() -> i64 {
                let ledger: [i64; 5] = [10, 20, 30, 40, 50];
                let r = 1..4;
                let sub = ledger[r];
                mut total: i64 = 0;
                for item in sub {
                    total = total + item;
                }
                return total;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/ranges_slices_inlay.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let hint_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "textDocument/inlayHint",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/ranges_slices_inlay.ifa"
                },
                "range": {
                    "start": { "line": 0, "character": 0 },
                    "end": { "line": 15, "character": 0 }
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&hint_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let hints = resp_val["result"].as_array().unwrap();
        assert!(!hints.is_empty(), "Hints must not be empty");
        let labels: Vec<&str> = hints.iter().filter_map(|h| h["label"].as_str()).collect();

        // Must contain inlay type hints for inferred range, slice, and loop variable
        assert!(
            labels.iter().any(|l| l.contains("Range")),
            "Expected Range type hint in labels: {:?}",
            labels
        );
        assert!(
            labels.iter().any(|l| l.contains("Slice")),
            "Expected Slice type hint in labels: {:?}",
            labels
        );
        assert!(
            labels.iter().any(|l| l.contains("i64")),
            "Expected i64 type hint in labels: {:?}",
            labels
        );
    }

    #[test]
    fn test_lsp_signature_help() {
        let mut server = LanguageServer::new();
        let code = r#"
            pub fn process_order(id: int, amount: float, active: bool) -> bool {
                return active;
            }

            pub fn main() -> () {
                let res = process_order(101, 45.5, );
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/sig.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        // Signature help right after comma: `process_order(101, 45.5, ` (line 6, character 50)
        let sig_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "textDocument/signatureHelp",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/sig.ifa"
                },
                "position": {
                    "line": 6,
                    "character": 50
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&sig_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let signatures = resp_val["result"]["signatures"].as_array().unwrap();
        assert_eq!(signatures.len(), 1);
        assert!(signatures[0]["label"]
            .as_str()
            .unwrap()
            .contains("process_order"));
        assert_eq!(resp_val["result"]["activeParameter"], 2);
    }

    #[test]
    fn test_lsp_workspace_symbols() {
        let mut server = LanguageServer::new();
        let code1 = r#"
            pub fn handle_deposit(account: int, amount: float) -> bool {
                return true;
            }
        "#;
        let code2 = r#"
            struct DepositRecord {
                tx_id: int,
            }
        "#;

        let open1 = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/doc1.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code1
                }
            }
        })
        .to_string();

        let open2 = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/doc2.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code2
                }
            }
        })
        .to_string();

        server.handle_message(&open1);
        server.handle_message(&open2);

        let ws_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "workspace/symbol",
            "params": {
                "query": "deposit"
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&ws_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let syms = resp_val["result"].as_array().unwrap();
        assert!(syms.len() >= 2);
        let names: Vec<&str> = syms.iter().filter_map(|s| s["name"].as_str()).collect();
        assert!(names.contains(&"handle_deposit"));
        assert!(names.contains(&"DepositRecord"));
    }

    #[test]
    fn test_lsp_code_action_format() {
        let mut server = LanguageServer::new();
        let code = "pub fn foo() -> () {\nlet x = 1;\nreturn ();\n}\n";

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/action.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let action_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "textDocument/codeAction",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/action.ifa"
                },
                "range": {
                    "start": { "line": 0, "character": 0 },
                    "end": { "line": 3, "character": 0 }
                },
                "context": {
                    "diagnostics": []
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&action_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let actions = resp_val["result"].as_array().unwrap();
        assert!(!actions.is_empty());
        assert!(actions
            .iter()
            .any(|a| a["title"].as_str().unwrap().contains("Format")));
    }

    #[test]
    fn test_lsp_disjoint_borrows_inlay_hints_and_hover() {
        let mut server = LanguageServer::new();
        let code = r#"
            struct Pair {
                a: int,
                b: int,
            }

            fn mutate_both(inout x: int, inout y: int) -> () {
                x = x + 1;
                y = y + 2;
                return ();
            }

            pub fn test_runner() -> () {
                let mut p = Pair(a: 10, b: 20);
                mutate_both(inout p.a, inout p.b);
                return ();
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/disjoint.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        // 1. Inlay hints request: must report disjoint borrow label
        let hints_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "textDocument/inlayHint",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/disjoint.ifa"
                },
                "range": {
                    "start": { "line": 0, "character": 0 },
                    "end": { "line": 16, "character": 0 }
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&hints_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let hints = resp_val["result"].as_array().unwrap();

        let labels: Vec<&str> = hints.iter().filter_map(|h| h["label"].as_str()).collect();
        assert!(
            labels.iter().any(|l| l.contains("disjoint: p.a ⟂ p.b")),
            "Inlay hints must include disjoint borrow indication for p.a: {:?}",
            labels
        );
        assert!(
            labels.iter().any(|l| l.contains("disjoint: p.b ⟂ p.a")),
            "Inlay hints must include disjoint borrow indication for p.b: {:?}",
            labels
        );

        // 2. Hover request over p.a: must display path-sensitive exclusivity markdown
        let hover_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/disjoint.ifa"
                },
                "position": { "line": 14, "character": 35 } // position of p.a
            }
        })
        .to_string();

        let (resp_hover, _) = server.handle_message(&hover_req);
        assert!(resp_hover.is_some());
        let hover_val: serde_json::Value = serde_json::from_str(&resp_hover.unwrap()).unwrap();
        assert!(hover_val["result"].is_object(), "Hover must return content");
        let content_str = hover_val["result"]["contents"]["value"].as_str().unwrap();
        assert!(
            content_str.contains("Exclusivité d'Accès Sensible au Chemin (IFA E0011)")
                || content_str.contains("p.a"),
            "Hover must detail path exclusivity analysis: {}",
            content_str
        );
    }

    #[test]
    fn test_lsp_generational_barrier_inlay_hints() {
        let mut server = LanguageServer::new();
        let code = r#"
            struct Node {
                val: int,
            }

            pub fn inspect_node(r: ref Node) -> int {
                let a = r.val;
                let b = r.val;
                return a + b;
            }
        "#;

        let open_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/gen_ref.ifa",
                    "languageId": "ifa",
                    "version": 1,
                    "text": code
                }
            }
        })
        .to_string();

        server.handle_message(&open_notif);

        let hints_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 16,
            "method": "textDocument/inlayHint",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/gen_ref.ifa"
                },
                "range": {
                    "start": { "line": 0, "character": 0 },
                    "end": { "line": 10, "character": 0 }
                }
            }
        })
        .to_string();

        let (resp, _) = server.handle_message(&hints_req);
        assert!(resp.is_some());
        let resp_val: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        let hints = resp_val["result"].as_array().unwrap();

        let labels: Vec<&str> = hints.iter().filter_map(|h| h["label"].as_str()).collect();
        assert!(
            labels.iter().any(|l| l.contains("[gen:")),
            "Inlay hints must present generational barrier status hints: {:?}",
            labels
        );
    }
}
