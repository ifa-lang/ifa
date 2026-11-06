use std::fs;
use std::process::Command;

fn get_ifa_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("ifa");
    path
}

#[test]
fn test_cli_wasm_inspect_and_bundle() {
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_wasm_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // Construct minimal valid WebAssembly binary with export section
    let mut wasm_bytes = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    let export_payload = [
        0x01, // 1 export
        0x03, b'a', b'd', b'd', // name "add"
        0x00, // kind: func
        0x00, // func idx: 0
    ];
    wasm_bytes.push(0x07); // section id 7 (Export)
    wasm_bytes.push(export_payload.len() as u8);
    wasm_bytes.extend_from_slice(&export_payload);

    let wasm_file = temp_dir.join("test_math.wasm");
    fs::write(&wasm_file, &wasm_bytes).unwrap();

    let ifa_bin = get_ifa_binary();

    // 1. Test `ifa wasm inspect`
    let inspect_status = Command::new(&ifa_bin)
        .arg("wasm")
        .arg("inspect")
        .arg(&wasm_file)
        .status();

    if let Ok(status) = inspect_status {
        assert!(status.success(), "ifa wasm inspect failed");
    }

    // 2. Test `ifa wasm bundle`
    let dist_dir = temp_dir.join("dist");
    let bundle_status = Command::new(&ifa_bin)
        .arg("wasm")
        .arg("bundle")
        .arg("test_math")
        .arg(&wasm_file)
        .arg("--out-dir")
        .arg(&dist_dir)
        .status();

    if let Ok(status) = bundle_status {
        assert!(status.success(), "ifa wasm bundle failed");
        assert!(dist_dir.join("test_math.wasm").exists());
        assert!(dist_dir.join("index.js").exists());
        assert!(dist_dir.join("index.d.ts").exists());
        assert!(dist_dir.join("package.json").exists());
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_lsp_stdio_handshake() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;

    let ifa_bin = get_ifa_binary();
    let mut child = Command::new(&ifa_bin)
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn `ifa lsp` process");

    let init_payload = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let request = format!(
        "Content-Length: {}\r\n\r\n{}",
        init_payload.len(),
        init_payload
    );

    {
        let stdin = child.stdin.as_mut().expect("Failed to open child stdin");
        stdin
            .write_all(request.as_bytes())
            .expect("Failed to write to LSP stdin");
        stdin.flush().expect("Failed to flush LSP stdin");
    }

    let stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut reader = BufReader::new(stdout);

    // Read Content-Length header
    let mut header_line = String::new();
    reader
        .read_line(&mut header_line)
        .expect("Failed to read LSP header");
    assert!(header_line.starts_with("Content-Length:"));

    let parts: Vec<&str> = header_line.trim().split(':').collect();
    let content_len: usize = parts[1].trim().parse().expect("Invalid Content-Length");

    // Read blank delimiter line
    let mut blank_line = String::new();
    reader
        .read_line(&mut blank_line)
        .expect("Failed to read header delimiter");

    // Read JSON-RPC response body
    let mut body_bytes = vec![0u8; content_len];
    std::io::Read::read_exact(&mut reader, &mut body_bytes).expect("Failed to read LSP body");
    let body_str = String::from_utf8(body_bytes).expect("Invalid UTF-8 in response");

    let resp_val: serde_json::Value =
        serde_json::from_str(&body_str).expect("Failed to parse JSON response");
    assert_eq!(resp_val["id"], 1);
    assert_eq!(resp_val["result"]["serverInfo"]["name"], "ifa-lsp");
    assert_eq!(resp_val["result"]["capabilities"]["textDocumentSync"], 1);

    // Terminate LSP child
    let _ = child.kill();
    let _ = child.wait();
}
