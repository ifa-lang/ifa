pub mod collections;
pub mod crypto;
pub mod csv;
pub mod fmt;
pub mod fs;
pub mod http;
pub mod io;
pub mod iter;
pub mod json;
pub mod net;
pub mod process;
pub mod sync;

pub use collections::{BinaryHeap, ByteBuffer, Deque, List, Map, Set, StringBuilder};
pub use crypto::{
    base64_decode, base64_encode, blake3, blake3_hex, hmac_sha1, hmac_sha1_hex, hmac_sha256,
    hmac_sha256_hex, hotp, pbkdf2_hmac_sha256, pbkdf2_hmac_sha256_hex, sha1, sha1_hex, sha256,
    sha256_hex, totp, totp_verify, websocket_accept_key,
};
pub use csv::{decode as decode_csv, encode as encode_csv, CsvTable};
pub use fmt::{
    format_binary, format_float, format_hex, format_octal, pad_center, pad_left, pad_right,
    Alignment, FormatSpecifier,
};
pub use fs::{
    append as fs_append, copy as fs_copy, create_dir as fs_create_dir,
    create_dir_all as fs_create_dir_all, exists as fs_exists, file_size as fs_file_size,
    is_dir as fs_is_dir, is_file as fs_is_file, list_dir as fs_list_dir, metadata as fs_metadata,
    read as fs_read, read_to_string as fs_read_to_string, remove_dir as fs_remove_dir,
    remove_dir_all as fs_remove_dir_all, remove_file as fs_remove_file, rename as fs_rename,
    walk_dir as fs_walk_dir, walk_dir_files as fs_walk_dir_files,
    walk_dir_matching as fs_walk_dir_matching, write as fs_write, write_string as fs_write_string,
    FileMetadata,
};
pub use http::{
    compute_etag, encode_basic_auth, format_form_urlencoded, format_set_cookie,
    is_hop_by_hop_header, matches_if_match, matches_if_none_match, negotiate_content_type,
    parse_accept_header, parse_basic_auth, parse_bearer_token, parse_cookies,
    parse_form_urlencoded, parse_multipart, parse_sse_events, url_decode, url_encode, AcceptItem,
    CorsConfig, HttpClient, HttpHandler, HttpHeaders, HttpLoadBalancer, HttpMethod,
    HttpProxyGateway, HttpRequest, HttpResponse, HttpRoute, HttpRouter, HttpServer, HttpStatus,
    LoadBalancingStrategy, MultipartBuilder, MultipartPart, RouteSegment, SseEvent,
    UpstreamBackend,
};
pub use io::{BufferedReader, BufferedWriter, MemoryStream};
pub use iter::{all, any, filter, find, fold, for_each, map, partition, reduce};
pub use json::{
    decode as decode_json, encode as encode_json, encode_pretty as encode_json_pretty, JsonValue,
};
pub use net::{
    lookup_mime_type, AsyncWsConnection, ConnectionInfo, TcpListener as NetTcpListener, TcpServer,
    TcpStream as NetTcpStream, TokenBucket, WsClient, WsDemux, WsFrame, WsMessage, WsOpcode,
    WsServer, WsSession,
};
pub use process::{
    find_best_assembler, find_best_linker, find_system_tool, invoke_assembler, invoke_linker,
    run as process_run, Command as ProcessCommand, ExitStatus as ProcessExitStatus, ProcessOutput,
};
pub use sync::{
    bounded, channel, AtomicFlag, AtomicInt, Receiver, RingBuffer, Select, Sender, WaitGroup,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_decode_and_encode() {
        let input =
            r#"{"amount":150.5,"currency":"EUR","items":["widget","gadget"],"success":true}"#;
        let val = decode_json(input).unwrap();

        assert_eq!(val.get("currency").and_then(|v| v.as_str()), Some("EUR"));
        assert_eq!(val.get("amount").and_then(|v| v.as_f64()), Some(150.5));
        assert_eq!(val.get("success").and_then(|v| v.as_bool()), Some(true));

        let items = val.get("items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_str(), Some("widget"));
        assert_eq!(items[1].as_str(), Some("gadget"));

        let encoded = encode_json(&val);
        let val_redecoded = decode_json(&encoded).unwrap();
        assert_eq!(val, val_redecoded);
    }

    #[test]
    fn test_csv_rfc4180_parsing_and_encoding() {
        let csv_src = "id,name,description\n1,Alice,\"Engineer, Systems\"\n2,Bob,\"Has \"\"quoted\"\" text\"\n";
        let table = decode_csv(csv_src, true, ',').unwrap();

        assert_eq!(table.headers, vec!["id", "name", "description"]);
        assert_eq!(table.row_count(), 2);
        assert_eq!(table.get_value(0, "description"), Some("Engineer, Systems"));
        assert_eq!(
            table.get_value(1, "description"),
            Some("Has \"quoted\" text")
        );

        let output = encode_csv(&table, ',');
        let re_table = decode_csv(&output, true, ',').unwrap();
        assert_eq!(table, re_table);
    }

    #[test]
    fn test_sha256_known_vector() {
        // Test vector: empty string
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Test vector: "Hello World"
        assert_eq!(
            sha256_hex(b"Hello World"),
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        );
    }

    #[test]
    fn test_blake3_hashing() {
        let hex = blake3_hex(b"IFA Programming Language");
        assert_eq!(
            hex,
            "eb6b3c8bcf187f9b99c2dacccec7b871b2b31f746b005e5cf58c81947cb3b438"
        );
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            blake3_hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        assert_eq!(
            blake3_hex(&vec![b'A'; 2000]),
            "fc6985444b763593734965947a328514e93ef2bae12db668a6d64147c5dcdde3"
        );
    }

    #[test]
    fn test_crypto_primitives_suite() {
        let key = b"12345678901234567890";
        assert_eq!(hotp(key, 0, 6), "755224");
        assert_eq!(totp(key, 59, 30, 6), "287082");
        assert!(totp_verify(key, "287082", 59, 30, 1));

        let derived = pbkdf2_hmac_sha256_hex(b"password", b"salt", 1, 32);
        assert_eq!(
            derived,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn test_http_request_response_wire() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "status".to_string(),
            JsonValue::String("healthy".to_string()),
        );
        let payload = JsonValue::Object(map);

        let res = HttpResponse::ok().json(&payload);
        assert_eq!(res.status, HttpStatus::OK);
        assert_eq!(res.headers.get("content-type"), Some("application/json"));

        let wire = res.to_wire_bytes();
        let wire_str = String::from_utf8(wire).unwrap();
        assert!(wire_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire_str.contains("application/json"));
        assert!(wire_str.ends_with("{\"status\":\"healthy\"}"));
    }

    #[test]
    fn test_sync_channel_and_waitgroup() {
        let (tx, rx) = bounded::<i64>(16);
        let wg = std::sync::Arc::new(WaitGroup::new());

        let num_items = 20;
        wg.add(1);
        let wg_prod = std::sync::Arc::clone(&wg);
        let tx_clone = tx.clone();

        std::thread::spawn(move || {
            for i in 0..num_items {
                tx_clone.send(i).unwrap();
            }
            tx_clone.close();
            wg_prod.done();
        });

        let mut received = Vec::new();
        for val in rx.iter() {
            received.push(val);
        }

        wg.wait();
        assert_eq!(received.len(), num_items as usize);
        assert_eq!(received[0], 0);
        assert_eq!(received[num_items as usize - 1], num_items - 1);
    }

    #[test]
    fn test_sync_multi_channel_select() {
        let (tx1, rx1) = bounded::<&'static str>(2);
        let (_tx2, rx2) = bounded::<&'static str>(2);

        tx1.send("fast_msg").unwrap();

        let res = Select::try_select(&[&rx1, &rx2]);
        assert_eq!(res, Some((0, "fast_msg")));

        let res_empty = Select::try_select(&[&rx1, &rx2]);
        assert_eq!(res_empty, None);
    }

    #[test]
    fn test_sync_atomics() {
        let counter = AtomicInt::new(10);
        assert_eq!(counter.fetch_add(5), 10);
        assert_eq!(counter.load(), 15);
        assert_eq!(counter.fetch_sub(3), 15);
        assert_eq!(counter.load(), 12);
        assert!(counter.compare_exchange(12, 42).is_ok());
        assert_eq!(counter.load(), 42);

        let flag = AtomicFlag::new(false);
        assert!(!flag.load());
        assert!(!flag.swap(true));
        assert!(flag.load());
    }

    #[test]
    fn test_fs_operations() {
        let temp_dir = std::env::temp_dir().join(format!("ifa_fs_test_{}", std::process::id()));
        fs_create_dir_all(&temp_dir).unwrap();
        assert!(fs_is_dir(&temp_dir));

        let file_path = temp_dir.join("test.txt");
        fs_write_string(&file_path, "Hello IFA File System!\n").unwrap();
        assert!(fs_exists(&file_path));
        assert!(fs_is_file(&file_path));

        fs_append(&file_path, b"Second line appended.\n").unwrap();
        let content = fs_read_to_string(&file_path).unwrap();
        assert_eq!(content, "Hello IFA File System!\nSecond line appended.\n");

        let copy_path = temp_dir.join("copy.txt");
        fs_copy(&file_path, &copy_path).unwrap();
        assert_eq!(
            fs_file_size(&file_path).unwrap(),
            fs_file_size(&copy_path).unwrap()
        );

        let entries = fs_list_dir(&temp_dir).unwrap();
        assert_eq!(entries.len(), 2);

        let meta = fs_metadata(&file_path).unwrap();
        assert!(meta.is_file);
        assert!(!meta.is_dir);

        fs_remove_file(&file_path).unwrap();
        assert!(!fs_exists(&file_path));

        fs_remove_dir_all(&temp_dir).unwrap();
        assert!(!fs_exists(&temp_dir));
    }

    #[test]
    fn test_io_buffered_and_memory_stream() {
        // Test memory stream
        let mut mem = MemoryStream::new();
        assert!(mem.is_empty());
        mem.write_bytes(b"IFA Memory Stream Data");
        assert_eq!(mem.len(), 22);

        mem.seek(4);
        let read_slice = mem.read_bytes(6);
        assert_eq!(read_slice, b"Memory");

        // Test buffered reader
        let cursor = std::io::Cursor::new(b"line 1\nline 2\r\nline 3");
        let reader = BufferedReader::new(cursor);
        let lines = reader.lines().unwrap();
        assert_eq!(lines, vec!["line 1", "line 2", "line 3"]);

        // Test buffered writer
        let mut sink = Vec::new();
        {
            let mut writer = BufferedWriter::new(&mut sink);
            writer.write_line("Alpha").unwrap();
            writer.write_line("Beta").unwrap();
            writer.flush().unwrap();
        }
        assert_eq!(sink, b"Alpha\nBeta\n");
    }

    #[test]
    fn test_http_wire_serialization_and_parsing() {
        let req = HttpRequest::new(HttpMethod::Post, "/api/v1/charge")
            .header("Host", "localhost:8080")
            .header("Content-Type", "application/json")
            .body(br#"{"amount":5000,"currency":"XOF"}"#.to_vec());

        let wire = req.to_wire_bytes();
        let (parsed_req, size) = HttpRequest::parse_from_wire(&wire).unwrap();
        assert_eq!(size, wire.len());
        assert_eq!(parsed_req.method, HttpMethod::Post);
        assert_eq!(parsed_req.path, "/api/v1/charge");
        assert_eq!(
            parsed_req.body_str().unwrap(),
            r#"{"amount":5000,"currency":"XOF"}"#
        );

        let resp = HttpResponse::created()
            .header("X-Powered-By", "IFA")
            .text("Transaction processed");
        let resp_wire = resp.to_wire_bytes();
        let (parsed_resp, resp_size) = HttpResponse::parse_from_wire(&resp_wire).unwrap();
        assert_eq!(resp_size, resp_wire.len());
        assert_eq!(parsed_resp.status, HttpStatus::CREATED);
        assert_eq!(parsed_resp.body_str().unwrap(), "Transaction processed");
    }

    #[test]
    fn test_async_http_server_and_client_fibers() {
        // Start HTTP Server on ephemeral port 0
        let mut server = HttpServer::new(0);

        server.get("/health", |_req| HttpResponse::ok().text("healthy"));

        server.post("/api/v1/charge", |req| {
            let body_str = req.body_str().unwrap_or("{}");
            let json = decode_json(body_str).unwrap_or(JsonValue::Null);
            let merchant = json
                .get("merchant_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let amount = json.get("amount_xof").and_then(|v| v.as_i64()).unwrap_or(0);

            let mut resp_map = std::collections::BTreeMap::new();
            resp_map.insert(
                "status".to_string(),
                JsonValue::String("success".to_string()),
            );
            resp_map.insert(
                "merchant".to_string(),
                JsonValue::String(merchant.to_string()),
            );
            resp_map.insert("amount".to_string(), JsonValue::Number(amount as f64));
            resp_map.insert(
                "tx_ref".to_string(),
                JsonValue::String("FA-TX-99482".to_string()),
            );

            HttpResponse::ok().json(&JsonValue::Object(resp_map))
        });

        let bound_addr = server
            .listen_background()
            .expect("Failed to bind HTTP server");
        let client = HttpClient::new();

        // 1. Test GET /health
        let health_resp = client
            .get("127.0.0.1", bound_addr.port(), "/health")
            .expect("GET health failed");
        assert_eq!(health_resp.status, HttpStatus::OK);
        assert_eq!(health_resp.body_str().unwrap(), "healthy");

        // 2. Test POST /api/v1/charge
        let mut payload_map = std::collections::BTreeMap::new();
        payload_map.insert(
            "merchant_id".to_string(),
            JsonValue::String("MOMOPAY_01".to_string()),
        );
        payload_map.insert("amount_xof".to_string(), JsonValue::Number(7500.0));
        payload_map.insert("currency".to_string(), JsonValue::String("XOF".to_string()));

        let charge_resp = client
            .post_json(
                "127.0.0.1",
                bound_addr.port(),
                "/api/v1/charge",
                &JsonValue::Object(payload_map),
            )
            .expect("POST charge failed");
        assert_eq!(charge_resp.status, HttpStatus::OK);
        let resp_json = decode_json(charge_resp.body_str().unwrap()).unwrap();
        assert_eq!(
            resp_json.get("status").and_then(|v| v.as_str()),
            Some("success")
        );
        assert_eq!(
            resp_json.get("merchant").and_then(|v| v.as_str()),
            Some("MOMOPAY_01")
        );
        assert_eq!(
            resp_json.get("tx_ref").and_then(|v| v.as_str()),
            Some("FA-TX-99482")
        );

        // 3. Test 404 for unknown route
        let not_found_resp = client
            .get("127.0.0.1", bound_addr.port(), "/unknown/path")
            .expect("GET unknown failed");
        assert_eq!(not_found_resp.status, HttpStatus::NOT_FOUND);

        server.stop();
    }

    #[test]
    fn test_collections_list_map_set() {
        // List
        let mut list = List::new();
        list.push(30);
        list.push(10);
        list.push(20);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], 30);
        list.sort();
        assert_eq!(list.as_slice(), &[10, 20, 30]);

        // Map
        let mut map = Map::new();
        map.insert("gamma", 3);
        map.insert("alpha", 1);
        map.insert("beta", 2);
        let keys: Vec<_> = map.keys().copied().collect();
        assert_eq!(keys, vec!["alpha", "beta", "gamma"]);
        assert_eq!(map.get(&"beta"), Some(&2));

        // Set
        let mut set = Set::new();
        assert!(set.insert(100));
        assert!(set.insert(50));
        assert!(set.insert(200));
        assert!(!set.insert(50)); // duplicate
        let sorted_elements: Vec<_> = set.iter().copied().collect();
        assert_eq!(sorted_elements, vec![50, 100, 200]);
    }

    #[test]
    fn test_byte_buffer_and_string_builder() {
        // ByteBuffer
        let mut buf = ByteBuffer::new();
        buf.write_u8(0x7F);
        buf.write_u32_le(0x12345678);
        buf.write_u64_be(0xDEADBEEFCAFE0011);
        buf.write_str("IFA_BOOTSTRAP");

        assert_eq!(buf.read_u8(0), Some(0x7F));
        assert_eq!(buf.read_u32_le(1), Some(0x12345678));
        assert_eq!(buf.read_u8(buf.len() - 1), Some(b'P'));

        // StringBuilder
        let mut sb = StringBuilder::new();
        sb.push_line("define i32 @main() {");
        sb.indent();
        sb.push_line("%t0 = add i32 10, 32");
        sb.push_line("ret i32 %t0");
        sb.dedent();
        sb.push_line("}");

        let result = sb.into_string();
        assert!(result.contains("define i32 @main() {"));
        assert!(result.contains("    %t0 = add i32 10, 32\n"));
        assert!(result.contains("    ret i32 %t0\n"));
        assert!(result.ends_with("}\n"));
    }

    #[test]
    fn test_process_command_execution() {
        let mut cmd = ProcessCommand::new("sh");
        cmd.arg("-c");
        cmd.arg("echo 'IFA_STDLIB_PROCESS_OK'");
        let output = cmd.output().expect("Execute sh command");
        assert!(output.success());
        assert_eq!(output.stdout_string().trim(), "IFA_STDLIB_PROCESS_OK");

        let echo_run = process_run("echo", ["test_run"]).expect("process_run echo");
        assert!(echo_run.success());
        assert_eq!(echo_run.stdout_string().trim(), "test_run");
    }

    #[test]
    fn test_fs_walk_dir() {
        let temp_dir =
            std::env::temp_dir().join(format!("ifa_walk_dir_test_{}", std::process::id()));
        let _ = fs_remove_dir_all(&temp_dir);
        fs_create_dir_all(temp_dir.join("sub/nested")).unwrap();

        fs_write_string(temp_dir.join("root.txt"), "root").unwrap();
        fs_write_string(temp_dir.join("sub/a.txt"), "a").unwrap();
        fs_write_string(temp_dir.join("sub/nested/b.txt"), "b").unwrap();

        let all_files = fs_walk_dir_files(&temp_dir).unwrap();
        assert_eq!(all_files.len(), 3);
        let file_names: Vec<_> = all_files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(file_names.contains(&"root.txt".to_string()));
        assert!(file_names.contains(&"a.txt".to_string()));
        assert!(file_names.contains(&"b.txt".to_string()));

        let _ = fs_remove_dir_all(&temp_dir);
    }
}
