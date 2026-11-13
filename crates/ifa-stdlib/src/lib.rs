pub mod collections;
pub mod crypto;
pub mod csv;
pub mod db;
pub mod fmt;
pub mod fs;
pub mod http;
pub mod io;
pub mod iter;
pub mod json;
pub mod net;
pub mod process;
pub mod simd_parser;
pub mod sync;
pub mod sys;

pub use collections::{BinaryHeap, ByteBuffer, Deque, List, Map, Set, StringBuilder};
pub use crypto::{
    base64_decode, base64_encode, base64url_decode, base64url_encode, blake3, blake3_hex,
    constant_time_eq, hmac_sha1, hmac_sha1_hex, hmac_sha256, hmac_sha256_hex, hotp,
    pbkdf2_hmac_sha256, pbkdf2_hmac_sha256_hex, sha1, sha1_hex, sha256, sha256_hex, totp,
    totp_verify, websocket_accept_key, HmacSha1, HmacSha256, Jwt, JwtClaims, JwtError, Sha1,
    Sha256,
};
pub use csv::{
    decode as decode_csv, decode_with_options as decode_csv_with_options, encode as encode_csv,
    encode_with_options as encode_csv_with_options, CsvError, CsvOptions, CsvReader, CsvTable,
    CsvWriter,
};
pub use db::{
    Database, DbError, KeysetPage, Page, PrefixScanner, Transaction, DB_MAGIC, DB_VERSION,
    PAGE_SIZE,
};
pub use fmt::{
    decode_hex, encode_hex, escape_str, format_binary, format_float, format_hex, format_hexdump,
    format_octal, pad_center, pad_left, pad_right, unescape_str, write_aligned, write_binary,
    write_escaped_str, write_float_prec, write_hex, write_hex_bytes, write_hexdump,
    write_int_aligned, write_octal, Alignment, FormatSpecifier, HexDump, HexError, UnescapeError,
};
pub use fs::{
    append as fs_append, copy as fs_copy, create_dir as fs_create_dir,
    create_dir_all as fs_create_dir_all, current_fs, current_target_kind, exists as fs_exists,
    file_size as fs_file_size, is_dir as fs_is_dir, is_file as fs_is_file, list_dir as fs_list_dir,
    metadata as fs_metadata, normalize_path, open_append as fs_open_append,
    open_read as fs_open_read, open_write as fs_open_write, read as fs_read,
    read_to_string as fs_read_to_string, remove_dir as fs_remove_dir,
    remove_dir_all as fs_remove_dir_all, remove_file as fs_remove_file, rename as fs_rename,
    reset_global_fs, set_global_fs, walk_dir as fs_walk_dir, walk_dir_files as fs_walk_dir_files,
    walk_dir_matching as fs_walk_dir_matching, with_target_fs, write as fs_write,
    write_string as fs_write_string, FileMetadata, FileStream, FileSystem, PosixFs, TargetKind,
    VirtualFs, WasiFs, WasiFsBuilder, WasiPreopen, WasiRights,
};
pub use http::{
    compute_etag, cors_middleware, csrf_protection_middleware, encode_basic_auth,
    format_form_urlencoded, format_set_cookie, http_should_keep_alive, is_hop_by_hop_header,
    jwt_auth_middleware, matches_if_match, matches_if_none_match, negotiate_content_type,
    parse_accept_header, parse_basic_auth, parse_bearer_token, parse_cookies,
    parse_form_urlencoded, parse_multipart, parse_sse_events, read_http_response, url_decode,
    url_encode, AcceptItem, CircuitState, Cookie, CookieJar, CorsConfig, HttpCircuitBreaker,
    HttpCircuitBreakerConfig, HttpClient, HttpConnectionPool, HttpConnectionPoolConfig,
    HttpHandler, HttpHeaders, HttpLoadBalancer, HttpMethod, HttpMiddleware, HttpProxyGateway,
    HttpRequest, HttpResponse, HttpRetryPolicy, HttpRetryReport, HttpRoute, HttpRouter, HttpServer,
    HttpSession, HttpStatus, LoadBalancingStrategy, MultipartBuilder, MultipartPart,
    PooledConnection, RouteSegment, SameSite, SessionStore, SseEvent, UpstreamBackend,
};
pub use io::{
    copy_stream, pipe_lines, read_to_end as io_read_to_end, read_to_string as io_read_to_string,
    BufferedReader, BufferedWriter, ChainedReader, CountingReader, CountingWriter, LimitedReader,
    LineWriter, MemoryStream, TeeReader, TeeWriter,
};
pub use iter::{all, any, filter, find, fold, for_each, map, partition, reduce};
pub use json::{
    create_merge_patch, create_patch as create_json_patch, decode as decode_json,
    diff as diff_json, encode as encode_json, encode_pretty as encode_json_pretty,
    execute_jsonpath, parse_jsonpath, parse_patch as parse_json_patch, query as query_jsonpath,
    FilterOp, FilterPredicate, JsonValue, PatchOperation, PathSegment,
};
pub use net::{
    lookup_mime_type, AsyncTcpListener, AsyncTcpStream, AsyncTimer, AsyncUdpSocket,
    AsyncWsConnection, BufferedTcpStream, ConnectionInfo, Datagram, SocketConfig,
    TcpListener as NetTcpListener, TcpListener, TcpServer, TcpStream as NetTcpStream, TcpStream,
    TokenBucket, UdpSocket as NetUdpSocket, UdpSocket, WsClient, WsDemux, WsFrame, WsMessage,
    WsOpcode, WsServer, WsSession,
};
pub use process::{
    find_best_assembler, find_best_linker, find_system_tool, invoke_assembler, invoke_linker,
    run as process_run, ChildProcess, Command as ProcessCommand, CommandPipeline,
    ExitStatus as ProcessExitStatus, Pipeline, ProcessOutput, Signal, Signal as ProcessSignal,
};
pub use simd_parser::{
    find_byte_vectorized, find_crlf_vectorized, parse_http_request_fast, parse_http_response_fast,
    FastHttpError, FastHttpRequest, FastHttpResponse, Http2FrameHeader, Http2FrameType,
};
pub use sync::{
    bounded, channel, AtomicFlag, AtomicInt, Receiver, RingBuffer, Select, Sender, WaitGroup,
};
pub use sys::{
    cpu_count, get_children_resource_usage, get_current_process_memory_info, get_host_memory_info,
    get_process_memory_info, get_resource_usage, get_self_resource_usage, get_system_load,
    HostMemoryInfo, ProcessMemoryInfo, ResourceScope, ResourceUsage, SystemLoad,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::Path;
    use std::sync::Arc;

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

        // Streaming Hasher tests from crate root
        let mut hasher256 = Sha256::new();
        hasher256.update(b"streaming ");
        hasher256.update(b"data");
        assert_eq!(hasher256.finalize(), sha256(b"streaming data"));

        let mut hasher1 = Sha1::new();
        hasher1.update(b"streaming ");
        hasher1.update(b"data");
        assert_eq!(hasher1.finalize(), sha1(b"streaming data"));

        let mut hmac = HmacSha256::new(key);
        hmac.update(b"streaming ");
        hmac.update(b"data");
        assert_eq!(hmac.finalize(), hmac_sha256(key, b"streaming data"));

        let mut hmac1 = HmacSha1::new(key);
        hmac1.update(b"streaming ");
        hmac1.update(b"data");
        assert_eq!(hmac1.finalize(), hmac_sha1(key, b"streaming data"));
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
    fn test_virtual_fs_in_memory_lifecycle() {
        let vfs = Arc::new(VirtualFs::new());
        assert_eq!(vfs.target_kind(), TargetKind::Virtual);

        with_target_fs(vfs.clone(), || {
            assert_eq!(current_target_kind(), TargetKind::Virtual);

            // Directory creation
            fs_create_dir_all("/var/log/ifa").unwrap();
            assert!(fs_is_dir("/var/log/ifa"));
            assert!(fs_exists("/var/log"));

            // File write and append
            let log_file = "/var/log/ifa/app.log";
            fs_write_string(log_file, "BOOT_OK\n").unwrap();
            assert!(fs_exists(log_file));
            assert!(fs_is_file(log_file));

            fs_append(log_file, b"EVENT_STARTED\n").unwrap();
            let content = fs_read_to_string(log_file).unwrap();
            assert_eq!(content, "BOOT_OK\nEVENT_STARTED\n");

            // Metadata and file size
            let meta = fs_metadata(log_file).unwrap();
            assert!(meta.is_file);
            assert_eq!(meta.size, 22);

            // Copy and rename
            let backup_file = "/var/log/ifa/app.log.bak";
            fs_copy(log_file, backup_file).unwrap();
            assert!(fs_exists(backup_file));

            let renamed_file = "/var/log/ifa/app.log.archive";
            fs_rename(backup_file, renamed_file).unwrap();
            assert!(!fs_exists(backup_file));
            assert!(fs_exists(renamed_file));

            // List and walk dir
            let entries = fs_list_dir("/var/log/ifa").unwrap();
            assert_eq!(entries.len(), 2);

            let walked = fs_walk_dir("/var/log").unwrap();
            assert!(walked.len() >= 3);

            // Readonly protection
            vfs.set_readonly(Path::new(renamed_file), true).unwrap();
            let append_err = fs_append(renamed_file, b"ILLEGAL");
            assert!(append_err.is_err());

            // Cleanup
            fs_remove_file(log_file).unwrap();
            assert!(!fs_exists(log_file));
            fs_remove_dir_all("/var").unwrap();
            assert!(!fs_exists("/var/log/ifa"));
        });
    }

    #[test]
    fn test_wasi_sandboxed_capabilities_and_preopen() {
        let temp_dir = std::env::temp_dir().join(format!("ifa_wasi_test_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let wasi = WasiFs::builder()
            .preopen("/sandbox", Some(temp_dir.clone()), WasiRights::READ_WRITE)
            .preopen("/read_only_data", None, WasiRights::READ_ONLY)
            .build();

        let wasi_arc = Arc::new(wasi);
        assert_eq!(wasi_arc.target_kind(), TargetKind::Wasi);

        with_target_fs(wasi_arc, || {
            assert_eq!(current_target_kind(), TargetKind::Wasi);

            // 1. Authorized read/write within preopened /sandbox
            let guest_path = "/sandbox/greeting.txt";
            fs_write_string(guest_path, "Hello from WASI sandbox!\n").unwrap();
            assert!(fs_exists(guest_path));
            assert!(fs_is_file(guest_path));

            let content = fs_read_to_string(guest_path).unwrap();
            assert_eq!(content, "Hello from WASI sandbox!\n");

            // 2. Reject write on read-only mount
            let ro_write_err = fs_write_string("/read_only_data/forbidden.txt", "Should fail");
            assert!(ro_write_err.is_err());
            assert_eq!(
                ro_write_err.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );

            // 3. Reject access completely outside preopened mounts
            let outside_err = fs_read_to_string("/etc/shadow");
            assert!(outside_err.is_err());
            assert_eq!(
                outside_err.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        });

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wasi_path_traversal_prevention() {
        let wasi = Arc::new(WasiFs::new_sandbox());
        with_target_fs(wasi, || {
            // Attempting path traversal escape out of /sandbox
            // /sandbox/../../etc/passwd resolves internally to /etc/passwd which is not preopened
            let escape_err = fs_write_string("/sandbox/../../etc/passwd", "malicious_root");
            assert!(escape_err.is_err());
            assert_eq!(
                escape_err.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        });
    }

    #[test]
    fn test_multi_target_transparent_switching() {
        // By default on Linux we run Posix
        assert_eq!(current_target_kind(), TargetKind::Posix);

        // Switch transparently to VirtualFs
        let vfs = Arc::new(VirtualFs::new());
        with_target_fs(vfs, || {
            assert_eq!(current_target_kind(), TargetKind::Virtual);
            fs_write_string("/demo.txt", "In-memory").unwrap();
            assert_eq!(fs_read_to_string("/demo.txt").unwrap(), "In-memory");
        });

        // Outside scoped block, returns to default Posix
        assert_eq!(current_target_kind(), TargetKind::Posix);
    }

    #[test]
    fn test_io_buffered_and_memory_stream() {
        use std::io::{Read, Seek, SeekFrom, Write};

        // Test memory stream inherent methods
        let mut mem = MemoryStream::new();
        assert!(mem.is_empty());
        mem.write_bytes(b"IFA Memory Stream Data");
        assert_eq!(mem.len(), 22);

        mem.set_position(4);
        let read_slice = mem.read_bytes(6);
        assert_eq!(read_slice, b"Memory");

        mem.seek(SeekFrom::Start(4)).unwrap();
        let read_slice2 = mem.read_bytes(6);
        assert_eq!(read_slice2, b"Memory");

        // Test std::io::Read, Write, Seek implementations on MemoryStream
        let mut io_mem = MemoryStream::from_bytes(b"First line\nSecond line\nThird line\n");
        let mut buf_reader = BufferedReader::new(&mut io_mem);
        let first = buf_reader.read_line().unwrap().unwrap();
        assert_eq!(first, "First line");

        // Test std::io::Write & Seek on MemoryStream
        let mut writable_mem = MemoryStream::new();
        writable_mem.write_all(b"Stream Start: ").unwrap();
        writable_mem.write_all(b"Payload Data").unwrap();
        assert_eq!(writable_mem.as_bytes(), b"Stream Start: Payload Data");

        writable_mem.seek(SeekFrom::Start(7)).unwrap();
        let mut read_buf = [0u8; 5];
        writable_mem.read_exact(&mut read_buf).unwrap();
        assert_eq!(&read_buf, b"Start");

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

        // Test pipe_lines and copy_stream
        let input_stream = MemoryStream::from_bytes(b"Row 1\nRow 2\nRow 3\n");
        let mut piped_reader = BufferedReader::new(input_stream);
        let mut output_buf = Vec::new();
        {
            let mut piped_writer = BufferedWriter::new(&mut output_buf);
            let count = pipe_lines(&mut piped_reader, &mut piped_writer).unwrap();
            assert_eq!(count, 3);
        }
        assert_eq!(output_buf, b"Row 1\nRow 2\nRow 3\n");

        let mut src = MemoryStream::from_bytes(b"Transfer Bytes");
        let mut dst = MemoryStream::new();
        let transferred = copy_stream(&mut src, &mut dst).unwrap();
        assert_eq!(transferred, 14);
        assert_eq!(dst.as_bytes(), b"Transfer Bytes");
    }

    #[test]
    fn test_multitarget_streaming_and_capabilities() {
        use std::io::{Read, Seek, SeekFrom, Write};

        // 1. VirtualFs streaming
        let vfs = VirtualFs::new();
        {
            let mut stream = vfs.open_write(std::path::Path::new("/stream.txt")).unwrap();
            stream.write_all(b"Header\n").unwrap();
            stream.write_all(b"Body line 1\n").unwrap();
            stream.flush().unwrap();
        }
        // Verify immediate persistence in VirtualFs
        assert_eq!(
            vfs.read_to_string(std::path::Path::new("/stream.txt"))
                .unwrap(),
            "Header\nBody line 1\n"
        );

        // Append to stream
        {
            let mut append_stream = vfs
                .open_append(std::path::Path::new("/stream.txt"))
                .unwrap();
            append_stream.write_all(b"Footer\n").unwrap();
            append_stream.flush().unwrap();
        }

        // Read through FileStream with Seek
        {
            let mut read_stream = vfs.open_read(std::path::Path::new("/stream.txt")).unwrap();
            let full_str = read_stream.read_to_string().unwrap();
            assert_eq!(full_str, "Header\nBody line 1\nFooter\n");

            // Seek back to start
            read_stream.seek(SeekFrom::Start(0)).unwrap();
            let mut initial_bytes = [0u8; 6];
            read_stream.read_exact(&mut initial_bytes).unwrap();
            assert_eq!(&initial_bytes, b"Header");
        }

        // 2. WASI capability enforcement on streams
        let wasi = WasiFs::builder()
            .preopen(
                "/sandbox",
                None,
                WasiRights {
                    read: true,
                    write: true,
                    create: true,
                    delete: true,
                    list: true,
                    traverse: true,
                },
            )
            .preopen(
                "/etc/config",
                None,
                WasiRights {
                    read: true,
                    write: false,
                    create: false,
                    delete: false,
                    list: true,
                    traverse: true,
                },
            )
            .build();

        // Write to read-only preopen must be denied
        let denied = wasi.open_write(std::path::Path::new("/etc/config/secret.key"));
        assert!(denied.is_err());
        assert_eq!(
            denied.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );

        // Path outside preopened mounts must be denied
        let jailbreak = wasi.open_read(std::path::Path::new("/root/.ssh/id_rsa"));
        assert!(jailbreak.is_err());

        // Write inside /sandbox must succeed
        {
            let mut writer = wasi
                .open_write(std::path::Path::new("/sandbox/app.log"))
                .unwrap();
            writer.write_all(b"Service started at 12:00").unwrap();
            writer.flush().unwrap();
        }

        // Read inside /sandbox must succeed
        {
            let mut reader = wasi
                .open_read(std::path::Path::new("/sandbox/app.log"))
                .unwrap();
            let content = reader.read_to_string().unwrap();
            assert_eq!(content, "Service started at 12:00");
        }

        // 3. Transparent scoped filesystem streaming
        with_target_fs(std::sync::Arc::new(vfs), || {
            let mut stream = fs_open_write("/transparent.txt").unwrap();
            stream.write_all(b"Transparent Stream Content").unwrap();
            stream.flush().unwrap();

            let mut reader = fs_open_read("/transparent.txt").unwrap();
            assert_eq!(
                reader.read_to_string().unwrap(),
                "Transparent Stream Content"
            );
        });
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
        let mut buf = ByteBuffer::with_capacity(64);
        assert!(buf.capacity() >= 64);
        buf.write_u8(0x7F);
        buf.write_u32_le(0x12345678);
        buf.write_u64_be(0xDEADBEEFCAFE0011);
        buf.write_i16_be(-1234);
        buf.write_f32_le(42.5);
        buf.write_f64_be(1234.5678);
        buf.write_str("IFA_BOOTSTRAP");

        assert_eq!(buf.read_u8(0), Some(0x7F));
        assert_eq!(buf.read_u32_le(1), Some(0x12345678));
        assert_eq!(buf.read_u64_be(5), Some(0xDEADBEEFCAFE0011));
        assert_eq!(buf.read_u8(buf.len() - 1), Some(b'P'));
        assert_eq!(buf.read_bytes(buf.len() - 3, 3), Some(b"RAP".as_slice()));

        // Hex conversion & parsing in ByteBuffer
        let hex_str = buf.to_hex(false);
        let mut hex_buf = ByteBuffer::new();
        let written = hex_buf.write_hex_str(&hex_str).unwrap();
        assert_eq!(written, buf.len());
        assert_eq!(hex_buf.as_slice(), buf.as_slice());

        // StringBuilder with fmt::Write support and streaming methods
        use std::fmt::Write;
        let mut sb = StringBuilder::with_capacity(128);
        writeln!(&mut sb, "header: {}", 1).unwrap();
        sb.push_line("define i32 @main() {");
        sb.indent();
        sb.push_line("%t0 = add i32 10, 32");
        sb.push_repeat("// comment\n", 2);
        sb.push_binary(0b1101, true);
        sb.push_char('\n');
        sb.push_hex_bytes(b"ABC", true);
        sb.push_char('\n');
        sb.push_aligned("val", 8, Alignment::Right, '.');
        sb.push_char('\n');
        sb.push_line("ret i32 %t0");
        sb.dedent();
        sb.push_line("}");

        assert!(sb.starts_with("header: 1\n"));
        assert!(sb.contains("// comment\n// comment\n"));
        assert!(sb.contains("0b1101\n414243\n.....val\n"));
        assert!(sb.ends_with("}\n"));

        let result = sb.into_string();
        assert!(result.contains("define i32 @main() {"));
        assert!(result.contains("    %t0 = add i32 10, 32\n"));
        assert!(result.contains("    ret i32 %t0\n"));
    }

    #[test]
    fn test_formatting_streaming_and_hexdump() {
        let mut out = String::new();
        write_aligned(&mut out, "hello", 10, Alignment::Center, '*').unwrap();
        assert_eq!(out, "**hello***");

        let data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0fHello World";
        let dump = format_hexdump(data);
        assert!(dump.starts_with(
            "00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |................|"
        ));
        assert!(dump
            .contains("00000010  48 65 6c 6c 6f 20 57 6f  72 6c 64                 |Hello World|"));

        // Hex encode & decode roundtrip
        let raw = b"IFA Fast Serialization Engine \xde\xad\xbe\xef";
        let hex = encode_hex(raw, true);
        let decoded = decode_hex(&hex).unwrap();
        assert_eq!(decoded, raw);

        // String escape & unescape roundtrip
        let unescaped = "Line 1\nLine 2\t\"Quotes\" & \\Backslashes\\ \u{1f980}";
        let escaped = escape_str(unescaped);
        let roundtrip = unescape_str(&escaped).unwrap();
        assert_eq!(roundtrip, unescaped);
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

        // Test pipeline integration with stream
        let mut mem_stream = MemoryStream::new();
        let pipeline = Pipeline::new()
            .stdin_str("pipeline row 1\npipeline row 2\n")
            .pipe(ProcessCommand::new("grep").arg("row 2"));
        let status = pipeline
            .output_to_writer(&mut mem_stream)
            .expect("execute pipeline to memory stream");
        assert!(status.success());
        assert_eq!(
            String::from_utf8_lossy(mem_stream.as_bytes()).trim(),
            "pipeline row 2"
        );
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

    #[test]
    fn test_net_udp_and_tcp_prelude_exports() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind prelude UdpSocket");
        assert!(sock.is_open());
        assert!(sock.port().unwrap() > 0);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind prelude TcpListener");
        assert!(listener.port().unwrap() > 0);
    }

    #[test]
    fn test_io_tee_stream_exports() {
        use std::io::{Read, Write};

        let data = b"tee stream verification";
        let mut tap = Vec::new();
        let mut tee = TeeReader::new(&data[..], &mut tap);
        let mut result = Vec::new();
        tee.read_to_end(&mut result).unwrap();

        assert_eq!(result, b"tee stream verification");
        assert_eq!(tap, b"tee stream verification");

        let mut dest1 = Vec::new();
        let mut dest2 = Vec::new();
        {
            let mut tw = TeeWriter::new(&mut dest1, &mut dest2);
            tw.write_all(b"dual write verification").unwrap();
            tw.flush().unwrap();
        }
        assert_eq!(dest1, b"dual write verification");
        assert_eq!(dest2, b"dual write verification");
    }
}
