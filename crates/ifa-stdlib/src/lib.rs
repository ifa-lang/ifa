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

pub use collections::{
    BinaryHeap, BitSet, BitSetError, BitSetIter, ByteBuffer, CycleError, Deque, DiGraph,
    DirectedGraph, DisjointSet, Eviction, FenwickTree, Interval, IntervalError, IntervalMap,
    IntervalMapIter, IntervalSet, List, LruCache, Map, Set, StringBuilder, Trie, TrieSet,
};
pub use crypto::{
    base64_decode, base64_encode, base64url_decode, base64url_encode, blake3, blake3_hex,
    constant_time_eq, constant_time_eq_hex, hex_decode, hex_encode, hkdf_sha1, hkdf_sha1_expand,
    hkdf_sha1_extract, hkdf_sha1_hex, hkdf_sha256, hkdf_sha256_expand, hkdf_sha256_extract,
    hkdf_sha256_hex, hmac_sha1, hmac_sha1_hex, hmac_sha1_verify, hmac_sha1_verify_hex, hmac_sha256,
    hmac_sha256_hex, hmac_sha256_verify, hmac_sha256_verify_hex, hotp, pbkdf2_hmac_sha1,
    pbkdf2_hmac_sha1_hex, pbkdf2_hmac_sha1_verify, pbkdf2_hmac_sha1_verify_hex, pbkdf2_hmac_sha256,
    pbkdf2_hmac_sha256_hex, pbkdf2_hmac_sha256_verify, pbkdf2_hmac_sha256_verify_hex,
    secure_random_bytes, secure_random_fill, secure_random_token, secure_random_token_base64, sha1,
    sha1_hex, sha256, sha256_hex, totp, totp_verify, websocket_accept_key, HmacSha1,
    HmacSha1Reader, HmacSha1Writer, HmacSha256, HmacSha256Reader, HmacSha256Writer, Jwt, JwtClaims,
    JwtError, Sha1, Sha1Reader, Sha1Writer, Sha256, Sha256Reader, Sha256Writer, Uuid, UuidError,
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
    adler32_digest, adler32_reader, adler32_writer, adler_framed_reader, adler_framed_writer,
    base64_reader, base64_writer, chain, chunk_reader, chunk_writer, chunks, copy_stream,
    crc32_digest, crc32_reader, crc32_writer, crc_framed_reader, crc_framed_writer, decode_ivarint,
    decode_sleb128, decode_uvarint, delimited_reader, delimited_writer, empty, encode_ivarint,
    encode_sleb128, encode_sleb128_vec, encode_uvarint, encode_uvarint_vec, framed_reader,
    framed_writer, hex_reader, hex_writer, limited, limited_writer, multi_reader, multi_writer,
    pad_writer, pipe_lines, prefix_writer, prefixed, pushback_reader, read_ivarint, read_sleb128,
    read_to_end as io_read_to_end, read_to_string as io_read_to_string, read_uvarint, repeat, sink,
    skip_reader, suffix_writer, suffixed, try_read_ivarint, try_read_sleb128, try_read_uvarint,
    varint_framed_reader, varint_framed_writer, varint_reader, varint_writer, write_ivarint,
    write_sleb128, write_uvarint, zigzag_decode, zigzag_encode, Adler32Hasher, Adler32Reader,
    Adler32Writer, AdlerFramedIter, AdlerFramedReader, AdlerFramedWriter, Base64Reader,
    Base64Writer, BufferedReader, BufferedWriter, ChainedReader, ChunkIter, ChunkReader,
    ChunkWriter, CountingReader, CountingWriter, Crc32Hasher, Crc32Reader, Crc32Writer,
    CrcFramedIter, CrcFramedReader, CrcFramedWriter, DelimitedIter, DelimitedReader,
    DelimitedWriter, EmptyReader, FramedIter, FramedReader, FramedWriter, HexReader, HexWriter,
    IVarintIter, LengthFieldKind, LimitedReader, LimitedWriter, LineWriter, MemoryStream,
    MultiReader, MultiWriter, PadWriter, PrefixWriter, PrefixedReader, PushbackReader,
    RepeatReader, SinkWriter, SkipReader, Sleb128Iter, SuffixWriter, SuffixedReader, TeeReader,
    TeeWriter, UVarintIter, VarintFramedIter, VarintFramedReader, VarintFramedWriter, VarintReader,
    VarintWriter, DEFAULT_MAX_DELIMITED_RECORD_SIZE, DEFAULT_MAX_FRAME_SIZE, MAX_VARINT_LEN_U32,
    MAX_VARINT_LEN_U64,
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

        // Streaming Hash Writer and Reader adapters
        use std::io::{Read, Write};
        let payload = b"Cryptographic streaming pipeline test payload.";

        let mut sink256 = Vec::new();
        let mut w256 = Sha256Writer::new(&mut sink256);
        w256.write_all(payload).unwrap();
        assert_eq!(w256.digest_hex(), sha256_hex(payload));
        assert_eq!(sink256.as_slice(), payload);

        let mut r256 = Sha256Reader::new(payload.as_slice());
        let mut drain256 = Vec::new();
        r256.read_to_end(&mut drain256).unwrap();
        assert_eq!(r256.digest_hex(), sha256_hex(payload));

        let mut sink1 = Vec::new();
        let mut w1 = Sha1Writer::new(&mut sink1);
        w1.write_all(payload).unwrap();
        assert_eq!(w1.digest_hex(), sha1_hex(payload));
        assert_eq!(sink1.as_slice(), payload);

        let mut r1 = Sha1Reader::new(payload.as_slice());
        let mut drain1 = Vec::new();
        r1.read_to_end(&mut drain1).unwrap();
        assert_eq!(r1.digest_hex(), sha1_hex(payload));

        // Hex codecs and constant-time verification
        let hex_val = hex_encode(b"ifa");
        assert_eq!(hex_val, "696661");
        assert_eq!(hex_decode(&hex_val).unwrap(), b"ifa");
        assert!(constant_time_eq_hex(b"ifa", "696661"));
        assert!(constant_time_eq_hex(b"ifa", "696661"));
        assert!(!constant_time_eq_hex(b"ifa", "696662"));

        // Streaming HMAC Writer and Reader adapters
        let mut hmac_sink256 = Vec::new();
        let mut hw256 = HmacSha256Writer::new(&mut hmac_sink256, key);
        hw256.write_all(payload).unwrap();
        assert_eq!(hw256.mac_hex(), hmac_sha256_hex(key, payload));
        assert!(hw256.verify_hex(&hmac_sha256_hex(key, payload)));
        assert_eq!(hmac_sink256.as_slice(), payload);

        let mut hr256 = HmacSha256Reader::new(payload.as_slice(), key);
        let mut hdrain256 = Vec::new();
        hr256.read_to_end(&mut hdrain256).unwrap();
        assert_eq!(hr256.mac_hex(), hmac_sha256_hex(key, payload));
        assert!(hr256.verify(&hmac_sha256(key, payload)));

        let mut hmac_sink1 = Vec::new();
        let mut hw1 = HmacSha1Writer::new(&mut hmac_sink1, key);
        hw1.write_all(payload).unwrap();
        assert_eq!(hw1.mac_hex(), hmac_sha1_hex(key, payload));
        assert!(hw1.verify_hex(&hmac_sha1_hex(key, payload)));
        assert_eq!(hmac_sink1.as_slice(), payload);

        let mut hr1 = HmacSha1Reader::new(payload.as_slice(), key);
        let mut hdrain1 = Vec::new();
        hr1.read_to_end(&mut hdrain1).unwrap();
        assert_eq!(hr1.mac_hex(), hmac_sha1_hex(key, payload));
        assert!(hr1.verify(&hmac_sha1(key, payload)));
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

    #[test]
    fn test_io_empty_sink_repeat_exports() {
        use std::io::{Read, Write};

        let mut r = empty();
        let mut b = [0u8; 4];
        assert_eq!(r.read(&mut b).unwrap(), 0);

        let mut s = sink();
        assert_eq!(s.write(b"void").unwrap(), 4);
        s.flush().unwrap();

        let mut rep = repeat(b'Q');
        let mut rep_buf = [0u8; 3];
        assert_eq!(rep.read(&mut rep_buf).unwrap(), 3);
        assert_eq!(rep_buf, [b'Q', b'Q', b'Q']);
    }

    #[test]
    fn test_io_sleb128_prelude_exports() {
        let mut sink = Vec::new();
        let written = encode_sleb128_vec(-12345, &mut sink);
        assert!(written > 0);

        let (val, consumed) = decode_sleb128(&sink).unwrap();
        assert_eq!(val, -12345);
        assert_eq!(consumed, written);

        let mut out = Vec::new();
        {
            let mut writer = varint_writer(&mut out);
            writer.write_sleb128(987654).unwrap();
        }

        let mut reader = varint_reader(out.as_slice());
        assert_eq!(reader.read_sleb128().unwrap(), 987654);
    }

    #[test]
    fn test_io_varint_framed_prelude_exports() {
        let mut sink = Vec::new();
        {
            let mut writer = varint_framed_writer(&mut sink);
            writer.write_frame_str("ifa-varint-frame").unwrap();
            writer.write_frame(b"stream payload").unwrap();
            assert_eq!(writer.frames_written(), 2);
        }

        let mut reader = varint_framed_reader(sink.as_slice());
        assert_eq!(
            reader.read_frame_to_string().unwrap(),
            Some("ifa-varint-frame".to_string())
        );
        assert_eq!(
            reader.read_frame().unwrap(),
            Some(b"stream payload".to_vec())
        );
        assert_eq!(reader.read_frame().unwrap(), None);
        assert_eq!(reader.frames_read(), 2);
    }

    #[test]
    fn test_io_adler_framed_prelude_exports() {
        let mut sink = Vec::new();
        {
            let mut writer = adler_framed_writer(&mut sink);
            writer.write_frame_str("ifa-adler-frame").unwrap();
            writer.write_frame(b"adler payload").unwrap();
            assert_eq!(writer.frames_written(), 2);
        }

        let mut reader = adler_framed_reader(sink.as_slice());
        assert_eq!(
            reader.read_frame_to_string().unwrap(),
            Some("ifa-adler-frame".to_string())
        );
        assert_eq!(
            reader.read_frame().unwrap(),
            Some(b"adler payload".to_vec())
        );
        assert_eq!(reader.read_frame().unwrap(), None);
        assert_eq!(reader.frames_read(), 2);
    }

    #[test]
    fn test_crypto_pbkdf2_and_hkdf_reexports() {
        // PBKDF2 HMAC-SHA256 verification
        assert!(pbkdf2_hmac_sha256_verify_hex(
            b"password",
            b"salt",
            1,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        ));

        // PBKDF2 HMAC-SHA1 verification
        assert!(pbkdf2_hmac_sha1_verify_hex(
            b"password",
            b"salt",
            1,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        ));

        // HKDF-SHA256
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm_hex = hkdf_sha256_hex(Some(&salt), &ikm, &info, 42).unwrap();
        assert_eq!(
            okm_hex,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // HKDF-SHA1
        let okm1_hex = hkdf_sha1_hex(Some(&salt), &ikm[..11], &info, 42).unwrap();
        assert_eq!(
            okm1_hex,
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        );

        // UUID v4 and Secure Random
        let u = Uuid::new_v4().unwrap();
        assert_eq!(u.version(), Some(4));
        let u_str = u.to_string();
        assert_eq!(u_str.len(), 36);
        let parsed: Uuid = u_str.parse().unwrap();
        assert_eq!(parsed, u);

        let tok = secure_random_token(16).unwrap();
        assert_eq!(tok.len(), 32);
        let b64 = secure_random_token_base64(24).unwrap();
        assert_eq!(b64.len(), 32);
    }

    #[test]
    fn test_lru_cache_operations() {
        let mut cache: LruCache<&str, i32> = LruCache::new(3);
        assert_eq!(cache.capacity(), 3);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert!(!cache.is_full());

        // Fill up to capacity
        assert_eq!(cache.put("k1", 100), None);
        assert_eq!(cache.put("k2", 200), None);
        assert_eq!(cache.put("k3", 300), None);
        assert_eq!(cache.len(), 3);
        assert!(cache.is_full());

        // Check MRU and LRU
        assert_eq!(cache.peek_mru(), Some((&"k3", &300)));
        assert_eq!(cache.peek_lru(), Some((&"k1", &100)));

        // Access "k1", promoting it to MRU
        assert_eq!(cache.get(&"k1"), Some(&100));
        assert_eq!(cache.peek_mru(), Some((&"k1", &100)));
        assert_eq!(cache.peek_lru(), Some((&"k2", &200)));

        // Insert "k4", which should evict "k2" (the LRU)
        let ev = cache.put_with_eviction("k4", 400);
        assert_eq!(ev.old_value, None);
        assert_eq!(ev.evicted, Some(("k2", 200)));
        assert_eq!(cache.len(), 3);
        assert!(!cache.contains_key(&"k2"));
        assert_eq!(cache.get(&"k2"), None);
        assert_eq!(cache.peek_mru(), Some((&"k4", &400)));
        assert_eq!(cache.peek_lru(), Some((&"k3", &300)));

        // Update existing key
        let ev_update = cache.put_with_eviction("k3", 350);
        assert_eq!(ev_update.old_value, Some(300));
        assert_eq!(ev_update.evicted, None);
        assert_eq!(cache.peek_mru(), Some((&"k3", &350)));
        assert_eq!(cache.peek_lru(), Some((&"k1", &100)));

        // Peek mutable without changing recency
        if let Some(val) = cache.peek_mut(&"k1") {
            *val += 5;
        }
        assert_eq!(cache.peek_lru(), Some((&"k1", &105)));

        // Iteration from MRU to LRU
        let items: Vec<(&&str, &i32)> = cache.iter().collect();
        assert_eq!(items, vec![(&"k3", &350), (&"k4", &400), (&"k1", &105)]);

        let keys: Vec<&str> = cache.keys().copied().collect();
        assert_eq!(keys, vec!["k3", "k4", "k1"]);

        // Remove
        assert_eq!(cache.remove(&"k4"), Some(400));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.peek_mru(), Some((&"k3", &350)));
        assert_eq!(cache.peek_lru(), Some((&"k1", &105)));

        // Pop LRU
        assert_eq!(cache.pop_lru(), Some(("k1", 105)));
        assert_eq!(cache.len(), 1);

        // Pop MRU
        assert_eq!(cache.pop_mru(), Some(("k3", 350)));
        assert!(cache.is_empty());
        assert_eq!(cache.pop_lru(), None);
        assert_eq!(cache.pop_mru(), None);

        // Clear
        cache.put("a", 1);
        cache.put("b", 2);
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_ring_buffer_fifo() {
        let mut rb = collections::RingBuffer::new(3);
        assert_eq!(rb.capacity(), 3);
        assert_eq!(rb.len(), 0);
        assert!(rb.is_empty());

        assert!(rb.push(10));
        assert!(rb.push(20));
        assert!(rb.push(30));
        assert!(rb.is_full());
        assert!(!rb.push(40));

        assert_eq!(rb.peek(), Some(&10));
        assert_eq!(rb.pop(), Some(10));
        assert_eq!(rb.pop(), Some(20));

        assert!(rb.push(50));
        assert_eq!(rb.pop(), Some(30));
        assert_eq!(rb.pop(), Some(50));
        assert_eq!(rb.pop(), None);
    }

    #[test]
    fn test_bitset_operations_and_dataflow() {
        // Basic creation and bit manipulation
        let mut bs = BitSet::new();
        assert!(bs.is_empty());
        assert_eq!(bs.len(), 0);
        assert_eq!(bs.count_ones(), 0);
        assert_eq!(bs.count_zeros(), 0);
        assert!(bs.none());
        assert!(!bs.any());

        assert!(bs.insert(0));
        assert!(bs.insert(2));
        assert!(bs.insert(63));
        assert!(bs.insert(64));
        assert!(bs.insert(130));
        assert!(!bs.insert(2)); // already present

        assert_eq!(bs.len(), 131);
        assert_eq!(bs.count_ones(), 5);
        assert_eq!(bs.count_zeros(), 126);
        assert!(bs.contains(0));
        assert!(bs.contains(2));
        assert!(bs.contains(63));
        assert!(bs.contains(64));
        assert!(bs.contains(130));
        assert!(!bs.contains(1));
        assert!(!bs.contains(131));
        assert_eq!(bs.get(130), Some(true));
        assert_eq!(bs.get(131), None);
        assert!(bs[0]);
        assert!(!bs[1]);

        // Toggle and remove
        assert!(!bs.toggle(0)); // 0 becomes false
        assert!(!bs.contains(0));
        assert!(bs.toggle(0)); // 0 becomes true again
        assert!(bs.contains(0));

        assert!(bs.remove(2));
        assert!(!bs.contains(2));
        assert!(!bs.remove(2)); // already removed

        // Ones iterator (ordered, deterministic)
        let ones: Vec<usize> = bs.ones().collect();
        assert_eq!(ones, vec![0, 63, 64, 130]);

        // String representation
        let bitstr = "1011001";
        let parsed = BitSet::from_bit_string(bitstr).unwrap();
        assert_eq!(parsed.len(), 7);
        assert_eq!(parsed.count_ones(), 4);
        assert_eq!(parsed.to_bit_string(), bitstr);

        let err = BitSet::from_bit_string("10120");
        assert!(matches!(
            err,
            Err(BitSetError::InvalidCharacter { pos: 3, ch: '2' })
        ));

        // Bytes roundtrip
        let bytes = parsed.to_bytes();
        let from_b = BitSet::from_bytes(&bytes, parsed.len()).unwrap();
        assert_eq!(from_b, parsed);

        let err_bytes = BitSet::from_bytes(&[0xFF], 16);
        assert!(matches!(
            err_bytes,
            Err(BitSetError::InsufficientBytes {
                required: 2,
                provided: 1
            })
        ));

        // Repeat, clear, and fill
        let mut rep = BitSet::repeat(true, 10);
        assert_eq!(rep.len(), 10);
        assert!(rep.all());
        assert_eq!(rep.count_ones(), 10);

        rep.clear();
        assert_eq!(rep.count_ones(), 0);
        assert!(rep.none());
        assert_eq!(rep.len(), 10);

        rep.fill(true);
        assert!(rep.all());

        rep.truncate(5);
        assert_eq!(rep.len(), 5);
        assert_eq!(rep.count_ones(), 5);

        rep.resize(8, false);
        assert_eq!(rep.len(), 8);
        assert_eq!(rep.count_ones(), 5);
        assert_eq!(rep.to_bit_string(), "11111000");

        // Set operations: union, intersect, difference, symmetric difference
        let mut a = BitSet::new();
        a.insert(1);
        a.insert(2);
        a.insert(3);

        let mut b = BitSet::new();
        b.insert(2);
        b.insert(3);
        b.insert(4);

        let union_set = &a | &b;
        assert_eq!(union_set.ones().collect::<Vec<_>>(), vec![1, 2, 3, 4]);

        let inter_set = &a & &b;
        assert_eq!(inter_set.ones().collect::<Vec<_>>(), vec![2, 3]);

        let diff_set = &a - &b;
        assert_eq!(diff_set.ones().collect::<Vec<_>>(), vec![1]);

        let sym_diff = &a ^ &b;
        assert_eq!(sym_diff.ones().collect::<Vec<_>>(), vec![1, 4]);

        // Disjoint, subset, superset
        let disjoint_set = BitSet::from_iter(vec![10, 20]);
        assert!(a.is_disjoint(&disjoint_set));

        assert!(inter_set.is_subset(&a));
        assert!(a.is_superset(&inter_set));

        // Display formatting
        let disp = format!("{inter_set}");
        assert_eq!(disp, "BitSet(2/4 bits: [2, 3])");
    }

    #[test]
    fn test_collections_disjoint_set() {
        let mut ds: DisjointSet<String> = DisjointSet::new();
        assert!(ds.is_empty());
        assert_eq!(ds.len(), 0);
        assert_eq!(ds.set_count(), 0);

        // Insert elements
        assert!(ds.insert("a".to_string()));
        assert!(ds.insert("b".to_string()));
        assert!(ds.insert("c".to_string()));
        assert!(ds.insert("d".to_string()));
        assert!(!ds.insert("a".to_string())); // duplicate

        assert_eq!(ds.len(), 4);
        assert_eq!(ds.set_count(), 4);
        assert!(ds.contains(&"a".to_string()));
        assert!(!ds.contains(&"z".to_string()));

        // Initial singletons: find returns themselves
        assert_eq!(ds.find(&"a".to_string()), Some("a".to_string()));
        assert_eq!(ds.find(&"b".to_string()), Some("b".to_string()));
        assert!(!ds.connected(&"a".to_string(), &"b".to_string()));

        // Union a and b
        assert!(ds.union(&"a".to_string(), &"b".to_string()));
        assert_eq!(ds.set_count(), 3);
        assert!(ds.connected(&"a".to_string(), &"b".to_string()));
        assert_eq!(ds.component_size(&"a".to_string()), Some(2));
        assert_eq!(ds.component_size(&"b".to_string()), Some(2));

        // Union duplicate should return false
        assert!(!ds.union(&"a".to_string(), &"b".to_string()));
        assert_eq!(ds.set_count(), 3);

        // Union c and d
        assert!(ds.union(&"c".to_string(), &"d".to_string()));
        assert_eq!(ds.set_count(), 2);

        // Union (a, b) group with (c, d) group
        assert!(ds.union(&"b".to_string(), &"c".to_string()));
        assert_eq!(ds.set_count(), 1);
        assert!(ds.connected(&"a".to_string(), &"d".to_string()));
        assert_eq!(ds.component_size(&"d".to_string()), Some(4));

        // Union insert
        assert!(ds.union_insert("e".to_string(), "f".to_string()));
        assert_eq!(ds.len(), 6);
        assert_eq!(ds.set_count(), 2);
        assert!(ds.connected(&"e".to_string(), &"f".to_string()));
        assert!(!ds.connected(&"a".to_string(), &"e".to_string()));

        // Roots and components
        let roots = ds.roots();
        assert_eq!(roots.len(), 2);

        let comps = ds.components();
        assert_eq!(comps.len(), 2);
        let total_elems: usize = comps.values().map(|s| s.len()).sum();
        assert_eq!(total_elems, 6);

        // FromIterator & Extend
        let mut ds2 = DisjointSet::from_iter(vec![1, 2, 3, 4, 5]);
        assert_eq!(ds2.len(), 5);
        assert_eq!(ds2.set_count(), 5);

        // Extend edges
        ds2.extend(vec![(1, 2), (2, 3), (4, 5)]);
        assert_eq!(ds2.set_count(), 2);
        assert!(ds2.connected(&1, &3));
        assert!(ds2.connected(&4, &5));
        assert!(!ds2.connected(&1, &5));

        // Clear
        ds2.clear();
        assert!(ds2.is_empty());
        assert_eq!(ds2.len(), 0);
        assert_eq!(ds2.set_count(), 0);
    }

    #[test]
    fn test_collections_directed_graph() {
        let mut g: DirectedGraph<&str, u32> = DirectedGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);

        // Add nodes
        assert!(g.add_node("A"));
        assert!(g.add_node("B"));
        assert!(!g.add_node("A")); // Duplicate
        assert_eq!(g.node_count(), 2);
        assert!(g.contains_node(&"A"));
        assert!(!g.contains_node(&"Z"));

        // Add edges (automatically creates C and D)
        assert_eq!(g.add_edge("A", "B", 10), None);
        assert_eq!(g.add_edge("B", "C", 20), None);
        assert_eq!(g.add_edge("A", "C", 15), None);
        assert_eq!(g.add_edge("C", "D", 30), None);
        assert_eq!(g.node_count(), 4);
        assert_eq!(g.edge_count(), 4);

        // Edge inspection & mutation
        assert!(g.contains_edge(&"A", &"B"));
        assert!(!g.contains_edge(&"B", &"A"));
        assert_eq!(g.edge_weight(&"A", &"B"), Some(&10));
        *g.edge_weight_mut(&"A", &"B").unwrap() = 12;
        assert_eq!(g.edge_weight(&"A", &"B"), Some(&12));

        // Degrees
        assert_eq!(g.in_degree(&"A"), 0);
        assert_eq!(g.out_degree(&"A"), 2);
        assert_eq!(g.in_degree(&"C"), 2);
        assert_eq!(g.out_degree(&"C"), 1);
        assert_eq!(g.in_degree(&"D"), 1);
        assert_eq!(g.out_degree(&"D"), 0);

        // Sources & Sinks
        assert_eq!(g.sources(), vec!["A"]);
        assert_eq!(g.sinks(), vec!["D"]);

        // Topological Sort on DAG
        let topo = g
            .topological_sort()
            .expect("DAG must have valid topological order");
        assert_eq!(topo[0], "A");
        assert_eq!(topo[3], "D");
        // Verify dependency order: A before B, A before C, B before C, C before D
        let pos_a = topo.iter().position(|&x| x == "A").unwrap();
        let pos_b = topo.iter().position(|&x| x == "B").unwrap();
        let pos_c = topo.iter().position(|&x| x == "C").unwrap();
        let pos_d = topo.iter().position(|&x| x == "D").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
        assert!(pos_c < pos_d);

        // Reachability & Shortest path
        let reachable_a = g.reachable_from(&"A");
        assert_eq!(reachable_a.len(), 4);
        assert!(g.is_reachable(&"A", &"D"));
        assert!(!g.is_reachable(&"D", &"A"));

        let path = g.shortest_path(&"A", &"D");
        assert_eq!(path, Some(vec!["A", "C", "D"])); // A -> C -> D has length 2

        // Transpose graph
        let trans = g.transpose();
        assert_eq!(trans.node_count(), 4);
        assert_eq!(trans.edge_count(), 4);
        assert!(trans.contains_edge(&"D", &"C"));
        assert!(trans.contains_edge(&"C", &"A"));
        assert_eq!(trans.sources(), vec!["D"]);
        assert_eq!(trans.sinks(), vec!["A"]);

        // Remove edge and node
        assert_eq!(g.remove_edge(&"A", &"C"), Some(15));
        assert_eq!(g.edge_count(), 3);
        assert!(!g.contains_edge(&"A", &"C"));

        assert!(g.remove_node(&"B"));
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 1); // Only C -> D remains
        assert!(!g.contains_node(&"B"));

        // Cycle detection & SCC
        let mut cyclic: DiGraph<i32> = DiGraph::new();
        cyclic.add_edge_unweighted(1, 2);
        cyclic.add_edge_unweighted(2, 3);
        cyclic.add_edge_unweighted(3, 1);
        cyclic.add_edge_unweighted(3, 4);

        assert!(cyclic.has_cycle());
        let cycle_path = cyclic.find_cycle();
        assert!(cycle_path.is_some());
        let c = cycle_path.unwrap();
        assert_eq!(c.first(), c.last()); // Must start and end at same node

        let err = cyclic.topological_sort().unwrap_err();
        assert!(err.cycle.is_some());

        // Strongly connected components
        let sccs = cyclic.strongly_connected_components();
        // Should have {1, 2, 3} as one SCC, and {4} as another
        assert_eq!(sccs.len(), 2);
        let scc_cycle = sccs.iter().find(|s| s.contains(&1)).unwrap();
        assert_eq!(scc_cycle.len(), 3);
        assert!(scc_cycle.contains(&1) && scc_cycle.contains(&2) && scc_cycle.contains(&3));

        let scc_leaf = sccs.iter().find(|s| s.contains(&4)).unwrap();
        assert_eq!(scc_leaf.len(), 1);

        // FromIterator & Extend
        let mut g2 = DiGraph::from_iter(vec![(10, 20), (20, 30)]);
        assert_eq!(g2.node_count(), 3);
        assert_eq!(g2.edge_count(), 2);
        g2.extend(vec![(30, 40), (40, 50)]);
        assert_eq!(g2.node_count(), 5);
        assert_eq!(g2.edge_count(), 4);

        g2.clear();
        assert!(g2.is_empty());
        assert_eq!(g2.node_count(), 0);
        assert_eq!(g2.edge_count(), 0);
    }

    #[test]
    fn test_collections_trie() {
        let mut trie: Trie<usize> = Trie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
        assert!(!trie.starts_with(""));
        assert_eq!(trie.get("test"), None);

        // Insertion
        assert_eq!(trie.insert("app", 1), None);
        assert_eq!(trie.insert("apple", 2), None);
        assert_eq!(trie.insert("application", 3), None);
        assert_eq!(trie.insert("apply", 4), None);
        assert_eq!(trie.insert("banana", 5), None);
        assert_eq!(trie.len(), 5);
        assert!(!trie.is_empty());

        // Overwrite
        assert_eq!(trie.insert("app", 10), Some(1));
        assert_eq!(trie.len(), 5);

        // Lookup & Indexing
        assert_eq!(trie.get("app"), Some(&10));
        assert_eq!(trie.get("apple"), Some(&2));
        assert_eq!(trie.get("appl"), None); // intermediate node without value
        assert_eq!(trie["application"], 3);
        assert!(trie.contains_key("apply"));
        assert!(!trie.contains_key("orange"));

        // Mutation via get_mut
        if let Some(v) = trie.get_mut("apple") {
            *v += 100;
        }
        assert_eq!(trie.get("apple"), Some(&102));

        // starts_with
        assert!(trie.starts_with(""));
        assert!(trie.starts_with("app"));
        assert!(trie.starts_with("appl"));
        assert!(trie.starts_with("banana"));
        assert!(!trie.starts_with("band"));
        assert!(!trie.starts_with("zoo"));

        // Longest prefix match
        assert_eq!(trie.longest_prefix("applesauce"), Some(("apple", &102)));
        assert_eq!(
            trie.longest_prefix("application_data"),
            Some(("application", &3))
        );
        assert_eq!(trie.longest_prefix("app"), Some(("app", &10)));
        assert_eq!(trie.longest_prefix("ap"), None);
        assert_eq!(trie.longest_prefix("ban"), None);
        assert_eq!(trie.longest_prefix("bananas"), Some(("banana", &5)));
        assert_eq!(trie.longest_prefix_value("applesauce"), Some(&102));
        assert_eq!(trie.longest_prefix_value("unknown"), None);

        // Predictive search / Autocomplete (deterministic order)
        let app_matches = trie.predictive_search("app");
        let app_keys: Vec<String> = app_matches.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(app_keys, vec!["app", "apple", "application", "apply"]);

        let keys_all = trie.keys();
        assert_eq!(
            keys_all,
            vec!["app", "apple", "application", "apply", "banana"]
        );

        // Subtrie extraction
        let sub = trie.subtrie("appl").expect("subtrie must exist");
        assert_eq!(sub.len(), 3); // "e" (from apple), "ication" (from application), "y" (from apply)
        assert_eq!(sub.get("e"), Some(&102));
        assert_eq!(sub.get("ication"), Some(&3));
        assert_eq!(sub.get("y"), Some(&4));
        assert_eq!(sub.get("other"), None);

        // Removal & Node pruning
        assert_eq!(trie.remove("apply"), Some(4));
        assert_eq!(trie.len(), 4);
        assert_eq!(trie.get("apply"), None);
        assert!(trie.contains_key("apple")); // apple must still exist

        assert_eq!(trie.remove("nonexistent"), None);
        assert_eq!(trie.len(), 4);

        assert_eq!(trie.remove("app"), Some(10));
        assert_eq!(trie.len(), 3);
        assert_eq!(trie.get("app"), None);
        assert!(trie.contains_key("apple")); // children still preserved

        // Unicode support
        let mut unicode_trie = Trie::new();
        unicode_trie.insert("café", "coffee");
        unicode_trie.insert("cafétéria", "cafeteria");
        unicode_trie.insert("caffè", "italian coffee");
        unicode_trie.insert("🦀", "crab");
        unicode_trie.insert("🦀🦀", "two crabs");

        assert_eq!(unicode_trie.len(), 5);
        assert_eq!(unicode_trie.get("café"), Some(&"coffee"));
        assert_eq!(
            unicode_trie.longest_prefix("cafétéria grande"),
            Some(("cafétéria", &"cafeteria"))
        );
        assert_eq!(
            unicode_trie.longest_prefix("🦀🦀🦀"),
            Some(("🦀🦀", &"two crabs"))
        );
        assert_eq!(
            unicode_trie.keys_with_prefix("caf"),
            vec!["caffè", "café", "cafétéria"]
        );
        assert_eq!(
            unicode_trie.keys_with_prefix("café"),
            vec!["café", "cafétéria"]
        );

        // FromIterator & Extend
        let mut from_iter_trie: Trie<i32> = Trie::from_iter(vec![("x", 10), ("y", 20)]);
        assert_eq!(from_iter_trie.len(), 2);
        from_iter_trie.extend(vec![("z".to_string(), 30)]);
        assert_eq!(from_iter_trie.len(), 3);
        assert_eq!(from_iter_trie["z"], 30);

        // Clear
        from_iter_trie.clear();
        assert!(from_iter_trie.is_empty());
        assert_eq!(from_iter_trie.len(), 0);
    }

    #[test]
    fn test_collections_trie_set() {
        let mut set = TrieSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);

        assert!(set.insert("hello"));
        assert!(set.insert("world"));
        assert!(set.insert("help"));
        assert!(!set.insert("hello")); // duplicate
        assert_eq!(set.len(), 3);

        assert!(set.contains("hello"));
        assert!(set.contains("help"));
        assert!(!set.contains("hel"));

        assert!(set.starts_with("he"));
        assert!(!set.starts_with("woa"));

        assert_eq!(set.longest_prefix("helper function"), Some("help"));
        assert_eq!(set.longest_prefix("worldwide"), Some("world"));
        assert_eq!(set.longest_prefix("nothing"), None);

        assert_eq!(set.keys_with_prefix("hel"), vec!["hello", "help"]);
        assert_eq!(set.keys(), vec!["hello", "help", "world"]);

        assert!(set.remove("help"));
        assert!(!set.remove("help"));
        assert_eq!(set.len(), 2);
        assert!(!set.contains("help"));
        assert!(set.contains("hello"));

        let set2 = TrieSet::from_iter(vec!["alpha", "beta", "gamma"]);
        assert_eq!(set2.len(), 3);
        assert!(set2.contains("alpha"));

        let mut set3 = TrieSet::from_iter(vec!["one".to_string()]);
        set3.extend(vec!["two".to_string()]);
        set3.extend(vec!["three"]);
        assert_eq!(set3.len(), 3);

        set3.clear();
        assert!(set3.is_empty());
    }

    #[test]
    fn test_collections_interval_operations() {
        // Validation and creation
        let iv = Interval::new(10, 20).unwrap();
        assert_eq!(iv.start, 10);
        assert_eq!(iv.end, 20);
        assert!(!iv.is_empty());
        assert_eq!(format!("{}", iv), "[10, 20)");

        let empty_iv = Interval::new(15, 15).unwrap();
        assert!(empty_iv.is_empty());

        let invalid = Interval::new(25, 10);
        assert!(matches!(
            invalid,
            Err(IntervalError::InvertedBounds { start: 25, end: 10 })
        ));
        assert!(format!("{}", invalid.unwrap_err()).contains("Invalid interval bounds"));

        let unchecked = Interval::new_unchecked(5, 12);
        assert_eq!(unchecked.start, 5);
        assert_eq!(unchecked.end, 12);

        // Point containment
        assert!(!iv.contains_point(&9));
        assert!(iv.contains_point(&10));
        assert!(iv.contains_point(&15));
        assert!(iv.contains_point(&19));
        assert!(!iv.contains_point(&20));

        // Interval containment
        let inner = Interval::new(12, 18).unwrap();
        assert!(iv.contains_interval(&inner));
        assert!(!inner.contains_interval(&iv));
        assert!(iv.contains_interval(&iv));

        // Overlap & Touches
        let disjoint_left = Interval::new(0, 10).unwrap();
        let disjoint_right = Interval::new(20, 30).unwrap();
        let overlap_left = Interval::new(5, 15).unwrap();
        let overlap_right = Interval::new(15, 25).unwrap();

        assert!(!iv.overlaps(&disjoint_left));
        assert!(iv.touches(&disjoint_left));
        assert!(!iv.overlaps(&disjoint_right));
        assert!(iv.touches(&disjoint_right));

        assert!(iv.overlaps(&overlap_left));
        assert!(!iv.touches(&overlap_left));
        assert!(iv.overlaps(&overlap_right));

        // Intersection
        assert_eq!(iv.intersection(&disjoint_left), None);
        assert_eq!(
            iv.intersection(&overlap_left),
            Some(Interval::new(10, 15).unwrap())
        );
        assert_eq!(
            iv.intersection(&overlap_right),
            Some(Interval::new(15, 20).unwrap())
        );

        // Span
        let spanned = iv.span(&overlap_right);
        assert_eq!(spanned, Interval::new(10, 25).unwrap());
        let spanned_disjoint = iv.span(&disjoint_left);
        assert_eq!(spanned_disjoint, Interval::new(0, 20).unwrap());
    }

    #[test]
    fn test_collections_interval_map() {
        let mut map: IntervalMap<i32, &'static str> = IntervalMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);

        // Insertion
        assert_eq!(map.insert(Interval::new(10, 20).unwrap(), "first"), None);
        assert_eq!(map.insert(Interval::new(25, 35).unwrap(), "second"), None);
        assert_eq!(map.insert(Interval::new(5, 15).unwrap(), "third"), None);
        assert_eq!(map.len(), 3);

        // Duplicate update
        assert_eq!(
            map.insert(Interval::new(10, 20).unwrap(), "first_updated"),
            Some("first")
        );
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(&Interval::new(10, 20).unwrap()),
            Some(&"first_updated")
        );
        assert_eq!(map[&Interval::new(10, 20).unwrap()], "first_updated");

        // get_mut
        if let Some(val) = map.get_mut(&Interval::new(10, 20).unwrap()) {
            *val = "first_mutated";
        }
        assert_eq!(
            map.get(&Interval::new(10, 20).unwrap()),
            Some(&"first_mutated")
        );

        // Point queries
        assert!(map.contains_point(&12));
        let point_12 = map.query_point(&12);
        assert_eq!(point_12.len(), 2); // [5, 15) and [10, 20)
        assert!(!map.contains_point(&40));
        assert!(map.query_point(&40).is_empty());

        // Overlapping queries
        let query_iv = Interval::new(18, 26).unwrap();
        assert!(map.any_overlaps(&query_iv));
        let overlap_res = map.query_overlapping(&query_iv);
        assert_eq!(overlap_res.len(), 2); // [10, 20) overlaps with [18, 26), and [25, 35) overlaps with [18, 26)

        let disjoint_query = Interval::new(40, 50).unwrap();
        assert!(!map.any_overlaps(&disjoint_query));
        assert!(map.query_overlapping(&disjoint_query).is_empty());

        // Removal
        assert_eq!(
            map.remove(&Interval::new(10, 20).unwrap()),
            Some("first_mutated")
        );
        assert_eq!(map.len(), 2);
        assert!(!map.contains_key(&Interval::new(10, 20).unwrap()));
        assert_eq!(map.remove(&Interval::new(10, 20).unwrap()), None);

        // Iteration and order
        let keys = map.intervals();
        assert_eq!(
            keys,
            vec![
                Interval::new(5, 15).unwrap(),
                Interval::new(25, 35).unwrap()
            ]
        );

        let collected: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(
            collected,
            vec![
                (Interval::new(5, 15).unwrap(), "third"),
                (Interval::new(25, 35).unwrap(), "second")
            ]
        );

        // FromIterator and Extend
        let mut from_iter_map: IntervalMap<i32, i32> = IntervalMap::from_iter(vec![
            (Interval::new(1, 5).unwrap(), 100),
            (Interval::new(6, 10).unwrap(), 200),
        ]);
        assert_eq!(from_iter_map.len(), 2);
        from_iter_map.extend(vec![(Interval::new(11, 15).unwrap(), 300)]);
        assert_eq!(from_iter_map.len(), 3);
        assert_eq!(
            from_iter_map.get(&Interval::new(11, 15).unwrap()),
            Some(&300)
        );

        // Stress balancing (AVL rotations)
        let mut avl_map = IntervalMap::new();
        for i in 0..50 {
            avl_map.insert(Interval::new(i * 10, i * 10 + 5).unwrap(), i);
        }
        assert_eq!(avl_map.len(), 50);
        for i in 0..50 {
            assert_eq!(
                avl_map.get(&Interval::new(i * 10, i * 10 + 5).unwrap()),
                Some(&i)
            );
        }
        for i in (0..50).step_by(2) {
            assert_eq!(
                avl_map.remove(&Interval::new(i * 10, i * 10 + 5).unwrap()),
                Some(i)
            );
        }
        assert_eq!(avl_map.len(), 25);
        for i in (1..50).step_by(2) {
            assert_eq!(
                avl_map.get(&Interval::new(i * 10, i * 10 + 5).unwrap()),
                Some(&i)
            );
        }

        avl_map.clear();
        assert!(avl_map.is_empty());
        assert_eq!(avl_map.len(), 0);
    }

    #[test]
    fn test_collections_interval_set() {
        let mut set: IntervalSet<i32> = IntervalSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);

        assert!(set.insert(Interval::new(10, 20).unwrap()));
        assert!(set.insert(Interval::new(30, 40).unwrap()));
        assert!(!set.insert(Interval::new(10, 20).unwrap())); // duplicate
        assert_eq!(set.len(), 2);

        assert!(set.contains(&Interval::new(10, 20).unwrap()));
        assert!(!set.contains(&Interval::new(15, 25).unwrap()));

        assert!(set.contains_point(&15));
        assert!(!set.contains_point(&25));
        assert!(set.contains_point(&35));

        assert!(set.any_overlaps(&Interval::new(15, 25).unwrap()));
        assert!(!set.any_overlaps(&Interval::new(21, 29).unwrap()));

        let pt_res = set.query_point(&15);
        assert_eq!(pt_res, vec![&Interval::new(10, 20).unwrap()]);

        let ov_res = set.query_overlapping(&Interval::new(18, 35).unwrap());
        assert_eq!(
            ov_res,
            vec![
                &Interval::new(10, 20).unwrap(),
                &Interval::new(30, 40).unwrap()
            ]
        );

        assert!(set.remove(&Interval::new(10, 20).unwrap()));
        assert!(!set.remove(&Interval::new(10, 20).unwrap()));
        assert_eq!(set.len(), 1);

        // Merging test
        let mut merge_set = IntervalSet::new();
        merge_set.insert(Interval::new(1, 5).unwrap());
        merge_set.insert(Interval::new(3, 8).unwrap());
        merge_set.insert(Interval::new(8, 10).unwrap());
        merge_set.insert(Interval::new(15, 20).unwrap());
        merge_set.insert(Interval::new(18, 22).unwrap());
        merge_set.insert(Interval::new(30, 35).unwrap());

        let merged = merge_set.merged();
        assert_eq!(
            merged,
            vec![
                Interval::new(1, 10).unwrap(),
                Interval::new(15, 22).unwrap(),
                Interval::new(30, 35).unwrap(),
            ]
        );

        // Empty set merge
        let empty: IntervalSet<i32> = IntervalSet::new();
        assert!(empty.merged().is_empty());

        // FromIterator and Extend
        let mut set2 = IntervalSet::from_iter(vec![
            Interval::new(0, 10).unwrap(),
            Interval::new(20, 30).unwrap(),
        ]);
        assert_eq!(set2.len(), 2);
        set2.extend(vec![Interval::new(40, 50).unwrap()]);
        assert_eq!(set2.len(), 3);

        set2.clear();
        assert!(set2.is_empty());
    }

    #[test]
    fn test_fenwick_tree_operations() {
        // Empty tree
        let empty: FenwickTree<i64> = FenwickTree::new(0);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.prefix_sum(0), None);
        assert_eq!(empty.range_sum(0, 0), None);

        // Incremental add
        let mut ft = FenwickTree::new(5);
        assert_eq!(ft.len(), 5);
        assert!(!ft.is_empty());

        assert!(ft.add(0, 3));
        assert!(ft.add(1, 2));
        assert!(ft.add(2, -1));
        assert!(ft.add(3, 6));
        assert!(ft.add(4, 5));
        assert!(!ft.add(5, 10)); // Out of bounds

        assert_eq!(ft.prefix_sum(0), Some(3));
        assert_eq!(ft.prefix_sum(1), Some(5));
        assert_eq!(ft.prefix_sum(2), Some(4));
        assert_eq!(ft.prefix_sum(3), Some(10));
        assert_eq!(ft.prefix_sum(4), Some(15));
        assert_eq!(ft.prefix_sum(5), None);

        // Range sums
        assert_eq!(ft.range_sum(0, 0), Some(3));
        assert_eq!(ft.range_sum(0, 4), Some(15));
        assert_eq!(ft.range_sum(1, 3), Some(7)); // 2 + (-1) + 6 = 7
        assert_eq!(ft.range_sum(2, 4), Some(10)); // -1 + 6 + 5 = 10
        assert_eq!(ft.range_sum(3, 2), None); // start > end
        assert_eq!(ft.range_sum(0, 5), None); // out of bounds

        // Construction from slice
        let vals = [10, 20, 30, 40, 50];
        let mut ft_slice = FenwickTree::from_slice(&vals);
        assert_eq!(ft_slice.prefix_sum(4), Some(150));
        assert_eq!(ft_slice.range_sum(1, 3), Some(90));

        // Update existing index
        ft_slice.add(2, -15); // index 2 becomes 30 - 15 = 15
        assert_eq!(ft_slice.range_sum(1, 3), Some(75));

        // Clear
        ft_slice.clear();
        assert_eq!(ft_slice.prefix_sum(4), Some(0));
    }
}
