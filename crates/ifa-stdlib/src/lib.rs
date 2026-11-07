pub mod crypto;
pub mod csv;
pub mod fs;
pub mod http;
pub mod io;
pub mod json;
pub mod sync;

pub use crypto::{blake3, blake3_hex, sha256, sha256_hex};
pub use csv::{decode as decode_csv, encode as encode_csv, CsvTable};
pub use fs::{
    append as fs_append, copy as fs_copy, create_dir as fs_create_dir,
    create_dir_all as fs_create_dir_all, exists as fs_exists, file_size as fs_file_size,
    is_dir as fs_is_dir, is_file as fs_is_file, list_dir as fs_list_dir, metadata as fs_metadata,
    read as fs_read, read_to_string as fs_read_to_string, remove_dir as fs_remove_dir,
    remove_dir_all as fs_remove_dir_all, remove_file as fs_remove_file, rename as fs_rename,
    write as fs_write, write_string as fs_write_string, FileMetadata,
};
pub use http::{HttpHeaders, HttpMethod, HttpRequest, HttpResponse, HttpStatus};
pub use io::{BufferedReader, BufferedWriter, MemoryStream};
pub use json::{
    decode as decode_json, encode as encode_json, encode_pretty as encode_json_pretty, JsonValue,
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
        assert_eq!(hex.len(), 64);
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
}
