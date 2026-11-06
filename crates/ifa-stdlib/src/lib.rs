pub mod crypto;
pub mod csv;
pub mod http;
pub mod json;

pub use crypto::{blake3, blake3_hex, sha256, sha256_hex};
pub use csv::{decode as decode_csv, encode as encode_csv, CsvTable};
pub use http::{HttpHeaders, HttpMethod, HttpRequest, HttpResponse, HttpStatus};
pub use json::{
    decode as decode_json, encode as encode_json, encode_pretty as encode_json_pretty, JsonValue,
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
}
