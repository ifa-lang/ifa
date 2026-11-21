# IFA Standard Library: Asynchronous Network Programming Guide

**Author:** ASSOGBA Prudence Dieudonné (@jprud67)  
**Status:** Canonical Reference Manual  
**License:** MIT OR Apache-2.0  
**Target:** IFA Standard Library (`std/net`)

---

## 1. Overview & Architectural Principles

The IFA standard library network subsystem (`std/net`) delivers deterministic, non-blocking, multi-protocol communication with zero garbage collection overhead. Built on asynchronous I/O abstractions and colorless fibers, `std/net` provides unified APIs for:

- **TCP & UDP Transport**: Non-blocking client/server sockets, dual-stack IPv4/IPv6 support, and fine-grained socket options (`TCP_NODELAY`, `SO_KEEPALIVE`, `SO_REUSEADDR`).
- **HTTP/1.1 & HTTP/2**: RFC 9113 compliant HTTP/2 frames, HPACK header compression/decompression, prioritized stream multiplexing, request/response interceptors, and connection pooling.
- **WebSocket (RFC 6455)**: Bidirectional framing (Text, Binary, Ping, Pong, Close), masking/unmasking, fragmented frame reassembly, and connection pooling with real-time health telemetry.
- **Server-Sent Events (SSE)**: W3C EventSource streaming (`text/event-stream`), structured field parsing (`id`, `event`, `data`, `retry`), keep-alive heartbeats, and session diagnostics.
- **SIMD-Accelerated Parsers**: Vectorized HTTP and URI parsing with zero-copy string views.

---

## 2. Asynchronous HTTP/2 Client with Interceptors

The HTTP/2 client pool (`AsyncHttp2Pool`) manages multiplexed connections to upstream hosts with support for custom request and response interceptors.

### Architecture

```
+-----------------------------------------------------------------------------------+
|                                 AsyncHttp2Pool                                    |
|                                                                                   |
|  [ Request Interceptors ]  -->  [ Multiplexed Connection ]  -->  [ Response Int. ] |
|  - Bearer Token Auth            - HPACK Header Compression       - Latency Audit  |
|  - Distributed Tracing          - Stream Prioritization          - Decompression  |
|  - Short-Circuit Validation     - Concurrent Exchange            - Telemetry Log  |
+-----------------------------------------------------------------------------------+
```

### Usage Pattern

```rust
use ifa_stdlib::net::{
    AsyncHttp2Pool, Http2ClientRequest, Http2ClientResponse,
    Http2RequestInterceptor, Http2ResponseInterceptor,
};
use std::sync::Arc;

// 1. Configure the HTTP/2 client pool
let mut pool = AsyncHttp2Pool::new(16);

// 2. Attach a request interceptor for authentication & tracing
pool.add_request_interceptor(Arc::new(|req: &mut Http2ClientRequest| -> Option<Http2ClientResponse> {
    req.add_header("Authorization", "Bearer ifa-sys-token-xyz");
    req.add_header("X-Correlation-ID", "req-trace-42");
    None // Allow the request to proceed to the wire
}));

// 3. Attach a response interceptor for telemetry and post-processing
pool.add_response_interceptor(Arc::new(|resp: &mut Http2ClientResponse| {
    resp.add_header("X-Processed-By", "ifa-http2-interceptor-v1");
}));

// 4. Send asynchronous multiplexed requests
let mut request = Http2ClientRequest::new("GET", "https://api.internal.local/v1/telemetry");
let response = pool.send_request("api.internal.local:443", request).await?;
assert_eq!(response.status, 200);
```

### Short-Circuiting in Interceptors

Request interceptors can return `Some(Http2ClientResponse)` to short-circuit upstream network calls (e.g. for mock testing or local caching):

```rust
pool.add_request_interceptor(Arc::new(|req: &mut Http2ClientRequest| -> Option<Http2ClientResponse> {
    if req.path == "/healthz" {
        let mut cached = Http2ClientResponse::new(200);
        cached.body = b"{\"status\":\"ok\",\"engine\":\"ifa\"}".to_vec();
        return Some(cached);
    }
    None
}));
```

### Transparent Content-Encoding Decompression (RFC 7230 / RFC 7694)

The HTTP/2 client pool automatically advertises standard compression formats (`Accept-Encoding: gzip, deflate, br`) and transparently decodes compressed response payloads on both single requests and progressive streaming flows:

```rust
let pool = AsyncHttp2Pool::new("api.example.com", 443, 8)
    .with_http_cache(true)
    .with_auto_decompress(true)
    .with_accept_encoding("gzip, deflate, br");

// Executing a request transparently negotiates compression and decodes gzip, deflate, or br
let resp = pool.execute_request("GET", "/data", &[], None)?;
assert_eq!(resp.status.0, 200);
// Content-Encoding header is stripped, Content-Length updated, body decompressed
assert!(resp.headers.get("content-encoding").is_none());
assert_eq!(pool.stats().decompressed_responses, 1);
```

---

## 3. WebSocket Client & Pooled Multiplexing

The WebSocket module implements RFC 6455 bidirectional message framing with connection pooling and telemetry diagnostics.

### Connection Lifecycle & Telemetry

```rust
use ifa_stdlib::net::{AsyncWsPool, WsFrame, WsPoolStats};

// Create a pool with maximum 32 concurrent connections
let mut ws_pool = AsyncWsPool::new(32);

// Check real-time pool telemetry
let stats: WsPoolStats = ws_pool.stats();
println!(
    "Active: {}, Idle: {}, Max: {}, Utilization: {:.1}%",
    stats.active_connections,
    stats.idle_connections,
    stats.max_capacity,
    stats.utilization_rate() * 100.0,
);

// Transmit structured frames
let frame = WsFrame::text("telemetry:cpu_load:12%");
ws_pool.broadcast("wss://stream.internal.local/feed", frame).await?;
```

---

## 4. Server-Sent Events (SSE) Streaming

The SSE module adheres to the W3C EventSource specification for unidirectional real-time server-to-client event streaming.

### Client Event Consumer & Statistics

```rust
use ifa_stdlib::net::{AsyncSseClient, SseClientStats, SseEvent};

let mut client = AsyncSseClient::connect("https://events.internal.local/live").await?;

// Read incoming events
while let Some(event) = client.next_event().await? {
    println!("Event: [{}] ID: [{}] Data: {}", event.event, event.id, event.data);
}

// Inspect client session statistics
let stats: SseClientStats = client.stats();
println!(
    "Total events: {}, Bytes received: {}, Reconnects: {}",
    stats.events_received,
    stats.bytes_received,
    stats.reconnect_count,
);
```

### Server Event Broadcast & Statistics

```rust
use ifa_stdlib::net::{AsyncSseServer, SseEvent, SseServerStats};

let mut server = AsyncSseServer::bind("127.0.0.1:8080").await?;

// Broadcast event to all active clients
let event = SseEvent::new("price_update")
    .with_id("evt-101")
    .with_data("{\"symbol\":\"IFA/USD\",\"price\":1337.0}");

server.broadcast(event).await?;

// Query server statistics
let stats: SseServerStats = server.stats();
println!(
    "Active clients: {}, Events sent: {}, Bytes emitted: {}",
    stats.active_subscribers,
    stats.total_events_emitted,
    stats.total_bytes_sent,
);
```

---

## 5. SIMD-Accelerated Protocol Parsing

For ultra-low-latency gateways, `std/net/simd_parser` utilizes 128-bit vector registers (SSE2 / AVX2 / NEON) to scan protocol delimiters, header boundaries, and HPACK bitstreams at multi-gigabyte-per-second rates.

```rust
use ifa_stdlib::simd_parser::{find_delimiter_simd, parse_http_request_simd};

let raw_request = b"GET /v1/market/tickers HTTP/1.1\r\nHost: api.ifa.org\r\n\r\n";
let parsed = parse_http_request_simd(raw_request)?;

assert_eq!(parsed.method, "GET");
assert_eq!(parsed.path, "/v1/market/tickers");
```

---

## 6. Profiling & Micro-Benchmarks Suite

The `ifa_stdlib::net` module provides built-in throughput and latency benchmarking tools to validate networking performance under heavy loads:

```rust
use ifa_stdlib::net::{
    benchmark_sse_parsing, benchmark_tcp_throughput, benchmark_token_bucket,
    benchmark_websocket_framing, run_net_benchmark_suite,
};

// Execute full micro-benchmark suite (WebSocket, SSE, TokenBucket, TCP Throughput)
let report = run_net_benchmark_suite(1_000);
println!("Benchmark suite completed in {:.2} ms", report.total_duration_ms);

for bench in &report.benchmarks {
    println!(
        "[{}] iterations: {}, throughput: {:.1} ops/sec, latency: {:.2} ns/op",
        bench.name, bench.iterations, bench.ops_per_sec, bench.ns_per_op
    );
}

// Or run dedicated concurrent TCP endurance benchmark:
let tcp_result = benchmark_tcp_throughput(8 /* clients */, 500 /* msgs/client */, 1024 /* payload bytes */)?;
println!("TCP Throughput: {:.1} ops/sec", tcp_result.ops_per_sec);
```

---

## 7. Best Practices for IFA Systems Developers

1. **Deterministic Resource Management**: Always close or return pooled connections to avoid channel capacity exhaustion.
2. **Backpressure Awareness**: When using high-frequency SSE or WebSocket feeds, inspect `stats.utilization_rate()` periodically to throttle upstream ingestion.
3. **Interceptor Layering**: Place security interceptors (token validation, mutual TLS verification) at the head of the interceptor pipeline, before logging or caching.
4. **Zero-Copy Serialization**: Prefer borrowing byte slices when constructing `WsFrame` or `Http2ClientRequest` payloads to leverage IFA's generational reference and CoW guarantees.
