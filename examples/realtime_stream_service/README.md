# Real-Time Streaming & WebSocket Service (Dogfooding Reference)

High-performance real-time event streaming service written entirely in pure IFA, showcasing asynchronous WebSockets (RFC 6455) and Server-Sent Events (SSE / W3C EventSource) with zero garbage collection overhead.

## Capabilities

- **RFC 6455 WebSocket Server & Client**:
  - Full handshake negotiation (`101 Switching Protocols`, `Sec-WebSocket-Accept` verification).
  - Complete frame handling: Text (`0x1`), Binary (`0x2`), Ping (`0x9`), Pong (`0xA`), and Close (`0x8`).
  - RFC 6455 client masking and unmasked server streaming.
  - Continuation frames and message reassembly.
- **W3C Server-Sent Events (SSE)**:
  - Streaming `text/event-stream` delivery.
  - Structured fields: `id`, `event`, `data`, `retry`, and heartbeat comments.
- **Multichannel Pub/Sub Router**:
  - Real-time event broadcasting to multiple concurrent subscribers.
  - Zero-copy stream fan-out.
- **Deterministic Concurrency & High Throughput**:
  - Non-blocking multiplexing across active sessions.
  - Resilient graceful close and reconnect isolation.

## Build and Run

To build with Kori:

```bash
kori build
```

To execute the service and run all internal dogfooding validation checks:

```bash
./target/dev/realtime_stream_service
```
