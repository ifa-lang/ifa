# Tour of IFA & Quickstart Guide (v0.1.* Series)

Welcome to the **IFA Systems Programming Language** (`ifa-lang`). IFA is a statically typed, compiled systems programming language engineered for deterministic reliability, fearless concurrency via colorless fibers, strict memory safety without garbage collection pauses, and multi-architecture native compilation (ELF64, Mach-O, PE32+/COFF, and WebAssembly).

---

## 1. Quickstart in 60 Seconds

### Installation & Verification

Once `ifa` is in your `PATH`, verify your installation:

```bash
ifa --version
```

### Hello, World

Create a file named `hello.ifa`:

```ifa
pub fn main() {
    println("Hello, IFA!");
}
```

Run it immediately with the unified runtime:

```bash
ifa run hello.ifa
```

Compile it to an optimized native binary:

```bash
ifa build hello.ifa -o hello
./hello
```

---

## 2. Package Management with Kori

Every production IFA project is organized as a package with a `kori.toml` manifest.

### Creating a New Project

```bash
ifa new my_project
cd my_project
```

This generates the canonical project structure:

```text
my_project/
├── kori.toml
└── src/
    └── main.ifa
```

### The Manifest (`kori.toml`)

```toml
[package]
name = "my_project"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT OR Apache-2.0"
description = "Production service in pure IFA"

[dependencies]
std = { path = "../std" }

[targets]
bin = [
    { name = "my_project", path = "src/main.ifa" }
]
lib = { name = "my_project", path = "src/lib.ifa", crate_types = ["ifalib"] }

[profiles.dev]
opt-level = 0
debug = true

[profiles.release]
opt-level = 3
lto = "fat"
```

### Building and Testing

```bash
# Compile development binary
ifa build

# Compile release binary with full optimizations
ifa build --release

# Run the project binary
ifa run

# Execute autonomous unit tests
ifa test

# Format code according to IFA style guidelines
ifa fmt
```

---

## 3. Language Fundamentals

### Variables and Mutability

By default, all bindings in IFA are immutable. Use `mut` to declare mutable state:

```ifa
let immutable_val: i64 = 42;
mut counter: i64 = 0;
counter = counter + 1;
```

### Functions and In-Out Parameters

Parameters are passed by value by default. Use `inout` for mutable in-place references:

```ifa
pub fn increment(inout val: i64, step: i64) {
    val = val + step;
}

pub fn main() {
    mut score = 100;
    increment(inout score, 15);
    println(score); // Prints 115
}
```

### Structs and Methods

Structs define typed, memory-efficient data structures:

```ifa
pub struct RequestHeader {
    name: String,
    value: String
}

pub struct HttpRequest {
    method: String,
    path: String,
    status_code: i64
}

pub fn make_get_request(path: String) -> HttpRequest {
    return HttpRequest(
        method: "GET",
        path: path,
        status_code: 200
    );
}
```

### Pattern Matching

IFA features exhaustive pattern matching on integers, strings, enums, and structured types:

```ifa
pub fn describe_status(code: i64) -> String {
    match code {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown Status"
    }
}
```

---

## 4. Standard Library Modules (`std/`)

IFA ships with a batteries-included, zero-dependency standard library:

| Module | Namespace | Capabilities |
| :--- | :--- | :--- |
| **Networking & HTTP** | `std::net` | TCP non-blocking sockets, HTTP/1.1 client & server, WebSocket RFC 6455 framing, SSE, JWT middleware, CSRF protection, connection pooling |
| **Cryptography** | `std::crypto` | BLAKE3 tree hashing, SHA-256, HMAC-SHA256, RFC 7519 JWT HS256, Base64/Base64URL codecs, constant-time equality |
| **Data Formats** | `std::json`, `std::csv` | High-throughput JSON parser & serializer, RFC 4180 CSV parser & generator |
| **Collections** | `std::collections` | Dynamic List, Robin-Hood Map, Set, Deque, RingBuffer, Priority Queue (Binary Heap), StringBuilder |
| **Concurrency** | `std::sync` | Colorless fibers, MPMC cross-fiber channels, WaitGroup, Atomic primitives (`AtomicI64`, `AtomicBool`) |
| **Embedded Database & WAL** | `std::db` | Zero-GC transactional key-value store, Write-Ahead Logging (WAL), atomic multi-operation transactions, rollback, prefix scanning, BLAKE3 crash recovery |
| **I/O & File System** | `std::io`, `std::fs` | Buffered streams, memory streams, atomic file writes, recursive directory walking |
| **Process & Environment** | `std::process`, `std::env` | Subprocess spawning, stdin/stdout/stderr pipeline capture, environment variable access |
| **Time & Formatting** | `std::time`, `std::fmt` | Monotonic high-resolution clocks, elapsed durations, formatted string interpolation |

---

## 5. End-to-End Examples

### Asynchronous REST Microservice

Compile and run the production HTTP microservice example from `examples/http_service`:

```bash
cd examples/http_service
ifa build
./target/dev/http_service
```

### Data Processing CLI

Execute structured telemetry transformation, threshold filtering, and BLAKE3 cryptographic digests:

```bash
cd examples/data_processor_cli
ifa build
./target/dev/data_processor_cli
```

### Transactional Key-Value Storage Engine

Embedded zero-GC transactional database service demonstrating atomic balance transfer, rollback, prefix scanning, and WAL recovery:

```bash
cd examples/kv_store_service
ifa build
./target/dev/kv_store_service
```

### Real-Time Streaming & WebSocket Service

High-throughput bidirectional event streaming service demonstrating RFC 6455 WebSocket framing, Server-Sent Events (SSE), and multichannel Pub/Sub fanout:

```bash
cd examples/realtime_stream_service
ifa build
./target/dev/realtime_stream_service
```

---

## 6. Language Server Protocol (LSP 3.17)

IFA provides built-in LSP support for editors such as VS Code, Neovim, and Helix:

```bash
ifa lsp
```

Supported LSP capabilities:
- Diagnostics on open and edit (parse errors, type mismatches, missing imports)
- Hover documentation for functions, structs, and fields
- Go-to-definition across local files and imported modules
- Auto-completion for symbols and standard library namespaces
- Document formatting via the canonical formatting engine

---

## 7. WebAssembly Component Model & WIT (WASI 0.2)

IFA provides first-class support for WASI 0.2 and the WebAssembly Component Model:

```bash
# Wrap a core Wasm module into a standard Component binary
ifa component wrap input.wasm -o component.wasm

# Inspect Component header and interface sections
ifa component info component.wasm

# Parse and validate a WIT (WebAssembly Interface Type) document
ifa wit check service.wit
```
