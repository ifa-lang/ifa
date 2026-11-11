# Embedded Key-Value Storage & ACID Transaction Service

A high-performance, zero-GC transactional key-value service written in pure IFA, demonstrating:

1. **Embedded Storage Engine**: Zero external C dependencies, low-latency in-memory and on-disk indexed storage.
2. **Write-Ahead Logging (WAL)**: Append-only durability with transaction checkpoints.
3. **Cryptographic Integrity**: Deterministic checksum validation of every WAL record to detect and guard against bit-rot or corruption.
4. **ACID Transactions**: Atomic staging and commit of multiple key mutations, supporting explicit rollback on constraint failure.
5. **Prefix Range Scanning**: Deterministic alphabetical scanning across keys (e.g. `acc:*`, `order:*`, `audit:*`).

## Building & Running

### Using the IFA Toolchain

```bash
cd examples/kv_store_service
ifa run src/main.ifa
```

### Running Autonomous Tests

```bash
cd examples/kv_store_service
ifa test
```

### Compiling to Optimized Standalone Binary

```bash
cd examples/kv_store_service
ifa build --release
./target/release/kv_store_service
```
