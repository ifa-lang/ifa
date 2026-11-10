# IFA Data Processor CLI

An autonomous, deterministic command-line data processing and analytics tool written in 100% pure IFA syntax.

## Features

- **JSON Ingestion & Validation**: Syntactic verification and structural inspection of metrics datasets.
- **Statistical Aggregation**: Deterministic computations including count, sum, minimum, maximum, and integer average.
- **Record Filtering**: Filter data streams by numeric thresholds with zero heap reallocation.
- **Cryptographic Digest**: BLAKE3 and SHA-256 data integrity fingerprints for audit logging.
- **Resilient Error Architecture**: Comprehensive CLI exit codes, structured error envelopes, and zero panics.

## Commands

```bash
# Display help and usage
ifa-data-processor-cli help

# Inspect JSON payload metadata
ifa-data-processor-cli inspect --input data.json

# Aggregate statistical metrics
ifa-data-processor-cli stats --input data.json

# Filter records with threshold
ifa-data-processor-cli filter --threshold 50 --input data.json

# Compute cryptographic integrity hash
ifa-data-processor-cli digest --algo blake3 --input data.json
```
