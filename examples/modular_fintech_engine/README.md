# Modular Fintech Engine Example

This showcase demonstrates the **Hierarchical Multi-Module System** in IFA:

- **Modular Architecture**:
  - `src/main.ifa`: Root orchestrator.
  - `src/accounting/ledger.ifa`: Domain-specific ledger records and balance operations.
  - `src/security/hasher.ifa`: Audit records and checksum generation.
- **Language Features Demonstrated**:
  - `import path::to::module as alias` with namespace resolution (`ledger::...`, `hasher::...`).
  - Strict visibility enforcement (`pub` vs private).
  - Cross-module struct instantiation and function calls.
  - Deterministic value semantics with in-place mutation.
  - Native compilation and linking using Kori build orchestrator.
