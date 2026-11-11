#!/usr/bin/env bash
# ==============================================================================
# IFA & Kori Toolchain - Multi-Platform Distribution Packaging Script
# Author: ASSOGBA Prudence Dieudonné <jprud67@gmail.com>
# License: MIT OR Apache-2.0
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="${1:-0.1.0}"
TARGET="${2:-x86_64-unknown-linux-gnu}"
DIST_DIR="${ROOT_DIR}/dist"
PACKAGE_NAME="ifa-v${VERSION}-${TARGET}"
STAGING_DIR="${DIST_DIR}/staging/${PACKAGE_NAME}"
ARCHIVE_NAME="${PACKAGE_NAME}.tar.gz"

echo "=== Building IFA Release Package: ${PACKAGE_NAME} ==="

# 1. Build release binaries
echo "[1/5] Compiling release binaries via Cargo..."
cargo build --release -p ifa-cli -p kori -p ifa-lsp

# 2. Prepare staging directory structure
echo "[2/5] Creating distribution staging structure..."
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/bin"
mkdir -p "${STAGING_DIR}/docs"

# 3. Copy binaries and create standard symlinks
echo "[3/5] Installing binaries and tools..."
cp "${ROOT_DIR}/target/release/ifa" "${STAGING_DIR}/bin/ifa"
chmod +x "${STAGING_DIR}/bin/ifa"

# Create canonical ifac binary alias
cp "${ROOT_DIR}/target/release/ifa" "${STAGING_DIR}/bin/ifac"
chmod +x "${STAGING_DIR}/bin/ifac"

if [ -f "${ROOT_DIR}/target/release/kori" ]; then
    cp "${ROOT_DIR}/target/release/kori" "${STAGING_DIR}/bin/kori"
    chmod +x "${STAGING_DIR}/bin/kori"
fi

if [ -f "${ROOT_DIR}/target/release/ifa-lsp" ]; then
    cp "${ROOT_DIR}/target/release/ifa-lsp" "${STAGING_DIR}/bin/ifa-lsp"
    chmod +x "${STAGING_DIR}/bin/ifa-lsp"
fi

# Copy Standard Library
echo "[4/5] Packaging Pure IFA Standard Library (std/)..."
cp -r "${ROOT_DIR}/std" "${STAGING_DIR}/"

# Copy Documentation, Examples and Licenses
cp -r "${ROOT_DIR}/examples" "${STAGING_DIR}/"
cp "${ROOT_DIR}/README.md" "${STAGING_DIR}/"
cp "${ROOT_DIR}/CHANGELOG.md" "${STAGING_DIR}/"
cp "${ROOT_DIR}/LICENSE-MIT" "${STAGING_DIR}/"
cp "${ROOT_DIR}/LICENSE-APACHE" "${STAGING_DIR}/"
cp "${ROOT_DIR}/docs/TOUR_OF_IFA.md" "${STAGING_DIR}/docs/"
cp "${ROOT_DIR}/docs/RELEASE_NOTES_v0.1.0.md" "${STAGING_DIR}/docs/"
cp "${ROOT_DIR}/docs/SPECIFICATION.md" "${STAGING_DIR}/docs/"

# 4. Create release tarball archive
echo "[5/5] Compressing distribution archive..."
mkdir -p "${DIST_DIR}"
tar -czf "${DIST_DIR}/${ARCHIVE_NAME}" -C "${DIST_DIR}/staging" "${PACKAGE_NAME}"

# Generate cryptographic checksums
cd "${DIST_DIR}"
sha256sum "${ARCHIVE_NAME}" > "${DIST_DIR}/SHA256SUMS"

echo "=== Packaging Complete ==="
echo "Artifact: ${DIST_DIR}/${ARCHIVE_NAME}"
echo "Checksum: $(cat "${DIST_DIR}/SHA256SUMS")"

# 5. Self-test extracted archive
echo "=== Validating Packaged Binaries ==="
TEST_EXTRACT_DIR="$(mktemp -d)"
tar -xzf "${DIST_DIR}/${ARCHIVE_NAME}" -C "${TEST_EXTRACT_DIR}"
"${TEST_EXTRACT_DIR}/${PACKAGE_NAME}/bin/ifa" --version
"${TEST_EXTRACT_DIR}/${PACKAGE_NAME}/bin/ifac" --version
if [ -f "${TEST_EXTRACT_DIR}/${PACKAGE_NAME}/bin/kori" ]; then
    "${TEST_EXTRACT_DIR}/${PACKAGE_NAME}/bin/kori" --version
fi
rm -rf "${TEST_EXTRACT_DIR}"
echo "Validation passed successfully."
