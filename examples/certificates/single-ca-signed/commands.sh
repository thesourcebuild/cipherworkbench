#!/usr/bin/env bash
set -eu

# Single (CA-Signed) Certificate Management & Verification
# Verify, test, or trust the Root CA and CA-signed server certificate on Linux / macOS.

if ! command -v openssl >/dev/null 2>&1; then
  echo "[ERROR] OpenSSL is not installed or not in PATH." >&2
  exit 1
fi

ACTION="${1:-verify}"
TLS_VER="${2:-auto}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="python3"
command -v python3 >/dev/null 2>&1 || PYTHON_BIN="python"

case "$ACTION" in
  run)
    echo "=== Generating CA and CA-Signed Certificate ==="
    npx tsx ./run.ts
    ;;
  verify)
    echo "=== Verifying Server Certificate Chain against Root CA ==="
    openssl verify -CAfile "./ca.crt" "./server.crt"
    ;;
  info)
    echo "=== Inspecting Server Certificate Extensions ==="
    openssl x509 -in "./server.crt" -noout -subject -issuer -dates -ext subjectAltName,basicConstraints,keyUsage,authorityKeyIdentifier
    ;;
  server)
    echo "=== Starting HTTPS Server on port 8443 (TLS Version: $TLS_VER) ==="
    "$PYTHON_BIN" ./server.py --tls-version "$TLS_VER"
    ;;
  client)
    echo "=== Connecting Client to Server (TLS Version: $TLS_VER) ==="
    "$PYTHON_BIN" ./client.py --tls-version "$TLS_VER"
    ;;
  test-tls)
    echo "=== Verifying TLS 1.3, TLS 1.2, and TLS 1.1 Support via Python Client ==="
    "$PYTHON_BIN" ./client.py --tls-version all
    ;;
  trust)
    echo "=== Importing Root CA to System Trust Store on macOS / Linux ==="
    if [ "$(uname)" = "Darwin" ]; then
      sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./ca.crt
      echo "[SUCCESS] Root CA trusted in macOS System Keychain! All browsers will trust server.crt."
    elif [ -d /usr/local/share/ca-certificates ]; then
      sudo cp ./ca.crt /usr/local/share/ca-certificates/cipherworkbench-root-ca.crt
      sudo update-ca-certificates
      echo "[SUCCESS] Root CA added to Linux CA trust store! All browsers will trust server.crt."
    else
      echo "Please consult your Linux distribution manual on adding Root CAs."
    fi
    ;;
  *)
    echo "Usage: ./commands.sh [run | verify | info | server | client | test-tls | trust] [auto | 1.1 | 1.2 | 1.3 | all]"
    ;;
esac
