#!/usr/bin/env bash
set -eu

# Single (Self-Signed) Certificate Management & Verification
# Inspect, verify, test, or trust the self-signed certificate on Linux / macOS.

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
    echo "=== Generating Self-Signed Certificate via TypeScript Engine ==="
    npx tsx ./run.ts
    ;;
  verify)
    echo "=== Verifying Certificate with OpenSSL ==="
    openssl x509 -in "./server.crt" -text -noout
    ;;
  info)
    echo "=== Inspecting Certificate Subject & SANs ==="
    openssl x509 -in "./server.crt" -noout -subject -issuer -dates -ext subjectAltName,basicConstraints,keyUsage
    ;;
  key)
    echo "=== Validating Private Key Parameters ==="
    openssl pkey -in "./private.key" -text -noout
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
    echo "=== Trusting Self-Signed Certificate on macOS / Linux ==="
    if [ "$(uname)" = "Darwin" ]; then
      sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain ./server.crt
      echo "[SUCCESS] Certificate trusted in macOS System Keychain!"
    elif [ -d /usr/local/share/ca-certificates ]; then
      sudo cp ./server.crt /usr/local/share/ca-certificates/single-self-signed.crt
      sudo update-ca-certificates
      echo "[SUCCESS] Certificate added to Linux CA trust store!"
    else
      echo "Please consult your Linux distribution manual on adding CA certificates."
    fi
    ;;
  *)
    echo "Usage: ./commands.sh [run | verify | info | key | server | client | test-tls | trust] [auto | 1.1 | 1.2 | 1.3 | all]"
    ;;
esac
