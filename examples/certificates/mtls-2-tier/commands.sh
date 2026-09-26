#!/usr/bin/env bash
set -eu

# mTLS (2-Tier) Suite Management & Verification
# Verify chains, run mTLS server, test Python / cURL / OpenSSL across TLS versions on Linux / macOS.

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
    echo "=== Generating 2-Tier mTLS Suite via TypeScript Engine ==="
    npx tsx ./run.ts
    ;;
  verify)
    echo "=== Verifying Server and Client Chains against Root CA ==="
    openssl verify -CAfile "./ca.crt" "./server.crt"
    openssl verify -CAfile "./ca.crt" "./client.crt"
    ;;
  server)
    echo "=== Starting 2-Tier mTLS Server on port 8443 (TLS Version: $TLS_VER) ==="
    "$PYTHON_BIN" ./server.py --tls-version "$TLS_VER"
    ;;
  client)
    echo "=== Running Python mTLS Client (TLS Version: $TLS_VER) ==="
    "$PYTHON_BIN" ./client.py --tls-version "$TLS_VER"
    ;;
  client-pem)
    echo "=== Testing mTLS Handshake with cURL (PEM certificates) ==="
    curl -vk https://localhost:8443/ --cacert "./ca.crt" --cert "./client.crt" --key "./client.key"
    ;;
  client-p12)
    echo "=== Testing mTLS Handshake with cURL (PKCS#12 container) ==="
    curl -vk https://localhost:8443/ --cacert "./ca.crt" --cert "./client.p12:changeit"
    ;;
  test-tls)
    echo "=== Verifying mTLS Support across TLS 1.3, TLS 1.2, and TLS 1.1 ==="
    "$PYTHON_BIN" ./client.py --tls-version all
    ;;
  trust-ca)
    echo "=== Importing Root CA to System Trust Store on macOS / Linux ==="
    if [ "$(uname)" = "Darwin" ]; then
      sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./ca.crt
      echo "[SUCCESS] Root CA trusted in macOS System Keychain!"
    elif [ -d /usr/local/share/ca-certificates ]; then
      sudo cp ./ca.crt /usr/local/share/ca-certificates/mtls-2tier-ca.crt
      sudo update-ca-certificates
      echo "[SUCCESS] Root CA added to Linux CA trust store!"
    else
      echo "Please consult your Linux distribution manual on adding Root CAs."
    fi
    ;;
  install-client)
    echo "=== Importing PKCS#12 Client Certificate into Keychain / Browser ==="
    echo "Password is: changeit"
    if [ "$(uname)" = "Darwin" ]; then
      security import ./client.p12 -k ~/Library/Keychains/login.keychain-db -P "changeit" -T /usr/bin/curl
      echo "[SUCCESS] Client certificate imported into macOS login keychain!"
    else
      echo "Please import client.p12 directly into your browser's Certificate Manager (Settings -> Security -> Certificates)."
    fi
    ;;
  *)
    echo "Usage: ./commands.sh [run | verify | server | client | client-pem | client-p12 | test-tls | trust-ca | install-client] [auto | 1.1 | 1.2 | 1.3 | all]"
    ;;
esac
