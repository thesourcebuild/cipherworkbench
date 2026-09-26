#!/usr/bin/env bash
set -eu

# mTLS Enterprise (3-Tier) Suite Management & Verification
# Verify 3-tier chains, test enterprise mTLS server/client, and validate TLS protocol versions on Linux / macOS.

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
    echo "=== Generating 3-Tier Enterprise PKI Suite via TypeScript Engine ==="
    npx tsx ./run.ts
    ;;
  verify)
    echo "=== Verifying 3-Tier Chains against Root CA (-untrusted intermediate.crt) ==="
    openssl verify -CAfile "./ca.crt" -untrusted "./intermediate.crt" "./server.crt"
    openssl verify -CAfile "./ca.crt" -untrusted "./intermediate.crt" "./client.crt"
    openssl crl -in "./ca.crl" -noout -text
    ;;
  server)
    echo "=== Starting 3-Tier Enterprise mTLS Server on port 8443 (TLS Version: $TLS_VER) ==="
    "$PYTHON_BIN" ./server.py --tls-version "$TLS_VER"
    ;;
  client)
    echo "=== Running Python 3-Tier Enterprise mTLS Client (TLS Version: $TLS_VER) ==="
    "$PYTHON_BIN" ./client.py --tls-version "$TLS_VER"
    ;;
  client-pem)
    echo "=== Testing 3-Tier mTLS Handshake with cURL (PEM chain) ==="
    curl -vk https://localhost:8443/ --cacert "./ca.crt" --cert "./client-chain.pem" --key "./client.key"
    ;;
  client-p12)
    echo "=== Testing 3-Tier mTLS Handshake with cURL (PKCS#12 container) ==="
    curl -vk https://localhost:8443/ --cacert "./ca.crt" --cert "./client.p12:EnterprisePass123!"
    ;;
  test-tls)
    echo "=== Verifying 3-Tier Enterprise mTLS across TLS 1.3, TLS 1.2, and TLS 1.1 ==="
    "$PYTHON_BIN" ./client.py --tls-version all
    ;;
  trust-root)
    echo "=== Importing Root CA to System Trust Store on macOS / Linux ==="
    if [ "$(uname)" = "Darwin" ]; then
      sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./ca.crt
      echo "[SUCCESS] Root CA trusted in macOS System Keychain! Browsers receiving server-chain.pem will trust it automatically."
    elif [ -d /usr/local/share/ca-certificates ]; then
      sudo cp ./ca.crt /usr/local/share/ca-certificates/enterprise-root-ca.crt
      sudo update-ca-certificates
      echo "[SUCCESS] Root CA added to Linux CA trust store! Browsers receiving server-chain.pem will trust it automatically."
    else
      echo "Please consult your Linux distribution manual on adding Root CAs."
    fi
    ;;
  install-client)
    echo "=== Importing PKCS#12 Client Certificate into Keychain / Browser ==="
    echo "Password is: EnterprisePass123!"
    if [ "$(uname)" = "Darwin" ]; then
      security import ./client.p12 -k ~/Library/Keychains/login.keychain-db -P "EnterprisePass123!" -T /usr/bin/curl
      echo "[SUCCESS] Client certificate imported into macOS login keychain!"
    else
      echo "Please import client.p12 directly into your browser's Certificate Manager (Settings -> Security -> Certificates)."
    fi
    ;;
  *)
    echo "Usage: ./commands.sh [run | verify | server | client | client-pem | client-p12 | test-tls | trust-root | install-client] [auto | 1.1 | 1.2 | 1.3 | all]"
    ;;
esac
