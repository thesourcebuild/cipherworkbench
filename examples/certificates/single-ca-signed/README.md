# 2. Single (CA-Signed) Certificate Example

---

## 📐 Architecture

* **Hierarchy:** 2-tier single leaf (`Server Cert` &rarr; `Root CA`).
* **Root CA (`ca.crt`):** `basicConstraints: critical,CA:TRUE`, `keyUsage: critical,keyCertSign,cRLSign`.
* **Server Cert (`server.crt`):** `basicConstraints: CA:FALSE`, `keyUsage: critical,digitalSignature`, `EKU: serverAuth`.
* **Authority Key Identifier:** Cryptographically linked to the CA's `subjectKeyIdentifier`.
* **SAN (Dual-Stack):** `DNS:localhost, IP:127.0.0.1, IP:::1`.

---

## 🚀 How to Run

### 1. Run Automated Generation & OpenSSL Chain Test:
```bash
npx tsx examples/certificates/single-ca-signed/run.ts
```
This script generates `ca.crt`, `ca.key`, `server.crt`, and `server.key`, verifies the chain with `openssl verify -CAfile ca.crt server.crt`, executes a live TLS handshake on port 9542, and validates the TLS 1.1 / TLS 1.2 / TLS 1.3 protocol matrix.

### 2. Test with Python (Server & Client):
In Terminal 1 (start server):
```bash
python examples/certificates/single-ca-signed/server.py
```

In Terminal 2 (run client):
```bash
python examples/certificates/single-ca-signed/client.py
```

### 3. Test Specific TLS Protocol Versions:
```bash
# Force TLS 1.3
python examples/certificates/single-ca-signed/client.py --tls-version 1.3

# Force TLS 1.2
python examples/certificates/single-ca-signed/client.py --tls-version 1.2

# Force TLS 1.1
python examples/certificates/single-ca-signed/client.py --tls-version 1.1

# Run protocol matrix test across all versions:
python examples/certificates/single-ca-signed/client.py --tls-version all
```

### 4. Windows PowerShell Helper:
```powershell
# Run automated generation & TLS matrix test:
.\commands.ps1 run

# Verify certificate chain:
.\commands.ps1 verify

# Inspect certificate extensions:
.\commands.ps1 info

# Test TLS 1.3, 1.2, and 1.1 protocol support via OpenSSL:
.\commands.ps1 test-tls

# Start Python HTTPS server:
.\commands.ps1 server

# Run Python client:
.\commands.ps1 client

# Import Root CA to Windows (gives clean padlock in Chrome/Edge):
.\commands.ps1 trust
```

---

## 🔒 TLS 1.1, TLS 1.2, and TLS 1.3 Protocol Support

| TLS Protocol | Status | Cipher Suite Negotiated | Security Context |
| :--- | :--- | :--- | :--- |
| **TLS 1.3** | **Supported** (Default) | `TLS_AES_256_GCM_SHA384` | Modern standard. Verified against Root CA. |
| **TLS 1.2** | **Supported** | `ECDHE-ECDSA-AES256-GCM-SHA384` | Universal enterprise standard. Forward-secret ECDHE. |
| **TLS 1.1** | **Supported** (Legacy) | `ECDHE-ECDSA-AES256-SHA` | Cryptographically valid. OpenSSL 3.0+ requires `@SECLEVEL=0` because RFC 8996 formally deprecated TLS 1.1. |

**OpenSSL CLI Testing Recipes:**
```bash
# Force TLS 1.3
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -tls1_3

# Force TLS 1.2
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -tls1_2

# Force TLS 1.1 (requires SECLEVEL=0 on OpenSSL 3.0+)
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -tls1_1 -cipher "DEFAULT:@SECLEVEL=0"
```
