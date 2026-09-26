# 3. mTLS (2-Tier) Suite Example

---

## 📐 Architecture

* **Hierarchy:** 2-tier PKI (`Root CA` &rarr; `Server Cert` + `Client Cert`).
* **Root CA (`ca.crt`):** `basicConstraints: critical,CA:TRUE`, `keyUsage: critical,keyCertSign,cRLSign`.
* **Server Cert (`server.crt`):** `basicConstraints: CA:FALSE`, `keyUsage: critical,digitalSignature`, `EKU: serverAuth`, `SAN: localhost, 127.0.0.1, ::1`.
* **Client Cert (`client.crt` & `client.p12`):** `basicConstraints: CA:FALSE`, `keyUsage: critical,digitalSignature`, `EKU: clientAuth`.
* **Revocation List (`ca.crl`):** RFC 5280 v2 Certificate Revocation List.

---

## 🚀 How to Run

### 1. Run Automated Generation & OpenSSL Handshake Tests:
```bash
npx tsx examples/certificates/mtls-2-tier/run.ts
```
This script generates the full suite, verifies both server and client certificate chains against the Root CA, tests mutual TLS authentication, verifies rejection of unauthenticated clients, and validates the TLS 1.1 / TLS 1.2 / TLS 1.3 protocol matrix.

### 2. Test with Python (Server & Client):
In Terminal 1 (start mTLS server):
```bash
python examples/certificates/mtls-2-tier/server.py
```

In Terminal 2 (run mTLS client):
```bash
python examples/certificates/mtls-2-tier/client.py
```

### 3. Test Specific TLS Protocol Versions:
```bash
# Force TLS 1.3
python examples/certificates/mtls-2-tier/client.py --tls-version 1.3

# Force TLS 1.2
python examples/certificates/mtls-2-tier/client.py --tls-version 1.2

# Force TLS 1.1
python examples/certificates/mtls-2-tier/client.py --tls-version 1.1

# Run matrix test across all versions:
python examples/certificates/mtls-2-tier/client.py --tls-version all
```

### 4. Windows PowerShell Helper:
```powershell
# Run automated generation & TLS matrix test:
.\commands.ps1 run

# Verify chains:
.\commands.ps1 verify

# Test mTLS across TLS 1.3, 1.2, and 1.1:
.\commands.ps1 test-tls

# Start Python mTLS server:
.\commands.ps1 server

# Run Python mTLS client:
.\commands.ps1 client

# Test mTLS with cURL (PEM certificates):
.\commands.ps1 client-pem

# Test mTLS with cURL (PKCS#12 container):
.\commands.ps1 client-p12

# Trust Root CA in Windows:
.\commands.ps1 trust-ca

# Install Client Certificate in Windows Personal Store for Browser testing:
.\commands.ps1 install-client
```

---

## 🔒 TLS 1.1, TLS 1.2, and TLS 1.3 Protocol Support

| TLS Protocol | Status | Cipher Suite Negotiated | Mutual Auth Notes |
| :--- | :--- | :--- | :--- |
| **TLS 1.3** | **Supported** (Default) | `TLS_AES_256_GCM_SHA384` | Encrypted Certificate messages; modern AEAD cipher. |
| **TLS 1.2** | **Supported** | `ECDHE-ECDSA-AES256-GCM-SHA384` | Standard mutual authentication handshake with ClientCertificateRequest. |
| **TLS 1.1** | **Supported** (Legacy) | `ECDHE-ECDSA-AES256-SHA` | Cryptographically valid. OpenSSL 3.0+ requires `@SECLEVEL=0` because RFC 8996 formally deprecated TLS 1.1. |

**OpenSSL CLI Testing Recipes:**
```bash
# Terminal 1: Server requiring client certificate (TLS 1.3)
openssl s_server -key server.key -cert server.crt -CAfile ca.crt -Verify 1 -tls1_3 -port 8443

# Terminal 2: Client presenting client certificate (TLS 1.3)
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -cert client.crt -key client.key -tls1_3

# Client under TLS 1.2
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -cert client.crt -key client.key -tls1_2

# Client under TLS 1.1 (requires SECLEVEL=0 on OpenSSL 3.0+)
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -cert client.crt -key client.key -tls1_1 -cipher "DEFAULT:@SECLEVEL=0"
```

---

## 🌐 Browser Testing with PKCS#12

1. Run `.\commands.ps1 trust-ca` to trust `ca.crt`.
2. Run `.\commands.ps1 install-client` (or double-click `client.p12`). Select "Current User" and enter password **`changeit`**.
3. Start the server (`python server.py` or `.\commands.ps1 server`).
4. Open `https://localhost:8443` in Chrome, Edge, or Firefox. The browser will prompt you to select your `client-worker-01` certificate to log in!
