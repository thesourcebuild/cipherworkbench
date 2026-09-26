# 4. mTLS Enterprise (3-Tier) Suite Example

---

## 📐 Architecture

* **Hierarchy:** 3-tier enterprise PKI (`Root CA` &rarr; `Intermediate Issuing CA` &rarr; `Server Cert` + `Client Cert`).
* **Root CA (`ca.crt`):** High-security offline trust anchor (`basicConstraints: critical,CA:TRUE`, `keyUsage: critical,keyCertSign,cRLSign`).
* **Intermediate CA (`intermediate.crt`):** Online issuing CA with `basicConstraints: critical,CA:TRUE,pathlen:0`.
* **Server Bundle (`server-chain.pem`):** `server.crt` + `intermediate.crt`.
* **Client Bundle (`client-chain.pem` & `client.p12`):** `client.crt` + `intermediate.crt` + PKCS#12 container.
* **Revocation List (`ca.crl`):** RFC 5280 v2 CRL issued by the authority.

---

## 🚀 How to Run

### 1. Run Automated Generation & 3-Tier OpenSSL Handshake Tests:
```bash
npx tsx examples/certificates/mtls-enterprise-3-tier/run.ts
```
This script generates the 3-tier hierarchy, verifies both server and client chains against the Root CA using `-untrusted intermediate.crt`, starts an OpenSSL server presenting `server-chain.pem`, validates mutual authentication, rejects unauthenticated clients, and verifies the TLS 1.1 / TLS 1.2 / TLS 1.3 protocol matrix.

### 2. Test with Python (Server & Client):
In Terminal 1 (start 3-tier server):
```bash
python examples/certificates/mtls-enterprise-3-tier/server.py
```

In Terminal 2 (run 3-tier client):
```bash
python examples/certificates/mtls-enterprise-3-tier/client.py
```

### 3. Test Specific TLS Protocol Versions:
```bash
# Force TLS 1.3
python examples/certificates/mtls-enterprise-3-tier/client.py --tls-version 1.3

# Force TLS 1.2
python examples/certificates/mtls-enterprise-3-tier/client.py --tls-version 1.2

# Force TLS 1.1
python examples/certificates/mtls-enterprise-3-tier/client.py --tls-version 1.1

# Run protocol matrix test across all versions:
python examples/certificates/mtls-enterprise-3-tier/client.py --tls-version all
```

### 4. Windows PowerShell Helper:
```powershell
# Run automated generation & TLS matrix test:
.\commands.ps1 run

# Verify 3-tier chains:
.\commands.ps1 verify

# Test 3-tier enterprise mTLS across TLS 1.3, 1.2, and 1.1:
.\commands.ps1 test-tls

# Start Python 3-tier enterprise mTLS server:
.\commands.ps1 server

# Run Python 3-tier enterprise mTLS client:
.\commands.ps1 client

# Test 3-tier mTLS with cURL (PEM chain):
.\commands.ps1 client-pem

# Test 3-tier mTLS with cURL (PKCS#12 container):
.\commands.ps1 client-p12

# Trust Root CA in Windows:
.\commands.ps1 trust-root

# Install Client Certificate in Windows Personal Store:
.\commands.ps1 install-client
```

---

## 🔒 TLS 1.1, TLS 1.2, and TLS 1.3 Protocol Support

| TLS Protocol | Status | Cipher Suite Negotiated | 3-Tier Chain Handling |
| :--- | :--- | :--- | :--- |
| **TLS 1.3** | **Supported** (Default) | `TLS_AES_256_GCM_SHA384` | Server transmits `server-chain.pem`; client transmits `client-chain.pem` inside encrypted handshake. |
| **TLS 1.2** | **Supported** | `ECDHE-ECDSA-AES256-GCM-SHA384` | Full certificate chain exchange in cleartext handshake messages. Verified to Root CA. |
| **TLS 1.1** | **Supported** (Legacy) | `ECDHE-ECDSA-AES256-SHA` | Cryptographically valid. OpenSSL 3.0+ requires `@SECLEVEL=0` because RFC 8996 formally deprecated TLS 1.1. |

**OpenSSL CLI Testing Recipes:**
```bash
# Terminal 1: 3-Tier Enterprise Server (TLS 1.3)
openssl s_server -key server.key -cert server-chain.pem -CAfile ca-chain.pem -Verify 1 -tls1_3 -port 8443

# Terminal 2: 3-Tier Enterprise Client (TLS 1.3)
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -cert client.crt -cert_chain intermediate.crt -key client.key -tls1_3

# Client under TLS 1.2
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -cert client.crt -cert_chain intermediate.crt -key client.key -tls1_2

# Client under TLS 1.1 (requires SECLEVEL=0 on OpenSSL 3.0+)
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt -cert client.crt -cert_chain intermediate.crt -key client.key -tls1_1 -cipher "DEFAULT:@SECLEVEL=0"
```

---

## 🏢 Why 3-Tier is Mandatory in Enterprise Production

1. **Air-Gapped Root Protection:** The Root CA private key is never exposed on an online server. It is kept in an offline HSM or cold storage.
2. **Blast Radius Isolation:** If an issuing server is compromised, only `intermediate.crt` is revoked. You do **not** need to reinstall Root CAs across thousands of devices and browsers.
3. **`pathlen:0` Enforcement:** Guarantees that the Intermediate CA cannot issue subordinate CAs.
