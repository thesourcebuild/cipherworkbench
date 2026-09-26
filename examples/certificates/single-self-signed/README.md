# 1. Single (Self-Signed) Certificate Example

---

## 📐 Architecture

* **Hierarchy:** Single certificate (`Issuer == Subject`). Length: 1.
* **Algorithm:** ECDSA (NIST P-256 / `prime256v1`) + SHA-256.
* **Basic Constraints:** `CA:FALSE` (pure end-entity leaf).
* **Key Usage:** `critical,digitalSignature` (strictly RFC 5480 compliant; no invalid `keyEncipherment` or static `keyAgreement`).
* **SAN (Dual-Stack):** `DNS:localhost, IP:127.0.0.1, IP:::1` (16-byte octet string).

---

## 🚀 How to Run

### 1. Generate & Run Automated OpenSSL Test:
```bash
npx tsx examples/certificates/single-self-signed/run.ts
```
This script invokes the CipherWorkbench engine, writes `certificate.crt` and `private.key`, verifies X.509 v3 extensions with native OpenSSL, starts a mock server on port 9541, and validates the TLS handshake.

### 2. Test with Python (Server & Client):
In Terminal 1 (start server):
```bash
python examples/certificates/single-self-signed/server.py
```

In Terminal 2 (run client):
```bash
python examples/certificates/single-self-signed/client.py
```

### 3. Test Specific TLS Protocol Versions:
```bash
# Python client enforcing TLS version:
python examples/certificates/single-self-signed/client.py --tls-version 1.3
python examples/certificates/single-self-signed/client.py --tls-version 1.2
python examples/certificates/single-self-signed/client.py --tls-version 1.1

# Test all TLS versions:
python examples/certificates/single-self-signed/client.py --tls-version all
```

### 4. Windows PowerShell Helper:
```powershell
# Run automated generation & TLS matrix test:
.\commands.ps1 run

# Inspect extensions:
.\commands.ps1 info

# Verify TLS 1.3, TLS 1.2, and TLS 1.1 support:
.\commands.ps1 test-tls

# Start Python HTTPS server:
.\commands.ps1 server

# Run Python client:
.\commands.ps1 client

# Import to Windows "Trusted People" store (for Chrome/Edge local trust):
.\commands.ps1 trust
```

---

## 🔒 TLS 1.1, TLS 1.2, and TLS 1.3 Protocol Support

| TLS Protocol | Status | Cipher Suite Negotiated | Security Context |
| :--- | :--- | :--- | :--- |
| **TLS 1.3** | **Supported** (Default) | `TLS_AES_256_GCM_SHA384` | Modern standard. Requires `digitalSignature` in `keyUsage` (fully compliant). |
| **TLS 1.2** | **Supported** | `ECDHE-ECDSA-AES256-GCM-SHA384` | Universal enterprise standard. Forward-secret ECDHE. |
| **TLS 1.1** | **Supported** (Legacy) | `ECDHE-ECDSA-AES256-SHA` | Cryptographically valid. OpenSSL 3.0+ requires `@SECLEVEL=0` because RFC 8996 formally deprecated TLS 1.1. |

**OpenSSL CLI Testing Recipes:**
```bash
# Force TLS 1.3
openssl s_client -connect 127.0.0.1:8443 -CAfile certificate.crt -tls1_3

# Force TLS 1.2
openssl s_client -connect 127.0.0.1:8443 -CAfile certificate.crt -tls1_2

# Force TLS 1.1 (requires SECLEVEL=0 on OpenSSL 3.0+)
openssl s_client -connect 127.0.0.1:8443 -CAfile certificate.crt -tls1_1 -cipher "DEFAULT:@SECLEVEL=0"
```

---

## 🌐 Browser Trust Notes

* **Chrome / Edge:** Import `certificate.crt` into Windows **"Trusted People"** (not Root CA):
  ```powershell
  Import-Certificate -FilePath .\certificate.crt -CertStoreLocation Cert:\CurrentUser\TrustedPeople
  ```
* **Developer Bypass:** Alternatively enable `chrome://flags/#allow-insecure-localhost`.
