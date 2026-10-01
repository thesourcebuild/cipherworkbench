# `sslx` CLI vs. Cipher Workbench Feature Parity & Architecture

This document provides a comprehensive mapping between the [`sslx`](https://github.com/glincker/sslx) terminal CLI utility and the **Certificate & PKI Tool Family** in **Cipher Workbench**.

Cipher Workbench delivers **100% feature parity** with every command in `sslx`, while expanding each capability into an interactive, zero-installation, air-gapped cryptographic laboratory that runs both in the web browser and within the native Electron desktop shell.

---

## 1. Feature Parity Matrix

| `sslx` Command | What `sslx` Does | Where It Lives in Cipher Workbench | Status in CW & Enhancements |
| :--- | :--- | :--- | :---: |
| **`sslx grade host`** | Grades TLS setup: TLS 1.3, ciphers, cert validity, key type, SAN matching, ALPN. Gives letter grade `A+` to `F`. | **TLS & Certificate Grader** (`tls-grader`) + **Live TLS Endpoint Prober** (🌐 Probe Host) | **✅ 100% Match**<br>*(Plus stapled OCSP check, AIA live query, Certificate Transparency log audit, and ASCII terminal card generator)* |
| **`sslx expiry host...`** | Multi-host expiration auditor with table, days left, and exit codes for CI/CD. | **Certificate Expiry Monitor** (`cert-expiry`) + **Live TLS Endpoint Prober** (🌐 Probe Host) | **✅ 100% Match**<br>*(Plus visual lifespan gauge bars, bulk PEM bundle parsing, and Prometheus alert rule generation)* |
| **`sslx inspect cert.pem`** | Colored X.509 certificate viewer: Subject, Issuer, Serial, Validity bar (`[██░░░░░░░░]`), Key, SANs, SHA-256. | **X.509 Certificate Inspector** (`x509`) + **Live TLS Endpoint Prober** (🌐 Probe Host) | **✅ 100% Match**<br>*(Plus deep interactive ASN.1 tree explorer, CA/B Forum 398-day limit audit, and key usage bitmask breakdown)* |
| **`sslx connect host`** | Connects to remote host, displays negotiated TLS version, cipher, ALPN `h2`, and certificate chain. | **Live TLS Endpoint Prober** (🌐 Probe Host) (`apps/desktop` native `node:tls` socket bridge) | **✅ 100% Match**<br>*(Plus RFC 8305 Happy Eyeballs IPv4/IPv6, handshake latency timing, IP resolution, and full chain download)* |
| **`sslx generate --cn ...`** | Self-signed certificate generator for local dev with EC P-256 / Ed25519. | **Certificate Creator** (`cert-creator`) | **✅ 100% Match**<br>*(Plus RSA 2048–4096, CA-signing, custom SANs, IaC configs for Nginx/Caddy/K8s/Docker, OpenSSH, and RFC 4716 SSH2 exports)* |
| **`sslx csr --cn ...`** | Generates PKCS#10 CSR (`csr.pem`) and private key (`key.pem`). | **CSR Creator** (`csr-creator`) | **✅ 100% Match**<br>*(Plus cryptographic self-signature verification & in-browser Micro-CA CSR Signer)* |
| **`sslx convert cert --to der`** | Converts between formats: PEM to DER, DER to PEM, PKCS#12 to PEM. | **Certificate Converter** (`cert-converter`) + **Live TLS Endpoint Prober** (🌐 Probe Host) | **✅ 100% Match**<br>*(Plus PKCS#7 `.p7b`, PuTTY `.ppk` v3, RFC 4716 SSH2, OpenSSH `authorized_keys`, and RFC 7512 PKCS#11 URIs)* |
| **`sslx match cert key`** | Cryptographically verifies if a private key matches a certificate without manual hash diffs. | **Cert & Key Matcher** (`cert-matcher`) + **Live TLS Endpoint Prober** (🌐 Probe Host) | **✅ 100% Match**<br>*(RSA modulus math + ECDSA/Ed25519 public coordinate derivation & zero-hash diffing)* |
| **`sslx extract bundle.p12`** | Extracts leaf cert, intermediate chain, and private key from password-protected `.p12`/`.pfx`. | **Certificate Converter** (`cert-converter` ➔ `pkcs12-to-pem`) | **✅ 100% Match**<br>*(SafeBags inspector, AES-256-CBC, legacy 3DES-SHA1, and password re-keying)* |
| **`sslx decode <token>`** | Sniffs unknown files/tokens: auto-detects JWTs, PEM/DER certs, keys, and CSRs. | **Universal Crypto Sniffer** (`universal-decoder`) + **Live TLS Endpoint Prober** (🌐 Probe Host) | **✅ 100% Match**<br>*(Plus CRLs, PKCS#7 bundles, WireGuard keys, PuTTY PPK, RFC 4716 SSH2 keys, and RFC 7512 PKCS#11 URIs)* |
| **`sslx verify cert --ca ca`** | Path validation and cryptographic signature verification from leaf to Root CA. | **Chain Verifier** (`cert-verifier`) + **Live TLS Endpoint Prober** (🌐 Probe Host) | **✅ 100% Match**<br>*(Plus visual ASCII PKI hierarchy tree, SKI/AKI authority linkage, and signature algorithm audits)* |

---

## 2. Command-by-Command Deep Dive

### 1. `sslx grade host` ➔ TLS & Certificate Grader (`tls-grader`)
* **`sslx` capability**: Evaluates 7 security checks (TLS 1.3, Cipher suite, Certificate validity, Key algorithm, Hostname SAN match, Chain completeness, ALPN `h2`) and assigns a letter grade (`A+` to `F`).
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/tls-grader.ts` and `apps/web/app/endpoint-probe-modal.tsx`.
  - Calculates a weighted score out of 100 points, strictly enforcing CA/B Forum guidelines and NIST SP 800-52r2 baselines.
  - Automatically triggers when using the **🌐 Probe Host** omnibox or pasting offline certificate text.
  - **Cipher Workbench Extras**:
    - **Stapled OCSP Verification**: Checks if the remote server provides a cryptographically valid OCSP staple.
    - **Live AIA Responder Query**: Desktop bridge can query the live CA OCSP responder over HTTP POST (`application/ocsp-request`).
    - **Certificate Transparency (CT) Logs**: Desktop bridge queries Certspotter & `crt.sh` to audit public CT log inclusion.
    - **ASCII Terminal Card Generator**: Copy-pasteable terminal card matching the `sslx` CLI interface directly from the browser/desktop UI.

### 2. `sslx expiry host...` ➔ Certificate Expiry Monitor (`cert-expiry`)
* **`sslx` capability**: Scans hosts, parses validity dates, and displays days remaining in a terminal table.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/cert-expiry.ts`.
  - Accepts single certificates, concatenated PEM bundles, or live probe results.
  - Calculates high-precision days and hours remaining, highlighting active, expiring (<30 days), and expired states.
  - **Cipher Workbench Extras**:
    - **Visual Lifespan Gauge**: High-contrast Unicode progress bar (e.g. `[████████░░] 80% (62 days left)`).
    - **Prometheus Alert Rules**: Auto-generates ready-to-deploy Prometheus YAML alert rules (`cert_expiry_days_remaining < 30`).

### 3. `sslx inspect cert.pem` ➔ X.509 Certificate Inspector (`x509`)
* **`sslx` capability**: Displays colored certificate metadata (Subject DN, Issuer DN, Serial, Key info, SAN list, SHA-256 fingerprint).
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/x509.ts`.
  - Parses ASN.1 DER and PEM formats entirely in pure TypeScript without native dependencies.
  - **Cipher Workbench Extras**:
    - **CA/B Forum 398-Day Audit**: Warns if public TLS certificates exceed the maximum allowed lifespan (398 days).
    - **Deep ASN.1 Tree Explorer**: Interactive visual tree of TLV (Tag-Length-Value) nodes with hex offsets and tag classes.
    - **Key Usage & Extended Key Usage**: Decodes digitalSignature, keyEncipherment, serverAuth, clientAuth, codeSigning bitmasks.

### 4. `sslx connect host` ➔ Live TLS Endpoint Prober
* **`sslx` capability**: Opens a TLS socket to a target host and displays negotiated parameters.
* **Cipher Workbench implementation**:
  - Implemented in `apps/desktop/src/main/network.ts` using native `node:tls` over an IPC bridge.
  - Respects the application's strict air-gap boundary: disabled in purely web environments, active in desktop mode.
  - **Cipher Workbench Extras**:
    - **RFC 8305 Happy Eyeballs**: Dual-stack parallel racing between IPv6 and IPv4 with 300ms fallback.
    - **ALPN Negotiation**: Explicitly offers `h2` (HTTP/2) and `http/1.1`, reporting the server's negotiated application protocol.
    - **Context-Aware Routing**: Clicking "Probe Host" from any PKI tool routes payloads directly into the active tool (e.g., loading OCSP responders into `ocsp`, or populating leaf vs. issuer into `cert-verifier`).

### 5. `sslx generate --cn ...` ➔ Certificate Creator (`cert-creator`)
* **`sslx` capability**: Creates quick self-signed certificates with EC P-256 or Ed25519 for local testing.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/create-cert.ts` and `src/crypto/keys.ts`.
  - Generates self-signed leaf certificates or CA-signed hierarchies in seconds.
  - **Cipher Workbench Extras**:
    - **Algorithm Breadth**: Supports EC (P-256, P-384), Ed25519, RSA (2048, 3072, 4096), and Post-Quantum ML-DSA (FIPS 204).
    - **Complete Export Bundle**: Exports `certificate.crt`, `private.key`, `public.key`, `commands.sh`, `commands.ps1`, `commands.bat`, `authorized_keys` (OpenSSH), and `id_ssh2.pub` (RFC 4716 SSH2).
    - **Infrastructure as Code (IaC)**: Generates production configurations for Nginx, Caddy, Kubernetes Secrets, and Docker Compose.

### 6. `sslx csr --cn ...` ➔ CSR Creator & Signer (`csr-creator`, `csr`, `csr-signer`)
* **`sslx` capability**: Generates a PKCS#10 Certificate Signing Request.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/create-csr.ts`, `src/asn1/csr.ts`, and `src/asn1/csr-signer.ts`.
  - **Cipher Workbench Extras**:
    - **In-Browser Micro-CA**: `csr-signer` signs uploaded CSRs using custom CAs or ephemeral in-browser root authorities.
    - **Cryptographic Self-Signature Audit**: Mathematically verifies the CSR's internal signature to protect against submission tampering.

### 7. `sslx convert cert ...` ➔ Certificate & Key Converter (`cert-converter`)
* **`sslx` capability**: Converts certificates between PEM, DER, and PKCS#12.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/converter.ts`.
  - Handles automatic detection of any cryptographic input.
  - **Cipher Workbench Extras**:
    - **PKCS#7 / CMS Bundles**: Converts multi-cert PEM chains into `.p7b` containers and extracts `.p7b` back into distinct PEM blocks.
    - **PuTTY Private Keys**: Converts OpenSSL PKCS#8 private keys to PuTTY `.ppk` v3 (with Argon2/HMAC-SHA-256 MAC) and vice versa.
    - **RFC 4716 SSH2 Public Keys**: Converts OpenSSH `authorized_keys` or X.509 certificates into multi-line `---- BEGIN SSH2 PUBLIC KEY ----` SECSH format and vice versa.
    - **RFC 7512 PKCS#11 URIs**: Inspects and canonicalizes hardware token URIs (`pkcs11:token=...;object=...`).

### 8. `sslx match cert key` ➔ Cert & Key Matcher (`cert-matcher`)
* **`sslx` capability**: Verifies that a private key matches a certificate without manual hash comparison.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/matcher.ts`.
  - **Cipher Workbench Extras**:
    - **RSA**: Extracts and matches the exact RSA modulus ($n$) and public exponent ($e$).
    - **ECDSA & Ed25519**: Mathematically derives the public $(x, y)$ affine coordinates from the private scalar and asserts exact byte-for-byte identity against the certificate's SPKI.

### 9. `sslx extract bundle.p12` ➔ PKCS#12 Keystore Inspector & Unpacker
* **`sslx` capability**: Unpacks certificates and keys from `.p12` / `.pfx` containers.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/pkcs12.ts`.
  - Supports modern PBKDF2 + AES-256-CBC SafeBags as well as legacy PKCS#12 v1 PBE (3DES-SHA1, 40-bit RC2).
  - **Cipher Workbench Extras**:
    - **SafeBags Visual Inspector**: Dumps container structure, friendly names, local key IDs, and MAC presence.
    - **Password Re-Keying**: Changes the password and re-encrypts `.p12` containers in-browser without OpenSSL.

### 10. `sslx decode <token>` ➔ Universal Crypto Sniffer (`universal-decoder`)
* **`sslx` capability**: Auto-detects unknown cryptographic artifacts.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/universal-decoder.ts`.
  - Automatically identifies and unpacks:
    1. **JWTs** (RFC 7519 headers, claims, expiration status)
    2. **RFC 7512 PKCS#11 URIs** (`pkcs11:token=...`)
    3. **OpenSSH & RFC 4716 SSH2 Public Keys**
    4. **WireGuard Keys** (Curve25519 32-byte base64)
    5. **X.509 Certificates & CRLs**
    6. **PKCS#10 CSRs & PKCS#7 Bundles**
    7. **Private Keys** (PKCS#1, PKCS#8, EC, OpenSSH)
    8. **Hex & Base64 Raw Payloads**

### 11. `sslx verify cert --ca ca` ➔ Chain Verifier (`cert-verifier`)
* **`sslx` capability**: Validates certificate trust path and cryptographic signatures.
* **Cipher Workbench implementation**:
  - Implemented in `packages/tools/certificates/src/asn1/chain-verifier.ts`.
  - **Cipher Workbench Extras**:
    - **Visual ASCII Hierarchy Tree**: Draws complete PKI trees:
      ```
      [Root CA] (Self-signed)
         └── [Intermediate CA] (Verified)
               └── [Leaf Server Cert] (Valid)
      ```
    - **AKI / SKI Linkage Audit**: Verifies Authority Key Identifier (AKI) to Subject Key Identifier (SKI) cryptographic linkage.
    - **Digital Signature Math**: Cryptographically verifies RSA-PKCS1, RSA-PSS, and ECDSA signatures across the entire chain.
