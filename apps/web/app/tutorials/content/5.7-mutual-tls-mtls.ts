import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "When you visit a high-security embassy, you first inspect the building's official crest, flag, and diplomatic credentials at the gate to ensure you haven't arrived at a counterfeit front (Server Authentication). But once you request access to the classified conference room, the guards don't open the door simply because you knocked! You must present your own government-issued biometric security passport, prove you are the rightful bearer, and log your cryptographic badge on the register (Client Authentication). Standard HTTPS is a one-way street: only the server shows a passport. Mutual TLS (mTLS) is the two-way checkpoint where both parties cryptographically inspect and verify each other before exchanging a single byte of sensitive data.",
  problem:
    "Standard HTTPS encrypts the wire and proves the server's identity, but leaves client authentication to fragile application-layer secrets: passwords, bearer tokens, cookies, and static API keys that can be intercepted, leaked, or stolen from browser caches. How can two systems establish bilateral, tamper-proof identity directly at the cryptographic transport layer without relying on shared static passwords?",
  mechanismDiagram: "mtls",
  steps: [
    {
      title: "Step 1: The asymmetry of standard one-way TLS",
      speaker: "Alice",
      content:
        "In everyday web browsing (one-way TLS), Bob's server sends his X.509 certificate to Alice. Alice's browser validates Bob's signature path back to a local Root CA and encrypts the connection.\n\nHowever, from Bob's perspective at the transport layer, **Alice is completely anonymous**. Bob only learns who Alice is after the TLS handshake completes, when Alice transmits an application-layer credential—such as an HTTP Basic Auth header, a Bearer JWT, or a session cookie.\n\nIf Mallory intercepts that bearer token or steals it from server logs, Mallory can replay it from any computer in the world.",
      callout: {
        type: "warning",
        text: "Bearer tokens are like paper cash: anyone holding the token can spend it. Transport layer mTLS binds identity cryptographically to a private key that never leaves the client.",
      },
    },
    {
      title: "Step 2: The server demands identification: CertificateRequest",
      speaker: "Bob",
      content:
        "When Bob configures his server for **Mutual TLS (mTLS)**, he instructs his TLS stack to demand client authentication during the handshake.\n\nIn TLS 1.3, immediately after Bob sends his encrypted server certificate, Bob sends a **`CertificateRequest`** message containing:\n\n1. **`signature_algorithms`**: The cryptographic hash and signature algorithms Bob supports (e.g. `ecdsa_secp256r1_sha256`, `ed25519`, `rsa_pss_rsae_sha256`).\n2. **`certificate_authorities`**: An explicit list of Distinguished Names of trusted CAs: *'I will only accept client certificates signed by Trent's Corporate Internal PKI!'*\n\nIf the client cannot or refuses to supply a valid certificate, the handshake immediately terminates with a TLS alert (`bad_certificate` or `certificate_required`).",
    },
    {
      title: "Step 3: Alice selects her client certificate",
      speaker: "Alice",
      content:
        "Upon receiving Bob's `CertificateRequest`, Alice's TLS client searches her local certificate store (or a hardware security token / PKCS#12 bundle):\n\n1. **Trust Anchor Matching:** The certificate's issuer chain must terminate at one of the CAs Bob specified in `certificate_authorities`.\n2. **Extended Key Usage (EKU):** Under RFC 5280, the certificate must explicitly contain the `clientAuth` Key Purpose ID (`id-kp-clientAuth`, OID `1.3.6.1.5.5.7.3.2`).\n3. **Validity Window:** The current timestamp must fall strictly within the certificate's `notBefore` and `notAfter` boundaries.\n\nAlice responds by sending her client **`Certificate`** message containing her leaf certificate and any intermediate certificates leading to the trusted CA.",
      callout: {
        type: "info",
        text: "Role Separation: A certificate with only 'serverAuth' cannot be used for client authentication, and a certificate with only 'clientAuth' cannot impersonate a web server.",
      },
    },
    {
      title: "Step 4: The Proof-of-Possession: CertificateVerify",
      speaker: "Alice",
      content:
        "Public certificates are public knowledge. If Mallory copies Alice's public certificate from a public log, can Mallory send it to Bob and impersonate Alice?\n\n**No!** Bob requires cryptographic **Proof-of-Possession**.\n\nImmediately after sending her certificate, Alice sends the **`CertificateVerify`** message. Alice computes a cryptographic digital signature using her **client private key** over the SHA-256 hash of the entire handshake transcript (ClientHello + ServerHello + EncryptedExtensions + CertificateRequest + Certificate + nonces).\n\nBecause the transcript includes Bob's random server nonces and session keys, Mallory cannot pre-calculate or replay this signature!",
      callout: {
        type: "security",
        text: "Transcript binding: The signature covers every single byte sent so far in this specific session. An attacker cannot replay a CertificateVerify message in another connection.",
      },
    },
    {
      title: "Step 5: Bob verifies signatures and enforces Authorization",
      speaker: "Bob",
      content:
        "Bob receives Alice's `Certificate` and `CertificateVerify`:\n\n1. Bob verifies Alice's certificate path against his configured client CA bundle.\n2. Bob verifies Alice's `CertificateVerify` signature using the public key from Alice's certificate.\n3. Bob extracts Alice's identity: either her **Subject Distinguished Name** (e.g. `CN=payment-processor-prod-01`) or a **Subject Alternative Name** URI (e.g. `spiffe://prod.cluster/ns/payments/sa/processor`).\n\nBoth endpoints then exchange `Finished` MAC seals. When the first HTTP request arrives, Bob's application layer doesn't need to ask for a password—Bob already holds mathematically proven cryptographic identity at the network transport layer!",
    },
    {
      title: "Step 6: Zero Trust & Service Meshes (Microservices)",
      speaker: "Trent",
      content:
        "In traditional networks, organizations relied on perimeter firewalls ('castle-and-moat'). If an attacker breached one perimeter web server, they could freely access unprotected internal databases and microservices.\n\n**Zero Trust Architecture (NIST SP 800-207)** replaces network perimeter assumptions with continuous, mutual authentication:\n\n* **Service Meshes (Istio, Envoy, Linkerd):** Automatically inject proxy sidecars that establish mTLS between every pod.\n* **SPIFFE / SPIRE:** Standardizes cryptographically verifiable identities (`spiffe://domain/workload`) using automated, short-lived (e.g., 1-hour) X.509 SVID certificates.\n* **No Hardcoded Secrets:** Microservices communicate securely without storing static database passwords or API keys in code or config maps.",
      callout: {
        type: "info",
        text: "Zero Trust principle: Assume the network is hostile. Authenticate and encrypt every RPC between every microservice using ephemeral mTLS certificates.",
      },
    },
  ],
  afterTimeline: {
    title: "Why don't everyday consumer websites use mTLS?",
    content:
      "If mTLS is so secure, why doesn't google.com or amazon.com ask everyday users for a client certificate?\n\nClient certificate management introduces severe consumer usability hurdles: users would need to generate keypairs, install PKCS#12 (.p12) bundles in Windows or iOS, back up private keys when buying a new phone, and deal with browser certificate selection prompts. For general consumer browsing, password managers and FIDO2 / WebAuthn passkeys solve client authentication at the application layer.\n\nHowever, mTLS is the dominant, unchallenged gold standard for B2B APIs (Open Banking, payment gateways, electronic data interchange), IoT fleets (smart meters, automotive ECUs), and internal cloud-native infrastructure.",
    callout: {
      type: "info",
      text: "mTLS excels where machines talk to machines (APIs, IoT, microservices), while WebAuthn/Passkeys excel where humans talk to machines.",
    },
  },
  takeaways: [
    "Standard TLS authenticates only the server; Mutual TLS (mTLS) cryptographically verifies both parties before application data flows.",
    "The server triggers mTLS by sending a CertificateRequest message specifying accepted CA trust anchors and signature algorithms.",
    "Client certificates must include the clientAuth Extended Key Usage (EKU) extension (OID 1.3.6.1.5.5.7.3.2) to prevent certificate role confusion.",
    "The client proves ownership of its private key by digitally signing the unique handshake transcript in the CertificateVerify message, defeating replay attacks.",
    "mTLS eliminates vulnerable static API keys and bearer tokens in microservices, serving as the cryptographic backbone of Zero Trust architectures and SPIFFE service meshes.",
  ],
  seed: {
    toolId: "cert-creator",
    sampleInput: "CN=client-workload-01, O=Fintech Corp, EKU=clientAuth",
    explanation:
      "Open Certificate Creator to generate an X.509 certificate configured with Extended Key Usage: clientAuth for mutual TLS authentication.",
  },
};

export default content;
