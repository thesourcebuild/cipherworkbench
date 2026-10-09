import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  sectionTitle: "Core Principles & Security Boundaries",
  analogy:
    "Imagine an armored bank courier transport system. Before opening the vault doors, the dispatchers verify radio identities using cryptographic badges (authentication & certificates). Next, the two dispatchers perform a rapid math challenge to generate a unique, one-time radio passcode valid only for today's trip (key exchange & HKDF). Finally, every bag loaded into the truck is locked with a numbered, tamper-evident security seal (AEAD record framing). Even if thieves attack the truck or tap the radio, they cannot listen, forge messages, or swap bags.\n\nSecure transport protocols—such as TLS 1.3, DTLS, and SSH—are the master orchestrators that combine isolated cryptographic tools into a resilient communication tunnel.",
  problem:
    "Individual cryptographic algorithms (AES, ECDH, SHA-256, X.509) do nothing on their own. How do networks combine them safely into a reliable, tamper-proof state machine that protects communications over untrusted wires?",
  steps: [
    {
      title: "What It Is: The Core Nature of Secure Transport Protocols",
      speaker: "Alice",
      content:
        "Secure transport protocols are network state machines operating between the transport layer (TCP or UDP) and application data (HTTP, WebSockets, DNS). They take disparate cryptographic primitives—asymmetric key exchange, digital certificates, key derivation functions, and symmetric AEAD ciphers—and synchronize them to protect sessions from end to end.",
      callout: {
        type: "info",
        text: "The primary secure transport protocols are TLS (for TCP streams), DTLS (for UDP datagrams), and SSH (for remote terminal sessions and file transfers).",
      },
    },
    {
      title: "What It Does: The Protocol Symphony in Four Acts",
      speaker: "Bob",
      content:
        "A secure protocol executes a coordinated sequence of operations:\n\n1. **Negotiation (ClientHello / ServerHello):** Agree on protocol versions, cipher suites, and supported curves.\n2. **Authentication & Key Exchange (ECDHE & X.509):** Exchange ephemeral key shares and verify server identity using signed certificate chains.\n3. **Key Derivation (HKDF):** Expand the ephemeral shared secret into distinct traffic keys, IVs, and initialization parameters for each transmission direction.\n4. **Encrypted Record Layer:** Frame application data into numbered records authenticated and encrypted with AEAD (AES-GCM or ChaCha20-Poly1305).",
      callout: {
        type: "info",
        text: "Modern TLS 1.3 completes this entire handshake in a single round-trip (1-RTT) and encrypts the handshake certificates, hiding server identity from eavesdroppers.",
      },
    },
    {
      title: "What It Can Do: Guarantees & Capabilities",
      speaker: "Alice",
      content:
        "When negotiated properly, secure transport protocols deliver robust guarantees:\n\n* **Confidentiality & Tamper Resistance:** Encrypts application payloads and detects any bit flips or frame modifications.\n* **Perfect Forward Secrecy (PFS):** Ephemeral Diffie-Hellman keys ensure that if a server's long-term certificate private key is stolen years later, recorded historical traffic cannot be decrypted.\n* **Replay & Sequence Protection:** Monotonic record sequence numbers prevent attackers from duplicating, dropping, or reordering packets.",
      callout: {
        type: "security",
        text: "Forward Secrecy protects you against 'Store Now, Decrypt Later' adversaries: historical sessions cannot be retroactively cracked even if the server key is subpoenaed or leaked.",
      },
    },
    {
      title: "What It Does NOT Do: Critical Security Boundaries",
      speaker: "Mallory",
      content:
        "Engineers often mistakenly assume that putting TLS on a connection makes the entire system secure. Here is what transport security does **NOT** do:\n\n* **Does NOT protect against Application-Layer Vulnerabilities:** A TLS connection will faithfully and securely deliver SQL injections, cross-site scripting (XSS), and malware payloads directly into your backend!\n* **Does NOT protect Endpoint Memory or Stored Data:** Once the bytes arrive at the web server and are decrypted into plaintext memory, TLS has finished its job. If the server application has a memory bug or the database is unencrypted, TLS provides zero defense.\n* **Does NOT hide all Traffic Metadata:** Network observers can still see IP addresses, packet timings, packet sizes, and unencrypted Server Name Indication (SNI) headers unless Encrypted Client Hello (ECH) is enabled.",
      callout: {
        type: "warning",
        text: "TLS protects the wire, never the endpoint. Security requires securing application logic and data at rest just as rigorously as data in flight.",
      },
    },
  ],
  takeaways: [
    "Secure transport protocols orchestrate multiple cryptographic primitives into a reliable state machine.",
    "The handshake authenticates endpoints and derives one-time ephemeral session keys.",
    "Forward Secrecy ensures future key compromises cannot expose past conversations.",
    "Transport security protects the pipe during transmission, not the server endpoint or application data once decrypted.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "GET /api/v1/user HTTP/1.1",
    explanation:
      "Open ECDH in Cipher Workbench to inspect how ephemeral key shares negotiate session keys during the TLS handshake.",
  },
};

export default content;
