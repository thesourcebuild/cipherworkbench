import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "tls-handshake", version: "1.2" },
  analogy:
    "Imagine Alice calling the same embassy over an older public switchboard. She begins on an open line by listing the secure systems she supports. Bob chooses compatible settings, shows his **CA-signed passport**, and sends a temporary ECDH public key signed with the passport's private key.\n\nAlice checks the passport, hostname, and signature, then returns her own temporary public key. Both independently calculate the same secret, derive matching record keys, and separately announce `ChangeCipherSpec` before exchanging protected `Finished` seals. Only then does HTTP begin.\n\nNormal HTTPS authenticates **the server**. Alice presents a certificate only when Bob explicitly requests mutual TLS (mTLS). TLS can likewise protect SMTP, IMAP, file transfer, and other application protocols over a reliable transport. It protects data in transit, not plaintext after either endpoint decrypts it.",
  problem:
    "How does TLS 1.2 negotiate a cipher suite, authenticate a server, establish record-protection keys, detect handshake tampering, and begin encrypted HTTP traffic in two network round trips?",
  steps: [
    {
      title: "Step 1: Alice sends ClientHello in plaintext",
      speaker: "Alice",
      content:
        "Alice's browser sends `ClientHello` with TLS 1.2, a client random, extensions, and an ordered list of cipher suites such as `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. It can also advertise supported groups and signature algorithms.\n\nUnlike TLS 1.3, a TLS 1.2 cipher-suite name bundles several choices: key exchange, certificate authentication, record cipher and mode, and a hash used by the PRF and/or record authentication. `ECDHE_RSA` means ephemeral ECDH authenticated by an RSA certificate; RSA does not transport the shared secret in that suite.",
      callout: {
        type: "warning",
        text: "ClientHello is visible on the network. The later Finished messages authenticate its contents, but do not retroactively hide metadata such as SNI.",
      },
    },
    {
      title: "Step 2: Bob selects parameters in ServerHello",
      speaker: "Bob",
      content:
        "Bob replies with a plaintext `ServerHello` selecting TLS 1.2, one offered cipher suite, a server random, and negotiated extensions. No shared record keys exist yet, so the rest of Bob's first flight also remains visible.\n\nFor a representative modern TLS 1.2 connection, Bob selects an ECDHE suite with AES-GCM or ChaCha20-Poly1305. TLS 1.2 also retained older RSA key-transport and CBC suites, which is why secure configuration matters as much as the protocol version.",
    },
    {
      title: "Step 3: Bob authenticates inside the plaintext server flight",
      speaker: "Bob",
      content:
        "Bob sends:\n\n1. `Certificate` — the server certificate chain.\n2. `ServerKeyExchange` — ephemeral ECDHE parameters and Bob's public share, signed with the certificate private key and bound to both hello randoms.\n3. `ServerHelloDone` — the end of Bob's flight.\n\nThese are separate **plaintext** handshake messages. With legacy RSA key exchange, `ServerKeyExchange` is normally omitted because Alice encrypts a premaster secret directly to the RSA key in Bob's certificate.",
      callout: {
        type: "security",
        text: "The ServerKeyExchange signature authenticates Bob's ephemeral share immediately. The later Finished messages authenticate the complete handshake transcript.",
      },
    },
    {
      title: "Step 4: Alice verifies Bob and establishes the shared secret",
      speaker: "Alice",
      content:
        "Alice validates the certificate chain, validity dates, constraints, key usage, and requested hostname, then verifies the `ServerKeyExchange` signature. She creates an ephemeral ECDH key pair and sends her public share in `ClientKeyExchange`. Alice and Bob now compute the same premaster secret.\n\nTLS 1.2's PRF combines that premaster secret with both hello randoms to derive a 48-byte `master_secret`, then expands it into direction-specific record keys, IV material, and MAC keys where the selected suite needs them. Most suites use SHA-256; designated suites use SHA-384.",
      callout: {
        type: "info",
        text: "ECDHE provides forward secrecy when temporary private keys are erased. TLS 1.2 does not require it: legacy RSA key transport lacks forward secrecy even though it also uses an RSA certificate.",
      },
    },
    {
      title: "Step 5: Alice and Bob send Finished, then HTTP begins",
      speaker: "Alice",
      content:
        "Alice sends `ChangeCipherSpec`, activating her negotiated write keys, followed by her first protected handshake message: `Finished`. Bob verifies it, sends his own `ChangeCipherSpec` and protected `Finished`, and Alice verifies that proof before accepting the connection. The normal full handshake takes **2 RTTs** before application data begins.\n\nHTTP records then use the selected suite. AEAD suites such as AES-GCM and ChaCha20-Poly1305 combine encryption and authentication. Older CBC suites use separate MAC-and-encrypt machinery with padding and a substantially more fragile security history.",
      callout: {
        type: "security",
        text: "Finished is derived from the master secret and transcript. Any silent change to the earlier plaintext negotiation causes verification to fail.",
      },
    },
    {
      title: "Step 6: Session tickets make later connections faster",
      speaker: "Bob",
      content:
        "Bob can establish resumable state using a session ID or session ticket. A later connection can reuse the existing master secret through an abbreviated handshake, reducing setup to **1 RTT** by skipping the certificate and key-exchange flights.\n\nTLS 1.2 has no standardized 0-RTT application data: resumed traffic still waits for the abbreviated handshake. Carefully configured TLS 1.2 remains a compatibility option, but new deployments should prefer TLS 1.3 and disable RSA key transport, CBC suites, weak signatures, and obsolete renegotiation behavior.",
      callout: {
        type: "warning",
        text: "A version label alone does not make TLS 1.2 safe. Prefer ECDHE, AEAD, SHA-256 or stronger signatures, and a current implementation with legacy suites disabled.",
      },
    },
  ],
  takeaways: [
    "A full certificate-authenticated TLS 1.2 handshake normally takes two round trips; resumption can reduce it to one, but not zero.",
    "`Certificate`, `ServerKeyExchange`, and `ServerHelloDone` are plaintext; Finished authenticates the complete transcript afterward.",
    "TLS 1.2's PRF derives a master secret and record keys, while each cipher suite bundles key exchange, authentication, cipher, mode, and hash choices.",
    "ECDHE provides optional forward secrecy. Legacy RSA key exchange does not, even when both modes use an RSA certificate.",
    "Modern TLS 1.2 configurations use AEAD suites; TLS 1.3 simplifies the choices, encrypts authentication messages, and removes a round trip.",
    "TLS 1.2 was standardized in RFC 5246 in 2008. Its security depends heavily on configuration because it retains both modern ECDHE/AEAD and obsolete RSA/CBC branches.",
    "TLS 1.2 has no standardized 0-RTT mode and normally needs two round trips for a full certificate handshake.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open the ECDH Workbench to reproduce the ephemeral shared-secret step used by a typical certificate-authenticated ECDHE TLS 1.2 handshake.",
  },
};

export default content;
