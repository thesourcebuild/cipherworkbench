import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "tls-handshake", version: "1.3" },
  analogy:
    "Imagine Alice calling an embassy. She begins on an open line by proposing a fresh one-use code system and sending her half of it. Bob chooses compatible settings and returns his half. At that instant they can independently calculate the same temporary secret.\n\nBob then uses the new private line to show his **CA-signed passport** and sign the complete conversation so far. Alice checks the passport, the hostname, the signature, and a final transcript authenticator. Only then does she send her own `Finished` seal and the HTTP request.\n\nNormal HTTPS authenticates **the server**. Alice presents a certificate only when Bob explicitly requests mutual TLS (mTLS). TLS 1.3 can also protect other application protocols over a reliable transport, but it secures data only while in transit; compromised endpoints can still read plaintext after decryption.",
  problem:
    "How does TLS 1.3 establish fresh keys, authenticate a server, detect handshake tampering, and begin encrypted HTTP traffic in a single network round trip?",
  steps: [
    {
      title: "Step 1: ClientHello",
      speaker: "Alice",
      content:
        "Alice's browser sends `ClientHello`, offering TLS 1.3, AEAD/HKDF cipher suites such as `TLS_AES_128_GCM_SHA256`, supported signature algorithms, key-exchange groups, and an ephemeral `key_share` (commonly X25519 or modern hybrid post-quantum groups such as `X25519MLKEM768`). Web connections also carry extensions such as SNI and ALPN.\n\nThe cipher-suite name selects the **record cipher and transcript hash**; it does not select the certificate algorithm or the key-exchange group.",
      callout: {
        type: "warning",
        text: "The first ClientHello is normally visible on the network. TLS protects its integrity through the later transcript, but does not retroactively make its metadata secret. Encrypted ClientHello (ECH) is a separate extension designed to hide more of it.",
      },
    },
    {
      title: "Step 2: Server flight: parameters & authentication",
      speaker: "Bob",
      content:
        "Bob replies with a single flight combining parameter selection and encrypted authentication:\n\n1. `ServerHello` (plaintext) — selects TLS 1.3, one cipher suite, and returns Bob's ephemeral key share. Alice and Bob combine shares to derive the shared secret and handshake traffic keys via HKDF.\n2. `EncryptedExtensions` — parameters that do not belong in plaintext `ServerHello`.\n3. `Certificate` — Bob's certificate chain.\n4. `CertificateVerify` — a signature over the entire transcript using Bob's certificate private key, binding his identity to this session.\n5. `Finished` — an HMAC authenticator confirming transcript integrity.\n\nEverything after `ServerHello` is encrypted under server handshake keys. Because Bob sends all of this in one return flight, server authentication completes in **one round trip**.",
      callout: {
        type: "security",
        text: "An attacker cannot silently swap a key share, cipher choice, certificate, or extension: transcript authentication makes Alice and Bob detect any mismatch before accepting the connection. If Alice did not send a usable key share, Bob replies with HelloRetryRequest, adding one round trip.",
      },
    },
    {
      title: "Step 3: Client completion & HTTP request",
      speaker: "Alice",
      content:
        "Alice validates Bob's certificate chain to a trusted root, checks the hostname, verifies `CertificateVerify`, and confirms Bob's `Finished` value.\n\nShe then sends her own `Finished` message using client handshake keys, sealing the handshake. In the **exact same flight**, Alice immediately follows with her HTTP request encrypted with client application traffic keys (`GET / HTTP/1.1` via AES-GCM or ChaCha20-Poly1305).\n\nAlice does not need to wait for another round trip before sending application data: data flows immediately after 1 RTT.",
      callout: {
        type: "security",
        text: "In a full certificate-authenticated (EC)DHE handshake, erasing the ephemeral private keys gives forward secrecy: later theft of Bob's certificate private key does not reveal recorded sessions.",
      },
    },
    {
      title: "Step 4: HTTP response",
      speaker: "Bob",
      content:
        "Bob verifies Alice's `Finished` message and processes the HTTP request. His HTTP response uses a separate server application traffic key. Mallory can alter or drop packets, but altered ciphertext fails AEAD authentication and is rejected rather than accepted as valid data.",
    },
  ],
  afterTimeline: {
    title: "After the Timeline: Session tickets, Post-Quantum keys & shrinking lifespans",
    content:
      "After the handshake, Bob can send one or more `NewSessionTicket` messages. A later connection can use that ticket as a pre-shared key (PSK) for resumption, optionally combined with a new (EC)DHE exchange for fresh forward secrecy.\n\nTLS 1.3 also permits **0-RTT early data** on resumed sessions. It arrives before the new handshake is authenticated, can be replayed, and does not gain forward secrecy from the new key exchange. Applications must restrict it to replay-safe operations.\n\n### Modern Evolution: PQC & Automated Lifecycles\n\n* **Post-Quantum Cryptography (PQC):** Modern browsers and servers deploy hybrid key exchange (such as `X25519MLKEM768`, combining classical X25519 with ML-KEM-768 / Kyber). Even with traditional certificates, hybrid key exchange ensures recorded ciphertext cannot be decrypted decades later by future quantum computers (\"Store Now, Decrypt Later\").\n* **Shrinking Certificate Lifespans:** CA/Browser Forum rules have dropped public TLS certificate validity to 398 days, with an industry roadmap targeting **47 days by 2029**. Manual renewal is unsustainable; automated ACME workflows and dedicated private PKIs (especially as public CAs sunset `clientAuth` for mTLS) are now critical operational requirements.",
    callout: {
      type: "warning",
      text: "Never treat 0-RTT as safe for non-idempotent actions such as charging a card, transferring money, or changing account state.",
    },
  },
  takeaways: [
    "TLS 1.3 completes a normal certificate-authenticated handshake in one round trip; application data can follow the client's Finished.",
    "`ServerHello` completes parameter selection and enables handshake encryption; the certificate, signature, and server Finished follow as separate encrypted messages in the same return flight.",
    "HKDF derives independent client/server handshake and application traffic secrets from the shared secret and transcript.",
    "Certificates establish trust and hostname identity, `CertificateVerify` proves private-key possession, and `Finished` authenticates the transcript.",
    "Full ephemeral (EC)DHE provides forward secrecy. PSK-only resumption and replayable 0-RTT require separate risk decisions.",
    "Hybrid Post-Quantum key exchange (such as `X25519MLKEM768`) protects TLS 1.3 session confidentiality against future 'Store Now, Decrypt Later' quantum attacks.",
    "Public TLS certificate lifespans are shortening toward 47 days by 2029, making automated issuance (ACME) and private PKIs essential operational requirements.",
    "TLS 1.3 was standardized in RFC 8446 in 2018 and removes static RSA/DH key exchange, CBC record suites, RC4, compression, and renegotiation.",
    "Only resumed sessions can offer 0-RTT early data; a normal full TLS 1.3 handshake is 1-RTT, and early data remains replayable.",
    "TLS provides connection confidentiality, authentication, and integrity—not protection for plaintext on a compromised client or server.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open the ECDH Workbench to reproduce the ephemeral shared-secret step used by a typical X25519 TLS 1.3 handshake.",
  },
};

export default content;
