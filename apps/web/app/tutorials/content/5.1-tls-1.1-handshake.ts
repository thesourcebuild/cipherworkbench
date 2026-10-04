import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "tls-handshake", version: "1.1" },
  analogy:
    "Imagine Alice calling the same embassy through an older public switchboard. She begins on an open line by listing the locks she supports. Bob chooses compatible settings, shows his **CA-signed passport**, and either sends a signed temporary key-exchange share or offers the RSA key printed in that passport.\n\nAlice checks the passport and hostname, then either returns her temporary share or sends a newly generated secret locked to Bob's RSA key. Both derive matching record keys, separately announce `ChangeCipherSpec`, and exchange protected `Finished` seals. Only after two network round trips is the private line ready.\n\nTLS can protect application protocols such as HTTP, SMTP, IMAP, and file transfer while their bytes cross a reliable transport. It provides confidentiality, peer authentication, and integrity for that connection—not security for plaintext on a compromised endpoint.\n\nThis explains how TLS 1.1, standardized in RFC 4346 in 2006, historically worked. RFC 8996 now says TLS 1.1 **must not** be used or negotiated.",
  problem:
    "How did TLS 1.1 negotiate RSA or ephemeral DH keys, authenticate a server, detect handshake tampering, and protect HTTP records—and why is that historical compatibility no longer modern security?",
  steps: [
    {
      title: "Step 1: ClientHello",
      speaker: "Alice",
      content:
        "Alice's browser sends `ClientHello` with TLS 1.1, a client random, session ID, supported cipher suites, compression methods, and extensions such as SNI. ECC-capable clients can also advertise supported curves and point formats.\n\nLike TLS 1.2 but unlike TLS 1.3, each cipher-suite name bundles the key exchange, server authentication, bulk cipher, and record MAC. A representative suite combines ECDHE authenticated by RSA with AES-CBC and HMAC-SHA-1.",
      callout: {
        type: "warning",
        text: "ClientHello is visible and initially unauthenticated. Its contents are authenticated only later when both peers verify Finished over the handshake transcript.",
      },
    },
    {
      title: "Step 2: Plaintext server flight",
      speaker: "Bob",
      content:
        "Bob replies with a plaintext `ServerHello` selecting TLS 1.1, one cipher suite, a compression method, a server random, and negotiated extensions. No shared record keys exist yet, so the rest of Bob's first flight also remains visible.\n\nTLS 1.1 can use RSA key transport or finite-field and elliptic-curve Diffie-Hellman through TLS extensions. The selected suite decides which branch the following messages take.\n\nBob sends his `Certificate` chain. With **RSA key transport**, the certificate contains an RSA encryption key and `ServerKeyExchange` is normally omitted. With **DHE or ECDHE**, Bob also sends ephemeral parameters and a public share in `ServerKeyExchange`, signed with his certificate key and bound to both hello randoms. `ServerHelloDone` ends the flight.\n\nThe certificate, parameters, and public shares are not secret. Signatures and the later Finished messages detect substitution; they do not hide this flight.",
      callout: {
        type: "security",
        text: "RSA and ECDHE_RSA both use RSA certificates differently: RSA key transport decrypts a premaster secret, while ECDHE_RSA signs an ephemeral ECDH exchange.",
      },
    },
    {
      title: "Step 3: Client key exchange and completion",
      speaker: "Alice",
      content:
        "Alice validates the certificate chain, dates, constraints, key usage, and requested hostname. With RSA key transport, she generates a 48-byte premaster secret. With DHE or ECDHE, she verifies Bob's parameter signature and computes the premaster secret using her temporary private value and Bob's public share.\n\nTLS 1.1's PRF splits the secret and XORs output from `P_MD5` and `P_SHA-1` to derive the 48-byte `master_secret`. A second expansion produces separate client/server MAC secrets, encryption keys, and IV material.\n\nAlice sends the premaster secret encrypted with RSA PKCS #1 v1.5 or, for DHE/ECDHE, sends her public share in `ClientKeyExchange`. Bob recovers or independently computes the same premaster secret and derives matching keys. Alice then sends `ChangeCipherSpec`, activating her pending write state, followed by her first protected handshake message: `Finished`.",
      callout: {
        type: "info",
        text: "RSA key transport has no forward secrecy. Ephemeral DHE/ECDHE can provide it when temporary private values are securely erased, but TLS 1.1 never required that choice.",
      },
    },
    {
      title: "Step 4: Server completion",
      speaker: "Bob",
      content:
        "Bob verifies Alice's `Finished`, sends his own `ChangeCipherSpec` and protected `Finished`, and Alice verifies that proof. The normal full handshake takes **2 RTTs** before application data begins.",
    },
    {
      title: "Step 5: HTTP request",
      speaker: "Alice",
      content:
        "Alice sends the HTTP request in a protected TLS application-data record using her client write state. A representative TLS 1.1 CBC record computes an HMAC, appends padding, and encrypts the result with an explicit per-record IV.",
    },
    {
      title: "Step 6: HTTP response",
      speaker: "Bob",
      content:
        "Bob returns the HTTP response using his independent server write keys. TLS 1.1's CBC protection is MAC-then-encrypt, not AEAD. The explicit IV improved on TLS 1.0, but CBC padding and timing hazards remained.",
      callout: {
        type: "warning",
        text: "TLS 1.1 defines no AEAD cipher suites and depends on legacy MD5/SHA-1 handshake constructions. Correct historical operation does not make it safe today.",
      },
    },
  ],
  afterTimeline: {
    title: "After the Timeline: Session tickets make later connections faster",
    content:
      "A later ClientHello can offer a session ID or, when the extension is supported, a session ticket. An abbreviated handshake reuses the cached master secret with fresh hello randoms, skips the certificate and key-exchange flights, and normally completes in **1 RTT**.\n\nTLS 1.1 has no 0-RTT mode: application data must wait for the resumed handshake. Resumption also adds no fresh DHE/ECDHE exchange, so its security remains tied to the original master secret. RFC 8996 moved TLS 1.1 to Historic status and requires implementations not to negotiate it.",
    callout: {
      type: "security",
      text: "TLS 1.1 support is historical interoperability, not a security feature. Use TLS 1.3, or carefully configured TLS 1.2 only where compatibility requires it.",
    },
  },
  takeaways: [
    "A full server-authenticated TLS 1.1 handshake normally takes two round trips; abbreviated resumption takes one, and TLS 1.1 has no 0-RTT.",
    "Hello, certificate, and key-exchange messages are plaintext; signatures and Finished authenticate the transcript afterward.",
    "RSA key transport lacks forward secrecy, while ephemeral DHE/ECDHE can provide it as an optional branch.",
    "The TLS 1.1 PRF combines MD5 and SHA-1, and representative CBC suites use explicit IVs with MAC-then-encrypt rather than AEAD.",
    "RFC 8996 deprecated TLS 1.1 and requires that it not be used or negotiated regardless of historical implementation support.",
    "TLS protects an application connection in transit; it does not secure data after either endpoint decrypts, stores, logs, or exposes it.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open the ECDH Workbench to reproduce TLS 1.1's optional ECDHE branch. RSA key transport instead encrypts a random premaster secret and provides no forward secrecy.",
  },
};

export default content;
