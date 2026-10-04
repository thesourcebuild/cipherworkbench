import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "dtls-handshake", version: "1.2" },
  analogy:
    "Imagine Alice and Bob exchanging sealed courier packets across a city where packets may vanish, arrive twice, or arrive out of order. Before Bob sends a bulky passport package, he returns a small address token. Alice echoes it, proving that her return address is real rather than Mallory's forged victim address.\n\nEvery handshake packet carries a conversation number and fragment coordinates. Alice and Bob can rebuild split messages, wait for a complete flight, and resend a whole flight when a timer expires. Once certificates and temporary ECDH shares establish keys, epochs and record sequence numbers protect independent application datagrams without changing UDP into a stream.",
  problem:
    "How does DTLS 1.2 adapt a TLS 1.2 ECDHE handshake to UDP, control amplification, recover lost handshake flights, reject replayed records, and preserve datagram semantics?",
  steps: [
    {
      title: "Step 1: Alice sends ClientHello in a UDP datagram",
      speaker: "Alice",
      content:
        "Alice sends a plaintext DTLS 1.2 `ClientHello` with a client random, session ID, cipher suites, extensions, and an initially empty cookie. A secure configuration offers ECDHE with AEAD, such as AES-GCM.\n\nBecause UDP supplies no connection setup, Mallory can forge a victim's source address. The datagram can also be lost, duplicated, fragmented, or reordered. DTLS adds explicit record sequence numbers and handshake `message_seq`, fragment offset, and fragment length fields to manage those conditions.",
      callout: {
        type: "info",
        text: "DTLS 1.2 is the datagram adaptation of TLS 1.2. It is not TLS carried inside a reliable UDP shim, and application datagrams remain unordered and unreliable.",
      },
    },
    {
      title: "Step 2: Bob optionally validates Alice's address",
      speaker: "Bob",
      content:
        "Bob normally returns `HelloVerifyRequest` with a stateless cookie derived from Alice's apparent address and server-held secret. Alice repeats `ClientHello` with that cookie. These are DTLS flights 1–3 in the cookie-verified path: initial ClientHello, HelloVerifyRequest, and ClientHello plus cookie. Bob verifies the cookie before committing expensive state or sending a much larger certificate flight.\n\nThe extra first ClientHello and HelloVerifyRequest are present only when Bob enforces this DoS protection. Without them, Bob answers the original ClientHello directly with the server flight. The two cookie messages are excluded from the authenticated handshake transcript. With the cookie exchange, a full handshake normally needs three network round trips.",
      callout: {
        type: "security",
        text: "The cookie proves return-path reachability, not identity. Bob still needs the certificate and Finished exchange to authenticate the cryptographic peer and transcript.",
      },
    },
    {
      title: "Step 3: Bob selects parameters and authenticates",
      speaker: "Bob",
      content:
        "After the verified ClientHello, Bob sends `ServerHello`, `Certificate`, a signed ephemeral share in `ServerKeyExchange`, optional `CertificateRequest`, and `ServerHelloDone`. These plaintext handshake messages may be split across datagrams. Alice buffers fragments and processes complete messages according to `message_seq`, not network arrival order.\n\nBob's signature binds the ECDHE parameters to the hello randoms and his certificate identity. `CertificateRequest` asks Alice to authenticate with a client certificate; it is omitted for server-only authentication. DTLS 1.2 also retained RSA key transport, static key exchange, CBC, and weak historical choices, so the version label alone does not guarantee a secure configuration.",
    },
    {
      title: "Step 4: Alice verifies Bob and establishes shared keys",
      speaker: "Alice",
      content:
        "Alice validates Bob's certificate and expected identity, verifies the `ServerKeyExchange` signature, and sends her ephemeral share in `ClientKeyExchange`. If Bob requested mutual authentication, she sends `Certificate` before the key exchange and `CertificateVerify` afterward to prove possession of the client private key. Both peers compute the same premaster secret.\n\nThe TLS 1.2 PRF, normally HMAC-SHA-256, derives the master secret and directional record keys. Extended Master Secret should bind the master secret to the handshake transcript. ECDHE provides forward secrecy when temporary private values are erased; RSA key transport and static DH/ECDH do not.",
      callout: {
        type: "security",
        text: "Prefer ECDHE, AEAD, Extended Master Secret, and current signature algorithms. CBC should not be treated as equivalent to modern AEAD protection.",
      },
    },
    {
      title: "Step 5: Alice and Bob finish, then application datagrams begin",
      speaker: "Alice",
      content:
        "Alice sends `ChangeCipherSpec`, which advances her write epoch, followed by protected `Finished`. Bob verifies Alice's optional certificate proof and Finished, advances his epoch with `ChangeCipherSpec`, and returns his protected `Finished`. AEAD-protected application datagrams can then flow independently in either direction.\n\nEach record carries a 16-bit epoch and a 48-bit per-epoch sequence number. An authenticated sliding replay window can discard duplicate or stale records, but replay filtering is optional and does not reorder valid application data.",
    },
    {
      title: "Step 6: DTLS recovers handshake loss and resumes sessions",
      speaker: "Bob",
      content:
        "Handshake messages are grouped into flights. If the expected response does not arrive, the sender retransmits the whole flight with exponential backoff. Retransmitted handshake messages keep their `message_seq` and original epoch keys but receive fresh record sequence numbers. A duplicate previous flight can also trigger retransmission of the response.\n\nSession IDs or tickets can resume cached master-secret state and skip certificate and key-exchange flights. Resumption adds no fresh ECDHE exchange, so it relies on protecting session state and ticket keys. Current guidance still requires DTLS 1.2 support for compatibility, while preferring DTLS 1.3 when available.",
      callout: {
        type: "warning",
        text: "DTLS retransmission covers handshake flights only. Real-time applications must decide independently whether and how to recover lost application datagrams.",
      },
    },
  ],
  takeaways: [
    "DTLS 1.2 adapts TLS 1.2 to UDP with cookies, explicit sequence numbers, numbered handshake messages, fragmentation, reassembly, and flight retransmission.",
    "HelloVerifyRequest normally adds an anti-amplification round trip but validates reachability rather than cryptographic identity.",
    "ECDHE plus AEAD is the secure compatibility profile; legacy RSA key transport, static key exchange, and CBC remain protocol hazards.",
    "An optional CertificateRequest branch adds client Certificate and CertificateVerify messages for mutual authentication.",
    "Epoch and record sequence numbers support optional replay filtering without giving application datagrams reliable ordering.",
    "DTLS 1.2 remains a supported compatibility baseline, but implementations should support and prefer DTLS 1.3.",
    "DTLS can protect UDP-based real-time, VPN, messaging, and IoT protocols in transit while preserving their application-level datagram semantics.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open the ECDH Workbench to reproduce the forward-secret shared-key step used by a secure ECDHE DTLS 1.2 configuration.",
  },
};

export default content;
