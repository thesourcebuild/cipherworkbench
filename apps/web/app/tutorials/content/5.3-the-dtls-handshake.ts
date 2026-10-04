import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "dtls-handshake", version: "1.3" },
  analogy:
    "Imagine Alice and Bob exchanging sealed courier packets across a city where packets may vanish, arrive twice, or arrive out of order. They cannot rely on a continuous phone call, so every handshake packet carries a conversation number and fragment coordinates. Missing handshake packets can be requested again without forcing application messages into a reliable stream.\n\nAlice includes a fresh ephemeral key share in her first packet. Bob may first return a stateless address-validation token; otherwise he answers with his own share and then sends his identity proof under newly derived handshake keys. Alice verifies Bob, returns `Finished`, and both move to independent application traffic keys. Selective acknowledgements recover lost handshake records while gaming, WebRTC, voice, VPN, and sensor protocols retain datagram behavior.\n\nDTLS protects datagrams in transit but does not make UDP reliable, secure already-decrypted endpoint data, or guarantee that the application handles message ordering and replay safely.",
  problem:
    "How does DTLS 1.3 provide TLS 1.3-style authentication and forward-secret AEAD over UDP while tolerating loss, duplication, reordering, fragmentation, spoofed source addresses, and replayed records?",
  steps: [
    {
      title: "Step 1: ClientHello",
      speaker: "Alice",
      content:
        "Alice sends a DTLS 1.3 `ClientHello` in epoch 0 with supported versions, AEAD cipher suites, signature algorithms, groups, and an ephemeral `key_share`, commonly X25519. The initial datagram is plaintext and may be lost, duplicated, reordered, or forged with a victim's source address.\n\nDTLS handshake headers add `message_seq`, `fragment_offset`, and `fragment_length`. Bob can reassemble fragments and process complete messages in logical order even when UDP delivers them differently.",
      callout: {
        type: "info",
        text: "DTLS makes its handshake reliable, not the application transport. Application datagrams can still be lost or reordered unless the application adds its own recovery rules.",
      },
    },
    {
      title: "Step 2: Optional HelloRetryRequest",
      speaker: "Bob",
      content:
        "Before sending a large certificate flight, Bob may reply with `HelloRetryRequest` carrying a stateless `cookie`. Bob should use this optional path when amplification is a concern, but it is not mandatory after another mechanism has validated Alice's address. Before validation, Bob limits his output to three times the bytes received.\n\nThe normal DTLS 1.3 path does not include HelloRetryRequest: it continues directly from the first ClientHello to ServerHello and remains a 1-RTT handshake.",
      callout: {
        type: "warning",
        text: "DTLS 1.3 uses the TLS 1.3 cookie extension inside HelloRetryRequest. It does not use the older HelloVerifyRequest message or legacy ClientHello cookie field.",
      },
    },
    {
      title: "Step 3: Retried ClientHello",
      speaker: "Alice",
      content:
        "Only after HelloRetryRequest, Alice echoes Bob's cookie in a second `ClientHello`, proving she can receive packets at the claimed address. She also supplies a compatible `key_share` if Bob requested another group. This retry path adds one RTT and does not occur on the normal no-retry path.",
    },
    {
      title: "Step 4: ServerHello",
      speaker: "Bob",
      content:
        "Bob sends a plaintext `ServerHello` with his ephemeral key share. Alice and Bob can now derive separate epoch-2 handshake traffic secrets using the TLS 1.3 HKDF schedule with DTLS's `dtls13` label prefix. Epochs separate key generations: epoch 0 carries plaintext setup, optional epoch 1 carries 0-RTT early data, epoch 2 carries handshake traffic, and epoch 3 begins normal application traffic. Each direction receives independent AEAD keys, IVs, and record-number protection keys.",
      callout: {
        type: "security",
        text: "The certificate key signs the ephemeral exchange; it does not transport the shared secret. Fresh (EC)DHE therefore provides forward secrecy when ephemeral secrets are erased.",
      },
    },
    {
      title: "Step 5: Encrypted server authentication",
      speaker: "Bob",
      content:
        "Bob encrypts `EncryptedExtensions`, optional `CertificateRequest`, `Certificate`, `CertificateVerify`, and `Finished`. `CertificateVerify` proves possession of Bob's certificate private key and binds his identity to this exchange. `Finished` authenticates the transcript. `CertificateRequest` asks Alice to authenticate too; it is omitted in the normal server-only flow. DTLS 1.3 has no `ServerHelloDone`, `ClientKeyExchange`, or compatibility `ChangeCipherSpec` messages.\n\nAlice validates Bob's certificate chain, validity, constraints, key usage, and expected identity, then verifies `CertificateVerify` and `Finished`. She reassembles any fragmented handshake messages before hashing their canonical forms into the transcript. If Bob sent `CertificateRequest`, Alice also chooses an acceptable client certificate and prepares to prove possession of its private key.",
    },
    {
      title: "Step 6: Client completion",
      speaker: "Alice",
      content:
        "For server-only authentication, Alice sends her protected epoch-2 `Finished`. If Bob requested mutual authentication, she first sends `Certificate` and `CertificateVerify`, proving possession of her client-certificate key, and then sends `Finished`. She can immediately follow that final handshake record with a separate epoch-3 application-data record, including in the same UDP datagram.",
    },
    {
      title: "Step 7: Selective acknowledgement",
      speaker: "Bob",
      content:
        "Because no responding handshake flight naturally acknowledges the client's terminal flight, Bob sends an explicit `ACK`. ACK is a separate DTLS content type, is excluded from the transcript, and acknowledges handshake records only—not application data. It identifies which records arrived so later retransmissions can omit acknowledged handshake messages or fragments.\n\nThe terminal ACK is protected, normally with epoch-3 application keys; it must use an epoch no lower than the epoch-2 Finished it acknowledges. Protected records carry truncated sequence-number bits masked with a per-epoch `sn_key`; the epoch remains visible so the receiver can select the right key. Bob may send a separate application-data record alongside the ACK.",
      callout: {
        type: "security",
        text: "Receiving the next handshake flight implicitly acknowledges the previous one. The terminal client flight has no natural response, so Bob's ACK confirms it and permits selective retransmission of any unacknowledged handshake records.",
      },
    },
  ],
  afterTimeline: {
    title: "After the Timeline: DTLS recovers handshake loss and resumes sessions",
    content:
      "If a timer expires, a sender retransmits the outstanding handshake flight with the same handshake bytes and original epoch keys but fresh record sequence numbers. Selective ACKs let the sender omit acknowledged messages or fragments where possible. The server also retransmits its terminal ACK when the client's final flight is repeated. This recovery machinery never turns ordinary UDP application data into a reliable stream.\n\nAfter the handshake, `NewSessionTicket` creates a resumption PSK and itself requires reliable delivery. A resumed connection can combine that PSK with fresh (EC)DHE for forward secrecy. Optional epoch-1 0-RTT data is replayable across connections and lacks fresh forward secrecy, so applications must restrict it to explicitly replay-safe operations.",
    callout: {
      type: "warning",
      text: "A DTLS record replay window only detects duplicates within its record-number context. It does not solve TLS 1.3's cross-connection 0-RTT replay problem.",
    },
  },
  takeaways: [
    "DTLS 1.3 keeps TLS 1.3's certificate-authenticated (EC)DHE and HKDF key schedule while adapting delivery to unreliable datagrams.",
    "A cookie-bearing HelloRetryRequest provides optional source-address validation and anti-amplification; it is not the legacy HelloVerifyRequest.",
    "CertificateRequest, client Certificate, and client CertificateVerify add optional mutual authentication without changing the key-exchange structure.",
    "Handshake sequence numbers, fragment coordinates, timers, and ACKs recover handshake loss without making application UDP reliable or ordered.",
    "Epochs identify key generations, per-epoch sequence numbers support replay windows, and protected records encrypt their sequence-number field.",
    "DTLS 1.3 is preferred over older DTLS versions; 0-RTT remains replayable and must be limited to application-defined safe uses.",
    "DTLS preserves datagram semantics for real-time and message-oriented applications; handshake reliability does not provide reliable application delivery.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open the ECDH Workbench to reproduce the ephemeral shared-secret step at the center of a full DTLS 1.3 certificate handshake.",
  },
};

export default content;
