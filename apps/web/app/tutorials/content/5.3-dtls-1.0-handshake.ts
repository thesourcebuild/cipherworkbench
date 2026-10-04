import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "dtls-handshake", version: "1.0" },
  analogy:
    "Imagine Alice and Bob exchanging sealed courier packets across a city where packets may vanish, arrive twice, or arrive out of order. Before Bob sends a bulky passport package, he returns a small address token. Alice must echo it to prove that Mallory did not forge a victim's return address.\n\nThe couriers number every handshake message and label every fragment so Alice and Bob can rebuild the conversation. If an expected response never arrives, they resend an entire flight. This was a pioneering way to adapt TLS 1.1-era security to datagrams, but its legacy key schedule and record choices are no longer acceptable.",
  problem:
    "How did DTLS 1.0 adapt TLS 1.1 to unreliable UDP using cookies, numbered fragments, epochs, replay windows, and retransmission—and why must it no longer be negotiated?",
  steps: [
    {
      title: "Step 1: Initial ClientHello (cookie path)",
      speaker: "Alice",
      content:
        "On the optional cookie-verified path, Alice sends a plaintext DTLS 1.0 `ClientHello` containing a random value, session ID, cipher suites, compression choices, and an empty cookie. If Bob does not enforce the cookie DoS check, this same initial ClientHello proceeds directly to the plaintext server flight instead. DTLS 1.0 is based on TLS 1.1; there was never a DTLS 1.1 protocol version.\n\nUDP may lose, duplicate, reorder, or fragment the datagram, and its source address can be forged. DTLS records therefore carry explicit epoch and sequence fields, while handshake messages carry `message_seq`, `fragment_offset`, and `fragment_length`.",
      callout: {
        type: "warning",
        text: "DTLS 1.0 is historical. RFC 8996 moved it to Historic status and requires that it not be used or negotiated.",
      },
    },
    {
      title: "Step 2: HelloVerifyRequest (optional DoS)",
      speaker: "Bob",
      content:
        "When Bob enforces stateless cookie DoS protection, he responds with `HelloVerifyRequest` containing a cookie derived from Alice's apparent address. This optional flight lets Bob defer costly state and a larger response. Without the cookie check, Bob does not send HelloVerifyRequest and answers the original ClientHello directly with the plaintext server flight.\n\nThe initial ClientHello and HelloVerifyRequest are the first two flights only on the cookie-verified path, and neither cookie message is included in the authenticated transcript.",
      callout: {
        type: "security",
        text: "A cookie limits spoofed-source denial-of-service and amplification. It does not authenticate Alice's identity and is not a replacement for certificates or Finished.",
      },
    },
    {
      title: "Step 3: ClientHello + cookie",
      speaker: "Alice",
      content:
        "Only after receiving HelloVerifyRequest, Alice repeats `ClientHello` with Bob's cookie. Echoing the cookie proves that Alice can receive traffic at the claimed source address before Bob allocates costly state or sends a larger response.\n\nThese are DTLS flights 1–3 in the cookie-verified path: initial ClientHello, HelloVerifyRequest, and ClientHello plus cookie. With cookie validation, a full handshake normally needs three round trips.",
    },
    {
      title: "Step 4: Plaintext server flight",
      speaker: "Bob",
      content:
        "Bob sends `ServerHello`, `Certificate`, an optional `ServerKeyExchange`, optional `CertificateRequest`, and `ServerHelloDone`. RSA key transport normally omits `ServerKeyExchange`; ephemeral DHE or ECDHE sends signed parameters and can provide forward secrecy. `CertificateRequest` asks Alice to authenticate with a client certificate. All of these messages remain plaintext.\n\nFragments can arrive in any order, but Alice waits for a complete logical message and processes `message_seq` values in order. Signatures and the later Finished proofs detect substitution rather than hiding the flight.",
    },
    {
      title: "Step 5: Client key exchange and completion",
      speaker: "Alice",
      content:
        "Alice validates Bob's certificate and expected identity. In RSA key transport she encrypts a random premaster secret to Bob's long-term key; in an ephemeral DHE/ECDHE suite she verifies Bob's signature, returns her public share, and computes the same secret. If Bob requested mutual authentication, Alice sends `Certificate` before `ClientKeyExchange` and `CertificateVerify` afterward to prove possession of the client private key.\n\nThe inherited TLS 1.1 PRF combines MD5 and SHA-1 output to derive a 48-byte master secret, then expands directional MAC secrets, encryption keys, and IV material. RSA key transport lacks forward secrecy; ephemeral key exchange only provides it when selected and implemented correctly. Alice then sends `ChangeCipherSpec`, advancing from epoch 0 to the negotiated record state, followed by protected `Finished`.",
    },
    {
      title: "Step 6: Server completion",
      speaker: "Bob",
      content:
        "Bob verifies Alice's optional certificate proof and Finished, then returns his own `ChangeCipherSpec` and `Finished`. Application datagrams use the selected record protection.\n\nDTLS 1.0 forbids RC4 and other stream ciphers because lost records would desynchronize stream state. Representative deployments instead used TLS 1.1-style CBC with an explicit IV and MAC-then-encrypt, retaining CBC padding and timing hazards.",
      callout: {
        type: "warning",
        text: "DTLS 1.0 defines no AEAD suites. Explicit IVs do not repair the broader weaknesses of legacy CBC, MD5/SHA-1 constructions, and obsolete cipher-suite choices.",
      },
    },
  ],
  afterTimeline: {
    title: "After the Timeline: DTLS recovers handshake loss and resumes sessions",
    content:
      "DTLS groups handshake messages into flights and retransmits an entire flight when its timer expires, using exponential backoff. The logical handshake `message_seq` stays the same, but each retransmission receives a fresh record sequence number. Reassembly and retransmission apply only to the handshake.\n\nAn abbreviated session-ID handshake can reuse cached master-secret state and skip certificates and key exchange. It adds no fresh forward-secret contribution. Per-epoch sliding windows can reject authenticated replayed records, but replay filtering is optional and application delivery stays unordered and unreliable.",
    callout: {
      type: "security",
      text: "Use DTLS 1.2 only where compatibility requires it and prefer DTLS 1.3. DTLS 1.0 must not be enabled as a fallback.",
    },
  },
  takeaways: [
    "DTLS 1.0 adapted TLS 1.1 to datagrams with stateless cookies, explicit record numbers, handshake fragments, and flight retransmission.",
    "HelloVerifyRequest limited spoofed-source amplification but did not authenticate the peer's identity.",
    "The protocol inherited the MD5/SHA-1 PRF and legacy CBC record protection; stream ciphers such as RC4 are forbidden in DTLS 1.0.",
    "An optional CertificateRequest branch adds client Certificate and CertificateVerify messages for mutual authentication.",
    "RSA key transport lacks forward secrecy, while ephemeral DHE/ECDHE made it optional rather than guaranteed.",
    "RFC 8996 prohibits negotiating DTLS 1.0; it belongs in protocol history, not a production configuration.",
    "DTLS protects datagrams in transit but does not secure plaintext on compromised endpoints or make application delivery reliable and ordered.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open the ECDH Workbench to explore DTLS 1.0's optional ephemeral branch. Common RSA key transport instead lacked forward secrecy.",
  },
};

export default content;
