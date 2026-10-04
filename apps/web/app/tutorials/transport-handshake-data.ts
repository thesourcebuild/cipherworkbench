import type { DtlsTutorialVersion, TlsTutorialVersion } from "./tutorial-types";

export type Direction = "client-to-server" | "server-to-client";
export type FlightProtection =
  | "plaintext"
  | "key transition"
  | "handshake to application"
  | "handshake keys"
  | "record keys"
  | "application keys";

export interface HandshakeFlight {
  step: number;
  direction: Direction;
  title: string;
  messages: readonly string[];
  protection: FlightProtection;
  note: string;
}

export interface VisualLegend {
  title: string;
  description: string;
  tone: "neutral" | "violet" | "cyan" | "emerald" | "amber";
}

export interface VersionVisual {
  eyebrow: string;
  title: string;
  rtt: string;
  summary: string;
  flights: readonly HandshakeFlight[];
  legend: readonly [VisualLegend, VisualLegend, VisualLegend];
}

export const TLS_VERSION_VISUALS: Record<TlsTutorialVersion, VersionVisual> = {
  "SSL 3.0": {
    eyebrow: "SSL 3.0 · Historical full handshake",
    title: "Two round trips to fragile legacy protection",
    rtt: "2-RTT",
    summary: "plaintext setup → ChangeCipherSpec → RC4/CBC records",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["SSL 3.0", "client_random", "session ID", "cipher suites"],
        protection: "plaintext",
        note: "Alice offers bundled choices for key exchange, encryption, and the SSL MAC.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: ["ServerHello", "Certificate", "ServerKeyExchange?", "ServerHelloDone"],
        protection: "plaintext",
        note: "A common RSA suite sends Bob's certificate, while export or DH suites add key-exchange data.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: ["ClientKeyExchange", "ChangeCipherSpec", "Finished"],
        protection: "key transition",
        note: "Alice sends an RSA-encrypted pre-master secret, derives keys, then protects Finished.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob activates his pending state and proves that he observed the same handshake.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "RC4 or CBC", "SSL MAC"],
        protection: "record keys",
        note: "Alice sends the request inside an SSL-protected application-data record.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "RC4 or CBC", "chained CBC IV"],
        protection: "record keys",
        note: "Bob returns protected content using the separate server write state.",
      },
    ],
    legend: [
      {
        title: "Plaintext setup",
        description: "Hello, certificate, and key exchange cross the network visibly.",
        tone: "neutral",
      },
      {
        title: "ChangeCipherSpec",
        description: "Each peer promotes pending keys before sending Finished.",
        tone: "cyan",
      },
      {
        title: "Obsolete records",
        description: "RC4 and SSLv3 CBC are broken; RFC 7568 prohibits SSL 3.0.",
        tone: "amber",
      },
    ],
  },
  "1.1": {
    eyebrow: "TLS 1.1 · Historical full handshake",
    title: "Two round trips, then legacy record protection",
    rtt: "2-RTT",
    summary: "plaintext setup → ChangeCipherSpec → CBC/HMAC records",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["TLS 1.1", "client_random", "bundled cipher suites", "SNI"],
        protection: "plaintext",
        note: "Alice offers legacy suites that bundle key exchange, cipher, and MAC choices.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: ["ServerHello", "Certificate", "ServerKeyExchange?", "ServerHelloDone"],
        protection: "plaintext",
        note: "DHE/ECDHE sends signed parameters; RSA key transport normally omits ServerKeyExchange.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: ["ClientKeyExchange", "ChangeCipherSpec", "Finished"],
        protection: "key transition",
        note: "The key exchange is visible; ChangeCipherSpec activates Alice's derived record keys.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob activates his write state and proves he saw the same transcript.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "CBC encryption", "HMAC", "explicit IV"],
        protection: "record keys",
        note: "Alice sends the request in a protected TLS application-data record.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "CBC encryption", "HMAC", "explicit IV"],
        protection: "record keys",
        note: "Bob returns protected content using his independent server write keys.",
      },
    ],
    legend: [
      {
        title: "Plaintext setup",
        description: "Hello, certificate, and key-exchange messages remain visible.",
        tone: "neutral",
      },
      {
        title: "ChangeCipherSpec",
        description: "Each peer separately activates its pending record keys.",
        tone: "cyan",
      },
      {
        title: "Legacy records",
        description: "CBC plus HMAC is fragile and TLS 1.1 is now deprecated.",
        tone: "amber",
      },
    ],
  },
  "1.2": {
    eyebrow: "TLS 1.2 · Production-compatible ECDHE + AEAD handshake",
    title: "Two round trips to AEAD record protection",
    rtt: "2-RTT",
    summary: "plaintext ECDHE → ChangeCipherSpec → AEAD-protected HTTP",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["TLS 1.2", "client_random", "cipher suites", "signature_algorithms"],
        protection: "plaintext",
        note: "Alice offers suites such as ECDHE_RSA with AES-GCM and SHA-256.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: ["ServerHello", "Certificate", "ServerKeyExchange", "ServerHelloDone"],
        protection: "plaintext",
        note: "Bob signs his ephemeral ECDHE parameters with the certificate key.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: ["ClientKeyExchange", "ChangeCipherSpec", "Finished"],
        protection: "key transition",
        note: "Alice sends her ECDHE share, derives record keys, and authenticates the transcript.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob verifies Alice, activates his record keys, and returns his Finished proof.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "AES-GCM / ChaCha20-Poly1305"],
        protection: "record keys",
        note: "Alice sends the request with the selected forward-secret AEAD suite.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "AES-GCM / ChaCha20-Poly1305"],
        protection: "record keys",
        note: "Bob returns AEAD-protected content using independent server write keys.",
      },
    ],
    legend: [
      {
        title: "Plaintext setup",
        description: "Certificate and ephemeral key exchange remain network-visible.",
        tone: "neutral",
      },
      {
        title: "ChangeCipherSpec",
        description: "Finished is the first protected handshake message from each peer.",
        tone: "cyan",
      },
      {
        title: "Production profile",
        description: "ECDHE plus AEAD provides forward secrecy and authenticated records.",
        tone: "emerald",
      },
    ],
  },
  "1.3": {
    eyebrow: "TLS 1.3 · Full certificate handshake",
    title: "One round trip to authenticated encryption",
    rtt: "1-RTT",
    summary: "public negotiation → encrypted authentication → protected HTTP",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: [
          "TLS 1.3 + cipher suites",
          "signature algorithms",
          "X25519 key_share",
          "SNI + ALPN",
        ],
        protection: "plaintext",
        note: "Alice offers capabilities and a fresh ephemeral public key.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "ServerHello",
        messages: ["selected version + suite", "server key_share"],
        protection: "plaintext",
        note: "Both sides can now derive directional handshake keys.",
      },
      {
        step: 3,
        direction: "server-to-client",
        title: "Encrypted server authentication",
        messages: ["EncryptedExtensions", "Certificate", "CertificateVerify", "Finished"],
        protection: "handshake keys",
        note: "Bob proves his identity and authenticates the transcript.",
      },
      {
        step: 4,
        direction: "client-to-server",
        title: "Client completion",
        messages: ["Finished"],
        protection: "handshake keys",
        note: "Alice verifies Bob and confirms that she observed the same transcript.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "AEAD-protected application data"],
        protection: "application keys",
        note: "Alice can send the request immediately after her Finished message.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "AEAD-protected application data"],
        protection: "application keys",
        note: "Bob replies with a separate server application traffic key.",
      },
    ],
    legend: [
      {
        title: "Before ServerHello",
        description: "Negotiation is visible but later transcript-authenticated.",
        tone: "neutral",
      },
      {
        title: "Handshake keys",
        description: "Protect identity proof and Finished messages.",
        tone: "violet",
      },
      {
        title: "Application keys",
        description: "Separate client/server AEAD keys protect HTTP.",
        tone: "emerald",
      },
    ],
  },
};

export const DTLS_VERSION_VISUALS: Record<DtlsTutorialVersion, VersionVisual> = {
  "1.0": {
    eyebrow: "DTLS 1.0 · Deprecated cookie-verified handshake",
    title: "Six-flight cookie path before legacy protection",
    rtt: "3-RTT*",
    summary: "optional DoS check → numbered fragments → protected Finished",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "Initial ClientHello (cookie path)",
        messages: ["DTLS 1.0", "client_random", "cipher suites", "empty cookie"],
        protection: "plaintext",
        note: "Flights 1–2 are used only when Bob enforces the stateless cookie DoS check.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "HelloVerifyRequest (optional DoS)",
        messages: ["stateless cookie"],
        protection: "plaintext",
        note: "Bob returns a cookie tied to Alice's apparent address; the exchange is recommended but optional.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "ClientHello + cookie",
        messages: ["same offer", "echoed cookie"],
        protection: "plaintext",
        note: "Echoing the cookie proves Alice can receive datagrams at the claimed source address.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: [
          "ServerHello",
          "Certificate",
          "ServerKeyExchange?",
          "CertificateRequest?",
          "ServerHelloDone",
        ],
        protection: "plaintext",
        note: "Bob optionally requests Alice's certificate for mutual authentication.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: [
          "Certificate?",
          "ClientKeyExchange",
          "CertificateVerify?",
          "ChangeCipherSpec",
          "Finished",
        ],
        protection: "key transition",
        note: "When requested, Alice proves possession of her certificate key before Finished.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob's Finished completes flight 6; protected application datagrams follow separately.",
      },
    ],
    legend: [
      {
        title: "Flights 1–2 optional",
        description:
          "Without the cookie DoS check, Bob answers the first ClientHello directly.",
        tone: "cyan",
      },
      {
        title: "Datagram recovery",
        description: "message_seq and fragment offsets rebuild reordered handshake messages.",
        tone: "violet",
      },
      {
        title: "Deprecated",
        description: "RFC 8996 says DTLS 1.0 must not be negotiated.",
        tone: "amber",
      },
    ],
  },
  "1.2": {
    eyebrow: "DTLS 1.2 · Production-compatible ECDHE + AEAD handshake",
    title: "Six-flight cookie path over unreliable UDP",
    rtt: "3-RTT*",
    summary: "optional DoS check → ECDHE exchange → protected Finished",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "Initial ClientHello (cookie path)",
        messages: ["DTLS 1.2", "client_random", "cipher suites", "empty cookie"],
        protection: "plaintext",
        note: "RFC 6347 recommends the cookie check by default for new handshakes.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "HelloVerifyRequest (optional DoS)",
        messages: ["stateless cookie"],
        protection: "plaintext",
        note: "Bob can validate reachability without retaining handshake state.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "ClientHello + cookie",
        messages: ["same offer", "echoed cookie"],
        protection: "plaintext",
        note: "The cookie round trip limits spoofed-source amplification before certificate data is sent.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: [
          "ServerHello",
          "Certificate",
          "ServerKeyExchange",
          "CertificateRequest?",
          "ServerHelloDone",
        ],
        protection: "plaintext",
        note: "Bob signs an ECDHE share and may request Alice's certificate for mutual authentication.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: [
          "Certificate?",
          "ClientKeyExchange",
          "CertificateVerify?",
          "ChangeCipherSpec",
          "Finished",
        ],
        protection: "key transition",
        note: "Alice optionally proves her identity, derives keys, and advances to epoch 1.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob's Finished completes flight 6; AEAD-protected application datagrams follow separately.",
      },
    ],
    legend: [
      {
        title: "Cookie recommended",
        description:
          "The exchange is optional on the wire but should be the default when amplification matters.",
        tone: "cyan",
      },
      {
        title: "Reliable handshake",
        description: "Timers retransmit whole flights while application UDP stays unreliable.",
        tone: "violet",
      },
      {
        title: "Record protection",
        description: "Use ECDHE and AEAD; DTLS 1.2 still permits weaker legacy choices.",
        tone: "emerald",
      },
    ],
  },
  "1.3": {
    eyebrow: "DTLS 1.3 · Full certificate handshake",
    title: "One RTT normally; two with the shown cookie retry",
    rtt: "1 RTT / 2 with HRR",
    summary: "optional cookie retry → encrypted identity → terminal ACK",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["DTLS 1.3", "X25519 key_share", "cipher suites", "signature algorithms"],
        protection: "plaintext",
        note: "Alice offers an ephemeral share in epoch 0; a normal path needs no cookie retry.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Optional HelloRetryRequest",
        messages: ["cookie", "selected group?"],
        protection: "plaintext",
        note: "Bob may request a cookie for address validation; this optional path adds one RTT.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Retried ClientHello",
        messages: ["cookie", "compatible key_share"],
        protection: "plaintext",
        note: "This flight appears only after HelloRetryRequest; otherwise the first ClientHello continues.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "ServerHello",
        messages: ["selected version + suite", "server key_share"],
        protection: "plaintext",
        note: "Both sides derive epoch-2 handshake traffic keys from ephemeral (EC)DHE.",
      },
      {
        step: 5,
        direction: "server-to-client",
        title: "Encrypted server authentication",
        messages: [
          "EncryptedExtensions",
          "CertificateRequest?",
          "Certificate",
          "CertificateVerify",
          "Finished",
        ],
        protection: "handshake keys",
        note: "Bob proves his identity and may request Alice's certificate for mutual authentication.",
      },
      {
        step: 6,
        direction: "client-to-server",
        title: "Client completion",
        messages: [
          "Certificate?",
          "CertificateVerify?",
          "Finished (epoch 2)",
          "optional app data (epoch 3 record)",
        ],
        protection: "handshake to application",
        note: "Alice optionally proves her identity, sends Finished, and can use epoch 3 immediately.",
      },
      {
        step: 7,
        direction: "server-to-client",
        title: "Selective acknowledgement",
        messages: ["terminal ACK (normally epoch 3)", "optional app data (separate record)"],
        protection: "application keys",
        note: "ACK confirms the terminal flight and lets retransmission omit acknowledged messages or fragments.",
      },
    ],
    legend: [
      {
        title: "Cookie optional",
        description:
          "HelloRetryRequest validates reachability when amplification is a concern.",
        tone: "cyan",
      },
      {
        title: "Epoch keys",
        description: "Epoch 0 is plaintext, 2 is handshake, and 3 starts application traffic.",
        tone: "violet",
      },
      {
        title: "Selective recovery",
        description: "ACKs and encrypted record numbers improve datagram handshake handling.",
        tone: "emerald",
      },
    ],
  },
};
