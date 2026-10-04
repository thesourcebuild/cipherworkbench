import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "tls-handshake", version: "1.3" },
  analogy:
    "Imagine Alice calling an embassy. She begins on an open line by proposing a fresh one-use code system and sending her half of it. Bob chooses compatible settings and returns his half. At that instant they can independently calculate the same temporary secret.\n\nBob then uses the new private line to show his **CA-signed passport** and sign the complete conversation so far. Alice checks the passport, the hostname, the signature, and a final transcript authenticator. Only then does she send her own `Finished` seal and the HTTP request.\n\nNormal HTTPS authenticates **the server**. Alice presents a certificate only when Bob explicitly requests mutual TLS (mTLS). TLS 1.3 can also protect other application protocols over a reliable transport, but it secures data only while in transit; compromised endpoints can still read plaintext after decryption.",
  problem:
    "How does TLS 1.3 establish fresh keys, authenticate a server, detect handshake tampering, and begin encrypted HTTP traffic in a single network round trip?",
  steps: [
    {
      title: "Step 1: Alice sends ClientHello in plaintext",
      speaker: "Alice",
      content:
        "Alice's browser sends `ClientHello`, offering TLS 1.3, AEAD/HKDF cipher suites such as `TLS_AES_128_GCM_SHA256`, supported signature algorithms, key-exchange groups, and an ephemeral `key_share` (commonly X25519). Web connections also carry extensions such as SNI and ALPN.\n\nThe cipher-suite name selects the **record cipher and transcript hash**; it does not select the certificate algorithm or the key-exchange group.",
      callout: {
        type: "warning",
        text: "The first ClientHello is normally visible on the network. TLS protects its integrity through the later transcript, but does not retroactively make its metadata secret. Encrypted ClientHello (ECH) is a separate extension designed to hide more of it.",
      },
    },
    {
      title: "Step 2: Bob selects parameters and both derive handshake keys",
      speaker: "Bob",
      content:
        "Bob replies with a plaintext `ServerHello` selecting TLS 1.3, one cipher suite, and a compatible ephemeral key share. Alice and Bob combine the two ephemeral shares to compute the same (EC)DHE shared secret.\n\nTLS feeds that shared secret and the handshake transcript into HKDF. It first derives separate **client handshake** and **server handshake** traffic secrets, then distinct AEAD keys and IVs for each direction. The ECDHE output is an input to this schedule; it is not itself the TLS `master_secret`.",
      callout: {
        type: "info",
        text: "If Alice did not send a usable key share, Bob can send `HelloRetryRequest`. That adds another ClientHello and another network round trip before the normal flow continues.",
      },
    },
    {
      title: "Step 3: Bob authenticates inside the encrypted server flight",
      speaker: "Bob",
      content:
        "Everything after `ServerHello` is encrypted with server handshake keys. Bob sends:\n\n1. `EncryptedExtensions` — negotiated options that do not belong in `ServerHello`.\n2. `Certificate` — the server certificate chain.\n3. `CertificateVerify` — a signature over the handshake transcript, proving possession of the certificate private key and binding that identity to this exact exchange.\n4. `Finished` — an HMAC-based authenticator over the transcript.\n\nThe certificate and signature are **not fields inside ServerHello**; they are separate encrypted handshake messages.",
      callout: {
        type: "security",
        text: "An attacker cannot silently swap a key share, cipher choice, certificate, or extension: transcript authentication makes Alice and Bob detect any mismatch before accepting the connection.",
      },
    },
    {
      title: "Step 4: Alice verifies Bob and the complete transcript",
      speaker: "Alice",
      content:
        "Alice validates the certificate chain to a trusted root, validity dates, constraints, key usage, and the requested website hostname. She then verifies `CertificateVerify` and Bob's `Finished` value.\n\nA valid certificate chain alone is not enough: the hostname must match, the signature must bind the certificate key to this handshake, and `Finished` must authenticate the same transcript Alice observed.",
    },
    {
      title: "Step 5: Alice sends Finished, then HTTP begins",
      speaker: "Alice",
      content:
        "Alice sends her encrypted `Finished` using the client handshake keys. She may immediately follow it with an HTTP request protected by client application traffic keys. Bob's HTTP response uses a separate server application traffic key.\n\nTLS 1.3 record protection uses an AEAD cipher: AES-GCM, ChaCha20-Poly1305, or AES-CCM. Eve can still observe sizes and timing. Mallory can alter or drop packets, but altered ciphertext fails authentication and is rejected rather than accepted as valid data.",
      callout: {
        type: "security",
        text: "In a full certificate-authenticated (EC)DHE handshake, erasing the ephemeral private keys gives forward secrecy: later theft of Bob's certificate private key does not reveal recorded sessions.",
      },
    },
    {
      title: "Step 6: Session tickets make later connections faster",
      speaker: "Bob",
      content:
        "After the handshake, Bob can send one or more `NewSessionTicket` messages. A later connection can use that ticket as a pre-shared key (PSK) for resumption, optionally combined with a new (EC)DHE exchange for fresh forward secrecy.\n\nTLS 1.3 also permits **0-RTT early data** on resumed sessions. It arrives before the new handshake is authenticated, can be replayed, and does not gain forward secrecy from the new key exchange. Applications must restrict it to replay-safe operations.",
      callout: {
        type: "warning",
        text: "Never treat 0-RTT as safe for non-idempotent actions such as charging a card, transferring money, or changing account state.",
      },
    },
  ],
  takeaways: [
    "TLS 1.3 completes a normal certificate-authenticated handshake in one round trip; application data can follow the client's Finished.",
    "`ServerHello` completes parameter selection and enables handshake encryption; the certificate, signature, and server Finished follow as separate encrypted messages.",
    "HKDF derives independent client/server handshake and application traffic secrets from the shared secret and transcript.",
    "Certificates establish trust and hostname identity, `CertificateVerify` proves private-key possession, and `Finished` authenticates the transcript.",
    "Full ephemeral (EC)DHE provides forward secrecy. PSK-only resumption and replayable 0-RTT require separate risk decisions.",
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
