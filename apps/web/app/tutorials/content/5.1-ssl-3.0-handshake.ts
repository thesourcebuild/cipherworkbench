import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "tls-handshake", version: "SSL 3.0" },
  analogy:
    "Imagine Alice calling Bob's 1996 mailroom over an open line. They first agree on one sealed-envelope system from a bundled catalog. Bob reads out a certified RSA padlock, and Alice locks a fresh one-use secret inside it. Both sides turn that secret and two public random values into matching encryption and MAC keys.\n\nAlice announces that she is switching to the new keys, sends a protected wax seal over the conversation, and Bob does the same. Only then do they exchange protected HTTP messages. Netscape's SSL 3.0 became the technical foundation for IETF-standardized TLS 1.0 in 1999, but its record protection and algorithm choices are now unsafe.\n\nSSL protected data while it crossed the network. It never protected plaintext after a compromised client or server decrypted it, and it never made either endpoint “unhackable.”",
  problem:
    "How did SSL 3.0 negotiate a cipher suite, authenticate a server, establish shared keys, and protect web traffic, and why is that once-pioneering protocol now prohibited?",
  steps: [
    {
      title: "Step 1: Alice sends the SSL 3.0 ClientHello in plaintext",
      speaker: "Alice",
      content:
        "Alice sends `ClientHello` with the highest protocol version she supports, a fresh `client_random`, an optional session ID, a list of cipher suites, and compression choices. A cipher suite bundles the key-exchange method, bulk cipher, and MAC algorithm, for example RSA key transport with RC4 and MD5.\n\nThis negotiation is visible to Eve because no shared keys exist yet.",
      callout: {
        type: "warning",
        text: "SSL 3.0 predates modern downgrade defenses. Today, allowing fallback to it would expose the connection to obsolete algorithms and protocol attacks.",
      },
    },
    {
      title: "Step 2: Bob selects one bundled cipher suite",
      speaker: "Bob",
      content:
        "Bob returns `ServerHello` with SSL 3.0, a `server_random`, a session ID, one cipher suite, and one compression method. In a representative RSA handshake he then sends his X.509 `Certificate` and `ServerHelloDone`. Other suites can add `ServerKeyExchange`, and mutual authentication can add `CertificateRequest`.\n\nUnlike TLS 1.3, Bob's certificate and the rest of this server flight remain plaintext.",
    },
    {
      title: "Step 3: Alice verifies Bob's certificate",
      speaker: "Alice",
      content:
        "Alice validates Bob's certificate chain and checks that the certificate identity matches the server she intended to reach. This establishes which RSA public key belongs to Bob.\n\nThe certificate does not itself create record keys. It authenticates the public key that Alice will use for the next key-exchange step.",
      callout: {
        type: "security",
        text: "Skipping certificate or hostname validation turns encrypted traffic into an authenticated connection with the wrong party, allowing Mallory to stand between Alice and Bob.",
      },
    },
    {
      title: "Step 4: Alice transports the pre-master secret",
      speaker: "Alice",
      content:
        "For RSA key transport, Alice generates a 48-byte `pre_master_secret`, encrypts it with Bob's RSA public key, and sends it in `ClientKeyExchange`. Bob decrypts it with his private key. Both sides combine the pre-master secret with `client_random` and `server_random` using SSL 3.0's MD5/SHA-1 construction to derive a 48-byte master secret, MAC secrets, encryption keys, and IV material.\n\nBecause the server's long-term RSA key unwraps the secret, later theft of that key can expose recorded sessions. This common mode does not provide forward secrecy.",
    },
    {
      title: "Step 5: ChangeCipherSpec and Finished activate protection",
      speaker: "Alice",
      content:
        "Alice sends `ChangeCipherSpec`, promoting her pending write state to the negotiated keys, followed by an encrypted `Finished` proof over the handshake. Bob verifies it, sends his own `ChangeCipherSpec`, and returns his protected `Finished`. The connection can then carry HTTP records.\n\nSSL 3.0 protects records with a separate legacy MAC and then encrypts them using ciphers such as RC4 or CBC. CBC records chain the previous ciphertext block as the next IV, and SSL 3.0's loose padding rules contributed to the POODLE padding-oracle attack.",
      callout: {
        type: "warning",
        text: "SSL 3.0 is a historical protocol, not a compatibility option. RFC 7568 prohibits its use; modern systems should negotiate TLS 1.2 or TLS 1.3 instead.",
      },
    },
    {
      title: "Step 6: Session IDs resume an earlier session",
      speaker: "Bob",
      content:
        "Bob can cache the session's master secret under a session ID. On a later connection Alice offers that ID; if Bob accepts it, both sides reuse the session state, exchange fresh random values, and move quickly to `ChangeCipherSpec` and `Finished` without repeating certificate processing and RSA key transport.\n\nResumption reduced expensive public-key work, but it did not repair SSL 3.0's obsolete cryptography or record-layer weaknesses.",
    },
  ],
  takeaways: [
    "SSL 3.0 established the recognizable hello, certificate, key-exchange, ChangeCipherSpec, Finished, and application-data sequence inherited by early TLS.",
    "SSL 3.0 was published in 1996 and became the foundation for TLS 1.0, standardized in RFC 2246 in 1999.",
    "A common RSA handshake transported a pre-master secret with the server's long-term public key, so it lacked forward secrecy.",
    "SSL 3.0 used custom MD5/SHA-1 derivation and MAC constructions rather than TLS 1.2's PRF or TLS 1.3's HKDF schedule.",
    "RC4, legacy CBC handling, weak/export suites, downgrade exposure, and POODLE make SSL 3.0 unsafe.",
    "RFC 7568 prohibits SSL 3.0. Study it to understand TLS history, never to configure a live service.",
    "Transport encryption protects data in transit; security of stored or already-decrypted endpoint data remains a separate responsibility.",
  ],
  seed: {
    toolId: "rsa",
    sampleInput: "",
    explanation:
      "Open the RSA Workbench to explore the public-key primitive historically used to transport SSL 3.0's pre-master secret.",
  },
};

export default content;
