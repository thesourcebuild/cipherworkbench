import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Imagine receiving a letter marked 'Transfer $1,000 to Bob' along with a perfect SHA-256 hash. The hash confirms the letter matches the digest on the envelope. But did Alice actually write this letter, or did Mallory write it and calculate the hash herself? Without Alice's signature or a shared secret wax seal, the hash alone cannot prove who created the message.\n\nAuthenticity bridges this gap by tying data to an identity or a secret key, ensuring Bob knows with mathematical certainty that Alice—and only Alice—authored the message.",
  problem:
    "Hashes verify that data matches a digest, but anyone can calculate a hash for forged data. How do systems mathematically prove the identity of the sender and detect unauthorized alterations by active attackers?",
  steps: [
    {
      title: "Step 1: What It Is (The Core Nature of Authenticity)",
      speaker: "Alice",
      content:
        "Authenticity is the cryptographic guarantee of origin and provenance. It proves that a message originated from a specific, identified sender, and that it has not been forged or tampered with by any intermediary.",
      callout: {
        type: "info",
        text: "While integrity asks 'Has this changed?', authenticity asks 'Who sent this, and did anyone tamper with it since they signed it?'",
      },
    },
    {
      title: "Step 2: What It Does (The Keyed Authentication Mechanism)",
      speaker: "Bob",
      content:
        "Authenticity binds the message payload to a cryptographic key. In symmetric systems, Alice and Bob share a secret key and compute a Message Authentication Code (e.g., HMAC-SHA256). In asymmetric systems, Alice signs the message with her Private Key (e.g., Ed25519 digital signature). In both cases, only someone possessing the secret or private key can create a valid authentication tag.",
      callout: {
        type: "info",
        text: "HMAC processes the secret key and message through nested hash rounds (H(K XOR opad || H(K XOR ipad || M))) to eliminate length-extension vulnerabilities.",
      },
    },
    {
      title: "Step 3: What It Can Do (Guarantees & Capabilities)",
      speaker: "Alice",
      content:
        "By enforcing keyed verification, authenticity provides formidable defenses:\n\n* **Thwarts Man-in-the-Middle Attackers (Mallory):** If Mallory intercepts a message and changes a single byte, she cannot regenerate a valid HMAC or signature because she does not possess the secret key.\n* **Secures Webhooks & APIs:** GitHub, Stripe, and Slack sign outgoing HTTP webhook payloads with HMAC so your server can verify they are genuine before executing actions.\n* **Protects Session State:** JSON Web Tokens (JWT) and signed cookies rely on HMAC or digital signatures to ensure clients cannot tamper with user IDs or permissions.",
      callout: {
        type: "security",
        text: "With asymmetric signatures (Ed25519, RSA-PSS), authenticity also yields non-repudiation: Alice cannot deny creating the message, because only she holds the private key.",
      },
    },
    {
      title: "Step 4: What It Does NOT Do (Critical Security Boundaries)",
      speaker: "Mallory",
      content:
        "Authenticity is powerful, but it has defined non-goals that cause vulnerabilities when misunderstood:\n\n* **Does NOT hide the contents (No Confidentiality):** An HMAC-signed API payload or JWT is sent in plain text. Eve can still read the entire message unless it is separately encrypted.\n* **Does NOT guarantee freshness against Replay Attacks:** A valid signature or HMAC remains valid forever. If Mallory records a legitimate 'Transfer $100' request, she can replay that exact packet 100 times unless the protocol enforces timestamps, monotonic sequence numbers, or nonces.\n* **Symmetric MACs do NOT provide Non-Repudiation:** Because Alice and Bob share the exact same key in HMAC, Bob cannot prove to a third-party judge that Alice sent the message rather than Bob himself.",
      callout: {
        type: "warning",
        text: "Authenticity without freshness leaves your system open to replay attacks. Always pair HMAC signatures with a timestamp and a unique nonce.",
      },
    },
  ],
  takeaways: [
    "Authenticity establishes message provenance, proving who created the data.",
    "A secret key (HMAC) or private key (digital signature) is mandatory; public hashes cannot prove authorship.",
    "Authenticity does not provide secrecy—authenticated payloads remain visible to passive eavesdroppers.",
    "Authenticity alone does not prevent replay attacks; protocols must track nonces or timestamps to verify freshness.",
  ],
  seed: {
    toolId: "hmac",
    sampleInput: "Action: Transfer $1000 to Bob",
    explanation:
      "Open HMAC in Cipher Workbench to see how combining a message with a secret key produces a tamper-proof tag that changes completely if the key or message is altered.",
  },
};

export default content;
