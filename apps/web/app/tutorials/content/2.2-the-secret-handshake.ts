import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "cryptographic-flow", id: "hmac" },
  analogy:
    "Imagine a club secret handshake. Before delivering news, Alice performs the secret handshake. If someone doesn't know the exact grip, Bob rejects whatever they say, even if their document looks neat and tidy. However, Alice is speaking out loud — anyone in the room can still hear the words!",
  problem:
    "How can high-speed APIs, webhooks (like Stripe or GitHub), and payment gateways authenticate millions of requests per second without heavy asymmetric math?",
  steps: [
    {
      title: "Step 1: The Shared API Secret",
      speaker: "Alice",
      content: "Alice and Bob establish a shared secret key: `sk_live_secret_99812`.",
    },
    {
      title: "Step 2: Computing the HMAC",
      speaker: "Alice",
      content:
        "Alice takes her message: `order_id=4821&amount=50.00`. She calculates `HMAC-SHA256(Key, Message)`. The result is a compact 32-byte authentication code.",
    },
    {
      title: "Step 3: Mallory is foiled",
      speaker: "Mallory",
      content:
        "Mallory intercepts the request and tries to alter `amount=50.00` to `amount=5000.00`. But Mallory cannot produce the matching HMAC because she lacks `sk_live_secret_99812`. Any code Mallory guesses has a 1-in-2²⁵⁶ chance of being correct — roughly 1 in 10⁷⁷, practically comparable to the total number of atoms in the observable universe (~10⁸⁰).",
    },
    {
      title: "Step 4: Bob verifies or rejects in constant time",
      speaker: "Bob",
      content:
        "Bob recalculates the HMAC over the exact bytes he received using his copy of the secret key, then compares the tags in constant time. Alice's unchanged request produces a match and is accepted. Mallory's altered amount produces a mismatch and is rejected.",
      callout: {
        type: "security",
        text: "Always use timing-safe comparison (`crypto.timingSafeEqual`) when verifying HMACs in code to prevent side-channel timing attacks!",
      },
    },
  ],
  afterTimeline: {
    title: "After the Timeline: HMAC does not hide the message",
    content:
      "Bob can verify Alice's authenticity, but the request itself was sent in plaintext. Eve can read the customer ID and order amount even though she cannot alter them without invalidating the tag. HMAC provides integrity and authenticity, not confidentiality. Alice must also use encryption when the message contents are sensitive.",
    callout: {
      type: "warning",
      text: "HMAC is an authentication tag, not encryption. Production protocols either encrypt separately or use an authenticated-encryption construction such as AES-GCM or ChaCha20-Poly1305.",
    },
  },
  takeaways: [
    "HMAC (RFC 2104) securely blends a secret key with a cryptographic hash function.",
    "It provides both Message Integrity (no alterations) and Authenticity (verified sender).",
    "HMAC does NOT provide confidentiality: eavesdroppers like Eve can read the plaintext unless you also encrypt it.",
    "HMAC is the industry standard for REST API signing, AWS request signatures, and webhook verification.",
  ],
  seed: {
    toolId: "hmac",
    sampleInput: "order_id=4821&amount=50.00",
    explanation: "Open HMAC Workbench with Alice's payload to inspect the authentication code.",
  },
};

export default content;
