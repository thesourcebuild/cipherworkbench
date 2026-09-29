import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Imagine a club secret handshake. Before delivering news, Alice performs the secret handshake. If someone doesn't know the exact grip, Bob rejects whatever they say, even if their document looks neat and tidy. However, Alice is speaking out loud — anyone in the room can still hear the words!",
  "problem": "How can high-speed APIs, webhooks (like Stripe or GitHub), and payment gateways authenticate millions of requests per second without heavy asymmetric math?",
  "steps": [
    {
      "title": "Step 1: The Shared API Secret",
      "speaker": "Alice",
      "content": "Alice and Bob establish a shared secret key: `sk_live_secret_99812`."
    },
    {
      "title": "Step 2: Computing the HMAC",
      "speaker": "Alice",
      "content": "Alice takes her message: `order_id=4821&amount=50.00`. She calculates `HMAC-SHA256(Key, Message)`. The result is a compact 32-byte authentication code."
    },
    {
      "title": "Step 3: Mallory is foiled",
      "speaker": "Mallory",
      "content": "Mallory intercepts the request and tries to alter `amount=50.00` to `amount=5000.00`. But Mallory cannot produce the matching HMAC because she lacks `sk_live_secret_99812`. Any code Mallory guesses has a 1-in-2²⁵⁶ chance of being correct — roughly 1 in 10⁷⁷, practically comparable to the total number of atoms in the observable universe (~10⁸⁰)."
    },
    {
      "title": "Step 4: Bob verifies in constant time",
      "speaker": "Bob",
      "content": "Bob recalculates the HMAC using his copy of the secret key. The codes match, proving Alice wrote the message and no one altered a single byte.",
      "callout": {
        "type": "security",
        "text": "Always use timing-safe comparison (`crypto.timingSafeEqual`) when verifying HMACs in code to prevent side-channel timing attacks!"
      }
    },
    {
      "title": "Step 5: The Critical Catch — Eve Can Still Read the Message!",
      "speaker": "Eve",
      "content": "Bob verified Alice's authenticity, but notice what happened on the wire: **Alice's message was sent in plaintext!** Eve intercepted the packet and now knows Bob's customer ID and order amount.\nHMAC provides **Integrity and Authenticity**, but **ZERO Confidentiality**. If Alice wants to hide the words from Eve, she needs **Symmetric Encryption (Stage 3)**!",
      "callout": {
        "type": "warning",
        "text": "A common beginner mistake is assuming HMAC encrypts data. It does not! HMAC is an authentication tag appended to visible data."
      }
    }
  ],
  "takeaways": [
    "HMAC (RFC 2104) securely blends a secret key with a cryptographic hash function.",
    "It provides both Message Integrity (no alterations) and Authenticity (verified sender).",
    "HMAC does NOT provide confidentiality: eavesdroppers like Eve can read the plaintext unless you also encrypt it.",
    "HMAC is the industry standard for REST API signing, AWS request signatures, and webhook verification."
  ],
  "seed": {
    "toolId": "hmac",
    "sampleInput": "order_id=4821&amount=50.00",
    "explanation": "Open HMAC Workbench with Alice's payload to inspect the authentication code."
  }
};

export default content;
