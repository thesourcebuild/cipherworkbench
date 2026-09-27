import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Alice sends her butler a signed letter: 'Please transfer £500 to the gardener.' The butler executes it. Mallory intercepts a photocopy of that same signed letter and re-submits it 50 more times. The signature is genuine — Alice really did write it. But Alice only authorised it once.",
  problem:
    "HMAC and digital signatures prove a message is authentic and unaltered. But they cannot prove it was not sent before. How do we stop a valid message from being reused as a weapon?",
  steps: [
    {
      title: "Step 1: Alice sends an authenticated command",
      speaker: "Alice",
      content:
        "Alice sends Bob a signed API request:\n\n`POST /transfer { amount: 500, to: 'gardener' }`\n\nAlice computes an HMAC over the payload using her shared API secret. Bob receives it, verifies the HMAC, and executes the transfer. Everything is correct.",
    },
    {
      title: "Step 2: Mallory captures and replays",
      speaker: "Mallory",
      content:
        "Mallory is monitoring the network. She captures Alice's request — HMAC and all. She doesn't need to forge anything. She simply **re-sends the exact same packet** to Bob's server 99 more times.\n\nBob verifies each HMAC. All 99 pass. Bob executes 99 more £500 transfers. Alice is cleaned out.\n\n**The HMAC was valid every single time — because the message genuinely was written by Alice.**",
      callout: {
        type: "warning",
        text: "This is the Replay Attack. The cryptographic primitives worked perfectly. The vulnerability was in the protocol design — not the algorithm.",
      },
    },
    {
      title: "Step 3: Fix #1 — Include a Timestamp",
      speaker: "Bob",
      content:
        "Bob's server rejects any request whose timestamp is more than **30 seconds old**.\n\nAlice now includes `timestamp: 1719432001` inside her signed payload. Mallory's replay arrives at T+120s — Bob rejects it immediately.\n\n**Limitation:** Mallory can still replay within the 30-second window, and clock skew between distributed servers can cause legitimate requests to be rejected.",
    },
    {
      title: "Step 4: Fix #2 — Include a Unique Nonce",
      speaker: "Alice",
      content:
        "Alice generates a **cryptographically random 128-bit nonce** and includes it in every request:\n\n`nonce: a3f1bc9d2e7840c1...`\n\nBob's server stores every nonce it has seen in a short-lived cache. When Mallory replays the old packet, Bob checks the nonce — it has already been used — and **rejects the replay unconditionally**, even within the timestamp window.",
      callout: {
        type: "security",
        text: "Production systems combine both: a short timestamp window (to bound the nonce cache size) AND a per-request nonce (to eliminate replays within the window). OAuth 1.0a, AWS Signature v4, and Stripe webhooks all use this pattern.",
      },
    },
    {
      title: "Step 5: Fix #3 — TLS Sequence Numbers",
      speaker: "Bob",
      content:
        "At the transport layer, **TLS 1.3 uses an implicit per-record sequence number** XOR'd into the nonce of each AES-GCM record. If Mallory replays or reorders even a single TLS record, the AEAD authentication tag immediately fails — the out-of-sequence number produces a different nonce, yielding different ciphertext that decrypts to garbage.",
    },
  ],
  takeaways: [
    "A replay attack reuses a legitimately signed message without breaking any cryptography.",
    "Fix: include a **timestamp** to bound the replay window.",
    "Fix: include a **unique per-request nonce** that the server tracks and refuses to reuse.",
    "TLS 1.3 prevents transport-layer replays via implicit sequence numbers in the AEAD nonce.",
    "The root cause is always protocol design, not algorithm weakness.",
  ],
  seed: {
    toolId: "hmac",
    sampleInput: "transfer=500&to=gardener&nonce=a3f1bc9d2e7840c1&ts=1719432001",
    explanation:
      "Open HMAC Workbench and observe how changing the nonce produces a completely different authentication tag — making the old tag useless for replay.",
  },
};

export default content;
