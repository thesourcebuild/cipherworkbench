import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "In a room of just 23 people, the probability that two people share a birthday exceeds 50%. With 70 people, it is 99.9%. This seems impossibly low — but the math is unforgiving. Hash collisions work exactly the same way: you do not need to find a message that matches a *specific* hash. You just need any two inputs that produce the same hash.",
  problem:
    "SHA-256 produces a 256-bit output. A brute-force attack finding a specific hash takes 2²⁵⁶ operations — impossible. But finding *any two inputs* with the same hash only takes 2¹²⁸ operations. Why, and why does this make MD5 and SHA-1 dangerous?",
  steps: [
    {
      title: "Step 1: What a Collision Is",
      speaker: "Alice",
      content:
        "A **hash collision** is when two different inputs produce the same hash output:\n\n`Hash(Message A) = Hash(Message B)` where A ≠ B\n\nFor a secure hash function, this should be computationally infeasible. But 'infeasible' depends critically on the output size.",
    },
    {
      title: "Step 2: The Birthday Paradox in Hash Math",
      speaker: "Eve",
      content:
        "If a hash function has an n-bit output, there are 2ⁿ possible hash values. To find a collision:\n\n- **Pre-image attack** (find input for a specific hash): requires ~2ⁿ attempts\n- **Collision attack** (find *any* two inputs with the same hash): requires only ~2^(n/2) attempts\n\nFor MD5 (128-bit output): collision attack requires ~2⁶⁴ operations — feasible on a modern GPU cluster in **hours**.\n\nFor SHA-1 (160-bit output): ~2⁸⁰ operations — Google's SHAttered attack produced a real SHA-1 collision in 2017, costing ~$100,000 in cloud compute.",
      callout: {
        type: "warning",
        text: "SHAttered (2017): Google produced two different PDF files with identical SHA-1 hashes. SHA-1 certificates were immediately deprecated by all major browsers. MD5 collisions have been demonstrated since 2004.",
      },
    },
    {
      title: "Step 3: Mallory Exploits a Collision",
      speaker: "Mallory",
      content:
        "Alice submits a benign software contract to Bob for signing. The contract hashes to `abc123...`.\n\nMallory has pre-computed a malicious contract that *also* hashes to `abc123...` (possible in MD5/SHA-1). She substitutes the malicious version after Bob signs.\n\nBob's signature is mathematically valid on the malicious document — because both documents have the same hash. **The signature was not forged. The collision was.**",
    },
    {
      title: "Step 4: Why SHA-256 Is Safe (For Now)",
      speaker: "Bob",
      content:
        "SHA-256 produces a 256-bit output. Collision resistance requires ~2¹²⁸ operations — equivalent to searching through more atoms than exist on Earth.\n\nSHA-3 (Keccak) provides an alternative with different internal construction, resistant to length-extension attacks that affect SHA-256.\n\nFor digital signatures, NIST recommends SHA-256 minimum, SHA-384 for 192-bit security, SHA-512 for 256-bit security.",
      callout: {
        type: "security",
        text: "Never use MD5 or SHA-1 for security purposes — only for non-security checksums where collision resistance is irrelevant (e.g. file deduplication in a trusted environment). Git is migrating from SHA-1 to SHA-256 (SHA-256 object format) for exactly this reason.",
      },
    },
    {
      title: "Step 5: Length Extension Attacks — SHA-256's Hidden Weakness",
      speaker: "Mallory",
      content:
        "SHA-256 uses the Merkle-Damgard construction. If Mallory knows `Hash(secret ∥ message)` and the length of `secret`, she can compute `Hash(secret ∥ message ∥ extra_data)` **without knowing the secret**.\n\nThis breaks naive MAC constructions like `SHA256(secret + message)`. This is why HMAC uses a double-hash construction: `HMAC = Hash(key ⊕ opad ∥ Hash(key ⊕ ipad ∥ message))`. SHA-3 (sponge construction) is immune to length extension.",
    },
  ],
  takeaways: [
    "A collision attack finds *any* two inputs with the same hash — only requires ~2^(n/2) work, not 2ⁿ.",
    "MD5 (128-bit): collisions demonstrated since 2004 — do not use for security.",
    "SHA-1 (160-bit): Google SHAttered attack (2017) — deprecated by all browsers and CAs.",
    "SHA-256 (256-bit): ~2¹²⁸ collision resistance — currently safe; minimum for new systems.",
    "Never construct a MAC as `Hash(secret ∥ message)` — use HMAC to avoid length extension attacks.",
  ],
  seed: {
    toolId: "sha256",
    sampleInput: "The quick brown fox jumps over the lazy dog",
    explanation:
      "Open Hash Workbench. Try SHA-256 vs MD5 on the same input and compare output sizes — the size difference directly determines collision resistance.",
  },
};

export default content;
