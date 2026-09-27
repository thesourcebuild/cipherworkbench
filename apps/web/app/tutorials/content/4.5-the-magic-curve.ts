import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Factoring large numbers (RSA) is like breaking a combination lock by trying every number one by one — very hard, but the difficulty grows slowly as the lock gets bigger. Elliptic curves are like a different kind of lock where difficulty grows exponentially faster — a 256-bit EC key provides the same security as a 3072-bit RSA key, but fits in a QR code.",
  problem:
    "Tutorial 4.2 used RSA with a 2048-bit key. Tutorial 4.1 used ECDH with a 256-bit key. Why does elliptic curve cryptography achieve the same security with keys 8× smaller — and why does that matter?",
  steps: [
    {
      title: "Step 1: The Hard Problem Behind RSA",
      speaker: "Alice",
      content:
        "RSA security rests on the **Integer Factorisation Problem**: given a large number N = p × q (where p and q are huge primes), find p and q.\n\nThe best known classical algorithm (General Number Field Sieve) requires roughly `e^(1.9 × ∛(ln N))` operations. For a 2048-bit N, that is astronomically large — but it scales sub-exponentially, meaning doubling security requires much more than doubling key size.",
    },
    {
      title: "Step 2: The Hard Problem Behind Elliptic Curves",
      speaker: "Alice",
      content:
        "Elliptic curves are equations of the form `y² = x³ + ax + b` over a finite field. A **point** on the curve is a pair (x, y) satisfying the equation.\n\nThe **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: given two points P and Q on the curve where `Q = k × P` (point multiplication), find k.\n\nPoint multiplication is easy (fast). Reversing it — finding k given P and Q — has no sub-exponential algorithm. The best attack is fully exponential, requiring ~2^(n/2) operations for an n-bit key.",
    },
    {
      title: "Step 3: The Key Size Comparison",
      speaker: "Bob",
      content:
        "Because ECDLP is harder to break than integer factorisation at equivalent key sizes, EC keys can be dramatically smaller for the same security level:\n\n- **128-bit security:** RSA-3072 vs EC-256 (e.g. P-256, X25519)\n- **192-bit security:** RSA-7680 vs EC-384 (e.g. P-384)\n- **256-bit security:** RSA-15360 vs EC-521 (e.g. P-521)\n\nSmaller keys mean faster handshakes, less bandwidth, and less power — critical for IoT and mobile devices.",
    },
    {
      title: "Step 4: Curve X25519 vs P-256 — What's the Difference?",
      speaker: "Alice",
      content:
        "Not all elliptic curves are equal. The two dominant curves today:\n\n- **P-256 (NIST):** Standardised by NIST. Widely supported. Some concerns about potential NSA backdoors in the seed constants (unproven). Used by TLS, Android, iOS.\n- **X25519 (Bernstein):** Designed with completely transparent, provably safe constants. Resistant to side-channel attacks by design. No patent issues. Used by TLS 1.3, WireGuard, Signal, SSH.",
      callout: {
        type: "security",
        text: "X25519 is the recommended choice for Diffie-Hellman key exchange. Ed25519 is its signing counterpart. Together they are the backbone of modern secure protocols (TLS 1.3, WireGuard, Signal Protocol).",
      },
    },
    {
      title: "Step 5: Why Not Just Use RSA Everywhere?",
      speaker: "Bob",
      content:
        "RSA still works, but has practical disadvantages:\n\n- A 4096-bit RSA key is 512 bytes. An X25519 key is 32 bytes — fits in a tweet.\n- RSA keygen is slow (must find large primes). EC keygen is instantaneous.\n- RSA-2048 is projected to be breakable by quantum computers with ~4000 logical qubits. The smaller the key, the sooner it breaks.\n- TLS 1.3 **removed** RSA key exchange entirely — only ECDH and DHE are allowed.",
    },
  ],
  takeaways: [
    "RSA security relies on integer factorisation (sub-exponential hardness); EC security relies on ECDLP (fully exponential hardness).",
    "A 256-bit EC key provides equivalent security to a 3072-bit RSA key.",
    "Smaller EC keys mean faster operations, less bandwidth, and lower power consumption.",
    "X25519 (key exchange) and Ed25519 (signatures) are the modern recommended curves — safe, fast, and patent-free.",
    "TLS 1.3 removed RSA key exchange — ECDH is now mandatory for all new connections.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open ECDH (X25519) Workbench to generate key pairs and compare their sizes to the equivalent RSA key that would provide the same security level.",
  },
};

export default content;
