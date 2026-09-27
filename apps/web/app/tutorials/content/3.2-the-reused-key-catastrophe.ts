import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Think of a sheet of physical carbon copy paper. If you write two completely different letters using the exact same carbon sheet without replacing it, the ink impressions of both letters overlap. An eavesdropper holding the carbon sheet up to the light can easily decipher both texts.",
  problem:
    "Why does modern symmetric encryption require an IV/Nonce alongside the key, and why does repeating it even once cause complete cryptographic collapse?",
  steps: [
    {
      title: "Step 1: How Stream Ciphers & CTR Mode Work",
      speaker: "Alice",
      content:
        "In AES-CTR and ChaCha20, the cipher does not encrypt the message directly. Instead it encrypts the **Key + Nonce** to produce a pseudo-random **Keystream** (K). The actual plaintext (P) is then combined with the keystream using XOR:\n\n`C = P ⊕ K`\n\nXOR is completely reversible: whoever holds K can recover P from C instantly. The security rests entirely on K being unique and secret.",
    },
    {
      title: "Step 2: Alice's Fatal Shortcut",
      speaker: "Alice",
      content:
        "Alice encrypts Message 1 with her key and nonce, producing:\n\n`C₁ = P₁ ⊕ K`\n\nLater, in a hurry, Alice encrypts a second message using the **exact same key and nonce**, producing:\n\n`C₂ = P₂ ⊕ K`\n\nBoth ciphertexts were produced with the identical keystream K. This is called a **two-time pad** and it is fatal.",
    },
    {
      title: "Step 3: Eve's Two-Time Pad Attack",
      speaker: "Eve",
      content:
        "Eve intercepts both C₁ and C₂ from the network. She XORs them together:\n\n`C₁ ⊕ C₂ = (P₁ ⊕ K) ⊕ (P₂ ⊕ K) = P₁ ⊕ P₂`\n\n**The secret key K has completely cancelled out.** Eve now holds the XOR of the two raw plaintexts. Because natural language is highly redundant, she can effortlessly recover both messages using English letter-frequency analysis and a technique called **crib dragging** — no key required.",
      callout: {
        type: "warning",
        text: "In AES-GCM, nonce reuse is even more catastrophic: it exposes the secret GHASH authentication key, allowing Eve to **forge arbitrary encrypted messages** that Bob will accept as authentic — complete authentication bypass.",
      },
    },
    {
      title: "Step 4: The Fix — Generate a Fresh Nonce Every Time",
      speaker: "Alice",
      content:
        "The solution is simple: **never reuse a nonce**. Generate a cryptographically random nonce for every single message.\n\n- **AES-GCM (96-bit nonce):** At high volumes, random nonces risk collision after ~2³² messages (birthday bound). Use a counter or switch to XChaCha20.\n- **XChaCha20-Poly1305 (192-bit nonce):** Large enough that random nonces are safe for any realistic volume.\n- **AES-GCM-SIV:** A nonce-misuse resistant mode — even if a nonce is accidentally reused, it only leaks *whether two plaintexts were identical*, nothing more.",
      callout: {
        type: "info",
        text: "TLS 1.3 avoids this entirely by deriving a unique per-record nonce from an incrementing sequence number XOR'd with the traffic secret — nonce reuse is structurally impossible.",
      },
    },
  ],
  takeaways: [
    "A Nonce/IV **must never be reused** with the same encryption key — even once breaks everything.",
    "Reusing a nonce with a stream cipher cancels out the key and exposes `P₁ ⊕ P₂`, recoverable by frequency analysis.",
    "In AES-GCM specifically, nonce reuse also forfeits the authentication tag, enabling message forgery.",
    "Use XChaCha20-Poly1305 (192-bit nonce) for high-volume systems, or AES-GCM-SIV for nonce-misuse resistance.",
  ],
  seed: {
    toolId: "aes",
    sampleInput: "Attack at dawn",
    explanation:
      "Open AES Workbench and observe how changing the IV/Nonce produces a completely different ciphertext — and what happens when you encrypt two different messages with the same IV.",
  },
};

export default content;
