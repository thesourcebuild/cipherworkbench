import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Imagine encrypting a page of text by replacing each letter with a different letter from a fixed substitution table. The *individual letters* are hidden, but someone still sees which letters repeat most often — and since 'e' is the most common letter in English, they can map patterns back to plaintext. AES-ECB makes exactly the same mistake, just with 16-byte blocks instead of individual letters.",
  problem:
    "AES is a secure block cipher. So why does choosing the wrong *mode of operation* completely destroy confidentiality even while using AES correctly?",
  steps: [
    {
      title: "Step 1: What a Block Cipher Mode Does",
      speaker: "Alice",
      content:
        "AES is a **block cipher** — it encrypts exactly 16 bytes at a time. A **mode of operation** defines how to handle messages longer than 16 bytes. The choice of mode is as critical as the choice of cipher.",
    },
    {
      title: "Step 2: ECB Mode — The Naive Approach",
      speaker: "Alice",
      content:
        "**ECB (Electronic Code Book)** splits the plaintext into 16-byte blocks and encrypts each block **independently** with the same key:\n\n`Block 1 → Encrypt(Key, Block 1) → Cipher Block 1`\n`Block 2 → Encrypt(Key, Block 2) → Cipher Block 2`\n\nIf Block 1 and Block 3 are identical plaintext, they produce **identical ciphertext blocks**. The structure of the data bleeds straight through the encryption.",
      callout: {
        type: "warning",
        text: "The famous 'ECB Penguin': encrypting a bitmap image of a penguin with AES-ECB produces an encrypted image where the penguin silhouette is still perfectly visible — because the white-background blocks all encrypt to the same value.",
      },
    },
    {
      title: "Step 3: Eve Exploits the Pattern",
      speaker: "Eve",
      content:
        "Eve intercepts Alice's encrypted database backup. She does not break AES. Instead, she notices that certain 16-byte ciphertext blocks repeat at fixed offsets. She identifies that blocks 3–5 always appear together — this is a known structure (e.g. a record header). By rearranging identical blocks, she can **corrupt, forge, or selectively delete records** without knowing the key.",
    },
    {
      title: "Step 4: CBC Mode — Chaining Solves Repetition",
      speaker: "Alice",
      content:
        "**CBC (Cipher Block Chaining)** XORs each plaintext block with the previous ciphertext block before encrypting:\n\n`Cipher Block N = Encrypt(Key, Plaintext Block N ⊕ Cipher Block N-1)`\n\nIdentical plaintext blocks now produce **different ciphertext** because each block depends on all blocks before it. The structure is hidden.\n\n**But:** CBC is sequential (slow to parallelise), requires padding (vulnerable to padding oracle attacks — Tutorial 6.3), and still has no authentication.",
    },
    {
      title: "Step 5: CTR Mode — The Stream Cipher Approach",
      speaker: "Alice",
      content:
        "**CTR (Counter)** turns AES into a stream cipher. It encrypts a counter value to produce a keystream, then XORs it with plaintext:\n\n`Keystream Block N = Encrypt(Key, Nonce ∥ Counter N)`\n`Ciphertext N = Plaintext N ⊕ Keystream N`\n\nCTR is fully parallelisable, has no padding, and each block is independent. **But**: nonce reuse is catastrophic (Tutorial 3.2), and there is still no authentication.",
    },
    {
      title: "Step 6: GCM Mode — The Modern Answer",
      speaker: "Bob",
      content:
        "**GCM (Galois/Counter Mode)** = CTR encryption + GHASH polynomial authentication in one pass. It provides **Confidentiality + Integrity + Authenticity** simultaneously. This is AEAD — covered in Tutorial 3.3.\n\nThe right choice in 2025:\n- **Symmetric encryption:** AES-256-GCM or ChaCha20-Poly1305\n- **Never use:** ECB (ever), raw CBC without HMAC, or CTR without authentication",
      callout: {
        type: "security",
        text: "Mode of operation is not a detail — it is the entire security model. AES-ECB with a 256-bit key is weaker than AES-GCM with a 128-bit key for any real-world message.",
      },
    },
  ],
  takeaways: [
    "AES is a secure primitive; choosing the wrong **mode of operation** destroys that security.",
    "ECB encrypts each block independently — identical plaintext blocks produce identical ciphertext (patterns leak).",
    "CBC uses chaining to hide patterns but is sequential, padded, and unauthenticated.",
    "CTR is parallelisable but unauthenticated and catastrophically vulnerable to nonce reuse.",
    "**Always use an AEAD mode**: AES-256-GCM or ChaCha20-Poly1305 — they encrypt and authenticate in one pass.",
  ],
  seed: {
    toolId: "aes",
    sampleInput: "AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA Hello, World!!!! AAAAAAAAAAAAAAAA",
    explanation:
      "Open AES Workbench, switch between ECB and GCM modes, and observe how identical 16-byte blocks produce identical ciphertext in ECB but unique ciphertext in GCM.",
  },
};

export default content;
