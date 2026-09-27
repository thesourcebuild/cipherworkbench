import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Alice writes a 500-page novel and wants to post it to Bob securely. She puts the manuscript in a box and locks it with a cheap, fast combination lock (AES). Then she takes the *combination code* and seals it inside a small tamper-evident envelope locked with Bob's personal padlock (RSA). She posts both together. Anyone can carry the box but cannot open it. Only Bob can open the padlock envelope, recover the combination, and then open the big box.",
  problem:
    "RSA public-key encryption is mathematically secure but devastatingly slow — encrypting 1 MB of data with RSA takes seconds. AES is blindingly fast but requires a shared secret. How do real systems encrypt large data for a recipient they have never met?",
  steps: [
    {
      title: "Step 1: Why Not Encrypt Everything with RSA?",
      speaker: "Alice",
      content:
        "RSA-2048 can encrypt at most **245 bytes** per operation (due to padding overhead). Encrypting Alice's 50 MB backup with RSA would require splitting it into thousands of chunks, each requiring a separate slow modular exponentiation.\n\nIn practice, RSA encryption is **~1000× slower than AES** for bulk data. It is mathematically the wrong tool for large payloads.",
    },
    {
      title: "Step 2: Alice generates a random session key",
      speaker: "Alice",
      content:
        "Alice generates a fresh, cryptographically random **256-bit AES session key** — just 32 bytes. This key was never seen before and will never be used again after this message.\n\n`Session Key = crypto.randomBytes(32)`\n\nThis is the combination for her box.",
    },
    {
      title: "Step 3: Alice encrypts the content with AES-GCM",
      speaker: "Alice",
      content:
        "Alice encrypts her entire 50 MB document with AES-256-GCM using the session key. This takes **milliseconds** and produces authenticated ciphertext.\n\nThe session key alone is useless to Eve unless she also has the plaintext or can break AES.",
    },
    {
      title: "Step 4: Alice encrypts the session key with RSA",
      speaker: "Alice",
      content:
        "Alice retrieves Bob's **RSA Public Key** (2048 or 4096-bit). She encrypts the tiny 32-byte AES session key using **RSA-OAEP padding**:\n\n`EncryptedKey = RSA_OAEP_Encrypt(Bob_PublicKey, SessionKey)`\n\nThis produces a ~256-byte encrypted blob. RSA only needs to encrypt 32 bytes — fast, and entirely within RSA's capability.",
      callout: {
        type: "info",
        text: "OAEP (Optimal Asymmetric Encryption Padding) is mandatory. The older PKCS#1 v1.5 padding has been broken by several attacks (ROBOT, Bleichenbacher). Always specify RSA-OAEP with SHA-256.",
      },
    },
    {
      title: "Step 5: Alice sends both together",
      speaker: "Alice",
      content:
        "Alice sends Bob one bundle:\n\n1. The AES-GCM encrypted ciphertext (50 MB)\n2. The RSA-encrypted session key (256 bytes)\n\nEve intercepts both. She cannot open the RSA envelope without Bob's private key. Even if she could, the session key only decrypts this one message — Alice will use a fresh key next time.",
    },
    {
      title: "Step 6: Bob decrypts in two steps",
      speaker: "Bob",
      content:
        "Bob uses his **RSA Private Key** to decrypt the session key bundle → recovers the 32-byte AES key.\n\nThen Bob uses the recovered AES session key to decrypt the main ciphertext → recovers Alice's full document.\n\n**This is Hybrid Encryption**: the best of both worlds — RSA's key transport capability with AES's speed.",
      callout: {
        type: "security",
        text: "PGP, S/MIME email encryption, TLS key encapsulation (pre-1.3), and age (the modern file encryption tool) all use hybrid encryption. In TLS 1.3, ECDH replaced RSA-KEM for the session key agreement, achieving Perfect Forward Secrecy — a significant upgrade.",
      },
    },
  ],
  takeaways: [
    "RSA is too slow for bulk data encryption — it is designed for small payloads like keys.",
    "Hybrid Encryption: encrypt the **data** with fast AES; encrypt the **AES key** with slow RSA.",
    "Always use RSA-OAEP padding — PKCS#1 v1.5 is broken and must never be used for new systems.",
    "PGP, S/MIME, and many file encryption tools use exactly this two-step pattern.",
    "TLS 1.3 replaced RSA-KEM with ECDH for the session key, gaining Perfect Forward Secrecy.",
  ],
  seed: {
    toolId: "rsa",
    sampleInput: "This is my secret AES session key material",
    explanation:
      "Open RSA Workbench to encrypt a small payload (simulating a session key) and observe how RSA-OAEP handles key transport.",
  },
};

export default content;
