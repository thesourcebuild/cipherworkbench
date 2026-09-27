import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "A physical safe box with one lock. Alice and Bob each hold an identical brass key. Alice can lock the box, ship it through the public postal system, and Bob can unlock it on arrival — but anyone who copies one of those keys can do the same.",
  problem:
    "How can Alice and Bob conceal the meaning of their messages from eavesdroppers like Eve?",
  steps: [
    {
      title: "Step 1: Alice writes the Plaintext",
      speaker: "Alice",
      content: "Alice writes: *\"Meet me at the cafeteria at noon\"*.",
    },
    {
      title: "Step 2: The Pre-Shared Secret",
      speaker: "Alice",
      content:
        "Before any messages can flow, **Alice and Bob must both possess the exact same secret key**. Symmetric cryptography has no public/private key split — a single 256-bit key both encrypts *and* decrypts.\n\nThis raises an immediate question: **how did they agree on that key in the first place without Eve learning it?** This is called the **Key Distribution Problem**, and it is one of the hardest challenges in cryptography.\n\n- **Pre-shared key (PSK):** Exchange the key in person ahead of time. Practical for two friends, impossible at internet scale.\n- **Key Exchange Protocol (e.g. Diffie-Hellman):** A mathematical trick that lets Alice and Bob derive the same shared secret over a public channel *without ever transmitting it*. Module 4 covers this in full.\n- **Key Encapsulation (KEM):** Wrap the symmetric key inside asymmetric encryption so only the intended recipient can unwrap it.",
      callout: {
        type: "warning",
        text: "Symmetric encryption **does not solve key distribution**. In practice, symmetric session keys are almost always established via an asymmetric handshake — TLS does exactly this: ECDH to agree on a session key, then AES-GCM for bulk data.",
      },
    },
    {
      title: "Step 3: Alice encrypts with AES-256",
      speaker: "Alice",
      content:
        "Assuming the key has been securely shared, Alice uses it to encrypt her message. AES-256 (Advanced Encryption Standard) scrambles the plaintext through **14 substitution-permutation rounds** into unreadable ciphertext.",
    },
    {
      title: "Step 4: What Eve sees on the wire",
      speaker: "Eve",
      content:
        "Eve intercepts the transmission over Wi-Fi. All she sees is high-entropy noise: `e4 2a 9c 51 0b 7f ...`. Without the shared key, breaking AES-256 by brute force would require more energy than all stars in the galaxy produce.",
    },
    {
      title: "Step 5: Bob decrypts with the shared key",
      speaker: "Bob",
      content:
        "Bob receives the ciphertext. Because he holds the **same secret key** as Alice, he inputs it into Cipher Workbench and clicks **Decrypt**. The original message appears instantly.",
    },
    {
      title: "Step 6: The Critical Catch — Encryption is NOT Integrity",
      speaker: "Mallory",
      content:
        "Even with a perfectly shared key, what if **Mallory** intercepts the ciphertext and flips a few bits before it reaches Bob? Without an authentication tag, legacy modes like AES-CBC or AES-CTR will silently decrypt into corrupted plaintext with no warning.\n\n**Encryption alone guarantees Confidentiality — it does NOT guarantee Integrity.** We solve this in Tutorial 3.3 with Authenticated Encryption (AEAD).",
      callout: {
        type: "warning",
        text: "A classic security mistake: assuming encryption prevents tampering. Unauthenticated encryption is vulnerable to bit-flipping and padding oracle attacks. Always use an AEAD mode (AES-GCM, ChaCha20-Poly1305) in production.",
      },
    },
  ],
  takeaways: [
    "Symmetric encryption uses the **same key** for both encryption and decryption — there is no public/private key split.",
    "AES-256 is the NIST-approved worldwide standard for confidential data.",
    "The **Key Distribution Problem**: securely agreeing on a shared key is a separate, hard problem not solved by symmetric encryption itself.",
    "In practice, symmetric keys are established via asymmetric key-exchange protocols (Diffie-Hellman, ECDH) — covered in Module 4.",
    "Encryption alone guarantees **Confidentiality** only. For Integrity, always use an AEAD mode — covered in Tutorial 3.3.",
  ],
  seed: {
    toolId: "aes",
    sampleInput: "Meet me at the cafeteria at noon",
    explanation:
      "Open AES Workbench to test live symmetric encryption and decryption.",
  },
};

export default content;
