import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "An armored bank truck that is both bulletproof (confidentiality) and sealed with tamper-evident electronic locks (authenticity). If Mallory tampers with the lock or drills a tiny hole in the armor, the entire truck deadbolts itself shut and refuses to open.",
  "problem": "Why is encryption alone NOT enough to stop Mallory from manipulating ciphertexts?",
  "steps": [
    {
      "title": "Step 1: Mallory's Bit-Flipping Attack on Plain CBC",
      "speaker": "Mallory",
      "content": "In legacy unauthenticated encryption (like AES-CBC), Mallory doesn't need to decrypt the message to attack it. By flipping specific bits in the ciphertext, she can predictably alter the decrypted text (e.g. turning `admin=0` into `admin=1`)."
    },
    {
      "title": "Step 2: Enter AEAD (AES-GCM)",
      "speaker": "Alice",
      "content": "Alice switches to **AES-GCM** (Galois/Counter Mode). While AES encrypts the text, a GHASH authenticator calculates a 128-bit authentication tag over both the ciphertext and unencrypted metadata (Associated Data / AAD)."
    },
    {
      "title": "Step 3: Mallory's Tampering is Rejected",
      "speaker": "Bob",
      "content": "Mallory attempts to modify 1 byte of the ciphertext. Bob's AES-GCM engine checks the tag before releasing plaintext. The tag does not match! Bob immediately rejects the packet, preventing bit-flipping and eliminating padding oracle attacks completely (as GCM requires no padding).",
      "callout": {
        "type": "security",
        "text": "Cipher Workbench Diagnostic Rule C001 warns whenever an unauthenticated mode (like ECB or CBC without MAC) is selected!"
      }
    }
  ],
  "takeaways": [
    "AEAD (Authenticated Encryption with Associated Data) guarantees both Secrecy and Authenticity.",
    "AES-GCM and ChaCha20-Poly1305 are the standard AEAD ciphers used in TLS 1.3, WireGuard, and SSH.",
    "Never write 'Encrypt-then-MAC' manually if you can use an audited AEAD primitive."
  ],
  "seed": {
    "toolId": "aes",
    "sampleInput": "Transfer $50,000 to Account 9812 — Alice",
    "explanation": "Open AES-GCM in Cipher Workbench to inspect how ciphertext and authentication tags work together."
  }
};

export default content;
