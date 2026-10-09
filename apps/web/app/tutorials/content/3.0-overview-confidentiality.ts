import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Imagine placing a private contract inside a heavy steel strongbox locked with a physical tumbler lock. As long as the box travels across the city, courier eavesdroppers (Eve) can see the heavy metal box, but they cannot see or read a single word of the paper inside. However, only someone who already possesses a copy of that exact physical key can unlock the box and read the contents.\n\nSymmetric encryption is the digital equivalent of that strongbox: it scrambles readable plaintext into pseudorandom ciphertext using a single shared secret key.",
  problem:
    "How can two parties communicate across an untrusted, eavesdropped network without unauthorized third parties reading their secrets, and why is hiding the text not enough to prevent tampering?",
  steps: [
    {
      title: "Step 1: What It Is (The Core Nature of Confidentiality)",
      speaker: "Alice",
      content:
        "Confidentiality is the property that sensitive information is kept secret from unauthorized observers. In symmetric cryptography, both the sender and the receiver share a single secret key (typically 128 or 256 bits) used to both encrypt and decrypt the payload.",
      callout: {
        type: "info",
        text: "Confidentiality is the 'C' in the CIA triad. Symmetric ciphers like AES and ChaCha20 are the fastest cryptographic algorithms available, capable of encrypting gigabytes per second on modern CPUs.",
      },
    },
    {
      title: "Step 2: What It Does (The Block & Stream Encryption Mechanism)",
      speaker: "Bob",
      content:
        "Symmetric ciphers take plaintext bytes and run them through reversible substitution-permutation rounds parameterized by the key and an initialization vector (IV or nonce). The resulting ciphertext appears indistinguishable from pure random noise. Only someone who feeds the ciphertext back into the decryption algorithm with the matching key can recover the original plaintext.",
      callout: {
        type: "info",
        text: "Block ciphers (AES) process fixed-size chunks (128 bits) in specific operational modes (GCM, CBC, CTR). Stream ciphers (ChaCha20) generate a pseudorandom keystream XORed directly with arbitrary byte streams.",
      },
    },
    {
      title: "Step 3: What It Can Do (Guarantees & Capabilities)",
      speaker: "Alice",
      content:
        "When implemented with modern standards, symmetric encryption achieves extraordinary protection:\n\n* **Blocks Passive Eavesdropping (Eve):** Protects web traffic, private chat messages, database records, and whole disks (BitLocker, LUKS) from being read.\n* **High-Throughput Performance:** Hardware instructions like AES-NI and ARM Cryptography extensions encrypt and decrypt in near-zero CPU cycles.\n* **AEAD Combined Guarantees:** Authenticated Encryption with Associated Data (such as AES-GCM or ChaCha20-Poly1305) simultaneously guarantees both confidentiality and tamper resistance in a single, atomic pass.",
      callout: {
        type: "security",
        text: "NIST and BSI consider AES-256 quantum-resistant against Grover's search algorithm, as Grover only halves effective key length from 256 bits to an insurmountable 128 bits.",
      },
    },
    {
      title: "Step 4: What It Does NOT Do (Critical Security Boundaries)",
      speaker: "Mallory",
      content:
        "Historically, symmetric encryption was misunderstood, leading to some of the internet's worst cryptographic catastrophes:\n\n* **Legacy encryption does NOT prevent tampering:** Plain ciphers like AES-CBC or AES-CTR provide zero integrity. Mallory can flip bits in CBC ciphertext to alter plaintext values without decrypting them, or trigger padding oracle errors (POODLE) to decrypt data byte-by-byte.\n* **Does NOT solve Key Delivery:** Both parties must already share the identical secret key prior to communication. It offers no built-in way for strangers to establish a key over an open wire.\n* **Catastrophic vulnerability to Nonce Reuse:** In stream and counter modes (CTR, GCM, ChaCha20), reusing the same IV/nonce with the same key strips away the keystream through simple XOR math, completely compromising confidentiality.",
      callout: {
        type: "warning",
        text: "Never use unauthenticated modes like ECB or unauthenticated CBC for new software. Modern engineering mandates AEAD (AES-GCM or ChaCha20-Poly1305).",
      },
    },
  ],
  takeaways: [
    "Symmetric encryption hides data from eavesdroppers using a single shared secret key.",
    "Unauthenticated encryption (CBC, CTR, ECB) does not prevent tampering; bit-flipping and padding oracles can defeat it.",
    "Modern systems mandate Authenticated Encryption (AEAD: AES-GCM, ChaCha20-Poly1305) to combine secrecy and integrity.",
    "Never reuse an IV or nonce under the same symmetric key.",
    "Symmetric cryptography assumes the secret key has already been securely exchanged.",
  ],
  seed: {
    toolId: "aes",
    sampleInput: "Confidential Data Payload",
    explanation:
      "Open AES in Cipher Workbench to test how different modes (ECB, CBC, GCM) encrypt data and observe the requirement for initialization vectors.",
  },
};

export default content;
