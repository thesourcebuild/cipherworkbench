import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Think of a physical street mailbox with a drop slot. Anyone can walk by and drop a letter in (Public Key). But only the mail carrier has the physical key to unlock the rear door and retrieve the mail (Private Key).",
  "problem": "How can anyone in the world send Bob an encrypted message without Bob having to share a private password with each person?",
  "steps": [
    {
      "title": "Step 1: Bob generates a Keypair",
      "speaker": "Bob",
      "content": "Bob generates two mathematically linked keys:\n1. **Public Key:** Shared openly on his website or directory.\n2. **Private Key:** Guarded carefully on Bob's local device. Never shared or uploaded."
    },
    {
      "title": "Step 2: Alice locks with Bob's Public Key",
      "speaker": "Alice",
      "content": "Alice downloads Bob's Public Key. She encrypts her secret message. Even Alice herself cannot decrypt the message once it is locked! The public key can only lock, never unlock."
    },
    {
      "title": "Step 3: Eve intercepts the parcel",
      "speaker": "Eve",
      "content": "Eve captures the encrypted parcel. Eve also has Bob's Public Key, but that is useless: public-key encryption is a one-way mathematical trapdoor. Only Bob's Private Key can invert the operation."
    },
    {
      "title": "Step 4: Bob decrypts with his Private Key",
      "speaker": "Bob",
      "content": "Bob enters his Private Key into Cipher Workbench and clicks **Decrypt**. The trapdoor opens, revealing Alice's note."
    },
    {
      "title": "Step 5: The Critical Catch — Who Sent the Parcel? (Lack of Authenticity)",
      "speaker": "Mallory",
      "content": "Bob unlocked the parcel, but **how does Bob know Alice actually wrote it?**\nBob's public key is public to the entire planet. Mallory could easily write: *'Hi Bob, it's Alice, please transfer $50,000 to Mallory'*, encrypt it using Bob's public key, and drop it in Bob's inbox!\nWhen Bob decrypts, it decrypts cleanly. Bob was fooled because **Public-Key Encryption provides Confidentiality for Bob, but ZERO Authenticity of the sender!**\nTo prove Alice sent it, Alice must sign the message with her own private key using a **Digital Signature (Tutorial 4.3)**.",
      "callout": {
        "type": "warning",
        "text": "Crucial rule: Encrypting with a recipient's public key only proves only THEY can read it. It proves nothing about who wrote it."
      }
    }
  ],
  "takeaways": [
    "Asymmetric encryption uses a keypair: a Public Key (to lock) and a Private Key (to unlock).",
    "Public keys can be freely published anywhere without compromising security.",
    "Encrypting with Bob's public key guarantees confidentiality for Bob, but zero authenticity of the sender.",
    "Anyone in the world can encrypt with Bob's public key; sender authenticity requires a digital signature."
  ],
  "seed": {
    "toolId": "rsa",
    "sampleInput": "Top secret message for Bob's eyes only",
    "explanation": "Open RSA Workbench to generate an RSA keypair and test asymmetric encryption live."
  }
};

export default content;
