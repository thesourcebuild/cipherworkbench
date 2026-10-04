import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "cryptographic-flow", id: "rsa" },
  analogy:
    "Think of a physical street mailbox with a drop slot. Anyone can walk by and drop a letter in (Public Key). But only the mail carrier has the physical key to unlock the rear door and retrieve the mail (Private Key).",
  problem:
    "How can anyone in the world send Bob an encrypted message without Bob having to share a private password with each person?",
  steps: [
    {
      title: "Step 1: Bob generates a Keypair",
      speaker: "Bob",
      content:
        "Bob generates two mathematically linked keys:\n1. **Public Key:** Shared openly on his website or directory.\n2. **Private Key:** Guarded carefully on Bob's local device. Never shared or uploaded.",
    },
    {
      title: "Step 2: Alice locks with Bob's Public Key",
      speaker: "Alice",
      content:
        "Alice obtains and authenticates Bob's public key, then encrypts a small secret using RSA-OAEP. The public key can create ciphertext but cannot reverse it. In production, RSA normally encrypts a random symmetric key rather than a large document directly.",
    },
    {
      title: "Step 3: Eve intercepts the parcel",
      speaker: "Eve",
      content:
        "Eve captures the encrypted parcel. Eve also has Bob's Public Key, but that is useless: public-key encryption is a one-way mathematical trapdoor. Only Bob's Private Key can invert the operation.",
    },
    {
      title: "Step 4: Bob decrypts with his Private Key",
      speaker: "Bob",
      content:
        "Bob enters his Private Key into Cipher Workbench and clicks **Decrypt**. The trapdoor opens, revealing Alice's note.",
    },
  ],
  afterTimeline: {
    title: "After the Timeline: Encryption does not identify the sender",
    content:
      "Bob can decrypt the parcel, but his public key is available to everyone. Mallory can create a different message, encrypt it for Bob, and claim Alice sent it. Public-key encryption provides confidentiality for Bob but does not authenticate the sender. Alice needs a digital signature or an authenticated protocol to prove authorship.",
    callout: {
      type: "warning",
      text: "Encrypting with the recipient's public key establishes who can read the ciphertext, not who created it.",
    },
  },
  takeaways: [
    "Asymmetric encryption uses a keypair: a Public Key (to lock) and a Private Key (to unlock).",
    "Public keys can be freely published anywhere without compromising security.",
    "Encrypting with Bob's public key guarantees confidentiality for Bob, but zero authenticity of the sender.",
    "Anyone in the world can encrypt with Bob's public key; sender authenticity requires a digital signature.",
  ],
  seed: {
    toolId: "rsa",
    sampleInput: "Top secret message for Bob's eyes only",
    explanation:
      "Open RSA Workbench to generate an RSA keypair and test asymmetric encryption live.",
  },
};

export default content;
