import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  sectionTitle: "Core Principles & Security Boundaries",
  analogy:
    "Imagine Bob wants to receive confidential letters from anyone in the world without having met them beforehand. He leaves open brass padlocks on his front porch for anyone to take. When Alice wants to send a secret letter, she snaps Bob's open padlock shut over her strongbox. Once clicked shut, not even Alice can open it! Only Bob, who keeps the private pocket key locked in his safe, can open the box.\n\nAsymmetric cryptography is the breakthrough that solved the historic key distribution paradox: using a mathematically paired **public key** (the open padlock) and **private key** (the pocket key).",
  problem:
    "How can two parties who have never met establish secure, encrypted communications over an untrusted public internet where every byte can be intercepted by eavesdroppers?",
  steps: [
    {
      title: "What It Is: The Core Nature of Dual-Key Cryptography",
      speaker: "Alice",
      content:
        "Asymmetric cryptography uses pairs of mathematically related keys. The **Public Key** can be broadcast openly to the entire world. The **Private Key** must be kept strictly confidential by its owner. The math is governed by one-way trapdoor functions—problems that are effortless to compute in one direction, but mathematically impossible to reverse without the private trapdoor.",
      callout: {
        type: "info",
        text: "Pioneered in the 1970s by Diffie, Hellman, Merkle, Rivest, Shamir, and Adleman, asymmetric cryptography underpins modern internet security.",
      },
    },
    {
      title: "What It Does: The Core Asymmetric Primitives",
      speaker: "Bob",
      content:
        "Asymmetric algorithms serve three fundamental functions across modern protocols:\n\n* **Key Exchange (Diffie-Hellman / ECDH):** Allows two parties to compute an identical shared secret across a public channel without transmitting the secret itself.\n* **Public-Key Encryption (RSA-OAEP):** Allows anyone with the recipient's public key to encrypt a small piece of data that only the private key holder can decrypt.\n* **Digital Signatures (Ed25519, ECDSA, RSA-PSS):** Allows the private key holder to sign a message such that anyone holding the public key can verify its authenticity and integrity.",
      callout: {
        type: "info",
        text: "Modern systems heavily favor Elliptic Curve Cryptography (ECDH on Curve25519, Ed25519 signatures) because a 256-bit EC key matches the security of a bulky 3072-bit RSA key with a fraction of the CPU and bandwidth cost.",
      },
    },
    {
      title: "What It Can Do: Guarantees & Capabilities",
      speaker: "Alice",
      content:
        "Asymmetric cryptography enables capabilities impossible with symmetric keys alone:\n\n* **Solves Key Exchange:** Enables instant secure connections between browsers and unknown servers without pre-shared keys.\n* **Provides True Non-Repudiation:** Because only Alice possesses her private signing key, she cannot claim someone else forged her signature on a Git commit, contract, or Bitcoin transaction.\n* **Hybrid Encryption:** By using asymmetric crypto to exchange an ephemeral 32-byte key, protocols can immediately transition to blazing-fast AES-256 for the bulk payload.",
      callout: {
        type: "security",
        text: "Hybrid encryption gives you the best of both worlds: asymmetric flexibility for key negotiation, followed by symmetric speed for gigabytes of bulk data transfer.",
      },
    },
    {
      title: "What It Does NOT Do: Critical Security Boundaries",
      speaker: "Mallory",
      content:
        "Asymmetric cryptography has significant architectural boundaries that developers must respect:\n\n* **Does NOT encrypt bulk data efficiently:** Asymmetric mathematics is 100× to 1000× slower than symmetric ciphers and cannot encrypt payloads larger than its mathematical modulus (e.g., ~214 bytes for RSA-2048 with OAEP).\n* **Does NOT prove real-world identity on its own:** A public key is simply a string of bits. An unauthenticated public key gives no assurance that it belongs to Bob rather than Mallory. Without a Certificate Authority or trust chain, Mallory can easily perform a Man-in-the-Middle attack by substituting her own public key.\n* **Vulnerable to Quantum Computers without PQC:** Classical asymmetric algorithms (RSA, ECDH, Ed25519) will be completely broken by Shor's algorithm on cryptographically relevant quantum computers, requiring transition to NIST Post-Quantum standards (ML-KEM, ML-DSA).",
      callout: {
        type: "warning",
        text: "Never use raw, unauthenticated Diffie-Hellman over the network. Without digital certificates or signatures, an active attacker can intercept and replace both halves of the exchange.",
      },
    },
  ],
  takeaways: [
    "Asymmetric cryptography uses mathematically linked public and private key pairs.",
    "Public keys can be freely published; private keys must never leave their host.",
    "Powers key agreement (ECDH), public-key encryption (RSA), and digital signatures (Ed25519).",
    "Bulk data encryption is always delegated to symmetric ciphers via hybrid encryption.",
    "A public key alone does not prove identity; it requires Public Key Infrastructure (PKI) and certificates to prevent impersonation.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "Ephemeral Session Key Agreement",
    explanation:
      "Open ECDH in Cipher Workbench to see how two parties generate private keys and combine public points to calculate an identical shared secret in broad daylight.",
  },
};

export default content;
