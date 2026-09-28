import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Alice claims she knows where Waldo is in a giant Where's Waldo poster. To prove it without revealing the location, she covers the entire poster with a large sheet of black paper, cuts a tiny Waldo-sized hole at the exact location, and holds it up. Bob sees Waldo through the hole — proof Alice knew the location — but the black sheet hides every other part of the poster, so Bob learns nothing about *where* the hole is. Alice proved knowledge without revealing it.",
  problem:
    "In every authentication system we have built, Alice must reveal her secret to prove she knows it: passwords, private keys used to sign challenges, decryption proofs. Is it mathematically possible to prove you know a secret *without ever revealing the secret or any information about it?*",
  steps: [
    {
      title: "Step 1: What Zero-Knowledge Means",
      speaker: "Alice",
      content:
        "A **Zero-Knowledge Proof (ZKP)** is a cryptographic protocol where Alice (the Prover) convinces Bob (the Verifier) that she knows some secret, without revealing:\n\n1. The secret itself\n2. Any partial information about the secret\n3. Anything Bob could not have computed alone\n\nAfter the proof, Bob is convinced Alice knows the secret. But Bob's knowledge is *zero* — he has learned nothing he could use to impersonate Alice or recover the secret.",
    },
    {
      title: "Step 2: The Cave of Ali Baba — Interactive ZKP",
      speaker: "Alice",
      content:
        "Alice knows the magic word to open a secret door inside a circular cave. The cave has two paths (Left and Right) that meet at the locked door.\n\n1. Bob waits outside. Alice walks in and randomly takes the **Left** or **Right** path.\n2. Bob enters and shouts: 'Come out via the **Right** path!'\n3. If Alice knows the magic word, she can always come out the correct side — even if she took the wrong path, she opens the door and crosses.\n4. If Alice is bluffing, she has a **50% chance** of getting caught each round.\n\nRepeat 30 times. If Alice succeeds every time, the probability she is bluffing is `(1/2)^30` — roughly 1 in 1 billion. Bob is convinced without ever learning the magic word.",
      callout: {
        type: "info",
        text: "This is the foundation of interactive ZKP. The security comes from repeated random challenges — Alice cannot predict which path Bob will demand, so she cannot fake knowledge over many rounds.",
      },
    },
    {
      title: "Step 3: Non-Interactive ZKPs — zk-SNARKs",
      speaker: "Alice",
      content:
        "Interactive ZKPs require Alice and Bob to be online simultaneously. **Non-Interactive Zero-Knowledge Proofs (NIZKs)** allow Alice to produce a single proof that anyone can verify at any time.\n\n**zk-SNARK** (Succinct Non-interactive ARgument of Knowledge): Alice produces a tiny proof (typically 200–400 bytes) that mathematically proves she performed a correct computation, without revealing the inputs.\n\nPractical uses:\n- **Blockchain privacy (Zcash):** Prove a transaction is valid (inputs balance outputs) without revealing sender, recipient, or amount.\n- **Age verification:** Prove you are over 18 without revealing your birth date or identity.\n- **Password authentication:** Prove you know the password without sending the password or a hash.",
    },
    {
      title: "Step 4: zk-STARKs — Post-Quantum ZKPs",
      speaker: "Bob",
      content:
        "**zk-STARKs** (Scalable Transparent ARguments of Knowledge) are a newer ZKP system with important advantages:\n\n- **No trusted setup:** zk-SNARKs require a one-time 'ceremony' to generate system parameters — if that ceremony is compromised, all proofs are forgeable. zk-STARKs require no trusted setup.\n- **Post-quantum secure:** zk-STARKs rely only on hash functions (collision resistance), which are quantum-resistant. zk-SNARKs rely on elliptic curves, which Shor's algorithm can break.\n- **Larger proofs:** The trade-off is bigger proof sizes (tens of kilobytes vs hundreds of bytes).\n\nEthereum Layer 2 scaling networks like StarkNet (using STARKs via Cairo) and Polygon Miden use zk-STARKs to prove thousands of transactions are valid with zero trusted setup.",
      callout: {
        type: "security",
        text: "zk-SNARKs have a 'toxic waste' problem: the trusted setup ceremony produces secrets that must be permanently destroyed. Zcash's original 2016 Sprout ceremony involved 6 participants — if even one destroyed their secrets, the setup was safe. (The 2018 Sapling upgrade expanded this to ~200 participants).",
      },
    },
    {
      title: "Step 5: Real-World ZKP Applications Today",
      speaker: "Alice",
      content:
        "Zero-knowledge proofs are no longer theoretical — they are deployed in production:\n\n- **Zcash (2016–present):** Pioneered production private cryptocurrency transactions using zk-SNARKs (originally BCTV14, later upgraded to Groth16 with the 2018 Sapling upgrade).\n- **Ethereum zkEVM (2023):** Prove Ethereum Virtual Machine execution correctness without re-running every computation.\n- **Proof of passport:** Prove your passport is valid and issued by a real government without revealing your name, nationality, or expiry date.\n- **FIDO2 / WebAuthn:** Contains ZKP-like properties — proves possession of a private key without transmitting it.\n- **Signal Protocol:** Zero-knowledge proofs used to verify group membership without revealing the group roster.",
    },
  ],
  takeaways: [
    "A Zero-Knowledge Proof lets Alice prove she knows a secret without revealing the secret or any information about it.",
    "Interactive ZKPs use repeated random challenges — 30 rounds reduces fraud probability to 1 in 1 billion.",
    "zk-SNARKs: tiny (200-byte) non-interactive proofs, but require a trusted setup ceremony.",
    "zk-STARKs: larger proofs but no trusted setup and post-quantum secure (hash-function based).",
    "Production uses: Zcash (private transactions), Ethereum Layer 2 scaling, passport verification, and age proofs.",
  ],
  seed: {
    toolId: "ed25519",
    sampleInput: "I know the secret",
    explanation:
      "Open Ed25519 Workbench — signing is a ZKP-adjacent concept: Alice proves she holds the private key by producing a signature, without ever transmitting the key itself.",
  },
};

export default content;
