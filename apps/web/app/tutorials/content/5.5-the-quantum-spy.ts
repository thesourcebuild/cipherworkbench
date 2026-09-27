import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Imagine a burglar filming you lock your safe with a 4-digit code. They don't have the combination today, but they know they will soon possess a quantum scanner that can test all mathematical combinations in a fraction of a second. To defeat them, you replace the lock with a multi-dimensional geometric labyrinth that even quantum supercomputers cannot solve.",
  "problem": "Why does Shor's algorithm on a quantum computer break RSA and Elliptic Curves, and how does lattice cryptography save the future of the internet?",
  "steps": [
    {
      "title": "Step 1: The Quantum Threat (Shor's Algorithm)",
      "speaker": "Eve",
      "content": "Classical computers cannot factor large numbers (RSA) or solve discrete logarithms (ECC). However, in 1994, mathematician Peter Shor proved that a sufficiently large quantum computer can solve both in polynomial time using quantum superposition and Fourier transforms."
    },
    {
      "title": "Step 2: The 'Store Now, Decrypt Later' Attack",
      "speaker": "Eve",
      "content": "Eve doesn't need a quantum computer today. Adversaries and intelligence agencies are recording encrypted TLS sessions right now, storing petabytes in data centers, waiting for quantum computers to retroactively decrypt government secrets, trade patents, and medical records."
    },
    {
      "title": "Step 3: Enter ML-KEM (Kyber / FIPS 203)",
      "speaker": "Bob",
      "content": "In August 2024, NIST officially standardized **ML-KEM (FIPS 203)**. Instead of prime numbers, ML-KEM is built on the **Module Learning with Errors (M-LWE)** problem over high-dimensional polynomial lattices.",
      "callout": {
        "type": "security",
        "text": "Lattice problems are believed to be immune to both classical and quantum algorithms because finding the closest vector in a 512-dimensional noisy grid has no known quantum shortcut."
      }
    },
    {
      "title": "Step 4: Alice & Bob Encapsulate",
      "speaker": "Alice",
      "content": "Bob shares his ML-KEM public key. Alice runs **Encapsulate** in Cipher Workbench, producing a shared secret and a ciphertext. Bob decapsulates it with his private key. Even with a million-qubit computer, Eve cannot reverse the lattice noise!",
      "callout": {
        "type": "info",
        "text": "KEM vs Signatures: ML-KEM (FIPS 203) handles quantum-safe Key Encapsulation (replacing ECDH/RSA key exchange). For quantum-safe Digital Signatures (replacing RSA/Ed25519 signing), NIST standardized ML-DSA (FIPS 204, based on Dilithium) and SLH-DSA (FIPS 205, based on SPHINCS+)."
      }
    }
  ],
  "takeaways": [
    "RSA, ECDSA, and Diffie-Hellman will be broken once cryptographically relevant quantum computers exist.",
    "Symmetric ciphers like AES-256 remain quantum-resistant (Grover's algorithm only halves key strength to 128 bits).",
    "NIST FIPS 203 (ML-KEM) is the new worldwide standard for quantum-safe key exchange.",
    "ML-KEM handles quantum-safe key exchange; ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) handle quantum-safe digital signatures."
  ],
  "seed": {
    "toolId": "ml-kem",
    "sampleInput": "",
    "explanation": "Open ML-KEM (FIPS 203) Workbench to generate quantum-safe lattice keypairs and test encapsulation live."
  }
};

export default content;
