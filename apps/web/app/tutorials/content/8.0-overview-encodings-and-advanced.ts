import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  sectionTitle: "Core Principles & Security Boundaries",
  analogy:
    "Imagine writing a confidential financial report in Morse code or Pig Latin instead of English. It might look unfamiliar at first glance, but anyone who understands Morse code can instantly translate every word back into plain English. There is no secret key, no lock, and no security—it is merely an alternate spelling.\n\nIn computing, **encodings** (Base64, Hex, URL encoding, UTF-8) are deterministic format transformations designed for transport across networks. They are frequently confused with encryption, resulting in severe real-world security vulnerabilities.",
  problem:
    "Why do software developers consistently confuse data encoding with encryption, what catastrophic vulnerabilities does this misunderstanding cause, and how do emerging advanced primitives like Zero-Knowledge Proofs extend the boundaries of modern cryptography?",
  steps: [
    {
      title: "What It Is: Encodings vs. Cryptographic Primitives",
      speaker: "Alice",
      content:
        "An **encoding** is a deterministic, unkeyed transformation of binary bytes into a standardized character set (such as Base64 or Hex) so that data can safely travel across text-only protocols like HTTP, JSON, or email without corruption.\n\nA **cryptographic primitive** is a mathematical algorithm that relies on secret keys and computational intractability to guarantee confidentiality, integrity, authenticity, or zero-knowledge verifiability.",
      callout: {
        type: "info",
        text: "Encodings solve transport compatibility; cryptography solves trust, privacy, and authenticity.",
      },
    },
    {
      title: "What It Does: The Mechanism Comparison",
      speaker: "Bob",
      content:
        "When data is encoded in Base64, every 3 bytes (24 bits) are re-grouped into four 6-bit numbers, each mapped to a printable ASCII character (`A-Z, a-z, 0-9, +, /`). Anyone in the world can reverse Base64 using a standard lookup table with a single function call.\n\nIn contrast, modern advanced cryptography—such as Zero-Knowledge Proofs (ZK-SNARKs and ZK-STARKs)—uses polynomial commitments and elliptic curves to allow a prover to mathematically prove that a statement is true (e.g., 'I know the secret password' or 'I am over 21 years old') without revealing the secret itself.",
      callout: {
        type: "info",
        text: "Zero-Knowledge Proofs satisfy three properties: Completeness (an honest prover convinces the verifier), Soundness (a cheating prover cannot convince the verifier), and Zero-Knowledge (the verifier learns nothing beyond statement truth).",
      },
    },
    {
      title: "What It Can Do: Guarantees & Applications",
      speaker: "Alice",
      content:
        "Both encodings and advanced primitives have critical, distinct roles in system architecture:\n\n* **Safe Binary Transport (Encodings):** Transmit raw cryptographic keys, public certificates, and binary signatures across JSON payloads, HTTP headers, and URL query strings.\n* **Standardized Formats (Encodings):** Enable cross-language interoperability (e.g., PEM files wrap DER binary keys in Base64 with header lines).\n* **Privacy-Preserving Verification (ZKPs):** Prove identity, solvency, or transaction validity on decentralized blockchains and privacy identity networks without revealing private account balances or personal data.",
      callout: {
        type: "security",
        text: "Zcash and modern Layer-2 rollups use ZKPs to compress thousands of verifiable transactions and shield private transaction amounts from public ledger view.",
      },
    },
    {
      title: "What It Does NOT Do: Critical Security Boundaries",
      speaker: "Mallory",
      content:
        "Confusing encodings with cryptography causes frequent, high-profile data breaches:\n\n* **Encodings provide NO secrecy or confidentiality:** Base64, Hex, ASCII, and URL-encoding are deterministic format conversions that anyone can reverse without any secret key, password, or cryptographic barrier.\n* **Storing secrets in Base64 is equivalent to plaintext:** Storing passwords, API tokens, or session tokens as Base64 in config files or cookies offers zero defense; attackers decode them instantly.\n* **JWT Payloads are NOT encrypted by default:** Standard JSON Web Tokens (JWS) are Base64URL-encoded and signed—their claims (user IDs, emails, roles) are completely readable by anyone who inspects the token string.\n* **Zero-Knowledge Proofs do NOT replace Transport Security:** While a ZKP proves mathematical statement validity without leaking secrets, communications must still occur over authenticated channels to prevent impersonation or man-in-the-middle manipulation.",
      callout: {
        type: "warning",
        text: "Base64 is NOT encryption. Encoding obfuscates appearance to human eyes, but offers no resistance against an adversary.",
      },
    },
  ],
  takeaways: [
    "Encoding formats binary data for safe text transport; it never provides secrecy.",
    "Base64 and Hex are deterministic representations that anyone can decode without a secret key.",
    "JWT payloads are Base64URL-encoded and public to anyone who views the token.",
    "Advanced primitives like Zero-Knowledge Proofs enable proving statements without revealing private underlying data.",
  ],
  seed: {
    toolId: "aes",
    sampleInput: "Base64 is an encoding, not encryption",
    explanation:
      "Open AES in Cipher Workbench to compare real authenticated encryption against simple format encoding.",
  },
};

export default content;
