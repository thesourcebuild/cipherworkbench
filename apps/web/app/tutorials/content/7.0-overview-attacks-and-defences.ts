import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  sectionTitle: "Core Principles & Security Boundaries",
  analogy:
    "Imagine installing a 10-ton titanium vault door with an impossible 128-digit combination lock. The safe manufacturer proved mathematically that trying every combination would take 100 billion years. But an observant burglar notices that when the lock mechanism encounters the correct digit, the brass tumbler clicks 2 milliseconds faster than when it hits a wrong digit. By listening with a sensitive microphone, the burglar opens the vault in 15 minutes without ever touching the mathematics.\n\nIn real-world cybersecurity, cryptography almost never breaks because someone cracked the math. It breaks because of implementation flaws, side channels, timing leaks, and error oracles.",
  problem:
    "If modern algorithms like AES-256 and SHA-256 are mathematically impregnable, why do cryptographic systems get compromised in production, and how do attackers break security without breaking the cipher?",
  steps: [
    {
      title: "What It Is: The Nature of Cryptanalytic Attacks",
      speaker: "Mallory",
      content:
        "Cryptographic attacks study the practical vulnerabilities in systems that implement cryptography. Attackers exploit boundaries in algorithm design (collision bounds), implementation behaviors (execution time, cache lines, power consumption), and protocol error feedback (oracles) to extract secrets or bypass defenses.",
      callout: {
        type: "info",
        text: "Mathematician Adi Shamir famously noted: 'Cryptography is typically bypassed, not penetrated.' Real breaches target software flaws, not mathematical theorems.",
      },
    },
    {
      title: "What It Does: The Common Attack Vectors",
      speaker: "Eve",
      content:
        "Attackers exploit three primary categories of implementation weaknesses:\n\n* **Timing Attacks (Side Channels):** If a string comparison exits early on the first non-matching byte (`if (a[i] !== b[i]) return false`), measuring the response time in nanoseconds reveals the secret token byte-by-byte.\n* **Error Oracles:** Padding oracle attacks (like POODLE and Lucky Thirteen) take advantage of systems that return different errors for invalid padding vs invalid MACs, allowing an attacker to decrypt ciphertext block-by-block without the key.\n* **Birthday Paradox Collisions:** Exploiting the mathematical probability that finding *any two inputs* that produce the same digest requires only 2^(n/2) work, which broke MD5 and SHA-1.",
      callout: {
        type: "info",
        text: "Side channels include timing differences, CPU cache hits/misses (Spectre/Meltdown variants), acoustic sound from capacitors, and electromagnetic power analysis on smart cards.",
      },
    },
    {
      title: "What It Can Do: Defensive Engineering Principles",
      speaker: "Bob",
      content:
        "Understanding attacks enables defensive security engineers to build hardened systems:\n\n* **Enforce Constant-Time Operations:** Use `crypto.timingSafeEqual()` or constant-time comparison primitives so comparisons take the exact same number of clock cycles regardless of where differences occur.\n* **Adopt AEAD Ciphers:** Authenticated encryption (AES-GCM) eliminates padding oracles by verifying authentication tags *before* attempting decryption.\n* **Deprecate Weak Primitives:** Proactively retire MD5, SHA-1, RC4, and Single-DES to stay ahead of collision and brute-force advances.",
      callout: {
        type: "security",
        text: "Constant-time programming requires avoiding secret-dependent branches (`if (secret_bit)`) and secret-dependent memory lookup indices (`table[secret_byte]`).",
      },
    },
    {
      title: "What It Does NOT Do: Critical Security Boundaries",
      speaker: "Alice",
      content:
        "Defensive engineering and attack countermeasures have clear boundaries:\n\n* **Defensive coding cannot salvage a mathematically broken primitive:** Writing constant-time code for MD5 or single-DES will not stop attackers from generating collisions or brute-forcing 56-bit keys.\n* **Cryptography cannot protect against Compromised Hosts:** If malware, a keylogger, or a memory scraper has root access on the host, keys can be read directly out of RAM before cryptographic routines even run.\n* **Does NOT replace Secure Software Development:** Buffer overflows, injection flaws, and logic bugs in business code completely bypass cryptographic mechanisms.",
      callout: {
        type: "warning",
        text: "Always remember Ken Thompson's lesson: if the underlying runtime or hardware cannot be trusted, no mathematical algorithm running on top of it can be trusted.",
      },
    },
  ],
  takeaways: [
    "Cryptography usually fails in code implementations and protocol flows, not in the math.",
    "String comparisons on hashes, MACs, and tokens must always be constant-time to stop timing leaks.",
    "Padding oracle attacks decrypt ciphertext by exploiting distinct server error messages; AEAD prevents this entirely.",
    "Good cryptographic engineering requires defending across math, implementation, protocol, and host security.",
  ],
  seed: {
    toolId: "sha256",
    sampleInput: "crypto.timingSafeEqual(hashA, hashB)",
    explanation:
      "Open SHA-256 in Cipher Workbench to inspect why identical digest lengths enable strict constant-time byte comparisons.",
  },
};

export default content;
