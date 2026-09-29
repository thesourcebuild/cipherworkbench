import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "A bank vault's combination is mathematically secure. But if Mallory watches the safe-cracker's hands through a telescope and times how long each dial click takes, she can deduce the combination without touching the lock. The mathematical security is irrelevant — the *physical implementation* leaked the secret.",
  problem:
    "Cryptographic algorithms are proven secure on paper. But the physical implementation — timing, power consumption, electromagnetic emissions, even sound — can leak secrets to an observer who never needs to break the math.",
  steps: [
    {
      title: "Step 1: Timing Attacks — The Most Common Side-Channel",
      speaker: "Mallory",
      content:
        "Bob's login server checks Alice's password byte-by-byte, returning an error as soon as it finds a mismatch:\n\n```\nif password[0] != stored[0]: return WRONG  // exits at byte 1\nif password[1] != stored[1]: return WRONG  // exits at byte 2\n...\n```\n\nMallory sends thousands of password guesses and measures the response time. A guess that takes **slightly longer** to reject means more bytes matched before the mismatch. Mallory recovers the password one byte at a time — without brute-forcing the full space.",
      callout: {
        type: "warning",
        text: "This is called an Early-Exit Timing Attack. It applies to HMAC verification, password comparison, RSA decryption, and AES key scheduling. The fix is trivial but routinely missed.",
      },
    },
    {
      title: "Step 2: The Fix — Constant-Time Comparison",
      speaker: "Bob",
      content:
        "A **constant-time comparison** always takes the same amount of time regardless of where the mismatch occurs:\n\n```\nresult = 0\nfor i in range(len(a)):\n    result |= a[i] ^ b[i]  // XOR: 0 if equal, non-zero if different\nreturn result == 0  // never exit early\n```\n\nEvery byte is always compared. The time taken is always `n` iterations. Mallory's timing measurements reveal nothing.\n\nIn Node.js: `crypto.timingSafeEqual(a, b)`. In Python: `hmac.compare_digest(a, b)`.",
      callout: {
        type: "security",
        text: "Every HMAC verification, password hash comparison, and token validation **must** use constant-time comparison. A regular `===` or `strcmp` is exploitable.",
      },
    },
    {
      title: "Step 3: Power Analysis Attacks",
      speaker: "Mallory",
      content:
        "Mallory attaches a current probe to a smart card processing an AES encryption. The power consumption varies based on the bits being processed — high bits cause more transistor switching than low bits.\n\n**Simple Power Analysis (SPA):** A single power trace reveals key bits directly.\n**Differential Power Analysis (DPA):** Statistical analysis over thousands of encryptions recovers the full key even with noise.\n\nThis is not theoretical — DPA attacks have recovered keys from bank cards, passports, and HSMs in laboratory conditions.",
    },
    {
      title: "Step 4: Cache Timing Attacks (Flush+Reload, Spectre)",
      speaker: "Eve",
      content:
        "Modern CPUs cache frequently accessed memory. Software AES implementations often use lookup tables (T-tables and S-boxes) stored in memory. If the table access pattern depends on key bits, cache timing reveals those bits.\n\n**Flush+Reload:** Eve flushes a cache line, waits for Bob to encrypt, then measures how fast she can reload it. If it's fast, Bob accessed that cache line — revealing which table entries he looked up — revealing key bits.\n\nCache timing measurement techniques like Flush+Reload also serve as the covert readout channel in speculative execution vulnerabilities like **Spectre** (2018).",
      callout: {
        type: "warning",
        text: "Modern AES-NI CPU instructions avoid this entirely by computing AES in dedicated hardware registers with no memory lookups. Always use hardware AES acceleration when available.",
      },
    },
    {
      title: "Step 5: The Rubber Hose Attack",
      speaker: "Mallory",
      content:
        "The most effective side-channel of all: Mallory kidnaps Alice and applies physical pressure until Alice reveals the key.\n\n**Countermeasure:** Plausible deniability encryption (VeraCrypt hidden volumes, Duress passwords) and key escrow with multi-party authorisation.\n\nCryptographers joke: 'No encryption algorithm survives a rubber hose attack.' The point is that operational security and threat modelling are as important as algorithm choice.",
    },
  ],
  takeaways: [
    "Side-channel attacks exploit the *physical implementation*, not the mathematical algorithm.",
    "Timing attacks: always use constant-time comparison for secrets (`crypto.timingSafeEqual`).",
    "Power analysis: use hardware AES-NI and constant-weight algorithms on embedded systems.",
    "Cache timing attacks: use hardware AES acceleration (AES-NI) to avoid software S-box table lookups.",
    "Perfect cryptography cannot protect against physical coercion — operational security matters.",
  ],
  seed: {
    toolId: "hmac",
    sampleInput: "password-candidate-to-verify",
    explanation:
      "Open HMAC Workbench. Observe that HMAC verification must compare the expected and computed tags in constant time — changing one bit should take identical time to reject as changing all bits.",
  },
};

export default content;
