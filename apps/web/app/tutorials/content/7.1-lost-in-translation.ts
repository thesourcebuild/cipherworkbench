import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Morse code translates letters into dots and dashes — it is not secret, it is just a different representation. Anyone with a Morse chart can decode it instantly. Base64 is the digital equivalent: a publicly documented, keyless reversible transformation that any computer on the planet can undo in microseconds. Calling it 'encryption' is like whispering in Morse code and thinking nobody can hear you.",
  problem:
    "Encoding and encryption are completely different things — but are confused constantly in production systems. A JWT with a Base64 payload, a 'hex-encoded' password in a config file, and a URL-encoded string are all readable to anyone. Why does this mistake keep happening, and what is the actual difference?",
  steps: [
    {
      title: "Step 1: What Encoding Is",
      speaker: "Alice",
      content:
        "**Encoding** transforms data from one representation to another for a specific technical purpose — transmission, storage, or interoperability. It requires **no key** and provides **no secrecy**.\n\nCommon encodings and their purpose:\n- **Base64:** Encodes binary data as ASCII text. Used when binary cannot be transmitted (email, JWT, data URIs). *Anyone can decode it.*\n- **Hex:** Represents bytes as two-digit hexadecimal numbers. Human-readable byte dumps. *Anyone can decode it.*\n- **URL encoding:** Replaces special characters with `%XX` sequences for safe URL transport. *Anyone can decode it.*\n- **UTF-8:** Encodes Unicode characters as byte sequences. *Anyone can decode it.*",
    },
    {
      title: "Step 2: The Catastrophic Mistake",
      speaker: "Mallory",
      content:
        "Bob's config file contains:\n\n`password: dXNlcjpwYXNzd29yZDEyMw==`\n\nBob's colleague told him 'the password is Base64 encoded for security.' Bob believes the password is protected.\n\nMallory finds the config file in a leaked GitHub commit. She decodes it in her browser console:\n\n`atob('dXNlcjpwYXNzd29yZDEyMw==')` → `user:password123`\n\n**Total attack time: 2 seconds.** Base64 provided zero security.",
      callout: {
        type: "warning",
        text: "This exact mistake has caused real breaches. MongoDB's default configuration shipped with 'admin:password' in Base64 in documentation examples. Slack, Uber, and Twitch have all had incidents where Base64-'obfuscated' secrets were exposed in source code.",
      },
    },
    {
      title: "Step 3: What Encryption Actually Is",
      speaker: "Alice",
      content:
        "**Encryption** transforms data using a **secret key** such that the output is unreadable to anyone without that key. The same input produces different output for different keys, and reversal requires the key.\n\n- AES-256-GCM: `Encrypt(key, plaintext, nonce)` → unreadable ciphertext\n- Without the key: computationally infeasible to reverse (2²⁵⁶ brute-force)\n- With the key: instant decryption\n\n**Encryption ≠ Encoding.** Encryption requires a key. Encoding never does.",
    },
    {
      title: "Step 4: JWTs — The Most Confused Encoding",
      speaker: "Eve",
      content:
        "A **JSON Web Token (JWT)** has three parts separated by dots:\n\n`header.payload.signature`\n\nThe header and payload are Base64URL-encoded JSON — **completely readable by anyone**. The signature is a cryptographic HMAC or RSA signature that proves the token was *issued by a trusted party*.\n\nA JWT provides **Authenticity** (the signature proves who issued it) and **Integrity** (the signature detects tampering). It provides **zero Confidentiality** — the payload is public.\n\nNever put sensitive data (passwords, SSNs, PII) in a JWT payload without separately encrypting it first (JWE).",
      callout: {
        type: "warning",
        text: "Paste any JWT into jwt.io — you will see the full plaintext payload instantly. If your JWT contains a user role like `'admin': true`, Mallory can read it. The signature prevents her from *changing* it, but not from *reading* it.",
      },
    },
    {
      title: "Step 5: When to Use Each",
      speaker: "Bob",
      content:
        "| Goal | Tool | Provides |\n|---|---|---|\n| Transport binary as text | Base64 | Compatibility only |\n| Hide content from everyone | AES-GCM encryption | Confidentiality |\n| Prove who sent a message | HMAC / Ed25519 | Authenticity |\n| Store a password | Argon2id | One-way hardness |\n| Compress data | Gzip / Brotli | Size reduction |\n\n**Rule:** If you need a key, it is cryptography. If you do not need a key, it is encoding.",
      callout: {
        type: "security",
        text: "Security through obscurity — hiding secrets by making them 'hard to read' (Base64, ROT13, hex) without a key — is not a security measure. It is a speed bump that delays a competent attacker by seconds.",
      },
    },
  ],
  takeaways: [
    "Encoding (Base64, Hex, URL) is keyless and reversible by anyone — it provides zero security.",
    "Encryption requires a secret key — without it, reversal is computationally infeasible.",
    "JWT payloads are Base64-encoded, not encrypted — never store sensitive data in them without JWE.",
    "Security through obscurity (hiding data in non-standard formats) is not a security mechanism.",
    "If it does not require a key, it is not encryption.",
  ],
  seed: {
    toolId: "aes",
    sampleInput: "user:password123",
    explanation:
      "Open AES Workbench and encrypt this string — compare the result to simply Base64-encoding the same string in your browser console with btoa('user:password123'). One requires a key to reverse; the other does not.",
  },
};

export default content;
