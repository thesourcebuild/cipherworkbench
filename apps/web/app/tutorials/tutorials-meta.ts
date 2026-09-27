import type { TutorialCharacter, TutorialConceptMeta, TutorialMeta } from "./tutorial-types";

export const CHARACTERS: Record<string, TutorialCharacter> = {
  "Alice": {
    "name": "Alice",
    "role": "Sender / Initiator",
    "avatar": "👩‍💻",
    "color": "border-sky-300 bg-sky-50 text-sky-800 dark:border-sky-800 dark:bg-sky-950/60 dark:text-sky-300"
  },
  "Bob": {
    "name": "Bob",
    "role": "Recipient / Verifier",
    "avatar": "👨‍💻",
    "color": "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300"
  },
  "Eve": {
    "name": "Eve",
    "role": "Passive Eavesdropper",
    "avatar": "🕵️‍♀️",
    "color": "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-300"
  },
  "Mallory": {
    "name": "Mallory",
    "role": "Active Malicious Attacker",
    "avatar": "🦹",
    "color": "border-rose-300 bg-rose-50 text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-300"
  },
  "Trent": {
    "name": "Trent",
    "role": "Trusted Authority / Notary",
    "avatar": "🏛️",
    "color": "border-indigo-300 bg-indigo-50 text-indigo-800 dark:border-indigo-800 dark:bg-indigo-950/60 dark:text-indigo-300"
  }
};

export const TUTORIAL_CONCEPTS_META: readonly TutorialConceptMeta[] = [
  {
    "id": "integrity",
    "title": "1. Data Integrity: Accidental Noise vs Tampering",
    "description": "Detecting accidental typos, transmission line static, and malicious alterations.",
    "badge": "Integrity",
    "tutorials": [
      {
        "id": "1.1-the-scratched-postcard",
        "number": "1.1",
        "title": "The Scratched Postcard: Checksums & Check Digits",
        "subtitle": "How Bob catches single-digit typos and swapped digits with the Luhn algorithm",
        "conceptId": "integrity",
        "family": "checksum",
        "toolId": "luhn",
        "difficulty": "Beginner",
        "readTime": "4 min",
        "characters": [
          "Alice",
          "Bob"
        ],
        "summary": "Alice writes a credit card or bank account number on a postcard. If a clerk mistypes one digit or accidentally swaps two adjacent numbers, Bob catches the error immediately using a check digit."
      },
      {
        "id": "1.2-the-static-on-the-wire",
        "number": "1.2",
        "title": "The Static on the Wire: Cyclic Redundancy Checks (CRC)",
        "subtitle": "How Ethernet, ZIP files, and hard drives detect bursts of electrical noise",
        "conceptId": "integrity",
        "family": "crc",
        "toolId": "crc32",
        "difficulty": "Beginner",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob"
        ],
        "summary": "Lightning strikes near a transmission cable, flipping 5 consecutive bits in an Ethernet frame. A simple sum checksum completely misses the burst, but CRC-32 polynomial division catches it with 99.999% mathematical certainty."
      },
      {
        "id": "1.3-the-digital-fingerprint",
        "number": "1.3",
        "title": "The Digital Fingerprint: Cryptographic Hashes",
        "subtitle": "Why CRC fails against attackers, and how SHA-256's avalanche effect stops Mallory",
        "conceptId": "integrity",
        "family": "hash",
        "toolId": "sha256",
        "difficulty": "Beginner",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Mallory"
        ],
        "summary": "Alice publishes software and posts its official SHA-256 fingerprint on her verified website. Bob downloads the installer from an untrusted mirror where Mallory injected malware. Because Mallory cannot force her malware to match Alice's pre-published SHA-256 hash, Bob immediately catches the tampering."
      }
    ]
  },
  {
    "id": "authenticity",
    "title": "2. Authenticity: Proving Who Sent the Message",
    "description": "Why hashes alone lack identity, and how HMAC uses shared secrets to prove authorship.",
    "badge": "Authenticity",
    "tutorials": [
      {
        "id": "2.1-the-tampered-hash-trap",
        "number": "2.1",
        "title": "The Tampered Hash Trap: Why Hashes Lack Identity",
        "subtitle": "What happens when Mallory intercepts both the message AND the hash?",
        "conceptId": "authenticity",
        "family": "hash",
        "toolId": "sha256",
        "difficulty": "Beginner",
        "readTime": "4 min",
        "characters": [
          "Alice",
          "Bob",
          "Mallory"
        ],
        "summary": "Alice writes a note and attaches its SHA-256 hash. Mallory intercepts the transmission, alters the note to 'Send $5,000 to Mallory', calculates a brand-new SHA-256 hash over her fake note, and gives both to Bob. Bob checks the hash against the note — it matches! Bob is fooled because a hash has no secret key."
      },
      {
        "id": "2.2-the-secret-handshake",
        "number": "2.2",
        "title": "The Secret Handshake: Message Authentication Codes (HMAC)",
        "subtitle": "Combining a shared secret with a hash so Bob can verify Alice's authorship",
        "conceptId": "authenticity",
        "family": "mac",
        "toolId": "hmac",
        "difficulty": "Intermediate",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve",
          "Mallory"
        ],
        "summary": "Alice and Bob agree on a secret password beforehand. When Alice sends an instruction, she combines the text with their secret key using HMAC. When Mallory intercepts the text, she cannot recalculate the HMAC because she does not know the secret key! But beware: Eve can still read the message in plaintext."
      }
    ]
  },
  {
    "id": "symmetric-ciphers",
    "title": "3. Confidentiality: Symmetric Encryption (1 Key)",
    "description": "Locking messages away from Eve, avoiding the nonce trap, and modern AEAD.",
    "badge": "Symmetric",
    "tutorials": [
      {
        "id": "3.1-the-locked-steel-box",
        "number": "3.1",
        "title": "The Locked Steel Box: Symmetric Encryption (AES-256)",
        "subtitle": "Hiding the contents with a single shared 256-bit key",
        "conceptId": "symmetric-ciphers",
        "family": "cipher",
        "toolId": "aes",
        "difficulty": "Beginner",
        "readTime": "4 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve",
          "Mallory"
        ],
        "summary": "Integrity and authenticity tell us who sent a message and if it changed, but what if we want to keep the contents secret? Alice puts her letter in a steel box, locks it with a 256-bit key, and sends it. Eve can only see unreadable scrambled noise."
      },
      {
        "id": "3.2-the-reused-key-catastrophe",
        "number": "3.2",
        "title": "The Reused Key Catastrophe: Never Reuse a Nonce",
        "subtitle": "How encrypting two messages with the same IV strips the key and exposes both",
        "conceptId": "symmetric-ciphers",
        "family": "cipher",
        "toolId": "aes",
        "difficulty": "Intermediate",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve"
        ],
        "summary": "A Nonce means 'Number used ONCE'. Alice lazily encrypts two different letters using the same key and the same IV. Eve captures both and uses simple XOR math to completely cancel out the key and read both messages!"
      },
      {
        "id": "3.3-the-perfect-fusion-aead",
        "number": "3.3",
        "title": "The Perfect Fusion: Authenticated Encryption (AEAD)",
        "subtitle": "Why modern protocols combine secrecy and authenticity in AES-GCM",
        "conceptId": "symmetric-ciphers",
        "family": "cipher",
        "toolId": "aes",
        "difficulty": "Intermediate",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve",
          "Mallory"
        ],
        "summary": "In the early days of cryptography, developers encrypted with CBC mode and hoped for the best. Mallory exploited padding oracles and bit-flipping attacks to forge commands. Modern cryptography solved this with AEAD: encrypting AND authenticating in one unified mathematical pass."
      }
    ]
  },
  {
    "id": "asymmetric-keys",
    "title": "4. Asymmetric Cryptography: Solving Key Delivery (2 Keys)",
    "description": "Diffie-Hellman key exchange, public-key encryption, and digital signatures.",
    "badge": "Asymmetric",
    "tutorials": [
      {
        "id": "4.1-the-paint-mixing-trick",
        "number": "4.1",
        "title": "The Paint Mixing Trick: Diffie-Hellman (ECDH)",
        "subtitle": "How Alice and Bob agree on a secret key in public without Eve ever learning it",
        "conceptId": "asymmetric-keys",
        "family": "asymmetric",
        "toolId": "ecdh",
        "difficulty": "Intermediate",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve",
          "Mallory"
        ],
        "summary": "Symmetric encryption is fast and secure, but how do Alice and Bob agree on that secret key if they have never met in person? In 1976, Whitfield Diffie and Martin Hellman discovered a mathematical miracle: agreeing on a secret color in broad daylight!"
      },
      {
        "id": "4.2-the-open-padlock",
        "number": "4.2",
        "title": "The Open Padlock: Public-Key Encryption (RSA)",
        "subtitle": "Bob leaves open padlocks for anyone to lock; only Bob's private key can open them",
        "conceptId": "asymmetric-keys",
        "family": "asymmetric",
        "toolId": "rsa",
        "difficulty": "Beginner",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve",
          "Mallory"
        ],
        "summary": "What if Alice wants to send a private message to Bob without coordinating a two-way Diffie-Hellman handshake first? Bob distributes open padlocks (Public Keys). Alice snaps one shut over her parcel. Once locked, only Bob's private pocket key can decrypt it."
      },
      {
        "id": "4.3-the-royal-signet-ring",
        "number": "4.3",
        "title": "The Royal Signet Ring: Digital Signatures (Ed25519)",
        "subtitle": "Signing with a private key so anyone with your public key can verify authenticity",
        "conceptId": "asymmetric-keys",
        "family": "asymmetric",
        "toolId": "ed25519",
        "difficulty": "Intermediate",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve",
          "Mallory"
        ],
        "summary": "The mathematical reverse of public-key encryption! Alice wants to issue an official decree. Anyone in the world should be able to read it, but Bob needs proof that Alice really wrote it and that Mallory didn't forge Alice's name. Alice signs with her Private Key."
      }
    ]
  },
  {
    "id": "putting-it-together",
    "title": "5. Putting It All Together: The Real-World Symphony",
    "description": "TLS 1.3, Certificate Authorities, password vaults, threshold cryptography, and Post-Quantum.",
    "badge": "Systems",
    "tutorials": [
      {
        "id": "5.1-the-complete-tls-handshake",
        "number": "5.1",
        "title": "The TLS 1.3 Handshake: The Full Symphony",
        "subtitle": "How ECDH, Digital Signatures, and AES-GCM combine to secure web browsers",
        "conceptId": "putting-it-together",
        "family": "asymmetric",
        "toolId": "ecdh",
        "difficulty": "Intermediate",
        "readTime": "6 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve",
          "Mallory"
        ],
        "summary": "When you type https:// into your browser, all four previous concepts execute in under 50 milliseconds! Alice (the browser) and Bob (the web server) use ECDH to agree on a session key, verify Bob's identity with Digital Signatures, and switch to AES-GCM for all webpage data."
      },
      {
        "id": "5.2-the-imposter-in-the-middle",
        "number": "5.2",
        "title": "The Imposter in the Middle: Trent & Certificates",
        "subtitle": "Why public keys alone are vulnerable, and how Certificate Authorities solve trust",
        "conceptId": "putting-it-together",
        "family": "certificates",
        "toolId": "cert-creator",
        "difficulty": "Intermediate",
        "readTime": "6 min",
        "characters": [
          "Alice",
          "Bob",
          "Mallory",
          "Trent"
        ],
        "summary": "Mallory intercepts Bob's public key and replaces it with her own! Alice encrypts for Mallory without realizing. Enter Trent (The Certificate Authority) to notarize Bob's identity with an X.509 digital certificate."
      },
      {
        "id": "5.3-the-password-vault",
        "number": "5.3",
        "title": "The Password Vault: Memory-Hard Argon2id",
        "subtitle": "Why Bob never stores plain passwords, and how salts and memory-hardness defeat GPU farms",
        "conceptId": "putting-it-together",
        "family": "kdf",
        "toolId": "argon2",
        "difficulty": "Intermediate",
        "readTime": "5 min",
        "characters": [
          "Alice",
          "Bob",
          "Mallory"
        ],
        "summary": "Alice creates an account on Bob's website. Mallory breaches Bob's server! Bob never stored Alice's password: he stored a salted, memory-hard Argon2id hash that makes cracking each password take millions of times longer, protecting Alice even after a data leak."
      },
      {
        "id": "5.4-the-pirate-treasure-chest",
        "number": "5.4",
        "title": "The Pirate Treasure Chest: Shamir's Secret Sharing",
        "subtitle": "Splitting a master key so any 3 of 5 lieutenants can unlock the vault",
        "conceptId": "putting-it-together",
        "family": "asymmetric",
        "toolId": "shamir",
        "difficulty": "Advanced",
        "readTime": "6 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve"
        ],
        "summary": "Alice has the master encryption key to a company vault. If one person holds it, it can be lost or stolen. Alice splits the key into 5 pieces such that ANY 3 pieces can reconstruct it, but ANY 2 pieces reveal zero information."
      },
      {
        "id": "5.5-the-quantum-spy",
        "number": "5.5",
        "title": "The Quantum Spy: Post-Quantum ML-KEM",
        "subtitle": "Defeating Shor's algorithm and 'Store Now, Decrypt Later' attacks with lattice crystals",
        "conceptId": "putting-it-together",
        "family": "asymmetric",
        "toolId": "ml-kem",
        "difficulty": "Intermediate",
        "readTime": "6 min",
        "characters": [
          "Alice",
          "Bob",
          "Eve"
        ],
        "summary": "Eve is recording all of Alice and Bob's encrypted internet traffic today, planning to decrypt it in 10 years when quantum computers arrive ('Store Now, Decrypt Later'). Alice and Bob switch to NIST FIPS 203 (ML-KEM) to future-proof their security."
      }
    ]
  }
];

export const ALL_TUTORIALS_META: readonly TutorialMeta[] = TUTORIAL_CONCEPTS_META.flatMap((c) => c.tutorials);

export const TOTAL_TUTORIALS_COUNT = ALL_TUTORIALS_META.length;

export function getTutorialMeta(id: string): TutorialMeta | undefined {
  return ALL_TUTORIALS_META.find((t) => t.id === id);
}
