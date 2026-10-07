import type { TutorialCharacter, TutorialConceptMeta, TutorialMeta } from "./tutorial-types";

export const CHARACTERS: Record<string, TutorialCharacter> = {
  Alice: {
    name: "Alice",
    role: "Sender / Initiator",
    avatar: "👩‍💻",
    color:
      "border-sky-300 bg-sky-50 text-sky-800 dark:border-sky-800 dark:bg-sky-950/60 dark:text-sky-300",
  },
  Bob: {
    name: "Bob",
    role: "Recipient / Verifier",
    avatar: "👨‍💻",
    color:
      "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300",
  },
  Eve: {
    name: "Eve",
    role: "Passive Eavesdropper",
    avatar: "🕵️‍♀️",
    color:
      "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-300",
  },
  Mallory: {
    name: "Mallory",
    role: "Active Malicious Attacker",
    avatar: "🦹",
    color:
      "border-rose-300 bg-rose-50 text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-300",
  },
  Trent: {
    name: "Trent",
    role: "Trusted Authority / Notary",
    avatar: "🏛️",
    color:
      "border-indigo-300 bg-indigo-50 text-indigo-800 dark:border-indigo-800 dark:bg-indigo-950/60 dark:text-indigo-300",
  },
};

export const TUTORIAL_CONCEPTS_META: readonly TutorialConceptMeta[] = [
  {
    id: "integrity",
    title: "1. Data Integrity: Accidental Noise vs Tampering",
    description:
      "Detecting accidental typos, transmission line static, and malicious alterations.",
    badge: "Integrity",
    tutorials: [
      {
        id: "1.1-the-scratched-postcard",
        number: "1.1",
        title: "The Scratched Postcard: Checksums & Check Digits",
        subtitle:
          "How additive checksums catch data corruption and Luhn check digits detect swapped digits",
        conceptId: "integrity",
        family: "checkdigit",
        toolId: "luhn",
        difficulty: "Beginner",
        readTime: "4 min",
        characters: ["Alice", "Bob"],
        summary:
          "Alice writes data records and account numbers on a postcard. How do simple additive checksums detect corrupted bytes, why do they fail when adjacent numbers swap, and how do weighted check digits like Luhn catch transpositions?",
      },
      {
        id: "1.2-the-static-on-the-wire",
        number: "1.2",
        title: "The Static on the Wire: Cyclic Redundancy Checks (CRC)",
        subtitle: "How Ethernet, ZIP files, and hard drives detect bursts of electrical noise",
        conceptId: "integrity",
        family: "crc",
        toolId: "crc32",
        difficulty: "Beginner",
        readTime: "5 min",
        characters: ["Alice", "Bob"],
        summary:
          "Lightning strikes near a transmission cable, flipping 5 consecutive bits in an Ethernet frame. A simple sum checksum completely misses the burst, but CRC-32 polynomial division catches it with 100% mathematical certainty (guaranteed for any burst up to 32 bits).",
      },
      {
        id: "1.3-the-digital-fingerprint",
        number: "1.3",
        title: "The Digital Fingerprint: Cryptographic Hashes",
        subtitle:
          "Why CRC fails against attackers, and how SHA-256's avalanche effect stops Mallory",
        conceptId: "integrity",
        family: "hash",
        toolId: "sha256",
        difficulty: "Beginner",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Alice publishes software and posts its official SHA-256 fingerprint on her verified website. Bob downloads the installer from an untrusted mirror where Mallory injected malware. Because Mallory cannot force her malware to match Alice's pre-published SHA-256 hash, Bob immediately catches the tampering.",
      },
    ],
  },
  {
    id: "authenticity",
    title: "2. Authenticity: Proving Who Sent the Message",
    description:
      "Why hashes alone lack identity, and how HMAC uses shared secrets to prove authorship.",
    badge: "Authenticity",
    tutorials: [
      {
        id: "2.1-the-tampered-hash-trap",
        number: "2.1",
        title: "The Tampered Hash Trap: Why Hashes Lack Identity",
        subtitle: "What happens when Mallory intercepts both the message AND the hash?",
        conceptId: "authenticity",
        family: "hash",
        toolId: "sha256",
        difficulty: "Beginner",
        readTime: "4 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Alice writes a note and attaches its SHA-256 hash. Mallory intercepts the transmission, alters the note to 'Send $5,000 to Mallory', calculates a brand-new SHA-256 hash over her fake note, and gives both to Bob. Bob checks the hash against the note — it matches! Bob is fooled because a hash has no secret key.",
      },
      {
        id: "2.2-the-secret-handshake",
        number: "2.2",
        title: "The Secret Handshake: Message Authentication Codes (HMAC)",
        subtitle: "Combining a shared secret with a hash so Bob can verify Alice's authorship",
        conceptId: "authenticity",
        family: "mac",
        toolId: "hmac",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Alice and Bob agree on a secret password beforehand. When Alice sends an instruction, she combines the text with their secret key using HMAC. When Mallory intercepts the text, she cannot recalculate the HMAC because she does not know the secret key! But beware: Eve can still read the message in plaintext.",
      },
      {
        id: "2.3-the-forged-timestamp",
        number: "2.3",
        title: "The Forged Timestamp: Replay Attacks",
        subtitle: "How Mallory reuses a valid signed message without breaking any cryptography",
        conceptId: "authenticity",
        family: "mac",
        toolId: "hmac",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Alice's API request is HMAC-signed and perfectly authenticated. Mallory captures it and submits it 99 more times. The HMAC passes every time — because Alice really did sign it. The primitives are fine; the protocol design is broken. How timestamps and nonces stop this.",
      },
    ],
  },
  {
    id: "symmetric-ciphers",
    title: "3. Confidentiality: Symmetric Encryption (1 Key)",
    description: "Locking messages away from Eve, avoiding the nonce trap, and modern AEAD.",
    badge: "Symmetric",
    tutorials: [
      {
        id: "3.1-the-locked-steel-box",
        number: "3.1",
        title: "The Locked Steel Box: Symmetric Encryption (AES-256)",
        subtitle: "Hiding the contents with a single shared 256-bit key",
        conceptId: "symmetric-ciphers",
        family: "cipher",
        toolId: "aes",
        difficulty: "Beginner",
        readTime: "4 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Integrity and authenticity tell us who sent a message and if it changed, but what if we want to keep the contents secret? Alice puts her letter in a steel box, locks it with a 256-bit key, and sends it. Eve can only see unreadable scrambled noise.",
      },
      {
        id: "3.2-the-reused-key-catastrophe",
        number: "3.2",
        title: "The Reused Key Catastrophe: Never Reuse a Nonce",
        subtitle:
          "How encrypting two messages with the same IV strips the key and exposes both",
        conceptId: "symmetric-ciphers",
        family: "cipher",
        toolId: "aes",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "A Nonce means 'Number used ONCE'. Alice lazily encrypts two different letters using the same key and the same IV. Eve captures both and uses simple XOR math to completely cancel out the key and read both messages!",
      },
      {
        id: "3.3-the-perfect-fusion-aead",
        number: "3.3",
        title: "The Perfect Fusion: Authenticated Encryption (AEAD)",
        subtitle: "Why modern protocols combine secrecy and authenticity in AES-GCM",
        conceptId: "symmetric-ciphers",
        family: "cipher",
        toolId: "aes",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "In the early days of cryptography, developers encrypted with CBC mode and hoped for the best. Mallory exploited padding oracles and bit-flipping attacks to forge commands. Modern cryptography solved this with AEAD: encrypting AND authenticating in one unified mathematical pass.",
      },
      {
        id: "3.4-the-ecb-penguin",
        number: "3.4",
        title: "The ECB Penguin: Block Cipher Modes",
        subtitle: "Why AES-ECB reveals patterns, and how CBC, CTR, and GCM fix it",
        conceptId: "symmetric-ciphers",
        family: "cipher",
        toolId: "aes",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "AES is secure. But encrypting a penguin image with AES-ECB still shows the penguin outline — identical plaintext blocks produce identical ciphertext. The mode of operation is as critical as the cipher itself. A guided comparison of ECB, CBC, CTR, and GCM.",
      },
    ],
  },
  {
    id: "asymmetric-keys",
    title: "4. Asymmetric Cryptography: Solving Key Delivery (2 Keys)",
    description: "Diffie-Hellman key exchange, public-key encryption, and digital signatures.",
    badge: "Asymmetric",
    tutorials: [
      {
        id: "4.1-the-paint-mixing-trick",
        number: "4.1",
        title: "The Paint Mixing Trick: Diffie-Hellman (ECDH)",
        subtitle:
          "How Alice and Bob agree on a secret key in public without Eve ever learning it",
        conceptId: "asymmetric-keys",
        family: "asymmetric",
        toolId: "ecdh",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Symmetric encryption is fast and secure, but how do Alice and Bob agree on that secret key if they have never met in person? In 1976, Whitfield Diffie and Martin Hellman discovered a mathematical miracle: agreeing on a secret color in broad daylight!",
      },
      {
        id: "4.2-the-open-padlock",
        number: "4.2",
        title: "The Open Padlock: Public-Key Encryption (RSA)",
        subtitle:
          "Bob leaves open padlocks for anyone to lock; only Bob's private key can open them",
        conceptId: "asymmetric-keys",
        family: "asymmetric",
        toolId: "rsa",
        difficulty: "Beginner",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "What if Alice wants to send a private message to Bob without coordinating a two-way Diffie-Hellman handshake first? Bob distributes open padlocks (Public Keys). Alice snaps one shut over her parcel. Once locked, only Bob's private pocket key can decrypt it.",
      },
      {
        id: "4.3-the-royal-signet-ring",
        number: "4.3",
        title: "The Royal Signet Ring: Digital Signatures (Ed25519)",
        subtitle:
          "Signing with a private key so anyone with your public key can verify authenticity",
        conceptId: "asymmetric-keys",
        family: "asymmetric",
        toolId: "ed25519",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "The mathematical reverse of public-key encryption! Alice wants to issue an official decree. Anyone in the world should be able to read it, but Bob needs proof that Alice really wrote it and that Mallory didn't forge Alice's name. Alice signs with her Private Key.",
      },
      {
        id: "4.4-the-wax-seal-envelope",
        number: "4.4",
        title: "The Wax Seal Envelope: Hybrid Encryption",
        subtitle: "How PGP, S/MIME, and TLS combine RSA and AES into one fast secure system",
        conceptId: "asymmetric-keys",
        family: "asymmetric",
        toolId: "rsa",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "RSA is mathematically secure but 1000× slower than AES for large data. The elegant solution: encrypt the 50 MB document with fast AES, then encrypt only the 32-byte AES key with RSA. PGP, S/MIME, and legacy TLS all use this exact two-step pattern.",
      },
      {
        id: "4.5-the-magic-curve",
        number: "4.5",
        title: "The Magic Curve: Elliptic Curve Cryptography",
        subtitle:
          "Why a 256-bit EC key beats a 3072-bit RSA key, and what X25519 and P-256 mean",
        conceptId: "asymmetric-keys",
        family: "asymmetric",
        toolId: "ecdh",
        difficulty: "Advanced",
        readTime: "6 min",
        characters: ["Alice", "Bob"],
        summary:
          "Tutorial 4.1 used ECDH with a 256-bit key. Tutorial 4.2 used RSA with 2048 bits. How can 256-bit EC provide the same security as 3072-bit RSA? The answer lies in the Elliptic Curve Discrete Logarithm Problem — and why X25519 is the preferred modern curve.",
      },
    ],
  },
  {
    id: "certificates",
    title: "5. Certificates & Public Key Infrastructure (PKI)",
    description:
      "Binding identity to public keys: X.509 certificates, trust chains, CSRs, revocation, and automated issuance.",
    badge: "Certificates",
    tutorials: [
      // Existing IDs remain stable because tutorial completion is persisted by ID.
      {
        id: "5.2-the-imposter-in-the-middle",
        number: "5.1",
        title: "The Imposter in the Middle: Digital Certificates",
        subtitle:
          "How X.509 certificate chains bind public keys to identities and stop key-substitution attacks",
        conceptId: "certificates",
        family: "certificates",
        toolId: "cert-creator",
        difficulty: "Intermediate",
        readTime: "7 min",
        characters: ["Alice", "Bob", "Mallory", "Trent"],
        summary:
          "Mallory can replace an unauthenticated public key with her own and silently relay traffic. Follow Bob's key from a certificate signing request through CA issuance, chain validation, hostname checks, and TLS proof of private-key possession.",
      },
      {
        id: "5.2-the-chain-of-trust",
        number: "5.2",
        title: "The Chain of Trust: Roots, Intermediates, and Trust Stores",
        subtitle:
          "Why root CAs sleep in vaults, how intermediate CAs issue leaf certificates, and how clients verify trust paths",
        conceptId: "certificates",
        family: "certificates",
        toolId: "cert-verifier",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Trent"],
        summary:
          "Why don't Root CAs directly sign website certificates? Alice discovers how a hierarchical PKI isolates risk: an offline Root CA delegates day-to-day issuance to Intermediate CAs. Bob traces how his browser uses Authority Key Identifiers (AKI), Subject Key Identifiers (SKI), and local root stores to build and verify a trusted cryptographic path.",
      },
      {
        id: "5.3-asking-for-permission-csr",
        number: "5.3",
        title: "Asking for Permission: Certificate Signing Requests (CSR)",
        subtitle:
          "How PKCS#10 requests prove key ownership and bind domain identities without leaking private keys",
        conceptId: "certificates",
        family: "certificates",
        toolId: "csr-creator",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Bob", "Trent", "Mallory"],
        summary:
          "Bob needs a certificate from CA Trent. Does Bob send his private key? Never! Bob creates a PKCS#10 Certificate Signing Request (CSR) containing only his public key, Subject DN, and requested SANs (Subject Alternative Names), signed with his private key as Proof-of-Possession (PoP). Mallory tries to request a cert for Bob's domain, but fails Trent's domain challenge.",
      },
      {
        id: "5.4-when-trust-breaks-revocation",
        number: "5.4",
        title: "When Trust Breaks: Revocation (CRLs vs OCSP & Stapling)",
        subtitle:
          "What happens when a private key leaks before expiration, why CRLs failed, and how OCSP Stapling preserves privacy",
        conceptId: "certificates",
        family: "certificates",
        toolId: "crl",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve", "Trent"],
        summary:
          "A server hard drive is stolen! Bob's certificate doesn't expire for 9 months, but its private key is compromised. Alice learns why certificates cannot be 'deleted', how Certificate Revocation Lists (CRLs) grew too large and slow, why real-time OCSP queries leaked browsing history to CAs, and how modern TLS solves both with OCSP Stapling.",
      },
      {
        id: "5.5-automated-trust-acme",
        number: "5.5",
        title: "Automating the Web: ACME & Certificate Transparency",
        subtitle:
          "How Let's Encrypt automated HTTPS via HTTP-01/DNS-01 challenges and how CT logs expose rogue CAs",
        conceptId: "certificates",
        family: "certificates",
        toolId: "acme",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Trent"],
        summary:
          "Web certificates used to cost hundreds of dollars and require manual paperwork every year. RFC 8555 (ACME) transformed the web by automating domain validation through HTTP-01 and DNS-01 challenges. Meanwhile, Certificate Transparency (CT) append-only Merkle tree logs ensure that no CA on Earth can issue a secret cert behind a domain owner's back.",
      },
      {
        id: "6.4-the-key-ceremony",
        number: "5.6",
        title: "The Key Ceremony: HSMs & Root of Trust",
        subtitle:
          "Air-gapped rooms, Shamir activation, and Certificate Transparency — protecting the keys that secure the internet",
        conceptId: "certificates",
        family: "certificates",
        toolId: "cert-creator",
        difficulty: "Advanced",
        readTime: "7 min",
        characters: ["Alice", "Bob", "Mallory", "Trent"],
        summary:
          "Root CA private keys secure every HTTPS connection on earth. If Mallory steals one, she can forge certificates for any website. This is how the internet protects them: Hardware Security Modules, air-gapped ceremonies, M-of-N Shamir activation, and Certificate Transparency logs.",
      },
    ],
  },
  {
    id: "putting-it-together",
    title: "6. Secure Transport & Protocols: The Real-World Symphony",
    description:
      "SSL 3.0, TLS, DTLS, password vaults, threshold cryptography, and Post-Quantum.",
    badge: "Protocols",
    tutorials: [
      {
        id: "5.1-ssl-3.0-handshake",
        number: "6.1",
        title: "SSL 3.0: The Handshake Before TLS",
        subtitle:
          "How the 1996 protocol negotiated RSA, RC4 or CBC, MACs, and resumable sessions",
        conceptId: "putting-it-together",
        family: "asymmetric",
        toolId: "rsa",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Trace the historical SSL 3.0 handshake from plaintext negotiation through RSA key transport, ChangeCipherSpec, Finished, and protected HTTP, then see why obsolete ciphers, brittle CBC records, and POODLE forced the protocol into retirement.",
      },
      {
        id: "5.1-the-complete-tls-handshake",
        number: "6.2",
        title: "The TLS Handshake: The Full Symphony",
        subtitle: "Compare the same HTTPS handshake across three protocol generations",
        conceptId: "putting-it-together",
        family: "asymmetric",
        toolId: "ecdh",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Compare how TLS 1.1, TLS 1.2, and TLS 1.3 negotiate keys, authenticate Bob, exchange Finished messages, protect HTTP, and reduce a full handshake from two round trips to one.",
        variants: [
          {
            id: "5.1-the-complete-tls-handshake",
            label: "TLS 1.3 (Current)",
            title: "The TLS Handshake: The Full Symphony",
            subtitle: "A message-by-message 1-RTT journey from ClientHello to encrypted HTTP",
            difficulty: "Intermediate",
            readTime: "6 min",
          },
          {
            id: "5.1-tls-1.2-handshake",
            label: "TLS 1.2 (Compatibility)",
            title: "The TLS 1.2 Handshake: The Transitional Workhorse",
            subtitle:
              "How ECDHE, certificates, ChangeCipherSpec, and AEAD complete a 2-RTT handshake",
            difficulty: "Intermediate",
            readTime: "6 min",
          },
          {
            id: "5.1-tls-1.1-handshake",
            label: "TLS 1.1 (Deprecated)",
            title: "The TLS 1.1 Handshake: The Legacy Baseline",
            subtitle:
              "How RSA or ephemeral DH, CBC records, and the legacy PRF secured older connections",
            difficulty: "Intermediate",
            readTime: "6 min",
          },
        ],
      },
      {
        id: "5.3-the-dtls-handshake",
        number: "6.3",
        title: "The DTLS Handshake: The Datagram Symphony",
        subtitle:
          "How TLS-style security survives UDP loss, reordering, duplication, and fragmentation",
        conceptId: "putting-it-together",
        family: "asymmetric",
        toolId: "ecdh",
        difficulty: "Advanced",
        readTime: "7 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Compare how DTLS 1.0, DTLS 1.2, and DTLS 1.3 adapt authenticated key exchange to unreliable datagrams using stateless cookies, numbered fragments, retransmitted flights, epochs, replay windows, and selective acknowledgements.",
        variants: [
          {
            id: "5.3-the-dtls-handshake",
            label: "DTLS 1.3 (Current)",
            title: "The DTLS Handshake: The Datagram Symphony",
            subtitle:
              "A 1-RTT authenticated handshake with epochs, encrypted record numbers, and selective ACKs",
            difficulty: "Advanced",
            readTime: "7 min",
          },
          {
            id: "5.3-dtls-1.2-handshake",
            label: "DTLS 1.2 (Compatibility)",
            title: "The DTLS 1.2 Handshake: TLS over Unreliable UDP",
            subtitle:
              "How cookies, numbered fragments, retransmitted flights, ECDHE, and AEAD secure datagrams",
            difficulty: "Advanced",
            readTime: "7 min",
          },
          {
            id: "5.3-dtls-1.0-handshake",
            label: "DTLS 1.0 (Deprecated)",
            title: "The DTLS 1.0 Handshake: The Deprecated Datagram Baseline",
            subtitle:
              "How the first DTLS adapted TLS 1.1 with cookies, epochs, fragments, and CBC records",
            difficulty: "Advanced",
            readTime: "7 min",
          },
        ],
      },
      {
        id: "5.3-the-password-vault",
        number: "6.4",
        title: "The Password Vault: Memory-Hard Argon2id",
        subtitle:
          "Why Bob never stores plain passwords, and how salts and memory-hardness defeat GPU farms",
        conceptId: "putting-it-together",
        family: "kdf",
        toolId: "argon2",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Alice creates an account on Bob's website. Mallory breaches Bob's server! Bob never stored Alice's password: he stored a salted, memory-hard Argon2id hash that makes cracking each password take millions of times longer, protecting Alice even after a data leak.",
      },
      {
        id: "5.4-the-pirate-treasure-chest",
        number: "6.5",
        title: "The Pirate Treasure Chest: Shamir's Secret Sharing",
        subtitle: "Splitting a master key so any 3 of 5 lieutenants can unlock the vault",
        conceptId: "putting-it-together",
        family: "asymmetric",
        toolId: "shamir",
        difficulty: "Advanced",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "Alice has the master encryption key to a company vault. If one person holds it, it can be lost or stolen. Alice splits the key into 5 pieces such that ANY 3 pieces can reconstruct it, but ANY 2 pieces reveal zero information.",
      },
      {
        id: "5.5-the-quantum-spy",
        number: "6.6",
        title: "The Quantum Spy: Post-Quantum ML-KEM",
        subtitle:
          "Defeating Shor's algorithm and 'Store Now, Decrypt Later' attacks with lattice crystals",
        conceptId: "putting-it-together",
        family: "asymmetric",
        toolId: "mlkem",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "Eve is recording all of Alice and Bob's encrypted internet traffic today, planning to decrypt it in 10 years when quantum computers arrive ('Store Now, Decrypt Later'). Alice and Bob switch to NIST FIPS 203 (ML-KEM) to future-proof their security.",
      },
    ],
  },
  {
    id: "attacks-defenses",
    title: "7. Attacks & Defences: How Cryptography Breaks in the Real World",
    description:
      "Birthday collisions, side-channel attacks, and padding oracles.",
    badge: "Attacks",
    tutorials: [
      {
        id: "6.1-the-birthday-collision",
        number: "7.1",
        title: "The Birthday Problem: Hash Collision Attacks",
        subtitle:
          "Why MD5 and SHA-1 are broken, and how the birthday paradox explains collision resistance",
        conceptId: "attacks-defenses",
        family: "hash",
        toolId: "sha256",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "In a room of 23 people, two share a birthday with 50% probability. Hash collisions work the same way — you do not need to match a specific hash, just any two inputs. This halves the effective security bits and is why Google's SHAttered attack broke SHA-1 in 2017.",
      },
      {
        id: "6.2-the-rubber-hose",
        number: "7.2",
        title: "The Rubber Hose: Side-Channel & Timing Attacks",
        subtitle:
          "How Mallory breaks crypto by measuring time, power, and cache — without touching the math",
        conceptId: "attacks-defenses",
        family: "mac",
        toolId: "hmac",
        difficulty: "Advanced",
        readTime: "7 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Perfect cryptography, broken implementation. Mallory does not attack the algorithm — she measures Bob's response time to recover passwords byte by byte, or attaches a probe to measure power consumption and extract AES keys from smart cards. The fix: constant-time comparison.",
      },
      {
        id: "6.3-the-padding-oracle",
        number: "7.3",
        title: "The Padding Oracle: How One Error Message Broke TLS",
        subtitle:
          "The POODLE and Lucky Thirteen attacks: decrypting AES-CBC ciphertext with padding oracle queries",
        conceptId: "attacks-defenses",
        family: "cipher",
        toolId: "aes",
        difficulty: "Advanced",
        readTime: "7 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Bob's server returns two different error messages: 'decryption failed' vs 'invalid padding'. Mallory uses that single bit of difference as an oracle, sending 4096 crafted requests per block to decrypt Alice's session cookie without ever knowing the key. The attack behind POODLE, Lucky Thirteen, and Vaudenay's oracle.",
      },
    ],
  },
  {
    id: "encoding-advanced",
    title: "8. Encoding & Advanced Concepts",
    description:
      "Encoding vs encryption, Zero-Knowledge Proofs, and the future of privacy-preserving cryptography.",
    badge: "Advanced",
    tutorials: [
      {
        id: "7.1-lost-in-translation",
        number: "8.1",
        title: "Lost in Translation: Encoding vs Encryption",
        subtitle:
          "Why Base64 is not encryption, and how this mistake causes real-world breaches",
        conceptId: "encoding-advanced",
        family: "cipher",
        toolId: "aes",
        difficulty: "Beginner",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve", "Mallory"],
        summary:
          "Bob stores a password as Base64 in a config file because his colleague said it was 'encoded for security'. Mallory decodes it in 2 seconds using atob(). A clear breakdown of what encoding (Base64, Hex, UTF-8) actually is, how it differs from encryption, and why JWT payloads are public.",
      },
      {
        id: "7.2-the-magic-wax",
        number: "8.2",
        title: "The Magic Wax: Zero-Knowledge Proofs",
        subtitle:
          "Proving you know a secret without revealing it — zk-SNARKs, zk-STARKs, and the cave of Ali Baba",
        conceptId: "encoding-advanced",
        family: "asymmetric",
        toolId: "ed25519",
        difficulty: "Advanced",
        readTime: "8 min",
        characters: ["Alice", "Bob"],
        summary:
          "Alice proves she knows where Waldo is by revealing only the exact spot through a hole in black paper — Bob sees Waldo but learns nothing about the poster layout. ZKPs apply the same logic to passwords, transactions, and age verification. The math behind zk-SNARKs, zk-STARKs, and why Zcash uses them.",
      },
    ],
  },
];

export const ALL_TUTORIALS_META: readonly TutorialMeta[] = TUTORIAL_CONCEPTS_META.flatMap(
  (c) => c.tutorials,
);

export const TOTAL_TUTORIALS_COUNT = ALL_TUTORIALS_META.length;

export function getTutorialMeta(id: string): TutorialMeta | undefined {
  return ALL_TUTORIALS_META.find((t) => t.id === id);
}
