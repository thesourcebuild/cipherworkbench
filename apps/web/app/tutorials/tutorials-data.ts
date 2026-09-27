import type { ToolFamily } from "@ocs/engine";

export interface TutorialCharacter {
  name: string;
  role: string;
  avatar: string;
  color: string;
}

export const CHARACTERS: Record<string, TutorialCharacter> = {
  Alice: {
    name: "Alice",
    role: "Sender / Initiator",
    avatar: "👩‍💻",
    color: "border-sky-300 bg-sky-50 text-sky-800 dark:border-sky-800 dark:bg-sky-950/60 dark:text-sky-300",
  },
  Bob: {
    name: "Bob",
    role: "Recipient / Verifier",
    avatar: "👨‍💻",
    color: "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300",
  },
  Eve: {
    name: "Eve",
    role: "Passive Eavesdropper",
    avatar: "🕵️‍♀️",
    color: "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-300",
  },
  Mallory: {
    name: "Mallory",
    role: "Active Malicious Attacker",
    avatar: "🦹",
    color: "border-rose-300 bg-rose-50 text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-300",
  },
  Trent: {
    name: "Trent",
    role: "Trusted Authority / Notary",
    avatar: "🏛️",
    color: "border-indigo-300 bg-indigo-50 text-indigo-800 dark:border-indigo-800 dark:bg-indigo-950/60 dark:text-indigo-300",
  },
};

export interface TutorialSeed {
  toolId: string;
  sampleInput: string;
  explanation: string;
}

export interface TutorialStep {
  title: string;
  speaker?: string;
  content: string;
  callout?: {
    type: "info" | "warning" | "security";
    text: string;
  };
}

export interface TutorialDef {
  id: string;
  number: string;
  title: string;
  subtitle: string;
  conceptId: string;
  family: ToolFamily;
  toolId: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  readTime: string;
  characters: string[];
  summary: string;
  analogy: string;
  problem: string;
  steps: TutorialStep[];
  takeaways: string[];
  seed: TutorialSeed;
}

export interface TutorialConcept {
  id: string;
  title: string;
  description: string;
  badge: string;
  tutorials: TutorialDef[];
}

export const TUTORIAL_CONCEPTS: readonly TutorialConcept[] = [
  {
    id: "confidentiality",
    title: "1. Confidentiality (Keeping Secrets from Eve)",
    description: "How Alice and Bob hide messages so Eve can only see unreadable noise.",
    badge: "Confidentiality",
    tutorials: [
      {
        id: "1.1-the-locked-box",
        number: "1.1",
        title: "The Locked Box: Symmetric Encryption",
        subtitle: "Using a single shared secret key to lock and unlock messages",
        conceptId: "confidentiality",
        family: "cipher",
        toolId: "aes",
        difficulty: "Beginner",
        readTime: "4 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "Alice puts a letter into a heavy steel box, locks it with a padlock, and passes it across the room. Bob can only read it if he has the identical physical key.",
        analogy:
          "Imagine a physical safe box with one lock. If Alice and Bob both have matching brass keys, Alice can lock the box, ship it through the postal service, and Bob can unlock it on arrival. But if Eve steals or copies the key while it is in transit, the entire system collapses.",
        problem:
          "How can Alice protect her note from Eve, and what is the fatal catch of having only one key?",
        steps: [
          {
            title: "Step 1: Alice writes the secret message",
            speaker: "Alice",
            content:
              'Alice writes down: *"Meet me at the cafeteria at noon — Alice"*. This is known as the **Plaintext**.',
          },
          {
            title: "Step 2: Alice locks the message with AES-256",
            speaker: "Alice",
            content:
              "Alice selects a 256-bit symmetric key. She runs the AES-GCM encryption algorithm in Cipher Workbench. The algorithm scrambles the letters into unreadable binary bytes (Ciphertext) and generates an authentication tag.",
            callout: {
              type: "info",
              text: "AES (Advanced Encryption Standard) is the worldwide standard approved by NIST and used in banking, government, and encrypted messaging.",
            },
          },
          {
            title: "Step 3: What Eve sees on the wire",
            speaker: "Eve",
            content:
              'Eve intercepts the transmission over Wi-Fi. All Eve sees is high-entropy noise: `e4 2a 9c 51 0b 7f ...`. Without the 256-bit key, cracking this by brute force would require more energy than all stars in the universe produce.',
          },
          {
            title: "Step 4: Bob unlocks the message",
            speaker: "Bob",
            content:
              "Bob receives the ciphertext. Because Bob already met Alice last week and agreed on the exact same secret key, Bob enters the key into Cipher Workbench and clicks **Decrypt**. The original plaintext instantly appears.",
          },
          {
            title: "The Key Distribution Dilemma",
            content:
              "Symmetric encryption is blazingly fast and impenetrable when keys are kept secret. However, **how did Alice give the key to Bob in the first place?** If they had to meet in person to exchange keys, they cannot easily talk to strangers online (like your browser visiting an HTTPS bank website for the first time). This fundamental problem led to the invention of Public-Key Cryptography!",
            callout: {
              type: "warning",
              text: "The Key Distribution Problem: You cannot securely transmit a secret key over an insecure channel without first having another secret channel.",
            },
          },
        ],
        takeaways: [
          "Symmetric encryption uses the exact same key for both encryption and decryption.",
          "AES-256-GCM provides both confidentiality (scrambling) and integrity (tamper detection).",
          "The biggest challenge is securely sharing the key beforehand without eavesdroppers copying it.",
        ],
        seed: {
          toolId: "aes",
          sampleInput: "Meet me at the cafeteria at noon — Alice",
          explanation: "Launch AES Workbench with Alice's note prefilled to test encryption and decryption live.",
        },
      },
      {
        id: "1.2-the-open-padlock",
        number: "1.2",
        title: "The Open Padlock: Public-Key Encryption",
        subtitle: "How anyone can encrypt a message that only Bob can decrypt",
        conceptId: "confidentiality",
        family: "asymmetric",
        toolId: "rsa",
        difficulty: "Beginner",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "Bob leaves open padlocks on his front porch for anyone to take. Alice puts her letter in a box, snaps Bob's padlock shut, and sends it. Once locked, only Bob's private pocket key can open it.",
        analogy:
          "Think of a physical mailbox with a drop slot. Anyone can walk by and drop a letter into Bob's box (Public Key). But only Bob has the physical key to unlock the door on the back of the box and retrieve the letters (Private Key).",
        problem:
          "How can two strangers communicate securely online without ever having met or agreed on a secret password beforehand?",
        steps: [
          {
            title: "Step 1: Bob generates a Keypair",
            speaker: "Bob",
            content:
              "Bob uses RSA or Post-Quantum ML-KEM to generate two mathematically linked keys:\n1. **Public Key:** Shared openly with the world (posted on Bob's website or public directory).\n2. **Private Key:** Guarded with Bob's life on his local device. Never shared or transmitted.",
          },
          {
            title: "Step 2: Alice locks her note with Bob's Public Key",
            speaker: "Alice",
            content:
              "Alice downloads Bob's Public Key. She encrypts her secret message. Here is the magic: **Even Alice herself cannot decrypt the message once it is locked!** The public key can only lock, never unlock.",
          },
          {
            title: "Step 3: Eve intercepts the parcel",
            speaker: "Eve",
            content:
              "Eve captures the encrypted parcel. Eve also has Bob's Public Key, but that does not help her at all: the public key is a one-way trapdoor function. Only Bob's Private Key can mathematically reverse the operation.",
          },
          {
            title: "Step 4: Bob decrypts with his Private Key",
            speaker: "Bob",
            content:
              "Bob uses his Private Key in Cipher Workbench. The mathematical trapdoor opens, revealing Alice's note.",
            callout: {
              type: "security",
              text: "In practice (like TLS / HTTPS), Public-Key cryptography is used to securely exchange a fast AES symmetric key, giving you the best of both worlds!",
            },
          },
        ],
        takeaways: [
          "Asymmetric cryptography uses a keypair: a Public Key (to encrypt) and a Private Key (to decrypt).",
          "Public keys can be freely published anywhere without compromising security.",
          "Never, under any circumstances, expose or upload your Private Key.",
        ],
        seed: {
          toolId: "rsa",
          sampleInput: "Top secret message for Bob's eyes only — Alice",
          explanation: "Launch RSA Workbench to generate an RSA keypair and test asymmetric encryption.",
        },
      },
    ],
  },
  {
    id: "key-agreement",
    title: "2. Key Agreement (Meeting in Daylight)",
    description: "Agreeing on an identical shared secret in public without Eve ever learning it.",
    badge: "Key Agreement",
    tutorials: [
      {
        id: "2.1-the-paint-mixing-trick",
        number: "2.1",
        title: "The Paint Mixing Trick: Diffie-Hellman",
        subtitle: "How Alice and Bob create a shared secret while Eve listens to every word",
        conceptId: "key-agreement",
        family: "asymmetric",
        toolId: "ecdh",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "Alice and Bob agree on Yellow in public. Alice secretly adds Red (sends Orange). Bob secretly adds Blue (sends Green). Both add their secret colors to the other's mix to create identical secret Brown!",
        analogy:
          "Mixing paints is easy, but separating mixed paint back into its original colors is virtually impossible. Cryptography uses mathematical operations (like modular exponentiation and elliptic curve scalar multiplication) that behave like one-way paint mixing.",
        problem:
          "Can two people establish a shared secret key over an open radio or unencrypted internet connection without sending the secret itself?",
        steps: [
          {
            title: "Step 1: Public Base Color",
            speaker: "Alice",
            content:
              "Alice and Bob publicly pick a common base: **Yellow** (in cryptography, a public prime number and generator base point on a curve). Eve hears this.",
          },
          {
            title: "Step 2: Alice & Bob pick Secret Colors",
            speaker: "Bob",
            content:
              "- Alice secretly picks **Red** (her private scalar).\n- Bob secretly picks **Blue** (his private scalar).\nNeither tells anyone, not even each other.",
          },
          {
            title: "Step 3: Mixing and Exchanging",
            content:
              "- Alice mixes Yellow + Red $\\rightarrow$ **Orange** and sends Orange across the wire.\n- Bob mixes Yellow + Blue $\\rightarrow$ **Green** and sends Green across the wire.\nEve captures both Orange and Green, but cannot separate them to discover Red or Blue.",
          },
          {
            title: "Step 4: The Shared Secret is Born",
            content:
              "- Alice takes Bob's **Green** (Yellow + Blue) and adds her secret **Red** $\\rightarrow$ **Brown**.\n- Bob takes Alice's **Orange** (Yellow + Red) and adds his secret **Blue** $\\rightarrow$ **Brown**.\nBoth now possess the exact same secret color (**Brown**), and Eve has no way to make it!",
            callout: {
              type: "info",
              text: "Modern browsers use ECDH (Elliptic Curve Diffie-Hellman, specifically X25519) on every HTTPS connection to establish session keys in milliseconds.",
            },
          },
        ],
        takeaways: [
          "Diffie-Hellman allows two parties with no prior shared secrets to establish one over an insecure channel.",
          "Neither party sends the shared secret across the wire; each computes it independently.",
          "Elliptic Curve Diffie-Hellman (ECDH) is the mathematical bedrock of TLS 1.3, Signal, and SSH.",
        ],
        seed: {
          toolId: "ecdh",
          sampleInput: "",
          explanation: "Launch ECDH (X25519) Workbench to generate Alice and Bob keys and compute their shared secret.",
        },
      },
    ],
  },
  {
    id: "integrity-authenticity",
    title: "3. Integrity & Authenticity (Stopping Mallory)",
    description: "Detecting when messages are altered and proving who actually wrote them.",
    badge: "Integrity",
    tutorials: [
      {
        id: "3.1-the-digital-fingerprint",
        number: "3.1",
        title: "The Digital Fingerprint: Hashes",
        subtitle: "How Bob detects if Mallory modified a single comma in transit",
        conceptId: "integrity-authenticity",
        family: "hash",
        toolId: "sha256",
        difficulty: "Beginner",
        readTime: "4 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Alice writes a public bank order: 'Transfer $10 to Bob'. Mallory intercepts it and changes it to 'Transfer $10,000'. Bob uses a digital fingerprint (hash) to immediately detect the forgery.",
        analogy:
          "A human fingerprint uniquely identifies a person. A cryptographic hash function takes any amount of data (a single word or an entire encyclopedia) and produces a fixed-size 'fingerprint' of 64 hexadecimal characters. If even one pixel or letter changes, the fingerprint becomes completely unrecognizable.",
        problem:
          "How can Bob know whether a file or message was corrupted or maliciously altered along the way?",
        steps: [
          {
            title: "Step 1: Alice computes the Hash",
            speaker: "Alice",
            content:
              'Alice types: *"Transfer $10 to Bob"*. Her computer runs SHA-256 and gets:\n`b61b8f047535b914...`\nShe includes this hash alongside the message.',
          },
          {
            title: "Step 2: Mallory alters the message",
            speaker: "Mallory",
            content:
              'Mallory intercepts the transmission and alters the text to *"Transfer $10,000 to Bob"*. Mallory hopes Bob won\'t notice.',
          },
          {
            title: "Step 3: The Avalanche Effect catches Mallory",
            speaker: "Bob",
            content:
              "Bob receives the message and recalculates the SHA-256 hash locally. Instead of `b61b8f...`, Bob gets a completely different string: `9f3c17...`.\nNot a single character matches! Bob knows instantly that the message was modified and discards it.",
            callout: {
              type: "security",
              text: "The Avalanche Effect: Changing just one single bit of input flips roughly 50% of the output bits in a secure cryptographic hash function.",
            },
          },
        ],
        takeaways: [
          "Hash functions are strictly one-way: you cannot reverse a hash back to the original text.",
          "Hashes are deterministic: the exact same input always produces the exact same hash digest.",
          "Even a microscopic change in the input completely randomizes the output hash.",
        ],
        seed: {
          toolId: "sha256",
          sampleInput: "Transfer $10 to Bob",
          explanation: "Open SHA-256 Workbench, type Alice's message, and try changing a single letter to watch the hash mutate.",
        },
      },
      {
        id: "3.2-the-royal-signet-ring",
        number: "3.2",
        title: "The Royal Signet Ring: Digital Signatures",
        subtitle: "Proving Alice really wrote the message and preventing impersonation",
        conceptId: "integrity-authenticity",
        family: "asymmetric",
        toolId: "ed25519",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Bob receives a note saying 'Cancel all orders — Alice'. Did Alice actually send this, or is Mallory impersonating her? Alice uses a digital signature to mathematically prove authenticity.",
        analogy:
          "In medieval times, a king pressed his unique personal signet ring into hot wax on a scroll. Anyone who knew the king's crest could see it was authentic, but no one could duplicate the wax seal without holding the physical ring.",
        problem:
          "A hash proves a message hasn't changed, but it doesn't prove WHO sent it! How can Bob guarantee a message truly originated from Alice?",
        steps: [
          {
            title: "Step 1: Alice creates her Signet Ring",
            speaker: "Alice",
            content:
              "Alice creates an Ed25519 keypair:\n- **Private Key (Signet Ring):** Only Alice possesses it.\n- **Public Key (Royal Crest):** Given to Bob and the public.",
          },
          {
            title: "Step 2: Alice Signs the message",
            speaker: "Alice",
            content:
              "Alice hashes her message, then uses her Private Key to mathematically stamp the hash. This stamp is called a **Digital Signature**.",
          },
          {
            title: "Step 3: Bob verifies the seal",
            speaker: "Bob",
            content:
              "Bob takes Alice's Public Key, the message, and the signature. He clicks **Verify** in Cipher Workbench. The math confirms: only the holder of Alice's private key could have produced this signature for this exact text!",
          },
          {
            title: "Step 4: Mallory attempts a forgery",
            speaker: "Mallory",
            content:
              "Mallory tries to send Bob a forged message claiming to be Alice. Because Mallory does not possess Alice's private key, any signature Mallory fabricates will be immediately rejected by Bob's verification math.",
            callout: {
              type: "info",
              text: "Non-repudiation: Once Alice signs a message, she cannot later claim 'I didn't send that,' because only her private key could have generated the signature.",
            },
          },
        ],
        takeaways: [
          "Digital signatures provide both Authenticity (who sent it) and Integrity (it wasn't altered).",
          "You sign with your Private Key; anyone verifies with your Public Key.",
          "Ed25519 and ECDSA are the modern standards used in Git commit signing, cryptocurrencies, and SSH.",
        ],
        seed: {
          toolId: "ed25519",
          sampleInput: "Approved and authorized by Alice",
          explanation: "Launch Ed25519 Workbench to generate a keypair, sign Alice's message, and verify the signature.",
        },
      },
      {
        id: "3.3-the-secret-handshake",
        number: "3.3",
        title: "The Secret Handshake: HMACs",
        subtitle: "Fast message authentication when Alice and Bob already share a secret",
        conceptId: "integrity-authenticity",
        family: "mac",
        toolId: "hmac",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Digital signatures with public keys can be computationally heavy. When Alice and Bob already share a secret password, they use an HMAC (Hash-based Message Authentication Code) for lightning-fast verification.",
        analogy:
          "Imagine a club secret handshake. Before telling you the news, Alice performs the secret handshake with you. If someone doesn't know the exact grip, you ignore whatever they say.",
        problem:
          "How can high-speed APIs, webhooks (like Stripe or GitHub), and payment gateways authenticate millions of requests per second without the overhead of asymmetric math?",
        steps: [
          {
            title: "Step 1: The Shared API Secret",
            speaker: "Alice",
            content:
              "Alice and Bob agree on a secret key: `sk_live_secret_99812`.",
          },
          {
            title: "Step 2: Computing the HMAC",
            speaker: "Alice",
            content:
              "Alice takes her message: `order_id=4821&amount=50.00`. She combines it with the secret key using **HMAC-SHA256**. The output is a compact authentication code.",
          },
          {
            title: "Step 3: Bob verifies in constant time",
            speaker: "Bob",
            content:
              "Bob receives the message and the HMAC. Bob calculates the HMAC using his copy of the secret key. If they match, Bob knows the message is authentic and untampered.",
            callout: {
              type: "warning",
              text: "Timing attacks: When verifying an HMAC in code, always use constant-time comparison (`crypto.timingSafeEqual`) to prevent attackers from guessing the MAC byte-by-byte.",
            },
          },
        ],
        takeaways: [
          "HMAC combines a cryptographic hash with a secret key.",
          "It is significantly faster than asymmetric digital signatures.",
          "It is the industry standard for API request signing and webhook security.",
        ],
        seed: {
          toolId: "hmac",
          sampleInput: "order_id=4821&amount=50.00",
          explanation: "Launch HMAC Workbench with Alice's payload to inspect the authentication code.",
        },
      },
    ],
  },
  {
    id: "trust-identity",
    title: "4. Trust & Identity (Trent & Public Keys)",
    description: "Why public keys alone are not enough, and how Certificate Authorities solve impersonation.",
    badge: "Trust & PKI",
    tutorials: [
      {
        id: "4.1-the-imposter-in-the-middle",
        number: "4.1",
        title: "The Imposter in the Middle: Certificates",
        subtitle: "Why public keys need Trent (The Certificate Authority) to foil Mallory",
        conceptId: "trust-identity",
        family: "certificates",
        toolId: "cert-creator",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Mallory", "Trent"],
        summary:
          "Mallory intercepts Bob's open padlock and replaces it with her own padlock! Alice encrypts for Mallory without realizing. Enter Trent (The Certificate Authority) to notarize Bob's padlock with an X.509 certificate.",
        analogy:
          "If a stranger hands you a passport on the street, how do you know it's legitimate? Because it was issued and stamped by a government authority whose official seal you recognize. Trent is the government notary of the internet.",
        problem:
          "Anyone can generate a public key that claims to belong to 'bank.com'. How does Alice know she is actually talking to Bob and not to Mallory pretending to be Bob?",
        steps: [
          {
            title: "Step 1: Mallory's Silent Man-in-the-Middle Attack",
            speaker: "Mallory",
            content:
              "1. Alice shouts: *'Bob, send me your public key!'*\n2. Mallory intercepts Bob's key and hides it in her pocket.\n3. Mallory sends **Mallory's public key** to Alice, claiming: *'Here is Bob's key!'*\n4. Alice encrypts her secret with Mallory's key.\n5. Mallory decrypts, reads everything, re-encrypts with Bob's real key, and forwards it to Bob.\nNeither Alice nor Bob realizes they've been spied on!",
          },
          {
            title: "Step 2: Enter Trent, the Trusted Authority",
            speaker: "Trent",
            content:
              "To stop this, Bob visits **Trent** (a Certificate Authority). Bob proves his legal identity. Trent inspects Bob's public key, bundles it into an **X.509 Certificate**, and digitally signs it with Trent's Root CA key.",
          },
          {
            title: "Step 3: Alice verifies Bob's Certificate",
            speaker: "Alice",
            content:
              "Now Bob sends his certificate to Alice. Alice checks Trent's signature (which is pre-installed in her browser's Trust Store). Alice sees that Trent guaranteed this specific key belongs to Bob, foiling Mallory!",
            callout: {
              type: "security",
              text: "This is how HTTPS (TLS) works: whenever you visit a website, your browser checks the site's X.509 certificate against trusted root CAs installed on your operating system.",
            },
          },
        ],
        takeaways: [
          "Public-key encryption alone cannot prevent Man-in-the-Middle (MitM) attacks.",
          "Certificate Authorities (CAs) act as trusted introducers by digitally signing public keys.",
          "X.509 certificates bind a public key to an authenticated domain or identity.",
        ],
        seed: {
          toolId: "cert-creator",
          sampleInput: "",
          explanation: "Open Certificate Creator to inspect and generate self-signed and CA-signed X.509 certificates.",
        },
      },
      {
        id: "4.2-the-pirate-treasure-chest",
        number: "4.2",
        title: "The Pirate Treasure Chest: Secret Sharing",
        subtitle: "Splitting a critical master key so any 3 of 5 people can unlock the vault",
        conceptId: "trust-identity",
        family: "asymmetric",
        toolId: "shamir",
        difficulty: "Advanced",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "Alice has the master encryption key to a company vault. If one person holds it, it can be lost or stolen. Alice splits the key into 5 pieces such that ANY 3 pieces can reconstruct it, but ANY 2 pieces reveal zero information.",
        analogy:
          "Any 2 points in space draw a straight line. But to define a specific curved parabola ($y = ax^2 + bx + c$), you mathematically require **3 distinct points**. Alice hides the secret at the point where the curve crosses the center ($y$-intercept), and hands 1 point to each lieutenant.",
        problem:
          "How can an organization eliminate single points of failure for root master keys without risking extortion or loss?",
        steps: [
          {
            title: "Step 1: Alice creates a Secret Polynomial",
            speaker: "Alice",
            content:
              "Alice sets Secret = `VaultMasterPassword99`. She configures a threshold of $k = 3$ and total shares $n = 5$. A degree-2 polynomial is generated over a Galois finite field.",
          },
          {
            title: "Step 2: Distributing the 5 Shares",
            speaker: "Alice",
            content:
              "Alice hands 1 share to Bob, 1 to Charlie, 1 to Dave, 1 to Eve, and 1 to Frank. None of them can decipher the secret alone.",
          },
          {
            title: "Step 3: Two Rogues Fail",
            speaker: "Eve",
            content:
              "Eve and Charlie collude. They put their 2 shares together. Because 2 points can fit an infinite number of parabolas, they have **zero mathematical information** about the secret!",
          },
          {
            title: "Step 4: The 3rd Lieutenant Arrives",
            speaker: "Bob",
            content:
              "Bob joins with his 3rd share. With 3 points, Lagrange polynomial interpolation locks into the unique curve, instantly recovering Alice's original secret code.",
            callout: {
              type: "info",
              text: "Shamir's Secret Sharing (SSSS) is information-theoretically secure: even an adversary with infinite supercomputers cannot recover the secret with fewer than the threshold number of shares.",
            },
          },
        ],
        takeaways: [
          "Threshold cryptography allows $k$-of-$n$ recovery of master secrets.",
          "Having $k-1$ shares yields zero leaked bits about the original secret.",
          "Widely used in hardware security modules (HSMs), cryptocurrency multisig, and nuclear launch codes.",
        ],
        seed: {
          toolId: "shamir",
          sampleInput: "MasterVaultCode-Alpha-Omega",
          explanation: "Open Shamir's Secret Sharing in the workbench to split a secret and test recovery with different shares.",
        },
      },
    ],
  },
  {
    id: "passwords-proofs",
    title: "5. Passwords & Proofs (Protecting Credentials)",
    description: "Why Bob never stores plain passwords, and how memory-hard Argon2id stops GPU cracking.",
    badge: "Passwords",
    tutorials: [
      {
        id: "5.1-the-password-vault",
        number: "5.1",
        title: "The Password Vault: Memory-Hard Hashing",
        subtitle: "How Bob securely verifies Alice's login without risking her password in a breach",
        conceptId: "passwords-proofs",
        family: "kdf",
        toolId: "argon2",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Mallory"],
        summary:
          "Alice creates an account on Bob's website. Mallory breaches Bob's server! Bob never stored Alice's password: he stored a salted, memory-hard Argon2id hash that makes cracking each password take millions of times longer, protecting Alice even after a data leak.",
        analogy:
          "Imagine a bank vault with a mechanical combination dial that intentionally takes 10 seconds of heavy hand-cranking to test a single guess. For Alice logging in once, 10 seconds is completely unnoticeable. But for Mallory trying to test 1 billion stolen passwords, that deliberate slowness means it would take over 300 years to crack the list!",
        problem:
          "How can Bob verify that Alice typed the correct password without Bob (or any database thief) ever knowing what Alice's password actually is?",
        steps: [
          {
            title: "Step 1: Alice creates her password",
            speaker: "Alice",
            content:
              'Alice types her chosen password: *"AliceSecretP@ssword2026"*. She sends it to Bob over an encrypted TLS connection.',
          },
          {
            title: "Step 2: Bob adds a unique Salt",
            speaker: "Bob",
            content:
              "Bob generates a random 16-byte cryptographic **Salt**. Even if 10,000 users all pick the exact same password (`Password123`), each user gets a unique salt, guaranteeing that every single hash in the database is completely different. This completely neutralizes precomputed Rainbow Tables!",
          },
          {
            title: "Step 3: The Argon2id Memory-Hard Engine",
            speaker: "Bob",
            content:
              "Bob runs **Argon2id**. Unlike fast hashes (SHA-256 can be computed 10 billion times per second on modern graphics cards), Argon2id forces the computer to allocate large blocks of RAM (e.g. 64 MB) and perform thousands of memory-access passes. Because GPUs cannot afford 64 MB of fast cache per core, GPU-accelerated cracking farms are stopped dead in their tracks.",
            callout: {
              type: "security",
              text: "Argon2id was chosen as the winner of the Password Hashing Competition (PHC) and is the modern standard recommended by OWASP and NIST.",
            },
          },
          {
            title: "Step 4: Mallory dumps the database",
            speaker: "Mallory",
            content:
              "Mallory breaches Bob's SQL server and dumps the table. All Mallory finds is the PHC string:\n`$argon2id$v=19$m=65536,t=3,p=4$...`\nMallory cannot reverse the hash. When Alice returns to log in, Bob computes Argon2id on Alice's input and compares it against the stored hash.",
          },
        ],
        takeaways: [
          "Never store passwords in plaintext or with fast general-purpose hashes like MD5, SHA-1, or SHA-256.",
          "Salts ensure identical passwords never produce the same hash, defeating rainbow tables.",
          "Argon2id uses configurable memory, time, and parallelism to resist ASIC and GPU brute-force attacks.",
        ],
        seed: {
          toolId: "argon2",
          sampleInput: "AliceSecretP@ssword2026",
          explanation: "Open Argon2 Workbench to compute memory-hard PHC hashes and verify password candidates live.",
        },
      },
    ],
  },
  {
    id: "pitfalls-attacks",
    title: "6. Pitfalls & Attacks (The Nonce-Reuse Trap)",
    description: "Why repeating an Initialization Vector (IV) completely shatters confidentiality.",
    badge: "Pitfalls",
    tutorials: [
      {
        id: "6.1-the-reused-key-catastrophe",
        number: "6.1",
        title: "The Reused Key Catastrophe: Never Reuse a Nonce",
        subtitle: "How reusing an IV strips the key and exposes both messages to Eve",
        conceptId: "pitfalls-attacks",
        family: "cipher",
        toolId: "aes",
        difficulty: "Intermediate",
        readTime: "5 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "A Nonce means 'Number used ONCE'. Alice lazily encrypts two different letters using the same key and the same IV. Eve captures both and uses simple XOR math to completely cancel out the key and read both messages!",
        analogy:
          "Think of a sheet of physical carbon copy paper. If you write two completely different letters using the exact same carbon sheet without replacing it, the ink impressions of both letters overlap. An eavesdropper holding the carbon sheet up to the light can easily decipher both texts.",
        problem:
          "Why does modern symmetric encryption require an IV/Nonce alongside the key, and why does repeating it even once cause complete cryptographic collapse?",
        steps: [
          {
            title: "Step 1: How Stream Ciphers & CTR Mode Work",
            speaker: "Alice",
            content:
              "In AES-CTR and ChaCha20, the cipher does not directly encrypt the message. Instead, it encrypts the Key + Nonce to produce a pseudo-random **Keystream** ($K$). The message ($P$) is then combined with the keystream via XOR: $C = P \\oplus K$.",
          },
          {
            title: "Step 2: Alice's Fatal Shortcut",
            speaker: "Alice",
            content:
              "Alice encrypts Message 1: $C_1 = P_1 \\oplus K$.\nLater that afternoon, Alice encrypts Message 2 with the *exact same key and nonce*: $C_2 = P_2 \\oplus K$.",
          },
          {
            title: "Step 3: Eve's Two-Time Pad Attack",
            speaker: "Eve",
            content:
              "Eve intercepts both $C_1$ and $C_2$. She performs a simple XOR subtraction:\n$C_1 \\oplus C_2 = (P_1 \\oplus K) \\oplus (P_2 \\oplus K) = P_1 \\oplus P_2$.\n**The secret key $K$ has completely cancelled out!** Eve now has the XOR of the two plaintexts, which can be effortlessly separated using English letter frequency and crib dragging.",
            callout: {
              type: "warning",
              text: "In AES-GCM, nonce reuse is even worse: it allows Eve to mathematically derive the secret GHASH authentication key, allowing Eve to forge arbitrary encrypted messages that Bob will accept as authentic!",
            },
          },
        ],
        takeaways: [
          "A Nonce (or IV) must NEVER be reused with the same encryption key.",
          "In modern AEAD ciphers, nonce reuse breaks both secrecy and message integrity.",
          "To avoid nonce collisions in high-speed systems, use random 192-bit nonces (XChaCha20) or nonce-misuse resistant modes (AES-GCM-SIV).",
        ],
        seed: {
          toolId: "aes",
          sampleInput: "Attack at dawn — Alice",
          explanation: "Open AES Workbench and check how changing the IV/Nonce produces completely different ciphertexts and protects against two-time pad attacks.",
        },
      },
    ],
  },
  {
    id: "post-quantum-era",
    title: "7. The Post-Quantum Era (Defeating the Quantum Spy)",
    description: "How Alice and Bob future-proof their secrets against quantum supercomputers.",
    badge: "Post-Quantum",
    tutorials: [
      {
        id: "7.1-the-quantum-spy",
        number: "7.1",
        title: "The Quantum Spy: Post-Quantum ML-KEM",
        subtitle: "Using lattice mathematics (FIPS 203) to defeat Shor's algorithm",
        conceptId: "post-quantum-era",
        family: "asymmetric",
        toolId: "ml-kem",
        difficulty: "Intermediate",
        readTime: "6 min",
        characters: ["Alice", "Bob", "Eve"],
        summary:
          "Eve is recording all of Alice and Bob's encrypted internet traffic today, planning to decrypt it in 10 years when quantum computers arrive ('Store Now, Decrypt Later'). Alice and Bob switch to NIST FIPS 203 (ML-KEM) to future-proof their security.",
        analogy:
          "Imagine a burglar filming you lock your safe with a 4-digit code. They don't have the combination today, but they know they will soon possess a quantum scanner that can test all mathematical combinations in a fraction of a second. To defeat them, you replace the lock with a multi-dimensional geometric labyrinth that even quantum supercomputers cannot solve.",
        problem:
          "Why does Shor's algorithm on a quantum computer break RSA and Elliptic Curves, and how does lattice cryptography save the future of the internet?",
        steps: [
          {
            title: "Step 1: The Quantum Threat (Shor's Algorithm)",
            speaker: "Eve",
            content:
              "Classical computers cannot factor large numbers (RSA) or solve discrete logarithms (ECC). However, in 1994, mathematician Peter Shor proved that a sufficiently large quantum computer can solve both in polynomial time using quantum superposition and Fourier transforms.",
          },
          {
            title: "Step 2: The 'Store Now, Decrypt Later' Attack",
            speaker: "Eve",
            content:
              "Eve doesn't need a quantum computer today. Adversaries and intelligence agencies are recording encrypted TLS sessions right now, storing petabytes in data centers, waiting for quantum computers to retroactively decrypt government secrets, trade patents, and medical records.",
          },
          {
            title: "Step 3: Enter ML-KEM (Kyber / FIPS 203)",
            speaker: "Bob",
            content:
              "In August 2024, NIST officially standardized **ML-KEM (FIPS 203)**. Instead of prime numbers, ML-KEM is built on the **Module Learning with Errors (M-LWE)** problem over high-dimensional polynomial lattices.",
            callout: {
              type: "security",
              text: "Lattice problems are believed to be immune to both classical and quantum algorithms because finding the closest vector in a 512-dimensional noisy grid has no known quantum shortcut.",
            },
          },
          {
            title: "Step 4: Alice & Bob Encapsulate",
            speaker: "Alice",
            content:
              "Bob shares his ML-KEM public key. Alice runs **Encapsulate** in Cipher Workbench, producing a shared secret and a ciphertext. Bob decapsulates it with his private key. Even with a million-qubit computer, Eve cannot reverse the lattice noise!",
          },
        ],
        takeaways: [
          "RSA, ECDSA, and Diffie-Hellman will be broken once cryptographically relevant quantum computers exist.",
          "Symmetric ciphers like AES-256 remain quantum-resistant (Grover's algorithm only halves key strength to 128 bits).",
          "NIST FIPS 203 (ML-KEM) is the new worldwide standard for quantum-safe key exchange.",
        ],
        seed: {
          toolId: "ml-kem",
          sampleInput: "",
          explanation: "Open ML-KEM (FIPS 203) Workbench to generate quantum-safe lattice keypairs and test encapsulation live.",
        },
      },
    ],
  },
];

export const ALL_TUTORIALS = TUTORIAL_CONCEPTS.flatMap((c) => c.tutorials);

export function getTutorial(id: string): TutorialDef | undefined {
  return ALL_TUTORIALS.find((t) => t.id === id);
}
