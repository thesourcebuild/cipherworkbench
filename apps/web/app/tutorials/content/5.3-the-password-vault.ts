import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Imagine a bank vault with a mechanical combination dial that intentionally takes 10 seconds of heavy hand-cranking to test a single guess. For Alice logging in once, 10 seconds is completely unnoticeable. But for Mallory trying to test 1 billion stolen passwords, that deliberate slowness means it would take over 300 years to crack the list!",
  "problem": "How can Bob verify that Alice typed the correct password without Bob (or any database thief) ever knowing what Alice's password actually is?",
  "steps": [
    {
      "title": "Step 1: Alice creates her password",
      "speaker": "Alice",
      "content": "Alice types her chosen password: *\"AliceSecretP@ssword2026\"*. She sends it to Bob over an encrypted TLS connection."
    },
    {
      "title": "Step 2: Bob adds a unique Salt",
      "speaker": "Bob",
      "content": "Bob generates a random 16-byte cryptographic **Salt**. Even if 10,000 users all pick the exact same password (`Password123`), each user gets a unique salt, guaranteeing that every single hash in the database is completely different. This completely neutralizes precomputed Rainbow Tables!",
      "callout": {
        "type": "warning",
        "text": "Salts defeat multi-user rainbow tables, but they do NOT protect a weak password like '123456' from being guessed individually! That is why memory hardness (Argon2id) and minimum password length policies must work together."
      }
    },
    {
      "title": "Step 3: The Argon2id Memory-Hard Engine",
      "speaker": "Bob",
      "content": "Bob runs **Argon2id**. Unlike fast hashes (SHA-256 can be computed 10 billion times per second on modern graphics cards), Argon2id forces the computer to allocate large blocks of RAM (e.g. 64 MB) and perform thousands of memory-access passes. Because GPUs cannot afford 64 MB of fast cache per core, GPU-accelerated cracking farms are stopped dead in their tracks.",
      "callout": {
        "type": "security",
        "text": "Argon2id was chosen as the winner of the Password Hashing Competition (PHC) and is the modern standard recommended by OWASP and NIST."
      }
    },
    {
      "title": "Step 4: Mallory dumps the database",
      "speaker": "Mallory",
      "content": "Mallory breaches Bob's SQL server and dumps the table. All Mallory finds is the PHC string:\n`$argon2id$v=19$m=65536,t=3,p=4$...`\nMallory cannot reverse the hash. When Alice returns to log in, Bob computes Argon2id on Alice's input and compares it against the stored hash."
    }
  ],
  "takeaways": [
    "Never store passwords in plaintext or with fast general-purpose hashes like MD5, SHA-1, or SHA-256.",
    "Salts ensure identical passwords produce unique hashes, completely neutralizing rainbow tables.",
    "Salts do not protect weak passwords; Argon2id memory-hardness is required to slow down brute force.",
    "Argon2id uses configurable memory, time, and parallelism to resist ASIC and GPU cracking clusters."
  ],
  "seed": {
    "toolId": "argon2",
    "sampleInput": "AliceSecretP@ssword2026",
    "explanation": "Open Argon2 Workbench to compute memory-hard PHC hashes and verify password candidates live."
  }
};

export default content;
