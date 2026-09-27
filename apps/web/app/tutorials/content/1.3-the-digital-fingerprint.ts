import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "A human fingerprint uniquely identifies an individual. A cryptographic hash takes any message — from one word to an entire operating system ISO — and compresses it into a 64-character hexadecimal digest. Unlike CRC, changing even one single bit completely explodes the hash into unrecognizably different characters (The Avalanche Effect).",
  "problem": "If Bob knows the expected fingerprint in advance, how does SHA-256 prevent Mallory from modifying the downloaded file to match that fingerprint?",
  "steps": [
    {
      "title": "Step 1: Alice publishes the Official Fingerprint",
      "speaker": "Alice",
      "content": "Alice builds a software update: `\"Install CipherWorkbench v0.14.0\"`. She computes the SHA-256 hash in Cipher Workbench:\n`b61b8f047535b914...`\nAlice posts this exact fingerprint on her verified website."
    },
    {
      "title": "Step 2: Mallory tries to tamper with the download mirror",
      "speaker": "Mallory",
      "content": "Bob downloads the installer from a public third-party mirror where Mallory has injected a trojan. Mallory wants Bob to believe her infected installer is genuine. With CRC-32, Mallory could easily append mathematical padding bytes to make her infected file match the original CRC! But with SHA-256, second pre-image resistance makes it mathematically impossible for Mallory to find any modified file that collides with Alice's fingerprint."
    },
    {
      "title": "Step 3: The Avalanche Effect catches Mallory",
      "speaker": "Bob",
      "content": "Bob downloads the file from the mirror and computes its SHA-256 hash locally. Instead of `b61b8f...`, Bob gets a completely different digest: `9f3c17...`.\nBecause Bob is comparing against Alice's pre-published fingerprint, Bob sees the mismatch instantly and deletes the infected file!",
      "callout": {
        "type": "security",
        "text": "Second Pre-image Resistance: Given an input and its SHA-256 hash, it is computationally impossible for an attacker to find a different input that produces the exact same hash."
      }
    },
    {
      "title": "The Critical Catch: What if the Hash Travels with the Message?",
      "content": "Notice a vital assumption in this scenario: **Bob learned Alice's expected fingerprint through an independent, trusted channel** (Alice's official site). What if Alice and Bob have no separate channel, and Alice simply sends the message AND the hash together over an insecure wire? That brings us to Stage 2: The Tampered Hash Trap!",
      "callout": {
        "type": "warning",
        "text": "If Mallory can intercept both the message AND the hash in transit, what stops Mallory from altering the message AND recalculating a new hash? Nothing! That is why hashes alone do not provide Authenticity."
      }
    }
  ],
  "takeaways": [
    "Cryptographic hashes provide integrity only when you can compare against a known, authentic digest.",
    "Second pre-image resistance prevents Mallory from modifying a file to match a pre-existing hash.",
    "If the attacker can alter both the message and the hash in flight, a standalone hash is not enough — you need a secret key (HMAC)!"
  ],
  "seed": {
    "toolId": "sha256",
    "sampleInput": "Install CipherWorkbench v0.14.0",
    "explanation": "Open SHA-256 Workbench, type Alice's installer payload, and change a single character to watch the hash completely change."
  }
};

export default content;
