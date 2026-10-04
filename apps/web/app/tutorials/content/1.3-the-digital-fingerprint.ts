import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "cryptographic-flow", id: "hash" },
  analogy:
    "A human fingerprint uniquely identifies an individual. A cryptographic hash takes any message — from one word to an entire operating system ISO — and compresses it into a 64-character hexadecimal digest. Unlike CRC, changing even one single bit completely explodes the hash into unrecognizably different characters (The Avalanche Effect).",
  problem:
    "If Bob knows the expected fingerprint in advance, how does SHA-256 prevent Mallory from modifying the downloaded file to match that fingerprint?",
  steps: [
    {
      title: "Step 1: Alice publishes the Official Fingerprint",
      speaker: "Alice",
      content:
        'Alice builds a software update: `"Install CipherWorkbench v0.14.0"`. She computes the SHA-256 hash in Cipher Workbench:\n`474c60ba2deb4a23...`\nAlice posts this exact fingerprint on her verified website.',
    },
    {
      title: "Step 2: Mallory tries to tamper with the download mirror",
      speaker: "Mallory",
      content:
        "Bob downloads the installer from a public third-party mirror where Mallory has injected a trojan. Mallory wants Bob to believe her infected installer is genuine. With CRC-32, Mallory could deliberately adjust bytes to make her infected file match the original CRC. With SHA-256, second-preimage resistance makes finding a modified file with Alice's fixed fingerprint computationally infeasible.",
    },
    {
      title: "Step 3: Bob detects the digest mismatch",
      speaker: "Bob",
      content:
        "Bob downloads the file from the mirror and computes its SHA-256 hash locally. Instead of `474c60...`, Bob gets a completely different digest: `9f3c17...`.\nBecause Bob compares against Alice's independently trusted fingerprint, he detects the mismatch and deletes the infected file. The avalanche effect makes the change conspicuous; second-preimage resistance prevents Mallory from feasibly preserving the trusted digest.",
      callout: {
        type: "security",
        text: "Second-preimage resistance: Given an input and its SHA-256 hash, it is computationally infeasible for an attacker to find a different input that produces the exact same hash.",
      },
    },
  ],
  afterTimeline: {
    title: "After the Timeline: What if the hash travels with the message?",
    content:
      "This scenario depends on Bob learning Alice's expected fingerprint through an independent, trusted channel such as Alice's authenticated official site. If Alice instead sends the file and its hash together over the same insecure channel, Mallory can replace both. That leads directly to the Tampered Hash Trap in Stage 2.",
    callout: {
      type: "warning",
      text: "A standalone hash does not prove who supplied it. If Mallory controls both the message and reference digest, Bob needs an authenticated channel, HMAC, or digital signature.",
    },
  },
  takeaways: [
    "Cryptographic hashes provide integrity only when you can compare against a known, authentic digest.",
    "Second pre-image resistance prevents Mallory from modifying a file to match a pre-existing hash.",
    "If the attacker can alter both the message and the hash in flight, a standalone hash is not enough — you need a secret key (HMAC)!",
  ],
  seed: {
    toolId: "sha256",
    sampleInput: "Install CipherWorkbench v0.14.0",
    explanation:
      "Open SHA-256 Workbench, type Alice's installer payload, and change a single character to watch the hash completely change.",
  },
};

export default content;
