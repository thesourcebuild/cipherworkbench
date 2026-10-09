import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Imagine mailing a letter in a sealed envelope. If raindrops smudge the paper in transit, the text becomes garbled. If a postal clerk writes a quick digit sum at the bottom of the page, the recipient can immediately detect that ink was lost to the rain. But if an imposter intercepts the letter, rewrites the contents, and recalculates a new sum at the bottom, the recipient is completely fooled.\n\nData integrity is the science of detecting changes to data. In modern systems, we divide integrity into two worlds: **accidental noise detection** (checksums and CRCs) and **adversarial tamper detection** (cryptographic hashes).",
  problem:
    "How does a receiving system determine whether the bytes it received are bit-for-bit identical to what was sent, and why must we distinguish accidental corruption from deliberate malicious alteration?",
  steps: [
    {
      title: "Step 1: What It Is (The Core Nature of Integrity)",
      speaker: "Alice",
      content:
        "Data integrity is the assurance that information remains unaltered, complete, and uncorrupted from the moment it is written or transmitted until it is read or received. It answers a single binary question: *Have these bytes changed since they were created?*",
      callout: {
        type: "info",
        text: "Integrity is the 'I' in the classic CIA security triad (Confidentiality, Integrity, Availability). It focuses exclusively on the correctness and consistency of data.",
      },
    },
    {
      title: "Step 2: What It Does (The Verification Mechanism)",
      speaker: "Bob",
      content:
        "To verify integrity, the sender runs an algorithm over the input bytes to produce a compact verification tag (a checksum, CRC, or cryptographic hash). The recipient computes the exact same algorithm over the received bytes. If even a single bit changed in transit, the calculated tag does not match the received tag, alerting the system to discard or re-request the data.",
      callout: {
        type: "info",
        text: "Simple additive checksums add byte values; CRCs use polynomial long division; cryptographic hashes (SHA-256) use one-way compression functions with an avalanche effect.",
      },
    },
    {
      title: "Step 3: What It Can Do (Guarantees & Capabilities)",
      speaker: "Alice",
      content:
        "Depending on the chosen primitive, integrity checks can:\n\n* **Detect human typos:** Single-digit entry errors and adjacent digit transpositions (e.g., Luhn check digits on credit cards).\n* **Catch transmission noise:** Lightning bursts, electrical static on Ethernet cables, and disk drive bit rot (e.g., CRC-32 in Ethernet frames and ZIP archives).\n* **Detect adversarial modification:** Flag any intentional change made by an attacker, provided the expected hash is verified through a secure, out-of-band channel (e.g., SHA-256 software release digests).",
      callout: {
        type: "security",
        text: "Cryptographic hash functions provide collision resistance and pre-image resistance: an attacker cannot find two different files with the same SHA-256 digest.",
      },
    },
    {
      title: "Step 4: What It Does NOT Do (Critical Security Boundaries)",
      speaker: "Mallory",
      content:
        "Understanding what integrity does **NOT** provide is the most critical lesson in cryptography:\n\n* **Does NOT hide data (No Confidentiality):** A hash or checksum leaves the payload completely readable to any eavesdropper.\n* **Does NOT prove who wrote it (No Authenticity):** A hash has no secret key. If Mallory intercepts both the message and the hash, she can change the message, compute a brand-new SHA-256 hash over her fake data, and send both to Bob.\n* **Does NOT prevent message withholding or deletion:** It only validates data that actually arrives; it cannot stop an attacker from dropping packets.",
      callout: {
        type: "warning",
        text: "Never assume a hash provides security against an active attacker unless the hash is digitally signed, generated with a secret key (HMAC), or delivered over an already-authenticated channel.",
      },
    },
  ],
  takeaways: [
    "Integrity guarantees that data has not changed, answering whether bytes arrived intact.",
    "Non-cryptographic checks (checksums, CRCs) catch accidental noise and line static, but offer zero resistance against an active attacker.",
    "Cryptographic hashes (SHA-256, BLAKE3) detect deliberate tampering, but only when the digest itself is verified over a trusted channel.",
    "Integrity alone provides neither confidentiality (secrecy) nor authenticity (authorship).",
  ],
  seed: {
    toolId: "sha256",
    sampleInput: "Integrity is not Authenticity",
    explanation:
      "Open SHA-256 in Cipher Workbench to see how modifying even a single character completely scrambles the output hash.",
  },
};

export default content;
