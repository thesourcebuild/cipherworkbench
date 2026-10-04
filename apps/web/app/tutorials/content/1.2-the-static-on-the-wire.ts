import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  mechanismDiagram: "crc",
  visualization: { kind: "cryptographic-flow", id: "crc" },
  analogy:
    "Imagine a long mathematical division problem. You divide a huge number by a predetermined generator polynomial and keep only the remainder (like the change left over in your pocket). If even a tiny cluster of bits flips, the remainder completely changes.",
  problem:
    "Why do simple addition checksums fail when network noise flips multiple bits, and how does CRC solve telecommunication burst errors?",
  steps: [
    {
      title: "Step 1: Alice computes and appends the CRC-32",
      speaker: "Alice",
      content:
        'Alice prepares an Ethernet packet: `"Download packet #4096"`. Her network interface card (NIC) calculates the standard IEEE 802.3 CRC-32 remainder: `0x7E060C31`, appending it to the tail of the frame as the 4-byte Frame Check Sequence (FCS).',
    },
    {
      title: "Step 2: The Valid Scenario — Bob verifies a clean packet",
      speaker: "Bob",
      content:
        "The packet arrives without interference. Bob's network card calculates CRC-32 over the received payload. The result matches the transmitted FCS `0x7E060C31` perfectly! Bob confirms the data is intact and forwards the packet up to the TCP/IP stack.",
    },
    {
      title: "Step 3: The Invalid Scenario — Lightning causes burst line noise",
      speaker: "Bob",
      content:
        "In a second transmission, lightning strikes near the outdoor cabling. Electromagnetic interference flips 3 adjacent bits. In an additive checksum, compensating errors (one bit 0→1, another 1→0) could cancel out. But CRC polynomial division treats bits as Galois field coefficients—burst errors up to 32 bits wide are mathematically guaranteed to alter the remainder.",
    },
    {
      title: "Step 4: Bob catches the corruption and drops the frame",
      speaker: "Bob",
      content:
        "Bob recalculates CRC-32 over the noisy packet. The computed remainder is completely different and fails to match `0x7E060C31`. Bob's hardware flags an FCS error and discards the damaged frame. Ethernet does not request retransmission itself; a higher-layer protocol may recover the lost data.",
      callout: {
        type: "warning",
        text: "CRC is strictly for accidental noise. Given any target CRC and the freedom to change a few bytes, producing data that matches it is straightforward arithmetic. It provides zero security against Mallory!",
      },
    },
  ],
  takeaways: [
    "CRC uses polynomial division over Galois fields to catch multi-bit burst errors.",
    "Every PNG image, ZIP file, SATA hard drive, and Ethernet packet relies on CRC-32.",
    "CRC is NOT a cryptographic tool: Mallory can forge matching CRCs in a fraction of a millisecond.",
  ],
  seed: {
    toolId: "crc32",
    sampleInput: "Download packet #4096",
    explanation: "Open CRC-32 Workbench to calculate IEEE 802.3 polynomial remainders live.",
  },
};

export default content;
