import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Imagine a long mathematical division problem. You divide a huge number by a special prime polynomial and keep only the remainder (like the change left over in your pocket). If even a tiny cluster of bits flips, the remainder completely changes.",
  "problem": "Why do simple addition checksums fail when network noise flips multiple bits, and how does CRC solve telecommunication burst errors?",
  "steps": [
    {
      "title": "Step 1: Alice transmits a packet",
      "speaker": "Alice",
      "content": "Alice transmits network packet: `\"Download packet #4096\"`. Her network card runs CRC-32 (IEEE 802.3 standard) and appends the 32-bit remainder `0x9c42a1b7` to the end of the frame."
    },
    {
      "title": "Step 2: Lightning causes burst line noise",
      "speaker": "Bob",
      "content": "As the packet travels down the copper wire, electrical interference flips 3 adjacent bits. In a simple addition checksum, one bit going 0→1 and another going 1→0 can cancel each other out! But CRC polynomial division treats bits as coefficients of a polynomial: errors do not cancel out."
    },
    {
      "title": "Step 3: Bob detects the burst error",
      "speaker": "Bob",
      "content": "Bob recalculates the CRC-32 over the received packet. The remainder doesn't match! The Ethernet card drops the packet and automatically requests a clean retransmission.",
      "callout": {
        "type": "warning",
        "text": "CRC is strictly for accidental noise. Given any target CRC and the freedom to change a few bytes, producing data that matches it is straightforward arithmetic. It provides zero security against Mallory!"
      }
    }
  ],
  "takeaways": [
    "CRC uses polynomial division over Galois fields to catch multi-bit burst errors.",
    "Every PNG image, ZIP file, SATA hard drive, and Ethernet packet relies on CRC-32.",
    "CRC is NOT a cryptographic tool: Mallory can forge matching CRCs in a fraction of a millisecond."
  ],
  "seed": {
    "toolId": "crc32",
    "sampleInput": "Download packet #4096",
    "explanation": "Open CRC-32 Workbench to calculate IEEE 802.3 polynomial remainders live."
  }
};

export default content;
