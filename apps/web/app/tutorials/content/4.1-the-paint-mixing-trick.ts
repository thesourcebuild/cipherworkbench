import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Mixing paints is easy, but separating mixed paint back into its original ingredients is virtually impossible. Alice and Bob publicly agree on Yellow. Alice secretly picks Red (sends Orange). Bob secretly picks Blue (sends Green). Both add their secret colors to the other's mixture to arrive at the exact same secret Brown — without ever sending Brown across the wire!",
  problem:
    "Can two parties establish a shared secret key over an insecure, monitored wire without sending the key itself?",
  steps: [
    {
      title: "Step 1: Public Base Color",
      speaker: "Alice",
      content:
        "Alice and Bob publicly pick a common base: **Yellow** (in elliptic curve math, a publicly known base point on curve X25519). Eve hears this — that is fine, knowing Yellow tells her nothing useful.",
    },
    {
      title: "Step 2: Alice & Bob pick Secret Colors",
      speaker: "Bob",
      content:
        "- Alice secretly picks **Red** (her private scalar key).\n- Bob secretly picks **Blue** (his private scalar key).\n\nNeither tells anyone — not even each other. These private colors never leave their owners.",
    },
    {
      title: "Step 3: Mixing and Exchanging",
      content:
        "- Alice mixes Yellow + Red → **Orange** and sends Orange across the wire.\n- Bob mixes Yellow + Blue → **Green** and sends Green across the wire.\n\nEve captures both Orange and Green, but **cannot unmix them** to discover Red or Blue. Paint mixing (and elliptic curve point multiplication) is a one-way operation — trivial to compute forward, computationally infeasible to reverse.",
    },
    {
      title: "Step 4: The Shared Secret is Born",
      content:
        "- Alice takes Bob's **Green** (Yellow + Blue) and mixes in her secret **Red** → **Brown**.\n- Bob takes Alice's **Orange** (Yellow + Red) and mixes in his secret **Blue** → **Brown**.\n\nBoth independently arrive at the exact same secret color — **Brown** — and passive Eve has no way to reproduce it!",
      callout: {
        type: "info",
        text: "Every HTTPS connection your browser makes uses ECDH (specifically curve X25519) to establish a fresh session key in milliseconds. This is happening right now as you browse the web.",
      },
    },
    {
      title: "Step 5: The Fatal Catch — The Man-in-the-Middle (MitM) Attack",
      speaker: "Mallory",
      content:
        "Notice who was watching in this scenario: **Eve, a passive eavesdropper**. What if **Mallory, an active attacker**, intercepts the wire?\n\nMallory intercepts Alice's Orange and sends Bob *Mallory's mixture* instead. Mallory intercepts Bob's Green and sends Alice *Mallory's mixture* instead.\n\nNow Alice establishes a shared Brown with Mallory — not Bob. Bob establishes a separate shared Brown with Mallory — not Alice. Mallory decrypts, reads, re-encrypts, and forwards all traffic undetected.\n\n**Unauthenticated Diffie-Hellman defeats passive Eve, but falls completely to active Mallory.** To stop Mallory, public keys must be authenticated using **Digital Signatures (Tutorial 4.3)** and **Certificates (Tutorial 5.2)**.",
      callout: {
        type: "security",
        text: "A fundamental cryptographic law: Diffie-Hellman provides **secrecy**, NOT **authentication**. Without signatures or certificates, unauthenticated DH is trivially hijacked by any active attacker on the wire.",
      },
    },
  ],
  takeaways: [
    "Diffie-Hellman allows two parties with no prior relationship to establish a shared secret without transmitting it.",
    "The security relies on the one-way nature of the operation: easy to mix, impossible to unmix.",
    "Unauthenticated DH only protects against passive eavesdroppers — an active MitM (Mallory) breaks it completely.",
    "Real-world protocols (TLS 1.3) pair ECDH with digital certificates and signatures to prove identity.",
  ],
  seed: {
    toolId: "ecdh",
    sampleInput: "",
    explanation:
      "Open ECDH (X25519) Workbench to generate Alice and Bob keys and compute their shared secret live.",
  },
};

export default content;
