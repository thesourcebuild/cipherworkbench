import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  visualization: { kind: "cryptographic-flow", id: "ecdh" },
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
        "- Alice takes Bob's **Green** (Yellow + Blue) and mixes in her secret **Red** → **Brown**.\n- Bob takes Alice's **Orange** (Yellow + Red) and mixes in his secret **Blue** → **Brown**.\n\nBoth independently arrive at the exact same secret color — **Brown** — and passive Eve has no way to reproduce it. In a real protocol, the raw ECDH result goes through a key-derivation function before becoming an encryption or authentication key.",
      callout: {
        type: "info",
        text: "Modern TLS commonly uses ephemeral ECDH with X25519 or P-256, then passes the shared secret through a key-derivation function to create fresh traffic keys.",
      },
    },
  ],
  afterTimeline: {
    title: "After the Timeline: Authenticate ECDH to stop MitM",
    content:
      "The timeline defeats passive Eve, but an active man-in-the-middle attacker such as Mallory can intercept both public shares and substitute her own. Alice then derives one secret with Mallory while Bob derives another, allowing Mallory to decrypt and relay traffic. Real protocols authenticate the exchange with signatures, certificates, or a previously established secret.",
    callout: {
      type: "security",
      text: "Diffie-Hellman provides key agreement, not identity. Unauthenticated ECDH is vulnerable to an active man-in-the-middle attacker.",
    },
  },
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
