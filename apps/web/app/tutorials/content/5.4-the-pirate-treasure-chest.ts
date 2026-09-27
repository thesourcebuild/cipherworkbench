import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Any 2 points in space draw a straight line. But to define a specific curved parabola (y = ax² + bx + c), you mathematically require **3 distinct points**. Alice hides the secret at the y-intercept of the curve, and hands 1 point to each lieutenant.",
  "problem": "How can an organization eliminate single points of failure for root master keys without risking extortion or loss?",
  "steps": [
    {
      "title": "Step 1: Alice creates a Secret Polynomial",
      "speaker": "Alice",
      "content": "Alice sets Secret = `MasterVaultCode-Alpha-Omega`. She configures a threshold of **k = 3** (minimum shares needed to recover) and distributes **n = 5** total shares. A degree-2 polynomial is generated over a Galois finite field."
    },
    {
      "title": "Step 2: Distributing the 5 Shares",
      "speaker": "Alice",
      "content": "Alice hands 1 share to Bob, 1 to Charlie, 1 to Dave, 1 to Eve, and 1 to Frank. None of them can decipher the secret alone."
    },
    {
      "title": "Step 3: Two Rogues Fail",
      "speaker": "Eve",
      "content": "Eve and Charlie collude. They put their 2 shares together. Because 2 points can fit an infinite number of parabolas, they have **zero mathematical information** about the secret!"
    },
    {
      "title": "Step 4: The 3rd Lieutenant Arrives",
      "speaker": "Bob",
      "content": "Bob joins with his 3rd share. With 3 points, Lagrange polynomial interpolation locks into the unique curve, instantly recovering Alice's original secret code.",
      "callout": {
        "type": "info",
        "text": "Information-Theoretic Secrecy: Having fewer than k shares leaks zero bits about the secret. However, basic Shamir's scheme does not verify share authenticity; production systems use Verifiable Secret Sharing (VSS) or digital signatures to detect fake shares submitted by rogue participants."
      }
    }
  ],
  "takeaways": [
    "Threshold cryptography allows k-of-n recovery of master secrets — any k holders can reconstruct; fewer cannot.",
    "Having fewer than k shares yields zero leaked bits about the original secret (information-theoretically secure).",
    "Plain Shamir provides confidentiality but not share integrity; production setups sign each share.",
    "Widely used in hardware security modules (HSMs), cryptocurrency multisig, and disaster recovery."
  ],
  "seed": {
    "toolId": "shamir",
    "sampleInput": "MasterVaultCode-Alpha-Omega",
    "explanation": "Open Shamir's Secret Sharing in the workbench to split a secret and test recovery with different shares."
  }
};

export default content;
