import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "In medieval times, a king pressed his unique personal signet ring into hot wax on a royal decree. Anyone who knew the royal crest could see it was authentic, but no one could duplicate the wax seal without holding the physical ring.",
  "problem": "How can Alice digitally sign a public document so that anyone can verify it, but nobody can forge it?",
  "steps": [
    {
      "title": "Step 1: Alice creates her Signet Ring",
      "speaker": "Alice",
      "content": "Alice creates an Ed25519 keypair:\n- **Private Key (Signet Ring):** Kept secure in Alice's hardware token.\n- **Public Key (Royal Crest):** Distributed to Bob and the public."
    },
    {
      "title": "Step 2: Alice Signs the decree",
      "speaker": "Alice",
      "content": "Alice hashes her decree, then uses her Private Key to mathematically stamp the hash. This stamp is called a **Digital Signature**."
    },
    {
      "title": "Step 3: Bob verifies the seal",
      "speaker": "Bob",
      "content": "Bob takes Alice's Public Key, the decree, and the signature. He clicks **Verify** in Cipher Workbench. The verification math confirms: only the holder of Alice's private key could have produced this signature for this exact text!"
    },
    {
      "title": "Step 4: Mallory attempts a forgery",
      "speaker": "Mallory",
      "content": "Mallory tries to send Bob a fake message claiming to be Alice. Because Mallory does not possess Alice's private key, any signature Mallory fabricates will be instantly rejected by Bob's verification math.",
      "callout": {
        "type": "info",
        "text": "Non-repudiation: Once Alice signs a message, she cannot claim 'I didn't send that,' because only her private key could have generated the signature."
      }
    },
    {
      "title": "Step 5: The Critical Catches — No Secrecy & Key Distribution",
      "speaker": "Eve",
      "content": "1. **Zero Confidentiality:** Alice's signed message is public. Eve reads every single word! Digital signatures verify *who wrote the text*, not *hide the text*.\n2. **The Public Key Trust Problem:** Bob verified using 'Alice's Public Key'. But how does Bob know that public key truly belongs to Alice? If Mallory had uploaded her own key labeled 'Alice', Bob would have been deceived!\nTo solve this, we need **Trent & Certificate Authorities (Section 5: Certificates & PKI)**.",
      "callout": {
        "type": "warning",
        "text": "A signature is only as trustworthy as your certainty of who owns the public key. This is why web browsers use Certificate Authorities (X.509 PKI)."
      }
    }
  ],
  "takeaways": [
    "Digital signatures provide both Authenticity (who sent it) and Integrity (it wasn't modified).",
    "You sign with your Private Key; anyone in the world verifies with your Public Key.",
    "Signatures do NOT conceal data: the message remains completely unencrypted and readable.",
    "Verifying a signature requires trustworthy public key distribution, solved by X.509 PKI (Section 5)."
  ],
  "seed": {
    "toolId": "ed25519",
    "sampleInput": "Official executive order signed by Alice",
    "explanation": "Open Ed25519 Workbench to generate a keypair, sign Alice's decree, and verify the signature."
  }
};

export default content;
