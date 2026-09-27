import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "If a stranger on the street hands you an open padlock with the label 'Bank of America', how do you know it really belongs to the bank? Because it comes with a government-certified passport signed by Trent, whose signature is pre-installed in your trust store.",
  "problem": "Anyone can generate an RSA or Ed25519 keypair claiming to belong to 'google.com'. How does Alice know she is actually talking to Bob and not to Mallory pretending to be Bob?",
  "steps": [
    {
      "title": "Step 1: Mallory's Man-in-the-Middle Attack",
      "speaker": "Mallory",
      "content": "1. Alice asks for Bob's public key.\n2. Mallory intercepts Bob's key and hides it in her pocket.\n3. Mallory sends **Mallory's public key** to Alice, claiming: *'Here is Bob's key!'*\n4. Alice encrypts her secret with Mallory's key.\n5. Mallory decrypts, reads everything, re-encrypts with Bob's real key, and forwards it to Bob.\nNeither Alice nor Bob realizes they are being spied on!"
    },
    {
      "title": "Step 2: Enter Trent, the Trusted Authority",
      "speaker": "Trent",
      "content": "To defeat Mallory, Bob visits **Trent** (a Certificate Authority). Bob proves his legal identity. Trent inspects Bob's public key, bundles it into an **X.509 Certificate**, and digitally signs it with Trent's Root CA key."
    },
    {
      "title": "Step 3: Alice verifies Bob's Certificate",
      "speaker": "Alice",
      "content": "When Bob connects, he presents his certificate. Alice verifies Trent's digital signature (which is already trusted in her operating system trust store). Alice confirms the key belongs to Bob, completely foiling Mallory!",
      "callout": {
        "type": "security",
        "text": "See Cipher Workbench's PKI Guide for full details on 2-tier and 3-tier certificate hierarchies and dual-stack localhost SAN validation."
      }
    }
  ],
  "takeaways": [
    "Public-key encryption alone cannot prevent Man-in-the-Middle (MitM) attacks.",
    "Certificate Authorities (CAs) act as trusted introducers by digitally signing public keys.",
    "X.509 certificates bind a public key to an authenticated domain name or identity.",
    "In standard HTTPS, certificates authenticate the server to the client; mutual TLS (mTLS) extends this to verify both parties."
  ],
  "seed": {
    "toolId": "cert-creator",
    "sampleInput": "",
    "explanation": "Open Certificate Creator to inspect and generate self-signed and CA-signed X.509 certificates live."
  }
};

export default content;
