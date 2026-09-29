import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Think of an international spy rendezvous — three phases that happen in rapid succession:\n\n1. **Verify credentials & passport** — Each agent presents a signed certificate from a trusted authority (CA) proving their identity. Forgeries are instantly rejected.\n2. **Agree on a secret code in public** — Using the paint-mixing trick (ECDH), both agents derive the same shared secret even while speaking openly. Any eavesdropper watching learns nothing.\n3. **Switch to high-speed encrypted walkie-talkies** — Once the shared secret is established, all further communication uses fast symmetric encryption (AES-GCM). Content is hidden; tampering is impossible.",
  "problem": "How do modern systems combine asymmetric keys, symmetric ciphers, and hash functions into one seamless, blazingly fast protocol?",
  "steps": [
    {
      "title": "Step 1: Client Hello & Ephemeral Key Share",
      "speaker": "Alice",
      "content": "Alice (browser) sends a `ClientHello` with her ephemeral ECDH public key (X25519) and a list of supported ciphers (e.g. `TLS_AES_256_GCM_SHA384`)."
    },
    {
      "title": "Step 2: Server Hello & Certificate Proof",
      "speaker": "Bob",
      "content": "Bob (server) responds with his ephemeral ECDH public key, his X.509 Certificate, and a digital signature proving he owns the domain private key."
    },
    {
      "title": "Step 3: Key Derivation (HKDF)",
      "speaker": "Alice",
      "content": "Both Alice and Bob combine their ECDH shares to produce the master secret, and feed it into HKDF (HMAC-based Key Derivation Function) to derive the symmetric AEAD traffic keys and IVs."
    },
    {
      "title": "Step 4: Encrypted Application Data",
      "content": "From this millisecond onward, all HTTP traffic, passwords, and credit card numbers are transmitted using AES-GCM or ChaCha20-Poly1305. Eve sees only encrypted bytes, and Mallory cannot modify a single bit.",
      "callout": {
        "type": "security",
        "text": "Forward Secrecy: In TLS 1.3, ephemeral ECDH keys are thrown away after each session. Even if Bob's private server key is stolen next year, past recorded traffic cannot be decrypted!"
      }
    }
  ],
  "takeaways": [
    "Modern secure channels never use just one algorithm; they use a coordinated suite.",
    "Asymmetric cryptography (ECDH/Signatures) handles the handshake; Symmetric cryptography (AES-GCM) handles the bulk data.",
    "TLS 1.3 eliminates legacy insecure handshakes and mandates Perfect Forward Secrecy."
  ],
  "seed": {
    "toolId": "ecdh",
    "sampleInput": "",
    "explanation": "Open ECDH Workbench to test the ephemeral key exchange that initiates every TLS 1.3 connection."
  }
};

export default content;
