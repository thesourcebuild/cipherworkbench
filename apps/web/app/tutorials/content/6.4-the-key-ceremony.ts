import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "The Vatican elects a new Pope through an elaborate ritual in a sealed room with no outside communication. Witnesses watch every step, the ballots are burned with coloured smoke to signal results, and the new Pope only appears publicly after a formal process involving multiple independent verifiers. Root CA key ceremonies are cryptography's equivalent — maximum paranoia to protect the most trusted key in the world.",
  problem:
    "Every HTTPS certificate on the internet chains back to a small set of Root CA private keys. If any one of these is compromised, every TLS connection globally can be forged. How do you protect a private key that must never touch a network, never exist on a single person's device, and must survive for 20 years?",
  steps: [
    {
      title: "Step 1: What a Root CA Key Is",
      speaker: "Trent",
      content:
        "A **Root Certificate Authority (Root CA)** is an entity whose public key is pre-installed in every operating system, browser, and device on the planet — approximately 3–5 billion devices.\n\nThe corresponding **Root CA private key** is used to sign Intermediate CA certificates, which in turn sign the TLS certificates for every website.\n\nIf Mallory steals this key, she can issue valid certificates for `google.com`, `bankofamerica.com`, or any domain — and every browser will silently accept them as legitimate.",
    },
    {
      title: "Step 2: The Hardware Security Module (HSM)",
      speaker: "Trent",
      content:
        "A **Hardware Security Module (HSM)** is a tamper-resistant physical device designed to generate, store, and use cryptographic keys — but never export them in plaintext.\n\n- If Mallory drills into the HSM, it destroys the key.\n- If she applies a voltage surge, it destroys the key.\n- If she attempts too many wrong PINs, it destroys the key.\n- The key can be used (to sign) but never read, copied, or extracted.\n\nRoot CA keys are generated inside an HSM and never leave it — ever.",
      callout: {
        type: "security",
        text: "FIPS 140-2 Level 3 (physical tamper-resistance) or Level 4 (environmental tamper-resistance) HSMs are required for Root CA operations by the CA/Browser Forum Baseline Requirements.",
      },
    },
    {
      title: "Step 3: The Ceremony — Zero Single Points of Failure",
      speaker: "Trent",
      content:
        "A Root CA key generation ceremony is a formal, audited, multi-person ritual:\n\n1. **Air-gapped room** — no network connections, no phones, Faraday cage against RF exfiltration.\n2. **Video recording** — a notary and multiple independent auditors film every action.\n3. **M-of-N activation cards** — the HSM's master activation is split using Shamir's Secret Sharing (Tutorial 5.4) across N smart cards held by N different trusted individuals in different countries. M cards are required to activate the HSM. No single person can activate it.\n4. **Script-driven** — every command is pre-written, reviewed, and read aloud before execution. No improvisation.\n5. **Signed transcript** — the ceremony produces a signed, timestamped audit log that is publicly published.",
    },
    {
      title: "Step 4: Certificate Transparency — Public Accountability",
      speaker: "Bob",
      content:
        "Even with all these safeguards, a rogue or compromised CA could issue fraudulent certificates. In 2011, attackers breached Dutch CA DigiNotar and issued fraudulent wildcard certificates for Google to spy on Iranian users. The rogue certs were caught only because Chrome had experimental public-key pinning hardcoded into the browser. That near-catastrophe inspired the creation of **Certificate Transparency (CT)**: a public append-only cryptographic log (using Merkle trees) of every certificate ever issued.\n\nBrowsers now require all TLS certificates to appear in public CT logs before trusting them. If a certificate is issued for `google.com` without Google's knowledge, automated monitoring systems detect it within minutes.",
      callout: {
        type: "info",
        text: "You can inspect any website's certificate history at crt.sh — a public CT log search engine. Every certificate ever issued for your domain is permanently recorded there.",
      },
    },
    {
      title: "Step 5: Key Rotation and Revocation",
      speaker: "Trent",
      content:
        "Root CA private keys are rotated every 20–25 years. But if a key is compromised before rotation:\n\n- **CRL (Certificate Revocation List):** A signed list of revoked certificate serial numbers. Browsers download it periodically — but it is often stale.\n- **OCSP (Online Certificate Status Protocol):** Real-time revocation check. But adds latency and leaks browsing history to the CA.\n- **OCSP Stapling:** The web server fetches and caches the OCSP response, serving it with the TLS handshake. No third-party query needed.\n- **Chrome's CRLSet / Firefox's OneCRL:** Browser vendors push emergency revocation lists to all users within hours of a major CA compromise.",
    },
  ],
  takeaways: [
    "Root CA private keys are the most critical secrets in the internet's trust infrastructure — compromise means global forgery.",
    "Hardware Security Modules (HSMs) generate and use keys without ever exporting them in plaintext.",
    "Key ceremonies use air-gapped rooms, video auditors, and M-of-N Shamir activation to eliminate single points of failure.",
    "Certificate Transparency logs make every issued certificate publicly auditable — rogue certificates are detectable in minutes.",
    "OCSP Stapling is the modern revocation mechanism — eliminates third-party queries while keeping revocation real-time.",
  ],
  seed: {
    toolId: "cert-creator",
    sampleInput: "",
    explanation:
      "Open Certificate Workbench to inspect and generate X.509 certificates — observe the chain of trust from Root CA to Intermediate CA to end-entity certificate.",
  },
};

export default content;
