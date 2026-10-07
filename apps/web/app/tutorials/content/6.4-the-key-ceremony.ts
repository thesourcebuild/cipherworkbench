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
        text: "FIPS 140-2 or FIPS 140-3 Level 3 (physical tamper-resistance) or Level 4 (environmental tamper-resistance) HSMs are required for Root CA operations by the CA/Browser Forum Baseline Requirements.",
      },
    },
    {
      title: "Step 3: The Ceremony — Zero Single Points of Failure",
      speaker: "Trent",
      content:
        "A Root CA key generation ceremony is a formal, audited, multi-person ritual:\n\n1. **Air-gapped room** — no network connections, no phones, Faraday cage against RF exfiltration.\n2. **Video recording** — a notary and multiple independent auditors film every action.\n3. **M-of-N activation cards** — Shamir's Secret Sharing (Tutorial 6.5) splits the HSM's master domain key / activation secret across N smart cards held by trusted key custodians in different locations. M cards are required to activate or authorize the HSM. No single person can activate it.\n4. **Script-driven** — every command is pre-written, reviewed, and read aloud before execution. No improvisation.\n5. **Signed transcript** — the ceremony produces a signed, timestamped audit log that is publicly published.",
      callout: {
        type: "security",
        text: "In practice, Shamir's Secret Sharing is used to split the HSM's master domain key / activation secret, rather than the raw RSA/ECDSA private key directly. The Root CA private key is generated purely inside the HSM's cryptographic boundary and never leaves it in plaintext under any circumstances.",
      },
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
      title: "Step 5: Key Lifecycles and Three-Tier Revocation",
      speaker: "Trent",
      content:
        "Root CA certificates are issued with long lifespans (typically **20–25 years**, such as Let's Encrypt's `ISRG Root X1` or `DigiCert Global Root CA`). This extended period is necessary because achieving universal trust across billions of devices—smartphones, laptops, smart TVs, and embedded IoT—requires a 5–10 year 'root proliferation' phase.\n\nRoot keys are **not rotated in-place**: you cannot simply replace the private key of an existing trust anchor without breaking every client certificate. Instead, CAs generate a brand new Root CA in a ceremony, cross-sign it with the existing root for backwards compatibility, and operate both in parallel over a decade-long transition.\n\n**What happens if a certificate in the chain is compromised?**\n\n1. **Leaf (Website) Certificate:** The issuing Intermediate CA revokes the certificate via **CRL** or **OCSP / OCSP Stapling** (RFC 6066). Modern short certificate lifespans (90 days) ensure exposure is strictly limited even if revocation fails.\n2. **Intermediate CA (Sub-CA):** The Root CA publishes a CRL revoking the subordinate CA, and browser vendors immediately push out-of-band blocks directly to users via **Chrome CRLSets** and **Firefox OneCRL** within hours.\n3. **Root CA Compromise:** Because a Root CA is a self-signed **trust anchor**, it cannot be revoked via its own CRL or OCSP (an attacker holding the key could forge valid status responses). It must be untrusted globally via **emergency OS and browser root-store updates** (e.g., Windows Update, Apple Software Update, Chrome Root Store), as occurred during the catastrophic DigiNotar breach in 2011.",
      callout: {
        type: "security",
        text: "Self-signed trust anchors cannot revoke themselves: if a Root CA key is compromised, CRL and OCSP are useless because the attacker can forge signed 'Good' responses. Only out-of-band root store updates from OS and browser vendors can strip trust from a compromised Root CA.",
      },
    },
  ],
  takeaways: [
    "Root CA private keys are the most critical secrets in the internet's trust infrastructure — compromise means global forgery.",
    "Hardware Security Modules (HSMs) generate and protect keys within a physical tamper-resistant cryptographic boundary.",
    "Key ceremonies use air-gapped rooms, video auditors, and M-of-N Shamir activation cards to eliminate single points of failure.",
    "Certificate Transparency logs make every issued certificate publicly auditable — rogue certificates are detectable in minutes.",
    "Leaf certs revoke via OCSP Stapling and CRLs, but a compromised Root CA requires emergency OS and browser root store updates.",
  ],
  seed: {
    toolId: "cert-creator",
    sampleInput: "",
    explanation:
      "Open Certificate Workbench to inspect and generate X.509 certificates — observe the chain of trust from Root CA to Intermediate CA to end-entity certificate.",
  },
};

export default content;
