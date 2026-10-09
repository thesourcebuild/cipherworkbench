import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Imagine arriving at an international border checkpoint. You show an ID badge claiming you are Bob. Anyone could print a plastic badge with the name 'Bob', so the border officer refuses to accept it on your word alone. Instead, you present a government-issued passport: your name and photo are bound together under an official holographic seal and digital signature from a sovereign state that the border officer already trusts.\n\nIn cryptography, a **Digital Certificate (X.509)** is that passport. It binds a server's public key to its real-world domain identity under the trusted digital signature of a Certificate Authority (CA).",
  problem:
    "If an asymmetric public key is just a number, how can Alice's browser verify that the public key she received over the internet really belongs to google.com and not to an imposter in the middle?",
  steps: [
    {
      title: "Step 1: What It Is (The Core Nature of PKI & Certificates)",
      speaker: "Trent",
      content:
        "Public Key Infrastructure (PKI) is the comprehensive ecosystem of Certificate Authorities, cryptographic standards (X.509 / RFC 5280), trust stores, and validation policies that binds cryptographic public keys to verifiable real-world identities, such as website domain names, organization titles, or email addresses.",
      callout: {
        type: "info",
        text: "The leaf certificate is the document; the PKI is the entire infrastructure—including Root CAs, Intermediate CAs, CSRs, CRLs, OCSP responders, and audit standards—that makes the document trustworthy.",
      },
    },
    {
      title: "Step 2: What It Does (The Identity Binding & Trust Chain Mechanism)",
      speaker: "Bob",
      content:
        "When Bob sets up a secure website, he creates a key pair and submits a Certificate Signing Request (CSR) to a Certificate Authority (Trent). Trent verifies that Bob truly controls the domain (e.g., via ACME automated DNS or HTTP challenges). Trent then signs an X.509 certificate that packages Bob's public key, domain names (Subject Alternative Names), and validity dates. When Alice visits Bob's website, her browser walks the cryptographic signature chain backward until it reaches a trusted Root CA stored inside her operating system.",
      callout: {
        type: "info",
        text: "A certificate chain typically has three tiers: Root CA (stored offline in a vault) -> Intermediate CA (issues daily certificates) -> End-Entity / Leaf Certificate (installed on Bob's web server).",
      },
    },
    {
      title: "Step 3: What It Can Do (Guarantees & Capabilities)",
      speaker: "Alice",
      content:
        "PKI solves the critical trust problem at global internet scale:\n\n* **Defeats Public Key Impersonation:** Mallory cannot forge a valid certificate for Bob's domain because she does not hold the CA's private signing key.\n* **Zero Configuration for Clients:** Millions of websites work automatically out of the box because operating systems and browsers ship with trusted Root CA stores.\n* **Automated Web Security:** Protocols like ACME (RFC 8555, popularized by Let's Encrypt) fully automate domain validation and certificate renewal, eliminating expired certificate outages.\n* **Public Transparency:** Certificate Transparency (CT) logs record all issued public certificates in publicly auditable, tamper-evident Merkle trees, ensuring rogue CAs are caught immediately.",
      callout: {
        type: "security",
        text: "Certificate Transparency logs ensure that no CA anywhere in the world can issue a secret certificate for your domain without it being publicly detected.",
      },
    },
    {
      title: "Step 4: What It Does NOT Do (Critical Security Boundaries)",
      speaker: "Mallory",
      content:
        "Certificates solve identity binding, but they do NOT provide blanket security against bad actors or server compromises:\n\n* **Does NOT guarantee a website is trustworthy or safe:** A Domain Validated (DV) certificate only proves the applicant controlled the domain name. Phishing sites, scam stores, and malware distributors easily obtain valid DV certificates!\n* **Does NOT protect against private key theft:** If an attacker compromises Bob's server and steals his private key, the certificate will validate the attacker's traffic as completely genuine until revoked.\n* **Does NOT encrypt data on its own:** A certificate is an authentication credential. It does not perform encryption itself; encryption is handled by the negotiated symmetric cipher (AES-GCM).\n* **Revocation is not instantaneous:** CRLs (Certificate Revocation Lists) and OCSP queries often fail open for performance reasons, meaning compromised certificates may still be accepted until cache TTLs expire.",
      callout: {
        type: "warning",
        text: "The padlock icon in your browser means 'your connection to this domain is encrypted and authenticated'—it does NOT mean 'this organization is honest and safe'.",
      },
    },
  ],
  takeaways: [
    "Certificates bind public keys to domain identities using trusted CA digital signatures.",
    "Trust is hierarchical: Root CAs delegate to Intermediate CAs, which sign leaf certificates.",
    "A valid certificate guarantees domain control, NOT that the website is safe or non-malicious.",
    "If a server's private key is stolen, the certificate remains dangerous until effectively revoked.",
    "Certificates provide authentication; negotiated session ciphers provide confidentiality.",
  ],
  seed: {
    toolId: "cert-creator",
    sampleInput: "CN=example.com, O=Example Corporation",
    explanation:
      "Open Certificate Creator in Cipher Workbench to inspect how Subject Alternative Names (SAN), Validity periods, and CA signatures assemble an X.509 certificate.",
  },
};

export default content;
