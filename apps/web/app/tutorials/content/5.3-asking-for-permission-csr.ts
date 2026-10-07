import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "When applying for an official government passport, you supply your name, address, photo, and signature on a paper application form. You never hand over your internal memories, diary, or brain! A Certificate Signing Request (CSR) is that formal application: Bob puts his public photo (Public Key) and server identities on the form, then seals it with his private signature (Proof-of-Possession). The Certificate Authority verifies the form and issues the passport — without ever touching Bob's private key.",
  problem:
    "To obtain an X.509 certificate, Bob needs a Certificate Authority to sign his public key. How does Bob prove to the CA that he owns the private key without ever sending the private key across the network, and how does the CA ensure Bob really controls the domain name?",
  steps: [
    {
      title: "Step 1: The sacred rule: Private keys never leave home",
      speaker: "Bob",
      content:
        "Bob generates a cryptographic keypair (RSA-2048, ECDSA P-256, or Ed25519) directly on his server. The golden rule of Public Key Infrastructure is:\n\n**A private key must NEVER leave the machine where it was generated.**\n\nIt must never be emailed, pasted into an online web form, uploaded to a CA portal, or stored in cloud backups. Any CA that asks you to upload your private key is insecure.",
      callout: {
        type: "security",
        text: "If a private key is transmitted across the internet, its secrecy is forever suspect. True security requires generating keys locally inside secure storage.",
      },
    },
    {
      title: "Step 2: Constructing the PKCS#10 structure",
      speaker: "Bob",
      content:
        "Bob packages his public key and intended credentials into a standardized ASN.1 DER data structure called **PKCS#10 (RFC 2986)**:\n\n1. **Subject Distinguished Name (DN):** Common Name (CN), Organization (O), Country (C).\n2. **Public Key Information:** Algorithm OID and raw public key bytes.\n3. **Requested Attributes & Extensions:** Specifically, the **Subject Alternative Name (SAN)** list (e.g. `DNS:bank.example`, `DNS:*.bank.example`).",
    },
    {
      title: "Step 3: Proof-of-Possession (PoP) signature",
      speaker: "Bob",
      content:
        "Anyone can copy Bob's public key from a public website. How does Trent the CA know that the entity requesting the certificate actually owns the corresponding private key?\n\nBob signs the entire CSR payload with his **own private key**. This self-signature serves as a mathematical **Proof-of-Possession (PoP)**. Trent verifies this signature using the public key inside the request before proceeding.",
      callout: {
        type: "info",
        text: "Proof-of-Possession guarantees that only someone holding the private key could have created the request. It prevents Mallory from requesting a cert with Bob's public key.",
      },
    },
    {
      title: "Step 4: SANs vs Common Name: The deprecation of CN",
      speaker: "Trent",
      content:
        "In the early days of SSL, web browsers matched the website URL against the certificate's `Common Name` (e.g., `CN=example.com`).\n\nHowever, Common Name only supported a single string and lacked clean parsing semantics. RFC 6125 and the CA/Browser Forum Baseline Requirements officially deprecated Common Name matching. Modern browsers (Chrome, Firefox, Safari) **strictly ignore the Common Name** for hostname validation! Every valid domain name must now be explicitly listed in the **Subject Alternative Name (SAN)** extension.",
    },
    {
      title: "Step 5: Domain Validation: Trent challenges Bob",
      speaker: "Trent",
      content:
        "Proof-of-Possession proves Bob has the private key, but it does NOT prove Bob owns `bank.example`! If Mallory generated her own keypair, she could create a valid CSR for `bank.example`.\n\nBefore issuing a certificate, Trent must independently verify domain control. Trent gives Bob an automated validation challenge:\n\n- **HTTP Validation:** Bob hosts a token at `http://bank.example/.well-known/acme-challenge/<token>`.\n- **DNS Validation:** Bob creates a DNS TXT record `_acme-challenge.bank.example` with a cryptographic digest.\n\nMallory cannot place files on Bob's server or edit Bob's DNS records, so Mallory's fraudulent request fails.",
    },
    {
      title: "Step 6: Trent issues the signed X.509 certificate",
      speaker: "Trent",
      content:
        "Once Bob successfully passes domain validation, Trent takes Bob's public key and validated SANs from the CSR, assigns a serial number and validity dates, discards the temporary CSR self-signature, and signs the resulting X.509 certificate with Trent's intermediate CA private key.\n\nTrent returns the signed certificate to Bob. Bob installs it on his web server alongside his original, untouched private key.",
    },
  ],
  afterTimeline: {
    title: "Why algorithm selection in CSRs matters",
    content:
      "When generating a CSR today, engineers face a choice between legacy RSA (2048 or 4096-bit) and modern Elliptic Curves (such as ECDSA P-256 or Ed25519). A 256-bit ECDSA key provides equivalent security to a 3072-bit RSA key, but reduces TLS handshake payloads by hundreds of bytes and uses significantly less server CPU during handshakes.",
    callout: {
      type: "info",
      text: "ECDSA P-256 is the modern default for TLS web certificates, combining rapid signing speeds with compact packet sizes.",
    },
  },
  takeaways: [
    "Private keys must be generated locally and never transmitted across the network.",
    "A PKCS#10 CSR contains the public key, requested domains, and a Proof-of-Possession digital signature.",
    "Proof-of-Possession proves key ownership to the CA without exposing any private key bits.",
    "Subject Alternative Names (SANs) are mandatory for hostname verification; the legacy Common Name (CN) is ignored by modern browsers.",
    "CAs must perform independent domain control validation (via HTTP or DNS challenges) before issuing a certificate.",
  ],
  seed: {
    toolId: "csr-creator",
    sampleInput: "",
    explanation:
      "Open CSR Creator to generate standard PKCS#10 requests, configure Subject DN attributes, add multi-domain SANs, and inspect the ASN.1 structure.",
  },
};

export default content;
