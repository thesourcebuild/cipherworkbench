import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Anyone can print a badge that says 'Bob'. A useful badge needs more: Bob's identity, Bob's public key, an expiry date, and a tamper-resistant signature from an issuer Alice already trusts. A digital certificate is that signed badge. A certificate chain lets an offline root authority delegate day-to-day issuance to intermediate authorities without exposing the root key.",
  problem:
    "Anyone can generate a keypair and claim the public key belongs to `bank.example`. If Alice accepts the first key she receives, Mallory can substitute her own key, decrypt and relay the traffic, and impersonate Bob to Alice. How can Alice authenticate Bob's public key before trusting it?",
  visualization: { kind: "cryptographic-flow", id: "certificate" },
  steps: [
    {
      title: "Step 1: Mallory substitutes an unauthenticated public key",
      speaker: "Mallory",
      content:
        "Alice asks for Bob's public key over an untrusted network. Mallory intercepts the request and returns **Mallory's public key** labeled as Bob's. If Alice has no trusted reference, encryption alone cannot reveal the substitution. Mallory can decrypt Alice's messages, read or modify them, then re-encrypt them for Bob.",
      callout: {
        type: "warning",
        text: "Public-key cryptography solves key secrecy, not key identity. An unauthenticated public key remains vulnerable to a man-in-the-middle attack.",
      },
    },
    {
      title: "Step 2: Bob creates a keypair and certificate request",
      speaker: "Bob",
      content:
        "Bob generates a private key that stays on his server and a corresponding public key. He creates a **Certificate Signing Request (CSR)** containing the public key and requested identities, such as `bank.example`, then signs the CSR with the private key. The signature proves control of that key to the Certificate Authority; it does not by itself prove control of the domain.",
    },
    {
      title: "Step 3: Trent validates Bob and issues a certificate",
      speaker: "Trent",
      content:
        "Trent, acting as a public Certificate Authority, validates that Bob controls `bank.example`. Public web certificates are usually **domain validated**; they do not necessarily verify the operator's legal identity. Trent's intermediate CA signs a leaf certificate that binds Bob's public key to the authorized DNS name, validity period, and permitted uses. The intermediate is itself signed by a root CA whose key is kept highly protected.",
      callout: {
        type: "info",
        text: "Using an intermediate CA limits exposure of the root key. The root can remain offline while the intermediate handles routine certificate issuance.",
      },
    },
    {
      title: "Step 4: Bob presents the certificate chain",
      speaker: "Bob",
      content:
        "During the TLS handshake, Bob sends his **leaf certificate** and the intermediate certificates needed to build a path toward a trusted root. Servers normally omit the root certificate because Alice's browser or operating system already has its own root trust store. The certificates are public; their purpose is authentication, not secrecy.",
    },
    {
      title: "Step 5: Alice validates the chain and server identity",
      speaker: "Alice",
      content:
        "Alice verifies every certificate signature up to a root in her trust store. She also checks the validity period, CA constraints, key usage, and that the requested hostname appears in the leaf certificate's **Subject Alternative Name (SAN)**. Depending on client policy and available mechanisms, she may also evaluate revocation information. Any failed check must stop the authenticated connection.",
      callout: {
        type: "security",
        text: "A mathematically valid chain is not enough: trusting the wrong root or skipping SAN/hostname validation still allows Mallory to impersonate Bob.",
      },
    },
    {
      title: "Step 6: Bob proves possession of the private key",
      speaker: "Bob",
      content:
        "A copied certificate is public and proves nothing by itself. In TLS 1.3, Bob sends `CertificateVerify`, a signature over the handshake transcript made with the private key corresponding to the certified public key. Alice verifies that signature and then the `Finished` message. Mallory cannot complete the authenticated handshake using Bob's certificate without Bob's private key.",
    },
  ],
  afterTimeline: {
    title: "What a certificate does not guarantee",
    content:
      "A certificate does **not encrypt application data**, prove that a website is honest, or make an endpoint secure. It binds a public key to an identity under a particular trust policy. A compromised or misbehaving CA can misissue certificates, and a phishing site can obtain a valid certificate for a domain it legitimately controls. Standard HTTPS authenticates the server; **mutual TLS (mTLS)** additionally asks the client to present a certificate and prove possession of its private key.",
    callout: {
      type: "warning",
      text: "Certificates make authentication possible only when chain building, hostname checks, trust-store policy, and private-key proof are all enforced.",
    },
  },
  takeaways: [
    "An unauthenticated public key can be replaced by an active man-in-the-middle attacker.",
    "An X.509 leaf certificate binds a public key to DNS names and other attributes under a CA's signature.",
    "Clients validate a chain to a locally trusted root and independently check SAN, validity, constraints, and key usage.",
    "TLS requires proof of the certified private key; presenting a public certificate alone is insufficient.",
    "Certificates authenticate identities under a trust policy, but they do not encrypt data or guarantee that a site is trustworthy.",
  ],
  seed: {
    toolId: "cert-creator",
    sampleInput: "",
    explanation:
      "Open Certificate Creator to inspect certificate fields and generate self-signed or CA-signed X.509 certificates.",
  },
};

export default content;
