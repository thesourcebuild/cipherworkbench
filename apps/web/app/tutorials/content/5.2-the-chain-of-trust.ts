import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "A sovereign monarch (Root CA) never sits in a port terminal stamping individual travel visas day in and day out — if the royal seal were lost or stolen, the entire realm would fall into chaos. Instead, the monarch commissions trusted Ministers of State (Intermediate CAs) with a royal charter. The ministers issue travel visas (Leaf certificates) to merchants. A border inspector (your browser) confirms that the visa was stamped by an authorized minister, whose credentials trace directly back to the monarch listed in their official Royal Registry (the local Trust Store).",
  problem:
    "If a Certificate Authority signed millions of everyday website certificates directly with its Root private key, an online server breach would invalidate trust across billions of smartphones, computers, and servers worldwide. How does the internet isolate risk while building a scalable chain of trust?",
  steps: [
    {
      title: "Step 1: The fragility of a single-tier PKI",
      speaker: "Trent",
      content:
        "Imagine a world where Root CAs directly signed every web certificate. To issue thousands of certificates every hour, the Root private key would have to stay connected to an online web server (a 'hot' key).\n\nA single remote code execution flaw or insider threat would expose the master key that billions of devices trust. Because root certificates are baked into operating system kernels and browser binaries, revoking and replacing a compromised root requires emergency global software updates across billions of devices.",
      callout: {
        type: "security",
        text: "Root private keys are so critical that they must never reside on an internet-connected machine. A single-tier PKI is an unacceptable single point of catastrophic failure.",
      },
    },
    {
      title: "Step 2: The Root CA — The offline trust anchor",
      speaker: "Trent",
      content:
        "Modern Public Key Infrastructure (PKI) solves this by splitting authority into a **hierarchical tree**.\n\nThe **Root CA** is an offline trust anchor. Its private key is generated during an audited ceremony inside an air-gapped Hardware Security Module (HSM). The Root CA issues only a handful of long-lived (10–15 year) **Intermediate CA** certificates, and is then immediately locked back in a physical vault.\n\nThe Root CA's public key is distributed ahead of time in OS and browser **Trust Stores** (such as Apple Keychain, Windows Root Certificate Store, or Mozilla NSS).",
    },
    {
      title: "Step 3: The Intermediate CA — The active workhorse",
      speaker: "Trent",
      content:
        "The **Intermediate CA** (also called a Subordinate CA or Sub-CA) is the active operational authority. It receives authorization from the Root (`BasicConstraints: CA=TRUE, pathlen=0`) to issue end-entity leaf certificates to domain owners like Bob.\n\nIf an Intermediate CA server is ever compromised or misissues a certificate, the Root CA simply issues a revocation for that single intermediate. The parent Root CA and all other intermediate branches remain completely safe and trusted.",
      callout: {
        type: "info",
        text: "Risk isolation: Intermediate CAs limit the blast radius of security incidents. Revoking an intermediate does not require touching device root stores.",
      },
    },
    {
      title: "Step 4: Linking the chain with AKI and SKI",
      speaker: "Alice",
      content:
        "How does a client connect Bob's certificate to Trent's intermediate? X.509 v3 defines key identifier extensions:\n\n- **Subject Key Identifier (SKI):** A cryptographic hash of the certificate's own public key.\n- **Authority Key Identifier (AKI):** In a child certificate, the AKI carries the exact key identifier of the parent certificate that signed it.\n\nWhen Bob's leaf certificate states `AKI = 8B:2F:...`, Alice's browser looks for an intermediate certificate whose `SKI = 8B:2F:...` and verifies the digital signature.",
    },
    {
      title: "Step 5: Verifying the cryptographic path",
      speaker: "Bob",
      content:
        "When Alice visits Bob's website over HTTPS, Bob's server provides the **Leaf Certificate** and the **Intermediate Certificate** bundle:\n\n1. Alice verifies the Leaf certificate's signature using the Intermediate CA's public key.\n2. Alice verifies the Intermediate certificate's signature using the Root CA's public key.\n3. Alice checks that the Root CA is already present in her local Trust Store.\n4. Alice checks constraints: validity dates, key usage flags, and hostname matching in the Subject Alternative Name (SAN).\n\nIf any signature fails, or if a certificate along the path is expired or untrusted, the browser displays a security warning.",
    },
    {
      title: "Step 6: Cross-signing and root transitions",
      speaker: "Alice",
      content:
        "When a new Root CA is established, it takes 5 to 10 years for software updates to propagate that new root to legacy smart TVs, older phones, and embedded devices.\n\nTo bridge this gap, CAs use **cross-signing**: an established, universally trusted legacy Root signs the new Intermediate or new Root certificate. Modern devices can validate the path directly to the new root, while older devices trace the path back to the legacy root.",
      callout: {
        type: "warning",
        text: "Cross-signing creates multiple valid paths to different trust anchors. Path building engines must search candidate paths until a trusted anchor is found.",
      },
    },
  ],
  afterTimeline: {
    title: "Why servers must not send the Root Certificate",
    content:
      "A common misconfiguration is including the Root CA certificate in the TLS server certificate bundle. Sending the root wastes network bandwidth and round-trip time. More importantly, client software will never trust a root certificate merely because the remote server presented it! A root certificate can ONLY be trusted if it was already pre-installed in the client's local root trust store before the connection began.",
    callout: {
      type: "info",
      text: "The TLS server should only send [Leaf Certificate, Intermediate 1, Intermediate 2...]. The Root CA is always looked up locally by the client.",
    },
  },
  takeaways: [
    "Root CAs stay completely offline in secure HSMs to eliminate exposure to network attacks.",
    "Intermediate CAs handle day-to-day certificate issuance, confining the damage of any key compromise to a single revocable branch.",
    "Authority Key Identifiers (AKI) and Subject Key Identifiers (SKI) link parent and child certificates in a verifiable path.",
    "Clients build a cryptographic chain from the server's leaf certificate through intermediate certificates up to a trusted local root.",
    "Trust stores in your operating system or browser serve as the ultimate trust anchors; roots sent over the wire are ignored.",
  ],
  seed: {
    toolId: "cert-verifier",
    sampleInput: "",
    explanation:
      "Open Chain Verifier to inspect multi-tier X.509 certificate chains, validate intermediate signatures, and verify root trust anchors.",
  },
};

export default content;
