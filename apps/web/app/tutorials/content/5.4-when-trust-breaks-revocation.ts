import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "If a physical credit card is lost or stolen, the issuing bank cannot physically teleport into the thief's pocket and vaporize the piece of plastic. Instead, the bank publishes a blacklist of canceled card numbers to cashiers. But if that blacklist grows to 50 million entries, cashiers cannot download a phonebook-sized PDF before every cup of coffee! The system needs a fast, lightweight mechanism to verify freshness — and even better, a pre-stamped digital proof attached right to the invoice.",
  problem:
    "Every X.509 certificate has a fixed expiry date. What happens if a server's private key is accidentally committed to a public Git repository, stolen in a server breach, or an intermediate CA is compromised 10 months before the certificate expires? How can clients discover that an unexpired certificate must no longer be trusted?",
  steps: [
    {
      title: "Step 1: The problem of immutable public credentials",
      speaker: "Bob",
      content:
        "Public-key certificates are distributed freely across the web. Once Trent signs Bob's leaf certificate, that certificate exists in caches, server memory, and client disks worldwide.\n\nTrent cannot 'delete' or 'recall' a certificate from the internet. When Bob discovers that his server's private key was leaked, he needs an out-of-band way to tell every browser on earth: *'Do not trust this certificate, even though its signature is valid and it hasn't reached its expiry date yet.'*",
    },
    {
      title: "Step 2: First generation: Certificate Revocation Lists (CRLs)",
      speaker: "Trent",
      content:
        "Under RFC 5280, the Certificate Authority periodically compiles and signs a **Certificate Revocation List (CRL)**: a list of revoked certificate serial numbers and revocation timestamps.\n\nWhen Alice's browser visits Bob's site, the certificate's `CRL Distribution Points` extension tells Alice where to download Trent's CRL file. But CRLs quickly collapsed under their own weight: large public CAs issued millions of certificates, causing CRL files to balloon to tens of megabytes. Downloading multi-megabyte CRL files destroyed web page load times.",
      callout: {
        type: "warning",
        text: "Bandwidth explosion: CRLs scale with the total number of revoked certificates across the entire CA, making them impractical for fast mobile web browsing.",
      },
    },
    {
      title: "Step 3: Second generation: Online Certificate Status Protocol (OCSP)",
      speaker: "Alice",
      content:
        "To fix CRL bloat, RFC 6960 introduced **OCSP (Online Certificate Status Protocol)**. Instead of downloading a massive list of all revocations, Alice's browser sends a tiny query directly to Trent's OCSP responder:\n\n*Client:* 'Is certificate serial number `0x48A2B9` valid right now?'\n*Trent's OCSP Responder:* 'Status: Good, signed by Trent, valid until 14:00 UTC.'\n\nThis reduced network payloads from megabytes to a few hundred bytes.",
    },
    {
      title: "Step 4: The fatal flaws of direct OCSP: Privacy & soft-fail",
      speaker: "Eve",
      content:
        "Despite solving bandwidth, direct client-to-CA OCSP introduced two catastrophic flaws:\n\n1. **Severe privacy leak:** Every time Alice visits a website, her browser queries Trent's OCSP server. Trent (the CA) can log Alice's IP address and track every single website she visits in real time!\n2. **The Soft-Fail trap:** What if Trent's OCSP server is offline or throttled? If browsers 'fail hard' (block the site), a CA outage breaks the entire web. Therefore, browsers adopted 'soft-fail' (ignore the error and proceed). Mallory can exploit this by simply blocking OCSP traffic, rendering revocation checks useless!",
      callout: {
        type: "security",
        text: "Soft-fail renders direct OCSP ineffective against active network attackers, because an attacker who can impersonate a server can also easily block OCSP responder packets.",
      },
    },
    {
      title: "Step 5: The modern standard: OCSP Stapling (RFC 6066)",
      speaker: "Bob",
      content:
        "The web solved both problems with **OCSP Stapling (Certificate Status Request)**.\n\nInstead of millions of browser visitors querying Trent directly, **Bob's web server** queries Trent's OCSP responder once every hour in the background, caches the signed timestamped response, and **staples** that signed response directly into the initial TLS handshake flight!\n\nWhen Alice connects to Bob over TLS, she receives the certificate AND the fresh OCSP proof in the exact same packet.",
    },
    {
      title: "Step 6: Real-world protection: OCSP Must-Staple & Short Lifespans",
      speaker: "Alice",
      content:
        "With OCSP Stapling, Alice never contacts the CA directly (preserving her browsing privacy), and there are zero extra network round trips.\n\nTo prevent Mallory from stripping the stapled response, certificates can include the **OCSP Must-Staple** extension, instructing browsers to strictly terminate the connection if no valid staple is present. Furthermore, the web has rapidly moved toward **short certificate lifespans (90 days or less)**, making natural expiration the primary defense against key compromise.",
    },
  ],
  afterTimeline: {
    title: "Browser Revocation Feeds: CRLSets and OneCRL",
    content:
      "Because live network revocation queries are prone to network timeouts, major browsers also maintain out-of-band push feeds. Google Chrome pushes 'CRLSets' and Mozilla Firefox distributes 'OneCRL' — curated, compressed lists of high-profile emergency revocations (such as compromised intermediate CAs) bundled directly into background browser updates.",
    callout: {
      type: "info",
      text: "Modern revocation is a layered defense: short lifespans (90 days) + OCSP Stapling on servers + browser CRLSet/OneCRL push feeds.",
    },
  },
  takeaways: [
    "Certificates cannot be recalled from the wild; revocation protocols inform clients when an unexpired certificate must be rejected.",
    "Certificate Revocation Lists (CRLs) distribute lists of revoked serials but became too bloated for high-speed browsing.",
    "Direct OCSP provides lightweight queries but leaks user browsing habits to CAs and is vulnerable to soft-fail attacks.",
    "OCSP Stapling lets the server fetch and bundle fresh, CA-signed revocation status directly inside the TLS handshake.",
    "Shortening certificate validity periods (from years to 90 days) fundamentally limits the exposure window of any leaked private key.",
  ],
  seed: {
    toolId: "crl",
    sampleInput: "",
    explanation:
      "Open CRL (Revocation List) to parse X.509 v2 revocation lists, inspect revoked serial numbers and reason codes, or build a custom CRL.",
  },
};

export default content;
