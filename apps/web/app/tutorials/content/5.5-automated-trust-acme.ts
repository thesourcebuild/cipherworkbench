import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Years ago, getting an official business certificate required waiting in line at city hall, paying hefty administrative fees, and renewing paperwork every few years. ACME is an automated 24/7 robotic dispenser: you prove you control the building by flashing a secret code through the window, and the dispenser prints your verified official credential in 3 seconds for free. And Certificate Transparency is a giant public ledger carved into stone in the town square: every issued credential is permanently recorded for everyone to inspect, ensuring no rogue official can secretly issue a fraudulent permit behind your back.",
  problem:
    "In 2014, less than a third of web traffic was encrypted because certificates were expensive, slow, and manually configured. Furthermore, when rogue or compromised CAs misissued fraudulent certificates in secret, domain owners had no way of knowing until attacks were already happening. How did the internet scale HTTPS to over 95% of traffic while making secret misissuance impossible?",
  steps: [
    {
      title: "Step 1: The friction of the manual certificate era",
      speaker: "Bob",
      content:
        "Before 2015, enabling HTTPS on a website was a painful, manual chore:\n\n1. Generate an RSA key and CSR via command-line tools.\n2. Pay commercial CAs between $50 and $300 per year per domain.\n3. Wait hours or days for manual email approval or administrative verification.\n4. Manually install certificates into web server configs.\n\nBecause certificates were valid for 2 to 5 years, system administrators frequently forgot when renewals were due. When certificates silently expired, production sites broke. As a result, millions of websites simply remained unencrypted.",
    },
    {
      title: "Step 2: The ACME Protocol (RFC 8555) & Let's Encrypt",
      speaker: "Trent",
      content:
        "The Internet Security Research Group (ISRG) launched **Let's Encrypt** and developed **ACME (Automated Certificate Management Environment)**, standardized as RFC 8555.\n\nACME turns certificate issuance and renewal into a fully automated, machine-to-machine protocol. Web servers run an ACME client (such as Certbot or Caddy) that generates keys locally, talks to the CA via a REST API, solves automated domain ownership challenges, and installs renewed certificates with zero human intervention.",
      callout: {
        type: "info",
        text: "By eliminating financial cost and human friction, ACME drove global HTTPS adoption from ~35% in 2014 to over 95% today.",
      },
    },
    {
      title: "Step 3: The HTTP-01 Challenge",
      speaker: "Bob",
      content:
        "How does an automated CA verify that Bob owns `example.com` without human paperwork? Under the **HTTP-01 challenge**:\n\n1. Trent gives Bob's ACME client a cryptographic token.\n2. Bob's ACME client writes a validation response to his web server at:\n   `http://example.com/.well-known/acme-challenge/<token>`\n3. Trent's servers send an HTTP GET request to that exact URI across multiple global vantage points.\n4. If the served token matches Bob's cryptographic authorization, Trent knows Bob controls the web server for `example.com`.",
    },
    {
      title: "Step 4: The DNS-01 Challenge: Wildcards and firewalls",
      speaker: "Bob",
      content:
        "What if Bob needs a wildcard certificate (`*.example.com`) or runs an internal staging server that isn't accessible from the public internet?\n\nBob uses the **DNS-01 challenge**:\n\n1. Trent's ACME server computes a SHA-256 digest of the challenge and Bob's ACME account key.\n2. Bob's client creates a DNS `TXT` record at `_acme-challenge.example.com`.\n3. Trent queries authoritative DNS nameservers globally. If the TXT record matches, domain ownership is verified!\n\nDNS-01 works for private intranet servers and enables issuance of wildcard certificates.",
    },
    {
      title: "Step 5: The threat of rogue CAs and the DigiNotar wake-up call",
      speaker: "Mallory",
      content:
        "Automation solved certificate issuance, but what about trust integrity? Any CA in a client's root store has the authority to issue certificates for ANY domain on earth.\n\nIn 2011, attackers compromised Dutch Certificate Authority **DigiNotar** and secretly issued fraudulent wildcard certificates for `*.google.com`. The attackers used these bogus certificates to execute man-in-the-middle surveillance on 300,000 Iranian internet users. Because DigiNotar issued the certificates in secret, the incident went undetected for weeks.",
      callout: {
        type: "warning",
        text: "The universal trust problem: A single compromised CA anywhere in the world could forge certificates for any website in secret.",
      },
    },
    {
      title: "Step 6: Certificate Transparency (CT logs) & SCTs",
      speaker: "Alice",
      content:
        "To eliminate secret misissuance, Google introduced **Certificate Transparency (CT, RFC 6962)**:\n\n- Before any browser trusts a certificate, the CA must submit the certificate to publicly auditable, append-only **Merkle tree logs**.\n- The CT log responds with a cryptographic receipt: a **Signed Certificate Timestamp (SCT)**, which is embedded inside the certificate itself.\n- Modern browsers require valid SCTs on all TLS certificates.\n\nBecause CT logs are public and permanent, domain owners run automated monitors (via services like crt.sh). If a rogue CA ever issues an unauthorized certificate for your domain, you are alerted within minutes.",
    },
  ],
  afterTimeline: {
    title: "How 90-day lifecycles enforce security hygiene",
    content:
      "Let's Encrypt certificates expire in 90 days (with auto-renewal at 60 days). This short lifespan was controversial initially, but it forced organizations to fully automate certificate lifecycles. Furthermore, if a server's private key ever leaks, the key's maximum exposure window is strictly bounded without relying solely on fragile revocation protocols.",
    callout: {
      type: "info",
      text: "The combination of ACME automated renewal and short 90-day validity turns certificate rotation into routine background maintenance rather than high-stakes emergency engineering.",
    },
  },
  takeaways: [
    "ACME (RFC 8555) turned certificate procurement and renewal into a zero-cost, fully automated machine protocol.",
    "HTTP-01 proves domain control by serving a challenge response over standard port 80 at `/.well-known/acme-challenge/`.",
    "DNS-01 proves domain ownership by publishing a cryptographic TXT record, enabling wildcard and firewalled certificate issuance.",
    "Certificate Transparency (CT) uses append-only Merkle tree logs to make every issued certificate publicly auditable globally.",
    "Signed Certificate Timestamps (SCTs) prove inclusion in CT logs; modern browsers reject certificates lacking valid SCTs.",
  ],
  seed: {
    toolId: "acme",
    sampleInput: "",
    explanation:
      "Open ACME Challenge Calculator to generate HTTP-01 thumbprints, calculate DNS-01 TXT record digests, and test domain verification scripts.",
  },
};

export default content;
