import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { buildVerificationScripts, type CommandScripts } from "../export/commands";
import { computeJwkThumbprint, spkiToJwk, toBase64Url, type Jwk } from "./jwk";
import { detectInputBytes } from "../asn1/pem";
import { parseAsn1, UniversalTag } from "../asn1/asn1";

export interface AcmeChallengeInput {
  domain: string;
  token: string;
  accountKeyOrThumbprint: string;
}

export interface AcmeHttp01Challenge {
  urlPath: string;
  fullUrl: string;
  keyAuthorization: string;
  curlCommand: string;
  nginxConfig: string;
  caddyConfig: string;
}

export interface AcmeDns01Challenge {
  recordName: string;
  recordType: "TXT";
  recordValue: string;
  zoneSnippet: string;
  digCommand: string;
  nslookupCommand: string;
  powershellCommand: string;
}

export interface AcmeTlsAlpn01Challenge {
  protocol: "acme-tls/1";
  extensionOid: "1.3.6.1.5.5.7.1.31";
  critical: true;
  sha256Hex: string;
  sha256Base64Url: string;
}

export interface AcmeChallengeResult {
  domain: string;
  cleanDomain: string;
  token: string;
  jwkThumbprint: string;
  keyAuthorization: string;
  http01: AcmeHttp01Challenge;
  dns01: AcmeDns01Challenge;
  tlsAlpn01: AcmeTlsAlpn01Challenge;
  commands: CommandScripts;
  exportFiles: Array<{ name: string; content: string | Uint8Array }>;
}

/**
 * Resolves or computes the RFC 7638 SHA-256 JWK Thumbprint from a given key input.
 * Input can be:
 * 1. A precomputed 43-character base64url thumbprint.
 * 2. A JSON string representing a JWK (e.g. { "kty": "RSA", ... }).
 * 3. A PEM-encoded RSA/EC private or public key, or certificate.
 */
export function resolveJwkThumbprint(input: string): string {
  const trimmed = input.trim();

  // 1. Precomputed Base64URL thumbprint (RFC 7638 SHA-256 is 32 bytes -> 43 chars base64url)
  if (/^[0-9a-zA-Z_-]{43}$/.test(trimmed)) {
    return trimmed;
  }

  // 2. JWK JSON
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const parsed = JSON.parse(trimmed) as Jwk;
      if (parsed.kty) {
        return computeJwkThumbprint(parsed);
      }
    } catch {
      // Continue to next attempts
    }
  }

  // 3. PEM Block (Certificate, Public Key, or Private Key)
  try {
    const detected = detectInputBytes(trimmed);
    const root = parseAsn1(detected.der);

    // If it's an X.509 certificate: SEQUENCE { tbsCertificate SEQUENCE { ... spki SEQUENCE } }
    if (detected.label?.includes("CERTIFICATE") && !detected.label.includes("REQUEST")) {
      const tbs = root.children[0];
      if (tbs) {
        let idx = 0;
        if (tbs.children[0]?.tagNumber === 0) idx++; // version
        idx += 5; // skip serial, sig, issuer, validity, subject
        const spkiNode = tbs.children[idx];
        if (spkiNode) {
          const jwk = spkiToJwk(spkiNode.raw);
          return computeJwkThumbprint(jwk);
        }
      }
    }

    // If it's a SubjectPublicKeyInfo directly: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    if (root.children.length === 2 && root.children[0]?.tagNumber === UniversalTag.Sequence) {
      try {
        const jwk = spkiToJwk(detected.der);
        return computeJwkThumbprint(jwk);
      } catch {
        // Fallback
      }
    }

    // PKCS#8 PrivateKeyInfo: SEQUENCE { INTEGER version, AlgorithmIdentifier, OCTET STRING privateKey }
    if (root.children.length >= 3 && root.children[2]?.tagNumber === UniversalTag.OctetString) {
      try {
        const pkcs1Node = parseAsn1(root.children[2].asOctetString());
        if (pkcs1Node.children.length >= 3) {
          let nBytes = pkcs1Node.children[1]!.valueBytes;
          let eBytes = pkcs1Node.children[2]!.valueBytes;
          if (nBytes[0] === 0x00 && nBytes.length > 1) nBytes = nBytes.subarray(1);
          if (eBytes[0] === 0x00 && eBytes.length > 1) eBytes = eBytes.subarray(1);
          const jwk: Jwk = {
            kty: "RSA",
            n: toBase64Url(nBytes),
            e: toBase64Url(eBytes),
          };
          return computeJwkThumbprint(jwk);
        }
      } catch {
        // Fallback
      }
    }

    // PKCS#1 RSA Private Key: SEQUENCE { INTEGER 0, INTEGER n, INTEGER e, ... }
    if (
      root.children.length >= 8 &&
      root.children[0]?.tagNumber === UniversalTag.Integer &&
      root.children[1]?.tagNumber === UniversalTag.Integer &&
      root.children[2]?.tagNumber === UniversalTag.Integer
    ) {
      let nBytes = root.children[1]!.valueBytes;
      let eBytes = root.children[2]!.valueBytes;
      if (nBytes[0] === 0x00 && nBytes.length > 1) nBytes = nBytes.subarray(1);
      if (eBytes[0] === 0x00 && eBytes.length > 1) eBytes = eBytes.subarray(1);

      const jwk: Jwk = {
        kty: "RSA",
        n: toBase64Url(nBytes),
        e: toBase64Url(eBytes),
      };
      return computeJwkThumbprint(jwk);
    }
  } catch {
    // Fall through
  }

  throw new Error(
    "Could not resolve JWK Thumbprint from input. Please provide a valid JWK JSON string, PEM private/public key, or a 43-character Base64URL thumbprint.",
  );
}

/**
 * Calculates RFC 8555 ACME HTTP-01 and DNS-01 challenge parameters.
 */
export function calculateAcmeChallenges(params: AcmeChallengeInput): AcmeChallengeResult {
  const rawDomain = params.domain.trim();
  if (!rawDomain) throw new Error("Domain name is required for ACME challenge calculation");

  const cleanDomain = rawDomain.replace(/^\*\./, "").trim();
  const token = params.token.trim();
  if (!token) throw new Error("ACME challenge token is required");

  const jwkThumbprint = resolveJwkThumbprint(params.accountKeyOrThumbprint);

  // RFC 8555 Section 8.1: Key Authorization = token || '.' || base64url(thumbprint)
  const keyAuthorization = `${token}.${jwkThumbprint}`;

  // SHA-256 Digest of Key Authorization
  const authBytes = new TextEncoder().encode(keyAuthorization);
  const authDigest = sha256(authBytes);
  const dns01Digest = toBase64Url(authDigest);
  const alpnDigestHex = bytesToHex(authDigest).toUpperCase();

  // 1. HTTP-01 Challenge
  const urlPath = `/.well-known/acme-challenge/${token}`;
  const fullUrl = `http://${cleanDomain}${urlPath}`;
  const curlCommand = `curl -iL "${fullUrl}"`;

  const nginxConfig = `# ACME HTTP-01 Challenge Validation Block for Nginx
server {
    listen 80;
    listen [::]:80;
    server_name ${cleanDomain}${rawDomain.startsWith("*.") ? ` *.${cleanDomain}` : ""};

    location /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /var/www/certbot;
        try_files $uri =404;
    }

    # Redirect all other HTTP traffic to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}`;

  const caddyConfig = `# Caddy ACME HTTP-01 Configuration
${cleanDomain} {
    handle /.well-known/acme-challenge/* {
        respond "${keyAuthorization}" 200
    }
}`;

  // 2. DNS-01 Challenge
  const recordName = `_acme-challenge.${cleanDomain}`;
  const zoneSnippet = `${recordName}. 300 IN TXT "${dns01Digest}"`;
  const digCommand = `dig +short TXT ${recordName}`;
  const nslookupCommand = `nslookup -q=txt ${recordName}`;
  const powershellCommand = `Resolve-DnsName -Name "${recordName}" -Type TXT`;

  // 3. TLS-ALPN-01 Challenge
  const tlsAlpn01: AcmeTlsAlpn01Challenge = {
    protocol: "acme-tls/1",
    extensionOid: "1.3.6.1.5.5.7.1.31",
    critical: true,
    sha256Hex: alpnDigestHex,
    sha256Base64Url: dns01Digest,
  };

  // 4. Cross-Platform Scripts via unified buildVerificationScripts
  const commands = buildVerificationScripts({
    title: `ACME Challenge Verification for ${cleanDomain}`,
    description: `Validate HTTP-01 and DNS-01 challenges before notifying ACME CA (Let's Encrypt / ZeroSSL).`,
    actions: [
      {
        id: "verify-dns",
        description: `Query public DNS for TXT record: ${recordName}`,
        commands: [
          `echo "Testing DNS-01 TXT record for ${recordName}..."`,
          `dig +short TXT "${recordName}" || nslookup -q=txt "${recordName}"`,
        ],
      },
      {
        id: "verify-http",
        description: `Fetch HTTP-01 challenge response from ${fullUrl}`,
        commands: [
          `echo "Testing HTTP-01 token response at ${fullUrl}..."`,
          `curl -fsSL "${fullUrl}"`,
          `echo ""`,
        ],
      },
    ],
  });

  // 5. Terraform DNS snippet
  const terraformConfig = `# Terraform ACME DNS-01 Record Configuration
resource "cloudflare_record" "acme_challenge" {
  zone_id = var.cloudflare_zone_id
  name    = "_acme-challenge"
  value   = "${dns01Digest}"
  type    = "TXT"
  ttl     = 120
}
`;

  // 6. Ansible HTTP-01 deployment playbook
  const ansiblePlaybook = `---
- name: Deploy ACME HTTP-01 Challenge File
  hosts: webservers
  become: true
  tasks:
    - name: Ensure ACME challenge directory exists
      ansible.builtin.file:
        path: /var/www/certbot/.well-known/acme-challenge
        state: directory
        owner: www-data
        group: www-data
        mode: "0755"

    - name: Write ACME challenge token response
      ansible.builtin.copy:
        dest: "/var/www/certbot/.well-known/acme-challenge/${token}"
        content: "${keyAuthorization}\n"
        owner: www-data
        group: www-data
        mode: "0644"
`;

  const exportFiles = [
    { name: token, content: keyAuthorization },
    { name: "dns-record.txt", content: zoneSnippet },
    { name: "nginx-acme.conf", content: nginxConfig },
    { name: "main.tf", content: terraformConfig },
    { name: "deploy-playbook.yaml", content: ansiblePlaybook },
    { name: "commands.sh", content: commands.sh },
    { name: "commands.ps1", content: commands.ps1 },
    { name: "commands.bat", content: commands.bat },
  ];

  return {
    domain: rawDomain,
    cleanDomain,
    token,
    jwkThumbprint,
    keyAuthorization,
    http01: {
      urlPath,
      fullUrl,
      keyAuthorization,
      curlCommand,
      nginxConfig,
      caddyConfig,
    },
    dns01: {
      recordName,
      recordType: "TXT",
      recordValue: dns01Digest,
      zoneSnippet,
      digCommand,
      nslookupCommand,
      powershellCommand,
    },
    tlsAlpn01,
    commands,
    exportFiles,
  };
}
