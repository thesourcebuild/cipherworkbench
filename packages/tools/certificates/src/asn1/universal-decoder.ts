import { parseAsn1, UniversalTag } from "./asn1";
import { parseCsr } from "./csr";
import { detectInputBytes } from "./pem";
import { parseX509Certificate } from "./x509";
import { base64url } from "@scure/base";

export type DetectedArtifactKind =
  | "jwt"
  | "x509-certificate"
  | "pkcs10-csr"
  | "private-key"
  | "public-key"
  | "x509-crl"
  | "ssh-public-key"
  | "wireguard-key"
  | "pkcs12-archive"
  | "base64-blob"
  | "hex-blob"
  | "raw-binary"
  | "unknown";

export interface DecodedProperty {
  label: string;
  value: string;
  hint?: string;
}

export interface UniversalDecoderResult {
  kind: DetectedArtifactKind;
  kindLabel: string;
  description: string;
  recommendedToolId: string;
  recommendedToolLabel: string;
  properties: DecodedProperty[];
  formattedDump: string;
  sslxCommand: string;
}

/**
 * Decode JWT token payload and header if string is 3 dot-separated base64url segments.
 */
function tryDecodeJwt(text: string): UniversalDecoderResult | null {
  const parts = text.trim().split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64] = parts;
  if (!headerB64 || !payloadB64) return null;

  try {
    const headerJson = new TextDecoder().decode(base64url.decode(headerB64));
    const payloadJson = new TextDecoder().decode(base64url.decode(payloadB64));
    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);

    const properties: DecodedProperty[] = [
      { label: "Algorithm", value: header.alg || "Unknown", hint: "JWT signing algorithm" },
      { label: "Type", value: header.typ || "JWT", hint: "Token type" },
    ];

    if (payload.sub) properties.push({ label: "Subject", value: String(payload.sub), hint: "User / Subject" });
    if (payload.iss) properties.push({ label: "Issuer", value: String(payload.iss), hint: "Issuing authority" });

    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      const isExpired = Date.now() > expDate.getTime();
      const status = isExpired ? `Expired on ${expDate.toISOString()}` : `Expires in ${Math.round((expDate.getTime() - Date.now()) / (1000 * 60))} minutes`;
      properties.push({ label: "Expiration", value: `${status} (${expDate.toISOString()})` });
    }

    if (payload.iat) {
      properties.push({ label: "Issued At", value: new Date(payload.iat * 1000).toISOString() });
    }

    const formattedDump = [
      "✓ Detected: JSON Web Token (JWT)",
      `Header:  ${JSON.stringify(header, null, 2)}`,
      `Payload: ${JSON.stringify(payload, null, 2)}`,
    ].join("\n");

    return {
      kind: "jwt",
      kindLabel: "JSON Web Token (JWT)",
      description: "Signed compact JSON Web Token claims container (RFC 7519).",
      recommendedToolId: "jwt",
      recommendedToolLabel: "JWT Decoder",
      properties,
      formattedDump,
      sslxCommand: "sslx decode <token>",
    };
  } catch {
    return null;
  }
}

/**
 * Sniff SSH public keys: "ssh-rsa ...", "ssh-ed25519 ...", "ecdsa-sha2-nistp256 ...".
 */
function tryDecodeSshPublicKey(text: string): UniversalDecoderResult | null {
  const trimmed = text.trim();
  const match = trimmed.match(/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-[a-z0-9]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$/);
  if (!match) return null;

  const keyType = match[1]!;
  const keyBase64 = match[2]!;
  const comment = match[3] || "(No comment)";

  return {
    kind: "ssh-public-key",
    kindLabel: "SSH Public Key",
    description: `OpenSSH authorized public key formatted with ${keyType}.`,
    recommendedToolId: "cert-converter",
    recommendedToolLabel: "Certificate & Key Converter",
    properties: [
      { label: "Key Type", value: keyType },
      { label: "Comment", value: comment },
      { label: "Key Data (Base64)", value: `${keyBase64.slice(0, 32)}... (${keyBase64.length} chars)` },
    ],
    formattedDump: `✓ Detected: OpenSSH Public Key\nType:    ${keyType}\nComment: ${comment}`,
    sslxCommand: "ssh-keygen -l -f <key.pub>",
  };
}

/**
 * Sniff WireGuard keys: exactly 44 characters base64 ending with =.
 */
function tryDecodeWireguardKey(text: string): UniversalDecoderResult | null {
  const trimmed = text.trim();
  if (/^[A-Za-z0-9+/]{43}=$/.test(trimmed)) {
    return {
      kind: "wireguard-key",
      kindLabel: "WireGuard Key",
      description: "Curve25519 32-byte base64-encoded WireGuard private or public key.",
      recommendedToolId: "ed25519",
      recommendedToolLabel: "Ed25519 / X25519 Tool",
      properties: [
        { label: "Key Format", value: "Base64 (32 raw bytes)" },
        { label: "Algorithm", value: "Curve25519 (X25519)" },
        { label: "Key", value: trimmed },
      ],
      formattedDump: `✓ Detected: WireGuard Key (Curve25519 32-byte key)`,
      sslxCommand: "wg pubkey < privatekey",
    };
  }
  return null;
}

/**
 * Universal Sniffer: Detects and inspects any unknown cryptographic artifact.
 */
export function decodeUniversalArtifact(input: Uint8Array | string): UniversalDecoderResult {
  const text = typeof input === "string" ? input : new TextDecoder().decode(input);
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;

  // 1. Try JWT
  const jwt = tryDecodeJwt(text);
  if (jwt) return jwt;

  // 2. Try SSH Public Key
  const ssh = tryDecodeSshPublicKey(text);
  if (ssh) return ssh;

  // 3. Try WireGuard Key
  const wg = tryDecodeWireguardKey(text);
  if (wg) return wg;

  // 4. Try PEM Detection
  const trimmed = text.trim();

  // X.509 Certificate
  if (trimmed.includes("-----BEGIN CERTIFICATE-----")) {
    try {
      const cert = parseX509Certificate(bytes);
      return {
        kind: "x509-certificate",
        kindLabel: "X.509 TLS/SSL Certificate",
        description: "RFC 5280 X.509 v3 public key certificate.",
        recommendedToolId: "x509",
        recommendedToolLabel: "X.509 Certificate Inspector",
        properties: [
          { label: "Subject", value: cert.subject.dn },
          { label: "Issuer", value: cert.issuer.dn },
          { label: "Validity", value: cert.validity.statusLabel },
          { label: "Lifespan Gauge", value: cert.validity.visualProgressBar },
          { label: "Public Key", value: `${cert.publicKey.algorithmName} (${cert.publicKey.details})` },
          { label: "Serial", value: cert.serialNumber },
          { label: "SANs", value: cert.extensions.sans.join(", ") || "(None)" },
        ],
        formattedDump: `✓ Detected: X.509 Certificate\nSubject: ${cert.subject.dn}\nIssuer:  ${cert.issuer.dn}\nExpires: ${cert.validity.notAfter.toISOString().split("T")[0]} (${cert.validity.daysRemaining} days left)`,
        sslxCommand: "sslx inspect cert.pem",
      };
    } catch {}
  }

  // PKCS#10 CSR
  if (trimmed.includes("BEGIN CERTIFICATE REQUEST") || trimmed.includes("BEGIN NEW CERTIFICATE REQUEST")) {
    try {
      const csr = parseCsr(bytes);
      return {
        kind: "pkcs10-csr",
        kindLabel: "PKCS#10 Certificate Signing Request (CSR)",
        description: "RFC 2986 Certificate Signing Request.",
        recommendedToolId: "csr",
        recommendedToolLabel: "CSR Inspector",
        properties: [
          { label: "Subject", value: csr.subject.dn },
          { label: "Public Key", value: `${csr.publicKey.algorithmName} (${csr.publicKey.details})` },
          { label: "Signature Algorithm", value: csr.signatureAlgorithmName },
          { label: "SANs", value: csr.requestedExtensions.sans.join(", ") || "(None)" },
        ],
        formattedDump: `✓ Detected: PKCS#10 CSR\nSubject: ${csr.subject.dn}\nKey:     ${csr.publicKey.algorithmName}`,
        sslxCommand: "sslx inspect request.csr",
      };
    } catch {}
  }

  // Private Key
  if (
    trimmed.includes("BEGIN PRIVATE KEY") ||
    trimmed.includes("BEGIN RSA PRIVATE KEY") ||
    trimmed.includes("BEGIN EC PRIVATE KEY") ||
    trimmed.includes("BEGIN OPENSSH PRIVATE KEY")
  ) {
    let keyType = "Private Key";
    if (trimmed.includes("RSA")) keyType = "RSA Private Key (PKCS#1)";
    else if (trimmed.includes("EC")) keyType = "EC Private Key (SEC1)";
    else if (trimmed.includes("OPENSSH")) keyType = "OpenSSH Private Key";
    else keyType = "PKCS#8 Encrypted/Unencrypted Private Key";

    return {
      kind: "private-key",
      kindLabel: keyType,
      description: "Cryptographic private key container in PEM format.",
      recommendedToolId: "cert-matcher",
      recommendedToolLabel: "Cert & Key Matcher",
      properties: [
        { label: "Container Type", value: keyType },
        { label: "Format", value: "PEM encoded" },
      ],
      formattedDump: `✓ Detected: ${keyType}`,
      sslxCommand: "sslx match cert.pem key.pem",
    };
  }

  // Public Key (SPKI)
  if (trimmed.includes("BEGIN PUBLIC KEY") || trimmed.includes("BEGIN RSA PUBLIC KEY")) {
    return {
      kind: "public-key",
      kindLabel: "Public Key (SPKI)",
      description: "SubjectPublicKeyInfo public key in PEM format.",
      recommendedToolId: "asymmetric",
      recommendedToolLabel: "Asymmetric Suite",
      properties: [
        { label: "Format", value: "SubjectPublicKeyInfo (SPKI) PEM" },
      ],
      formattedDump: "✓ Detected: Public Key (SPKI)",
      sslxCommand: "openssl pkey -pubin -in public.key -text -noout",
    };
  }

  // X.509 CRL
  if (trimmed.includes("BEGIN X509 CRL")) {
    return {
      kind: "x509-crl",
      kindLabel: "Certificate Revocation List (CRL)",
      description: "RFC 5280 X.509 v2 Certificate Revocation List in PEM format.",
      recommendedToolId: "crl",
      recommendedToolLabel: "CRL Inspector",
      properties: [{ label: "Format", value: "X.509 CRL PEM" }],
      formattedDump: "✓ Detected: X.509 Certificate Revocation List (CRL)",
      sslxCommand: "openssl crl -in revoked.crl -text -noout",
    };
  }

  // 5. Try DER / Binary ASN.1 Sniffing
  try {
    const detected = detectInputBytes(bytes);
    const asn = parseAsn1(detected.der);
    if (asn.tagNumber === UniversalTag.Sequence) {
      // Check if it's an X.509 DER
      try {
        const cert = parseX509Certificate(detected.der);
        return {
          kind: "x509-certificate",
          kindLabel: "X.509 Certificate (Binary DER)",
          description: "Binary DER-encoded X.509 certificate.",
          recommendedToolId: "x509",
          recommendedToolLabel: "X.509 Inspector",
          properties: [
            { label: "Subject", value: cert.subject.dn },
            { label: "Issuer", value: cert.issuer.dn },
            { label: "Format", value: "Raw DER" },
          ],
          formattedDump: `✓ Detected: Binary DER X.509 Certificate\nSubject: ${cert.subject.dn}`,
          sslxCommand: "sslx inspect cert.der",
        };
      } catch {}
    }
  } catch {}

  // 6. Hex string
  if (/^[0-9a-fA-F\s:]{16,}$/.test(trimmed)) {
    const cleanHex = trimmed.replace(/[\s:]/g, "");
    if (cleanHex.length % 2 === 0) {
      return {
        kind: "hex-blob",
        kindLabel: "Hexadecimal Byte Sequence",
        description: `Hex encoded sequence of ${cleanHex.length / 2} bytes.`,
        recommendedToolId: "hex",
        recommendedToolLabel: "Hex Encoder / Decoder",
        properties: [
          { label: "Byte Length", value: `${cleanHex.length / 2} bytes` },
          { label: "Hex Characters", value: String(cleanHex.length) },
        ],
        formattedDump: `✓ Detected: Hex Sequence (${cleanHex.length / 2} bytes)`,
        sslxCommand: "xxd -r -p",
      };
    }
  }

  // 7. Base64
  if (/^[A-Za-z0-9+/=\s]{24,}$/.test(trimmed) && trimmed.length % 4 === 0) {
    return {
      kind: "base64-blob",
      kindLabel: "Base64 Encoded Data",
      description: "Standard Base64 encoded payload.",
      recommendedToolId: "base64",
      recommendedToolLabel: "Base64 Tool",
      properties: [
        { label: "Character Length", value: String(trimmed.length) },
      ],
      formattedDump: `✓ Detected: Base64 Payload`,
      sslxCommand: "openssl base64 -d",
    };
  }

  // Fallback: Unknown
  return {
    kind: "unknown",
    kindLabel: "Unknown Plaintext or Binary Data",
    description: "Unrecognized data format. Could not match known cryptographic headers.",
    recommendedToolId: "x509",
    recommendedToolLabel: "X.509 Inspector",
    properties: [
      { label: "Input Length", value: `${bytes.length} bytes` },
    ],
    formattedDump: "Unrecognized cryptographic artifact.",
    sslxCommand: "sslx decode <file>",
  };
}
