import { TagClass } from "./asn1";
import {
  encodeDerBitString,
  encodeDerBoolean,
  encodeDerContext,
  encodeDerInteger,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  encodeDerTime,
  encodeDistinguishedName,
  encodeDerTlv,
  type RdnEntry,
} from "./encoder";
import {
  generateKeyBundle,
  type KeyAlgorithmType,
  type HashAlgorithmType,
  type GeneratedKeyBundle,
} from "../crypto/keys";
import { encodePem } from "./pem";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export interface CertificateCreatorOptions {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  state: string;
  locality: string;
  keyType: KeyAlgorithmType;
  hashType: HashAlgorithmType;
  validityDays: number;
  isCa: boolean;
  san: string;
  serverAuth?: boolean;
  clientAuth?: boolean;
  codeSigning?: boolean;
  emailProtection?: boolean;
  customSerialHex?: string;
}

export interface CreatedCertificateResult {
  certPem: string;
  certDer: Uint8Array;
  privateKeyPem: string;
  publicKeyPem: string;
  serialNumberHex: string;
  subjectDn: string;
  issuerDn: string;
  notBefore: Date;
  notAfter: Date;
  fingerprintSha256: string;
  opensslCommand: string;
  keyBundle: GeneratedKeyBundle;
}

/**
 * Parses an IPv4 address string into a 4-byte Uint8Array, or null if invalid.
 */
function parseIpv4(ip: string): Uint8Array | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i]!;
    if (!/^\d+$/.test(p)) return null;
    const num = parseInt(p, 10);
    if (num < 0 || num > 255) return null;
    bytes[i] = num;
  }
  return bytes;
}

/**
 * Encodes Subject Alternative Names into DER GeneralNames sequence.
 */
export function encodeSanExtension(sanStr: string): Uint8Array | null {
  const items = sanStr
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (items.length === 0) return null;

  const generalNames: Uint8Array[] = [];

  for (const raw of items) {
    let type = "dns";
    let val = raw;

    if (raw.toLowerCase().startsWith("dns:")) {
      type = "dns";
      val = raw.slice(4).trim();
    } else if (raw.toLowerCase().startsWith("ip:")) {
      type = "ip";
      val = raw.slice(3).trim();
    } else if (raw.toLowerCase().startsWith("email:")) {
      type = "email";
      val = raw.slice(6).trim();
    } else if (raw.toLowerCase().startsWith("uri:")) {
      type = "uri";
      val = raw.slice(4).trim();
    } else if (raw.includes("@")) {
      type = "email";
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(raw)) {
      type = "ip";
    } else if (raw.includes("://")) {
      type = "uri";
    }

    if (type === "ip") {
      const ipBytes = parseIpv4(val);
      if (ipBytes) {
        // [7] IMPLICIT OCTET STRING
        generalNames.push(encodeDerTlv(7, TagClass.ContextSpecific, false, ipBytes));
        continue;
      }
      // If parsing fails, fall back to DNS
    }

    if (type === "email") {
      // [1] IMPLICIT IA5String
      generalNames.push(encodeDerTlv(1, TagClass.ContextSpecific, false, new TextEncoder().encode(val)));
    } else if (type === "uri") {
      // [6] IMPLICIT IA5String
      generalNames.push(encodeDerTlv(6, TagClass.ContextSpecific, false, new TextEncoder().encode(val)));
    } else {
      // [2] IMPLICIT IA5String (dNSName)
      generalNames.push(encodeDerTlv(2, TagClass.ContextSpecific, false, new TextEncoder().encode(val)));
    }
  }

  if (generalNames.length === 0) return null;
  return encodeDerSequence(generalNames);
}

/**
 * Encodes Key Usage bit string.
 */
export function encodeKeyUsageBitString(bits: number[]): Uint8Array {
  if (bits.length === 0) return new Uint8Array(0);
  const maxBit = Math.max(...bits);
  const numBytes = Math.floor(maxBit / 8) + 1;
  const raw = new Uint8Array(numBytes);

  for (const bit of bits) {
    const byteIdx = Math.floor(bit / 8);
    const bitIdx = 7 - (bit % 8);
    raw[byteIdx] = (raw[byteIdx] ?? 0) | (1 << bitIdx);
  }

  const lastByte = raw[numBytes - 1] ?? 0;
  let unusedBits = 0;
  for (let i = 0; i < 8; i++) {
    if ((lastByte & (1 << i)) !== 0) {
      unusedBits = i;
      break;
    }
  }

  return encodeDerBitString(raw, unusedBits);
}

/**
 * Generates a full self-signed X.509 v3 Certificate.
 */
export async function createCertificate(
  opts: CertificateCreatorOptions,
): Promise<CreatedCertificateResult> {
  const keyBundle = await generateKeyBundle(opts.keyType, opts.hashType);

  // 1. Subject DN
  const rdnEntries: RdnEntry[] = [
    { oid: "2.5.4.6", value: opts.country.slice(0, 2).toUpperCase(), isPrintable: true }, // C
    { oid: "2.5.4.8", value: opts.state }, // ST
    { oid: "2.5.4.7", value: opts.locality }, // L
    { oid: "2.5.4.10", value: opts.organization }, // O
    { oid: "2.5.4.11", value: opts.organizationalUnit }, // OU
    { oid: "2.5.4.3", value: opts.commonName }, // CN
  ].filter((e) => e.value.length > 0);

  const subjectDnDer = encodeDistinguishedName(rdnEntries);
  const issuerDnDer = subjectDnDer; // Self-signed: Issuer == Subject

  const dnStringParts: string[] = [];
  for (const entry of rdnEntries) {
    let name = entry.oid;
    if (entry.oid === "2.5.4.3") name = "CN";
    else if (entry.oid === "2.5.4.10") name = "O";
    else if (entry.oid === "2.5.4.11") name = "OU";
    else if (entry.oid === "2.5.4.6") name = "C";
    else if (entry.oid === "2.5.4.8") name = "ST";
    else if (entry.oid === "2.5.4.7") name = "L";
    dnStringParts.push(`${name}=${entry.value}`);
  }
  const subjectDnStr = dnStringParts.join(", ");
  const issuerDnStr = subjectDnStr;

  // 2. Validity
  const now = new Date();
  const notBefore = new Date(now.getTime() - 5 * 60 * 1000); // 5 minutes back for clock skew leeway
  const notAfter = new Date(now.getTime() + opts.validityDays * 24 * 60 * 60 * 1000);
  const validityDer = encodeDerSequence([encodeDerTime(notBefore), encodeDerTime(notAfter)]);

  // 3. Serial Number
  let serialBigInt: bigint;
  if (opts.customSerialHex && /^[0-9a-fA-F]+$/.test(opts.customSerialHex)) {
    serialBigInt = BigInt("0x" + opts.customSerialHex);
  } else {
    // Generate positive 128-bit random serial number
    const randomBytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(randomBytes);
    randomBytes[0] = (randomBytes[0] ?? 0) & 0x7f; // ensure positive
    let hex = "";
    for (let i = 0; i < 16; i++) {
      hex += (randomBytes[i] ?? 0).toString(16).padStart(2, "0");
    }
    serialBigInt = BigInt("0x" + hex);
  }
  const serialNumberHex = serialBigInt.toString(16).toUpperCase();

  // 4. Extensions
  const extensions: Uint8Array[] = [];

  // 4a. Basic Constraints (OID 2.5.29.19)
  const basicConstraintsDer = opts.isCa
    ? encodeDerSequence([encodeDerBoolean(true)])
    : encodeDerSequence([encodeDerBoolean(false)]);
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.19"),
      encodeDerBoolean(opts.isCa), // critical if CA
      encodeDerOctetString(basicConstraintsDer),
    ]),
  );

  // 4b. Key Usage (OID 2.5.29.15)
  // Bits: 0: digitalSignature, 1: nonRepudiation, 2: keyEncipherment, 4: keyAgreement, 5: keyCertSign, 6: cRLSign
  const kuBits = opts.isCa
    ? [0, 5, 6] // digitalSignature, keyCertSign, cRLSign
    : [0, 2, 4]; // digitalSignature, keyEncipherment, keyAgreement
  const kuBitString = encodeKeyUsageBitString(kuBits);
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.15"),
      encodeDerBoolean(true), // critical
      encodeDerOctetString(kuBitString),
    ]),
  );

  // 4c. Extended Key Usage (OID 2.5.29.37)
  if (!opts.isCa) {
    const ekuOids: Uint8Array[] = [];
    if (opts.serverAuth !== false) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.1")); // serverAuth
    if (opts.clientAuth !== false) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.2")); // clientAuth
    if (opts.codeSigning) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.3")); // codeSigning
    if (opts.emailProtection) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.4")); // emailProtection

    if (ekuOids.length > 0) {
      const ekuSequence = encodeDerSequence(ekuOids);
      extensions.push(
        encodeDerSequence([
          encodeDerOid("2.5.29.37"),
          encodeDerOctetString(ekuSequence),
        ]),
      );
    }
  }

  // 4d. Subject Alternative Names (OID 2.5.29.17)
  const sanDer = encodeSanExtension(opts.san || opts.commonName);
  if (sanDer) {
    extensions.push(
      encodeDerSequence([
        encodeDerOid("2.5.29.17"),
        encodeDerOctetString(sanDer),
      ]),
    );
  }

  // 4e. Subject Key Identifier (OID 2.5.29.14)
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.14"),
      encodeDerOctetString(encodeDerOctetString(keyBundle.ski)),
    ]),
  );

  // 4f. Authority Key Identifier (OID 2.5.29.35)
  // For self-signed, AKI == SKI
  const akiInner = encodeDerSequence([
    encodeDerContext(0, keyBundle.ski, false),
  ]);
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.35"),
      encodeDerOctetString(akiInner),
    ]),
  );

  // 5. Assemble TBSCertificate
  const tbsSequence = encodeDerSequence([
    // version: [0] EXPLICIT INTEGER 2 (v3)
    encodeDerContext(0, encodeDerInteger(2), true),
    // serialNumber: INTEGER
    encodeDerInteger(serialBigInt),
    // signature: AlgorithmIdentifier
    keyBundle.signatureAlgorithmDer,
    // issuer: Name
    issuerDnDer,
    // validity: Validity
    validityDer,
    // subject: Name
    subjectDnDer,
    // subjectPublicKeyInfo: SubjectPublicKeyInfo
    keyBundle.spkiBytes,
    // extensions: [3] EXPLICIT Extensions
    encodeDerContext(3, encodeDerSequence(extensions), true),
  ]);

  // 6. Sign TBSCertificate
  const signatureBytes = await keyBundle.signTbs(tbsSequence);
  const signatureBitString = encodeDerBitString(signatureBytes, 0);

  // 7. Assemble Full Certificate
  const certDer = encodeDerSequence([
    tbsSequence,
    keyBundle.signatureAlgorithmDer,
    signatureBitString,
  ]);

  const certPem = encodePem("CERTIFICATE", certDer);
  const fingerprintSha256 = bytesToHex(sha256(certDer)).toUpperCase().match(/../g)?.join(":") ?? "";

  // 8. OpenSSL Command reproduction
  let opensslKeyOpt = "-newkey ec -pkeyopt ec_paramgen_curve:prime256v1";
  if (opts.keyType === "rsa-2048") opensslKeyOpt = "-newkey rsa:2048";
  else if (opts.keyType === "rsa-4096") opensslKeyOpt = "-newkey rsa:4096";
  else if (opts.keyType === "ecdsa-p384") opensslKeyOpt = "-newkey ec -pkeyopt ec_paramgen_curve:secp384r1";
  else if (opts.keyType === "ed25519") opensslKeyOpt = "-newkey ed25519";

  const opensslCommand = `openssl req -x509 ${opensslKeyOpt} -keyout key.pem -out cert.pem -days ${opts.validityDays} -nodes -subj "/CN=${opts.commonName}"`;

  return {
    certPem,
    certDer,
    privateKeyPem: keyBundle.privateKeyPem,
    publicKeyPem: keyBundle.publicKeyPem,
    serialNumberHex,
    subjectDn: subjectDnStr,
    issuerDn: issuerDnStr,
    notBefore,
    notAfter,
    fingerprintSha256,
    opensslCommand,
    keyBundle,
  };
}
