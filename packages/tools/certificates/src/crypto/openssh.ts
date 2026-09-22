import { sha256 } from "@noble/hashes/sha2.js";
import { parseAsn1, UniversalTag } from "../asn1/asn1";
import { detectInputBytes } from "../asn1/pem";
import type { KeyAlgorithmType } from "./keys";

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function writeUint32Be(val: number): Uint8Array {
  return new Uint8Array([
    (val >>> 24) & 0xff,
    (val >>> 16) & 0xff,
    (val >>> 8) & 0xff,
    val & 0xff,
  ]);
}

export function sshString(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const lenHeader = writeUint32Be(bytes.length);
  const out = new Uint8Array(4 + bytes.length);
  out.set(lenHeader, 0);
  out.set(bytes, 4);
  return out;
}

export function sshMpint(value: Uint8Array | bigint): Uint8Array {
  let bytes: Uint8Array;
  if (typeof value === "bigint") {
    if (value === 0n) {
      return new Uint8Array([0, 0, 0, 0]);
    }
    let hex = value.toString(16);
    if (hex.length % 2 !== 0) hex = "0" + hex;
    const numBytes = hex.length / 2;
    bytes = new Uint8Array(numBytes);
    for (let i = 0; i < numBytes; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
  } else {
    bytes = value;
  }

  // Remove redundant leading zeros
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00 && (bytes[start + 1]! & 0x80) === 0) {
    start++;
  }
  const trimmed = bytes.subarray(start);

  // If MSB is set, prepend 0x00 for two's-complement positive representation
  let finalPayload: Uint8Array;
  if ((trimmed[0] ?? 0) >= 0x80) {
    finalPayload = new Uint8Array(trimmed.length + 1);
    finalPayload[0] = 0x00;
    finalPayload.set(trimmed, 1);
  } else {
    finalPayload = trimmed;
  }

  const lenHeader = writeUint32Be(finalPayload.length);
  const out = new Uint8Array(4 + finalPayload.length);
  out.set(lenHeader, 0);
  out.set(finalPayload, 4);
  return out;
}

function concatSshChunks(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export interface OpenSshKeyResult {
  keyType: string;
  wireBlob: Uint8Array;
  base64: string;
  authorizedKeysLine: string;
  sha256Fingerprint: string;
}

/**
 * Extracts and formats an OpenSSH public key (RFC 4253 / RFC 8709) from SPKI DER bytes.
 */
export function spkiToOpenSsh(
  spkiBytes: Uint8Array,
  algorithmType?: KeyAlgorithmType,
  comment = "user@cipherworkbench",
): OpenSshKeyResult {
  const root = parseAsn1(spkiBytes);
  if (root.tagNumber !== UniversalTag.Sequence || root.children.length < 2) {
    throw new Error("Invalid SPKI ASN.1: expected SubjectPublicKeyInfo SEQUENCE");
  }

  const algSeq = root.children[0]!;
  const algOid = algSeq.children[0]?.asOid();
  const bitStringNode = root.children[1]!;
  const { bytes: pubKeyRaw } = bitStringNode.asBitString();

  let wireBlob: Uint8Array;
  let keyType: string;

  // 1. Ed25519 (OID 1.3.101.112)
  if (algOid === "1.3.101.112" || algorithmType === "ed25519") {
    keyType = "ssh-ed25519";
    wireBlob = concatSshChunks(
      sshString("ssh-ed25519"),
      sshString(pubKeyRaw),
    );
  } else if (algOid === "1.2.840.113549.1.1.1" || algorithmType?.startsWith("rsa")) {
    // 2. RSA (OID 1.2.840.113549.1.1.1)
    keyType = "ssh-rsa";
    const rsaNode = parseAsn1(pubKeyRaw);
    if (rsaNode.children.length < 2) {
      throw new Error("Invalid RSA public key internal ASN.1: expected modulus and exponent");
    }
    const modulusBytes = rsaNode.children[0]!.valueBytes;
    const exponentBytes = rsaNode.children[1]!.valueBytes;

    wireBlob = concatSshChunks(
      sshString("ssh-rsa"),
      sshMpint(exponentBytes),
      sshMpint(modulusBytes),
    );
  } else if (algOid === "1.2.840.10045.2.1" || algorithmType?.startsWith("ecdsa")) {
    // 3. ECDSA (OID 1.2.840.10045.2.1)
    const curveOid = algSeq.children[1]?.asOid();
    let curveName = "nistp256";
    if (curveOid === "1.3.132.0.34" || algorithmType === "ecdsa-p384") {
      curveName = "nistp384";
    } else if (curveOid === "1.3.132.0.35" || algorithmType === "ecdsa-p521") {
      curveName = "nistp521";
    }

    keyType = `ecdsa-sha2-${curveName}`;
    wireBlob = concatSshChunks(
      sshString(keyType),
      sshString(curveName),
      sshString(pubKeyRaw),
    );
  } else {
    throw new Error(`Unsupported public key algorithm for OpenSSH: OID ${algOid}`);
  }

  const b64 = uint8ArrayToBase64(wireBlob);
  const commentStr = comment ? ` ${comment}` : "";
  const authorizedKeysLine = `${keyType} ${b64}${commentStr}`;

  // SHA256 Fingerprint (OpenSSH format: SHA256:<base64-unpadded>)
  const digest = sha256(wireBlob);
  const fpB64 = uint8ArrayToBase64(digest).replace(/=+$/, "");
  const sha256Fingerprint = `SHA256:${fpB64}`;

  return {
    keyType,
    wireBlob,
    base64: b64,
    authorizedKeysLine,
    sha256Fingerprint,
  };
}

/**
 * Extracts and formats an OpenSSH public key from a PEM string (PUBLIC KEY or CERTIFICATE).
 */
export function pemToOpenSsh(pemOrDer: string | Uint8Array, comment?: string): OpenSshKeyResult {
  const bytes = typeof pemOrDer === "string" ? new TextEncoder().encode(pemOrDer) : pemOrDer;
  const detected = detectInputBytes(bytes);
  let spkiDer = detected.der;

  // If input is an X.509 certificate, extract SPKI from TBSCertificate
  const parsed = parseAsn1(spkiDer);
  if (
    parsed.tagNumber === UniversalTag.Sequence &&
    parsed.children.length === 3 &&
    parsed.children[0]?.children.length &&
    parsed.children[0]!.children.length > 5
  ) {
    const tbs = parsed.children[0]!;
    for (const child of tbs.children) {
      if (
        child.tagNumber === UniversalTag.Sequence &&
        child.children.length === 2 &&
        child.children[1]?.tagNumber === UniversalTag.BitString
      ) {
        spkiDer = child.raw;
        break;
      }
    }
  }

  return spkiToOpenSsh(spkiDer, undefined, comment);
}
