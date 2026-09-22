import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { parseAsn1, UniversalTag } from "./asn1";
import {
  encodeDerInteger,
  encodeDerNull,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
} from "./encoder";
import { parseAllPem, detectInputBytes } from "./pem";
import { parseX509Certificate, type ParsedX509Certificate } from "./x509";
import { parseCsr, type ParsedCsr } from "./csr";

export interface CertMatcherResult {
  matches: boolean;
  targetType: "certificate" | "csr";
  keyType: string;
  keyDetails: string;
  fingerprints: {
    certOrCsrPublicKeySha256: string;
    privateKeyDerivedPublicKeySha256?: string;
  };
  details: {
    subjectDn?: string;
    serialNumber?: string;
    notAfter?: string;
    probeVerified: boolean;
  };
  summary: string;
  errors: string[];
}

/**
 * Normalizes private key DER bytes into PKCS#8 structure.
 * Handles PKCS#1 RSA private keys and SEC1 EC private keys.
 */
export function ensurePkcs8(keyBytes: Uint8Array): Uint8Array {
  try {
    const root = parseAsn1(keyBytes);

    // 1. Already PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING (privateKey) }
    if (
      root.children.length >= 3 &&
      root.children[0]?.tagNumber === UniversalTag.Integer &&
      root.children[1]?.tagNumber === UniversalTag.Sequence &&
      root.children[2]?.tagNumber === UniversalTag.OctetString
    ) {
      return keyBytes;
    }

    // 2. PKCS#1 RSA Private Key: SEQUENCE { INTEGER 0, INTEGER n, INTEGER e, INTEGER d, ... }
    if (
      root.children.length >= 8 &&
      root.children[0]?.tagNumber === UniversalTag.Integer &&
      root.children[1]?.tagNumber === UniversalTag.Integer &&
      root.children[2]?.tagNumber === UniversalTag.Integer
    ) {
      const rsaAlgId = encodeDerSequence([encodeDerOid("1.2.840.113549.1.1.1"), encodeDerNull()]);
      return encodeDerSequence([
        encodeDerInteger(0),
        rsaAlgId,
        encodeDerOctetString(keyBytes),
      ]);
    }

    // 3. SEC1 EC Private Key: SEQUENCE { INTEGER 1, OCTET STRING privateKey, [0] parameters, [1] publicKey }
    if (
      root.children.length >= 2 &&
      root.children[0]?.tagNumber === UniversalTag.Integer &&
      root.children[1]?.tagNumber === UniversalTag.OctetString
    ) {
      let curveOid = "1.2.840.10045.3.1.7"; // prime256v1 default
      for (const child of root.children) {
        if (child.tagClass === 2 && child.tagNumber === 0 && child.children[0]) {
          try {
            curveOid = child.children[0].asOid();
          } catch {
            // keep default
          }
        }
      }
      const ecAlgId = encodeDerSequence([
        encodeDerOid("1.2.840.10045.2.1"), // id-ecPublicKey
        encodeDerOid(curveOid),
      ]);
      return encodeDerSequence([
        encodeDerInteger(0),
        ecAlgId,
        encodeDerOctetString(keyBytes),
      ]);
    }
  } catch {
    // Return original if parsing fails
  }

  return keyBytes;
}

/**
 * Checks whether an X.509 Certificate or CSR cryptographically matches a Private Key.
 */
export async function verifyCertificateKeyPair(
  certOrCsrInput: string | Uint8Array,
  keyInput?: string | Uint8Array,
): Promise<CertMatcherResult> {
  const errors: string[] = [];
  let certDer: Uint8Array | undefined;
  let csrDer: Uint8Array | undefined;
  let rawKeyDer: Uint8Array | undefined;
  let targetType: "certificate" | "csr" = "certificate";

  // 1. Separate combined inputs if only one parameter was supplied
  if (!keyInput || (typeof keyInput === "string" && keyInput.trim().length === 0)) {
    if (typeof certOrCsrInput === "string") {
      const blocks = parseAllPem(certOrCsrInput);
      for (const block of blocks) {
        const lbl = block.label.toUpperCase();
        if (lbl.includes("CERTIFICATE") && !lbl.includes("REQUEST")) {
          certDer = block.bytes;
        } else if (lbl.includes("CERTIFICATE REQUEST") || lbl.includes("CSR")) {
          csrDer = block.bytes;
        } else if (lbl.includes("PRIVATE KEY")) {
          rawKeyDer = block.bytes;
        }
      }
    }
  } else {
    // Inputs were provided separately
    if (typeof certOrCsrInput === "string") {
      const blocks = parseAllPem(certOrCsrInput);
      if (blocks.length > 0 && blocks[0]) {
        if (blocks[0].label.includes("REQUEST") || blocks[0].label.includes("CSR")) {
          csrDer = blocks[0].bytes;
        } else {
          certDer = blocks[0].bytes;
        }
      } else {
        certDer = detectInputBytes(certOrCsrInput).der;
      }
    } else {
      certDer = certOrCsrInput;
    }

    if (typeof keyInput === "string") {
      const keyBlocks = parseAllPem(keyInput);
      if (keyBlocks.length > 0 && keyBlocks[0]) {
        rawKeyDer = keyBlocks[0].bytes;
      } else {
        rawKeyDer = detectInputBytes(keyInput).der;
      }
    } else {
      rawKeyDer = keyInput;
    }
  }

  if (!certDer && !csrDer) {
    throw new Error("No valid X.509 Certificate or PKCS#10 CSR found in the provided input.");
  }
  if (!rawKeyDer) {
    throw new Error("No private key found. Paste the matching private key (PEM or DER).");
  }

  let parsedCert: ParsedX509Certificate | undefined;
  let parsedCsr: ParsedCsr | undefined;
  let certPubSpki: Uint8Array;
  let certKeyType: string;
  let certKeyDetails: string;
  let subjectDn = "";
  let serialNumber: string | undefined;
  let notAfter: string | undefined;

  if (certDer) {
    targetType = "certificate";
    parsedCert = parseX509Certificate(certDer);
    certPubSpki = parsedCert.publicKey.spkiDer;
    certKeyType = parsedCert.publicKey.keyType;
    certKeyDetails = parsedCert.publicKey.details;
    subjectDn = parsedCert.subject.dn;
    serialNumber = parsedCert.serialNumber;
    notAfter = parsedCert.validity.notAfter.toISOString();
  } else {
    targetType = "csr";
    parsedCsr = parseCsr(csrDer!);
    certPubSpki = parsedCsr.publicKey.spkiDer;
    certKeyType = parsedCsr.publicKey.keyType;
    certKeyDetails = parsedCsr.publicKey.details;
    subjectDn = parsedCsr.subject.dn;
  }

  const pkcs8Key = ensurePkcs8(rawKeyDer);
  const subtle = globalThis.crypto?.subtle;
  let probeVerified = false;

  // 2. Cryptographic Probe Verification
  const challenge = new TextEncoder().encode(`CipherWorkbench-MatchProbe-${Date.now()}`);

  if (certKeyType === "ed25519") {
    try {
      const seed = pkcs8Key.slice(-32);
      const privPub = ed25519.getPublicKey(seed);
      const rawPub = certPubSpki.slice(-32);

      const pubMatches = bytesToHex(privPub) === bytesToHex(rawPub);
      if (!pubMatches) {
        errors.push("Ed25519 public key bytes do not match the private key.");
      }

      const sig = ed25519.sign(challenge, seed);
      probeVerified = ed25519.verify(sig, challenge, rawPub);
      if (!probeVerified) {
        errors.push("Ed25519 signature probe verification failed.");
      }
    } catch (err) {
      errors.push(`Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else if (certKeyType === "rsa") {
    if (!subtle) {
      throw new Error("WebCrypto is not available in this environment.");
    }
    try {
      const privKey = await subtle.importKey(
        "pkcs8",
        pkcs8Key as unknown as BufferSource,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const pubKey = await subtle.importKey(
        "spki",
        certPubSpki as unknown as BufferSource,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );

      const signature = await subtle.sign("RSASSA-PKCS1-v1_5", privKey, challenge);
      probeVerified = await subtle.verify("RSASSA-PKCS1-v1_5", pubKey, signature, challenge);

      if (!probeVerified) {
        errors.push("RSA signature verification probe failed: public key and private key do not form a key pair.");
      }
    } catch (err) {
      errors.push(`RSA key probe failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else if (certKeyType === "ec") {
    if (!subtle) {
      throw new Error("WebCrypto is not available in this environment.");
    }
    try {
      const namedCurve =
        certKeyDetails.includes("P-384") || certKeyDetails.includes("secp384r1")
          ? "P-384"
          : certKeyDetails.includes("P-521") || certKeyDetails.includes("secp521r1")
            ? "P-521"
            : "P-256";

      const privKey = await subtle.importKey(
        "pkcs8",
        pkcs8Key as unknown as BufferSource,
        { name: "ECDSA", namedCurve },
        false,
        ["sign"],
      );
      const pubKey = await subtle.importKey(
        "spki",
        certPubSpki as unknown as BufferSource,
        { name: "ECDSA", namedCurve },
        false,
        ["verify"],
      );

      const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privKey, challenge);
      probeVerified = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, signature, challenge);

      if (!probeVerified) {
        errors.push("ECDSA signature verification probe failed: key coordinates do not match.");
      }
    } catch (err) {
      errors.push(`ECDSA key probe failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else {
    errors.push(`Unsupported or unrecognized key algorithm: ${certKeyType}`);
  }

  const pubSha256 = bytesToHex(sha256(certPubSpki)).toUpperCase().match(/../g)?.join(":") ?? "";
  const matches = probeVerified && errors.length === 0;

  const summary = matches
    ? `MATCH CONFIRMED: The private key mathematically and cryptographically corresponds to this ${targetType.toUpperCase()} (${certKeyDetails}).`
    : `KEY MISMATCH: The private key does NOT correspond to this ${targetType.toUpperCase()}. Errors: ${errors.join("; ")}`;

  return {
    matches,
    targetType,
    keyType: certKeyType.toUpperCase(),
    keyDetails: certKeyDetails,
    fingerprints: {
      certOrCsrPublicKeySha256: pubSha256,
      privateKeyDerivedPublicKeySha256: probeVerified ? pubSha256 : undefined,
    },
    details: {
      subjectDn,
      serialNumber,
      notAfter,
      probeVerified,
    },
    summary,
    errors,
  };
}
