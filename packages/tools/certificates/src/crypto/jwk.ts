import { sha256 } from "@noble/hashes/sha2.js";
import { parseAsn1, UniversalTag } from "../asn1/asn1";
import { detectInputBytes } from "../asn1/pem";
import type { KeyAlgorithmType } from "./keys";

export interface RsaJwk {
  kty: "RSA";
  use?: string;
  alg?: string;
  kid?: string;
  n: string;
  e: string;
}

export interface EcJwk {
  kty: "EC";
  use?: string;
  alg?: string;
  kid?: string;
  crv: "P-256" | "P-384" | "P-521";
  x: string;
  y: string;
}

export interface OkpJwk {
  kty: "OKP";
  use?: string;
  alg?: string;
  kid?: string;
  crv: "Ed25519";
  x: string;
}

export type Jwk = RsaJwk | EcJwk | OkpJwk;

export interface JwksBundle {
  keys: Jwk[];
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.length;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Computes RFC 7638 SHA-256 JWK Thumbprint (canonical JSON representation).
 */
export function computeJwkThumbprint(jwk: Jwk): string {
  let canonicalJson: string;
  if (jwk.kty === "RSA") {
    // Alphabetical order: e, kty, n
    canonicalJson = JSON.stringify({
      e: jwk.e,
      kty: "RSA",
      n: jwk.n,
    });
  } else if (jwk.kty === "EC") {
    // Alphabetical order: crv, kty, x, y
    canonicalJson = JSON.stringify({
      crv: jwk.crv,
      kty: "EC",
      x: jwk.x,
      y: jwk.y,
    });
  } else if (jwk.kty === "OKP") {
    // Alphabetical order: crv, kty, x
    canonicalJson = JSON.stringify({
      crv: jwk.crv,
      kty: "OKP",
      x: jwk.x,
    });
  } else {
    throw new Error("Unsupported JWK key type for thumbprint");
  }

  const digest = sha256(new TextEncoder().encode(canonicalJson));
  return toBase64Url(digest);
}

/**
 * Converts SPKI DER bytes into an RFC 7517 / RFC 8037 JSON Web Key (JWK).
 */
export function spkiToJwk(
  spkiBytes: Uint8Array,
  algorithmType?: KeyAlgorithmType,
  kid?: string,
): Jwk {
  const root = parseAsn1(spkiBytes);
  if (root.tagNumber !== UniversalTag.Sequence || root.children.length < 2) {
    throw new Error("Invalid SPKI ASN.1: expected SubjectPublicKeyInfo SEQUENCE");
  }

  const algSeq = root.children[0]!;
  const algOid = algSeq.children[0]?.asOid();
  const bitStringNode = root.children[1]!;
  const { bytes: pubKeyRaw } = bitStringNode.asBitString();

  // 1. Ed25519 (OID 1.3.101.112)
  if (algOid === "1.3.101.112" || algorithmType === "ed25519") {
    const x = toBase64Url(pubKeyRaw);
    const jwk: OkpJwk = {
      kty: "OKP",
      crv: "Ed25519",
      use: "sig",
      alg: "EdDSA",
      x,
    };
    jwk.kid = kid ?? computeJwkThumbprint(jwk);
    return jwk;
  }

  // 2. RSA (OID 1.2.840.113549.1.1.1)
  if (algOid === "1.2.840.113549.1.1.1" || algorithmType?.startsWith("rsa")) {
    const rsaNode = parseAsn1(pubKeyRaw);
    if (rsaNode.children.length < 2) {
      throw new Error("Invalid RSA public key internal ASN.1: expected modulus and exponent");
    }

    let nBytes = rsaNode.children[0]!.valueBytes;
    const eBytes = rsaNode.children[1]!.valueBytes;

    // RFC 7518: Strip leading zero byte if present in modulus
    if (nBytes[0] === 0x00 && nBytes.length > 1) {
      nBytes = nBytes.subarray(1);
    }

    const jwk: RsaJwk = {
      kty: "RSA",
      use: "sig",
      alg: "RS256",
      n: toBase64Url(nBytes),
      e: toBase64Url(eBytes),
    };
    jwk.kid = kid ?? computeJwkThumbprint(jwk);
    return jwk;
  }

  // 3. ECDSA (OID 1.2.840.10045.2.1)
  if (algOid === "1.2.840.10045.2.1" || algorithmType?.startsWith("ecdsa")) {
    const curveOid = algSeq.children[1]?.asOid();
    let crv: "P-256" | "P-384" | "P-521" = "P-256";
    let coordLen = 32;
    let alg = "ES256";

    if (curveOid === "1.3.132.0.34" || algorithmType === "ecdsa-p384") {
      crv = "P-384";
      coordLen = 48;
      alg = "ES384";
    } else if (curveOid === "1.3.132.0.35" || algorithmType === "ecdsa-p521") {
      crv = "P-521";
      coordLen = 66;
      alg = "ES512";
    }

    // Uncompressed point starts with 0x04, followed by X (coordLen) and Y (coordLen)
    if (pubKeyRaw[0] !== 0x04 || pubKeyRaw.length < 1 + coordLen * 2) {
      throw new Error(`Invalid uncompressed EC point for curve ${crv}`);
    }

    const xBytes = pubKeyRaw.subarray(1, 1 + coordLen);
    const yBytes = pubKeyRaw.subarray(1 + coordLen, 1 + coordLen * 2);

    const jwk: EcJwk = {
      kty: "EC",
      crv,
      use: "sig",
      alg,
      x: toBase64Url(xBytes),
      y: toBase64Url(yBytes),
    };
    jwk.kid = kid ?? computeJwkThumbprint(jwk);
    return jwk;
  }

  throw new Error(`Unsupported public key algorithm for JWK: OID ${algOid}`);
}

/**
 * Converts a PEM string (PUBLIC KEY or CERTIFICATE) into an RFC 7517 JWK.
 */
export function pemToJwk(pemOrDer: string | Uint8Array, kid?: string): Jwk {
  const bytes = typeof pemOrDer === "string" ? new TextEncoder().encode(pemOrDer) : pemOrDer;
  const detected = detectInputBytes(bytes);
  let spkiDer = detected.der;

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

  return spkiToJwk(spkiDer, undefined, kid);
}

/**
 * Formats one or more JWKs into a standard RFC 7517 JWKS JSON bundle.
 */
export function formatJwks(keys: Jwk[]): string {
  const bundle: JwksBundle = { keys };
  return JSON.stringify(bundle, null, 2);
}
