/**
 * BLS12-381 Pairing-Friendly Elliptic Curve Signatures and Aggregation
 * Specification: RFC 9380 (Hashing to Elliptic Curves) & IETF draft-irtf-cfrg-bls-signature
 *
 * Used extensively in Ethereum 2.0 consensus, Filecoin, Chia, and threshold cryptography.
 *
 * Properties:
 *  - Public keys: G1 curve points (48 bytes compressed)
 *  - Signatures: G2 curve points (96 bytes compressed)
 *  - Fast Aggregate: Multi-party signatures on the SAME message verified via e(sum(PK_i), H(m)) == e(G1, sig_agg)
 *  - General Aggregate: Distinct messages verified via prod(e(PK_i, H(m_i))) == e(G1, sig_agg)
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";

export const BLS12381_DEFAULT_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
export const BLS12381_G1_PUBKEY_SIZE = 48;
export const BLS12381_G2_SIGNATURE_SIZE = 96;
export const BLS12381_SECRET_KEY_SIZE = 32;

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < bytes.length; i++) {
    res = (res << 8n) | BigInt(bytes[i]!);
  }
  return res;
}

function bigIntToBytesBE(num: bigint, len: number): Uint8Array {
  const res = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    res[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return res;
}

function parsePointBytes(bytes: Uint8Array | string): Uint8Array {
  if (typeof bytes === "string") {
    const clean = bytes.replace(/^0x/i, "").trim();
    if (clean.length % 2 !== 0) throw new Error("Invalid hex string length");
    const arr = new Uint8Array(clean.length / 2);
    for (let i = 0; i < arr.length; i++) {
      arr[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return arr;
  }
  return bytes;
}

/**
 * Validates and converts 32-byte secret key scalar.
 */
export function bls12381NormalizeSecretKey(secretKey: Uint8Array | string): bigint {
  const bytes = parsePointBytes(secretKey);
  if (bytes.length !== BLS12381_SECRET_KEY_SIZE) {
    throw new Error(`BLS12-381 secret key must be ${BLS12381_SECRET_KEY_SIZE} bytes, got ${bytes.length}`);
  }
  const scalar = bytesToBigIntBE(bytes) % bls12_381.fields.Fr.ORDER;
  if (scalar === 0n) {
    throw new Error("BLS12-381 secret key scalar cannot be 0");
  }
  return scalar;
}

/**
 * Generates a fresh BLS12-381 secret key and corresponding G1 public key.
 */
export function bls12381Keygen(seed?: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  let skBytes: Uint8Array;
  if (seed) {
    if (seed.length < 32) throw new Error("Keygen seed must be at least 32 bytes");
    skBytes = seed.slice(0, 32);
  } else {
    skBytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(skBytes);
  }

  // Ensure non-zero mod Fr
  let scalar = bytesToBigIntBE(skBytes) % bls12_381.fields.Fr.ORDER;
  if (scalar === 0n) scalar = 1n;
  const secretKey = bigIntToBytesBE(scalar, 32);
  const publicKey = bls12381GetPublicKey(secretKey);
  return { secretKey, publicKey };
}

/**
 * Derives a compressed 48-byte G1 public key from a 32-byte secret key.
 */
export function bls12381GetPublicKey(secretKey: Uint8Array | string): Uint8Array {
  const scalar = bls12381NormalizeSecretKey(secretKey);
  const pubPoint = bls12_381.G1.Point.BASE.multiply(scalar);
  return pubPoint.toBytes(true);
}

/**
 * Signs a message into a compressed 96-byte G2 signature.
 */
export function bls12381Sign(
  message: Uint8Array,
  secretKey: Uint8Array | string,
  dst: string = BLS12381_DEFAULT_DST,
): Uint8Array {
  const scalar = bls12381NormalizeSecretKey(secretKey);
  const hashPoint = bls12_381.G2.hashToCurve(message, { DST: dst });
  const sigPoint = hashPoint.multiply(scalar);
  return sigPoint.toBytes(true);
}

/**
 * Verifies a 96-byte G2 signature against a 48-byte G1 public key and message.
 */
export function bls12381Verify(
  signature: Uint8Array | string,
  message: Uint8Array,
  publicKey: Uint8Array | string,
  dst: string = BLS12381_DEFAULT_DST,
): boolean {
  try {
    const sigBytes = parsePointBytes(signature);
    const pubBytes = parsePointBytes(publicKey);
    if (sigBytes.length !== BLS12381_G2_SIGNATURE_SIZE) return false;
    if (pubBytes.length !== BLS12381_G1_PUBKEY_SIZE) return false;

    const sigPoint = bls12_381.G2.Point.fromBytes(sigBytes);
    const pubPoint = bls12_381.G1.Point.fromBytes(pubBytes);
    const hashPoint = bls12_381.G2.hashToCurve(message, { DST: dst });

    // Check pairing: e(pub, H(m)) == e(G1_BASE, sig)
    const p1 = bls12_381.pairing(pubPoint, hashPoint);
    const p2 = bls12_381.pairing(bls12_381.G1.Point.BASE, sigPoint);
    return bls12_381.fields.Fp12.eql(p1, p2);
  } catch {
    return false;
  }
}

/**
 * Aggregates multiple G2 signatures into a single compressed 96-byte G2 signature.
 */
export function bls12381AggregateSignatures(signatures: (Uint8Array | string)[]): Uint8Array {
  if (signatures.length === 0) {
    throw new Error("Cannot aggregate empty list of signatures");
  }

  let aggPoint = bls12_381.G2.Point.ZERO;
  for (const s of signatures) {
    const bytes = parsePointBytes(s);
    if (bytes.length !== BLS12381_G2_SIGNATURE_SIZE) {
      throw new Error(`Signature must be ${BLS12381_G2_SIGNATURE_SIZE} bytes, got ${bytes.length}`);
    }
    const pt = bls12_381.G2.Point.fromBytes(bytes);
    aggPoint = aggPoint.add(pt);
  }
  return aggPoint.toBytes(true);
}

/**
 * Aggregates multiple G1 public keys into a single compressed 48-byte G1 public key.
 */
export function bls12381AggregatePublicKeys(publicKeys: (Uint8Array | string)[]): Uint8Array {
  if (publicKeys.length === 0) {
    throw new Error("Cannot aggregate empty list of public keys");
  }

  let aggPoint = bls12_381.G1.Point.ZERO;
  for (const pk of publicKeys) {
    const bytes = parsePointBytes(pk);
    if (bytes.length !== BLS12381_G1_PUBKEY_SIZE) {
      throw new Error(`Public key must be ${BLS12381_G1_PUBKEY_SIZE} bytes, got ${bytes.length}`);
    }
    const pt = bls12_381.G1.Point.fromBytes(bytes);
    aggPoint = aggPoint.add(pt);
  }
  return aggPoint.toBytes(true);
}

/**
 * Fast verification when ALL signers signed the SAME message.
 * Verifies e(sum(PK_i), H(m)) == e(G1_BASE, sig_agg) with only 2 pairings.
 */
export function bls12381VerifyFastAggregate(
  aggregateSignature: Uint8Array | string,
  message: Uint8Array,
  publicKeys: (Uint8Array | string)[],
  dst: string = BLS12381_DEFAULT_DST,
): boolean {
  try {
    if (publicKeys.length === 0) return false;
    const aggPub = bls12381AggregatePublicKeys(publicKeys);
    return bls12381Verify(aggregateSignature, message, aggPub, dst);
  } catch {
    return false;
  }
}

/**
 * Verifies an aggregate signature when different signers signed DIFFERENT messages.
 * Verifies e(G1_BASE, sig_agg) == prod(e(PK_i, H(m_i))).
 */
export function bls12381VerifyBatch(
  aggregateSignature: Uint8Array | string,
  messages: Uint8Array[],
  publicKeys: (Uint8Array | string)[],
  dst: string = BLS12381_DEFAULT_DST,
): boolean {
  try {
    if (messages.length === 0 || messages.length !== publicKeys.length) return false;
    const sigBytes = parsePointBytes(aggregateSignature);
    if (sigBytes.length !== BLS12381_G2_SIGNATURE_SIZE) return false;

    const sigPoint = bls12_381.G2.Point.fromBytes(sigBytes);
    const pLeft = bls12_381.pairing(bls12_381.G1.Point.BASE, sigPoint);

    let pRightProd: ReturnType<typeof bls12_381.pairing> | null = null;
    for (let i = 0; i < publicKeys.length; i++) {
      const pubBytes = parsePointBytes(publicKeys[i]!);
      const pubPoint = bls12_381.G1.Point.fromBytes(pubBytes);
      const hashPoint = bls12_381.G2.hashToCurve(messages[i]!, { DST: dst });
      const p = bls12_381.pairing(pubPoint, hashPoint);

      if (pRightProd === null) {
        pRightProd = p;
      } else {
        pRightProd = bls12_381.fields.Fp12.mul(pRightProd, p);
      }
    }

    if (!pRightProd) return false;
    return bls12_381.fields.Fp12.eql(pLeft, pRightProd);
  } catch {
    return false;
  }
}
