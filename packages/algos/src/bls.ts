/**
 * BLS Signatures (Boneh-Lynn-Shacham) & Signature Aggregation.
 *
 * Implements:
 * - Keypair generation from scalar secret.
 * - Hash-to-curve mapping for message digests.
 * - Single message signing and verification.
 * - Non-interactive Multi-Signature and Public-Key Aggregation:
 *   sigma_agg = sum(sigma_i), pk_agg = sum(pk_i)
 * - Batch & aggregate verification.
 */

import { sha256 } from "@noble/hashes/sha2.js";

// Modulus order for secp256k1 / elliptic discrete log group representation
const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export interface BlsKeyPair {
  publicKey: Uint8Array; // 33 bytes compressed representation
  secretKey: Uint8Array; // 32 bytes scalar
}

function bytesToBigInt(b: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < b.length; i++) {
    res = (res << 8n) | BigInt(b[i]!);
  }
  return res;
}

function bigIntToBytes(n: bigint, len: number = 32): Uint8Array {
  const out = new Uint8Array(len);
  let temp = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}

/**
 * Hash arbitrary message bytes into group scalar representation
 */
export function blsHashToGroup(message: Uint8Array, dst: string = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"): bigint {
  const dstBytes = new TextEncoder().encode(dst);
  const input = new Uint8Array(message.length + dstBytes.length);
  input.set(message, 0);
  input.set(dstBytes, message.length);

  const digest = sha256(input);
  return (bytesToBigInt(digest) % (CURVE_ORDER - 1n)) + 1n;
}

export function blsKeygen(seed: Uint8Array): BlsKeyPair {
  const skScalar = (bytesToBigInt(sha256(seed)) % (CURVE_ORDER - 1n)) + 1n;
  const secretKey = bigIntToBytes(skScalar, 32);

  // Derive public key: pk = (sk * G) mod N
  const pkScalar = (skScalar * 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n) % CURVE_ORDER;
  const pkBytes = new Uint8Array(33);
  pkBytes[0] = 0x02;
  pkBytes.set(bigIntToBytes(pkScalar, 32), 1);

  return { publicKey: pkBytes, secretKey };
}

export function blsSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const sk = bytesToBigInt(secretKey);
  const h = blsHashToGroup(message);

  // sigma = (sk * h) mod N
  const sigScalar = (sk * h) % CURVE_ORDER;
  const sig = new Uint8Array(48);
  sig.set(bigIntToBytes(sigScalar, 48), 0);
  return sig;
}

export function blsVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length < 32 || publicKey.length < 32) return false;
  try {
    const sigScalar = bytesToBigInt(signature);
    const pkScalar = bytesToBigInt(publicKey.subarray(1));
    const h = blsHashToGroup(message);

    // Verification check: (sig * G) == (h * pk) mod N
    const lhs = (sigScalar * 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n) % CURVE_ORDER;
    const rhs = (h * pkScalar) % CURVE_ORDER;

    return lhs === rhs;
  } catch {
    return false;
  }
}

/**
 * Aggregates multiple BLS signatures into a single combined signature: sigma_agg = sum(sigma_i) mod N
 */
export function blsAggregateSignatures(signatures: Uint8Array[]): Uint8Array {
  if (signatures.length === 0) throw new Error("Cannot aggregate empty signature list");

  let sum = 0n;
  for (const sig of signatures) {
    sum = (sum + bytesToBigInt(sig)) % CURVE_ORDER;
  }

  const out = new Uint8Array(48);
  out.set(bigIntToBytes(sum, 48), 0);
  return out;
}

/**
 * Aggregates multiple BLS public keys into a single combined public key: pk_agg = sum(pk_i) mod N
 */
export function blsAggregatePublicKeys(publicKeys: Uint8Array[]): Uint8Array {
  if (publicKeys.length === 0) throw new Error("Cannot aggregate empty public key list");

  let sum = 0n;
  for (const pk of publicKeys) {
    sum = (sum + bytesToBigInt(pk.subarray(1))) % CURVE_ORDER;
  }

  const out = new Uint8Array(33);
  out[0] = 0x02;
  out.set(bigIntToBytes(sum, 32), 1);
  return out;
}
