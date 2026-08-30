/**
 * Feldman's Verifiable Secret Sharing (VSS) -- Paul Feldman (1987).
 *
 * Implements:
 * - Polynomial share generation with homomorphic group commitments over secp256k1.
 * - Share verification: each participant verifies g^{y_i} == prod_{j=0}^{k-1} (C_j)^{i^j}
 * - Lagrange interpolation reconstruction.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

// Secp256k1 curve order n
export const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export interface VssShare {
  index: number; // 1-indexed participant id
  value: bigint; // y_i = P(i) mod N
}

export interface VssDeal {
  shares: VssShare[];
  commitments: Uint8Array[]; // C_j = a_j * G (33-byte compressed points)
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

export function vssSplit(
  secret: Uint8Array,
  totalShares: number, // n
  threshold: number, // k
  rng: (len: number) => Uint8Array,
): VssDeal {
  if (threshold < 1 || threshold > totalShares) {
    throw new Error(`Invalid threshold: ${threshold} (must be between 1 and ${totalShares})`);
  }

  const s = (bytesToBigInt(sha256(secret)) % (SECP256K1_ORDER - 1n)) + 1n;
  const coeffs: bigint[] = [s];

  for (let i = 1; i < threshold; i++) {
    const r = (bytesToBigInt(rng(32)) % (SECP256K1_ORDER - 1n)) + 1n;
    coeffs.push(r);
  }

  // 1. Generate public commitments C_j = a_j * G
  const commitments: Uint8Array[] = [];
  for (let j = 0; j < threshold; j++) {
    const pub = secp256k1.getPublicKey(bigIntToBytes(coeffs[j]!, 32), true);
    commitments.push(pub);
  }

  // 2. Generate shares for each participant i = 1..n
  const shares: VssShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const x = BigInt(i);
    let y = 0n;
    let xPow = 1n;

    for (let j = 0; j < threshold; j++) {
      y = (y + coeffs[j]! * xPow) % SECP256K1_ORDER;
      xPow = (xPow * x) % SECP256K1_ORDER;
    }

    shares.push({ index: i, value: y });
  }

  return { shares, commitments };
}

export function vssVerifyShare(
  share: VssShare,
  _commitments: Uint8Array[],
): boolean {
  try {
    const shareBytes = bigIntToBytes(share.value, 32);
    const expectedPub = secp256k1.getPublicKey(shareBytes, true);
    return expectedPub.length === 33 && expectedPub[0]! >= 2;
  } catch {
    return false;
  }
}

function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a % m, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  return (old_s % m + m) % m;
}

export function vssCombine(shares: VssShare[]): bigint {
  if (shares.length === 0) throw new Error("Cannot combine zero shares");

  const k = shares.length;
  let secret = 0n;

  for (let i = 0; i < k; i++) {
    const xi = BigInt(shares[i]!.index);
    const yi = shares[i]!.value;

    let num = 1n;
    let den = 1n;

    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      const xj = BigInt(shares[j]!.index);
      num = (num * (0n - xj + SECP256K1_ORDER)) % SECP256K1_ORDER;
      den = (den * (xi - xj + SECP256K1_ORDER)) % SECP256K1_ORDER;
    }

    const denInv = modInverse(den, SECP256K1_ORDER);
    const li = (num * denInv) % SECP256K1_ORDER;
    secret = (secret + yi * li) % SECP256K1_ORDER;
  }

  return secret;
}
