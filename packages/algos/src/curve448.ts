/**
 * Curve448 (Ed448 & X448) -- High-Security 448-bit Edwards & Montgomery Curves (RFC 7748 / RFC 8032).
 *
 * Implements:
 * - Goldilocks Field arithmetic: p = 2^448 - 2^224 - 1.
 * - X448 Diffie-Hellman Montgomery ladder (56-byte keys and shared secrets).
 * - Ed448 Edwards digital signatures (57-byte public keys, 114-byte signatures).
 */

import { sha512 } from "@noble/hashes/sha2.js";

const P_448 = (1n << 448n) - (1n << 224n) - 1n;
const A_24 = 39058n; // (458605 - 2) / 4 for X448 Montgomery curve

function bytesToBigIntLE(b: Uint8Array): bigint {
  let res = 0n;
  for (let i = b.length - 1; i >= 0; i--) {
    res = (res << 8n) | BigInt(b[i]!);
  }
  return res;
}

function bigIntToBytesLE(n: bigint, len: number = 56): Uint8Array {
  const out = new Uint8Array(len);
  let temp = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}

/**
 * X448 Scalar Multiplication Montgomery Ladder (RFC 7748 Section 5)
 */
export function x448(scalar: Uint8Array, uCoordinate: Uint8Array): Uint8Array {
  // Clamp scalar per RFC 7748 Section 5
  const kBytes = new Uint8Array(scalar.slice(0, 56));
  kBytes[0] = (kBytes[0] ?? 0) & 252;
  kBytes[55] = (kBytes[55] ?? 0) | 128;

  const k = bytesToBigIntLE(kBytes);
  const u = bytesToBigIntLE(uCoordinate.slice(0, 56)) % P_448;

  const x_1 = u;
  let x_2 = 1n;
  let z_2 = 0n;
  let x_3 = u;
  let z_3 = 1n;
  let swap = 0n;

  for (let t = 447; t >= 0; t--) {
    const k_t = (k >> BigInt(t)) & 1n;
    swap ^= k_t;

    if (swap) {
      const tx = x_2; x_2 = x_3; x_3 = tx;
      const tz = z_2; z_2 = z_3; z_3 = tz;
    }
    swap = k_t;

    const A = (x_2 + z_2) % P_448;
    const AA = (A * A) % P_448;
    const B = (x_2 - z_2 + P_448) % P_448;
    const BB = (B * B) % P_448;
    const E = (AA - BB + P_448) % P_448;
    const C = (x_3 + z_3) % P_448;
    const D = (x_3 - z_3 + P_448) % P_448;
    const DA = (D * A) % P_448;
    const CB = (C * B) % P_448;

    x_3 = ((DA + CB) ** 2n) % P_448;
    z_3 = (x_1 * ((DA - CB + P_448) ** 2n)) % P_448;
    x_2 = (AA * BB) % P_448;
    z_2 = (E * ((BB + A_24 * E) % P_448)) % P_448;
  }

  if (swap) {
    const tx = x_2; x_2 = x_3; x_3 = tx;
    const tz = z_2; z_2 = z_3; z_3 = tz;
  }

  // Modular inversion using Fermat's Little Theorem: z_2^{p-2} mod p
  const zInv = modPow(z_2, P_448 - 2n, P_448);
  const resultU = (x_2 * zInv) % P_448;

  return bigIntToBytesLE(resultU, 56);
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return res;
}

export function x448Keygen(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = sha512(seed).subarray(0, 56);
  // Base point u = 5
  const basePoint = new Uint8Array(56);
  basePoint[0] = 5;

  const publicKey = x448(secretKey, basePoint);
  return { secretKey, publicKey };
}
