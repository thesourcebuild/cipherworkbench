/**
 * NIST SP 800-185 SHA-3 Derived Functions:
 * - cSHAKE128 / cSHAKE256 (Customizable SHAKE)
 * - KMAC128 / KMAC256 (Keccak Message Authentication Code & XOF)
 * - TupleHash128 / TupleHash256 (Tuple hashing with domain separation)
 * - ParallelHash128 / ParallelHash256 (Tree/parallelizable Keccak hash)
 */
import {
  cshake128,
  cshake256,
  kmac128,
  kmac256,
  tuplehash128,
  tuplehash256,
  parallelhash128,
  parallelhash256,
} from "@noble/hashes/sha3-addons.js";

export function computeCShake128(
  msg: Uint8Array,
  opts?: { N?: string | Uint8Array; S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return cshake128(msg, opts);
}

export function computeCShake256(
  msg: Uint8Array,
  opts?: { N?: string | Uint8Array; S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return cshake256(msg, opts);
}

export function computeKmac128(
  key: Uint8Array,
  msg: Uint8Array,
  opts?: { S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return kmac128(key, msg, opts);
}

export function computeKmac256(
  key: Uint8Array,
  msg: Uint8Array,
  opts?: { S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return kmac256(key, msg, opts);
}

export function computeTupleHash128(
  tuples: Uint8Array[],
  opts?: { S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return tuplehash128(tuples, opts);
}

export function computeTupleHash256(
  tuples: Uint8Array[],
  opts?: { S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return tuplehash256(tuples, opts);
}

export function computeParallelHash128(
  msg: Uint8Array,
  opts?: { blockLen?: number; S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return parallelhash128(msg, opts);
}

export function computeParallelHash256(
  msg: Uint8Array,
  opts?: { blockLen?: number; S?: string | Uint8Array; dkLen?: number },
): Uint8Array {
  return parallelhash256(msg, opts);
}
