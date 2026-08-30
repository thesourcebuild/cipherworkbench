/**
 * Pedersen Commitments -- Cryptographic commitment scheme with additive homomorphism.
 *
 * Implements C = g^m * h^r mod p in cyclic group / scalar fields,
 * satisfying Perfect Hiding and Computational Binding properties.
 */

export const PEDERSEN_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const PEDERSEN_G = 3n;
export const PEDERSEN_H = 5n;

/**
 * Modular exponentiation: base^exp mod p
 */
export function modExp(base: bigint, exp: bigint, p: bigint): bigint {
  let res = 1n;
  let b = base % p;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) res = (res * b) % p;
    b = (b * b) % p;
    e >>= 1n;
  }
  return res;
}

export interface PedersenCommitment {
  commitment: bigint; // C = g^m * h^r mod p
  message: bigint; // m
  blindingFactor: bigint; // r
}

/**
 * Creates a Pedersen commitment for message m using blinding factor r
 */
export function pedersenCommit(
  message: bigint | Uint8Array,
  blindingFactor: bigint | Uint8Array,
  p: bigint = PEDERSEN_PRIME,
  g: bigint = PEDERSEN_G,
  h: bigint = PEDERSEN_H,
): PedersenCommitment {
  const m = typeof message === "bigint"
    ? message % p
    : bytesToBigInt(message) % p;

  const r = typeof blindingFactor === "bigint"
    ? blindingFactor % p
    : bytesToBigInt(blindingFactor) % p;

  const gm = modExp(g, m, p);
  const hr = modExp(h, r, p);
  const commitment = (gm * hr) % p;

  return { commitment, message: m, blindingFactor: r };
}

/**
 * Verifies that commitment C opens to message m with blinding factor r
 */
export function pedersenVerify(
  commitment: bigint,
  message: bigint | Uint8Array,
  blindingFactor: bigint | Uint8Array,
  p: bigint = PEDERSEN_PRIME,
  g: bigint = PEDERSEN_G,
  h: bigint = PEDERSEN_H,
): boolean {
  const m = typeof message === "bigint"
    ? message % p
    : bytesToBigInt(message) % p;

  const r = typeof blindingFactor === "bigint"
    ? blindingFactor % p
    : bytesToBigInt(blindingFactor) % p;

  const expected = (modExp(g, m, p) * modExp(h, r, p)) % p;
  return commitment === expected;
}

/**
 * Homomorphic Addition: C(m1 + m2, r1 + r2) = C(m1, r1) * C(m2, r2) mod p
 */
export function pedersenAdd(
  c1: PedersenCommitment,
  c2: PedersenCommitment,
  p: bigint = PEDERSEN_PRIME,
): PedersenCommitment {
  const commitment = (c1.commitment * c2.commitment) % p;
  const message = (c1.message + c2.message) % p;
  const blindingFactor = (c1.blindingFactor + c2.blindingFactor) % p;
  return { commitment, message, blindingFactor };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let val = 0n;
  for (let i = 0; i < bytes.length; i++) {
    val = (val << 8n) | BigInt(bytes[i]!);
  }
  return val;
}
