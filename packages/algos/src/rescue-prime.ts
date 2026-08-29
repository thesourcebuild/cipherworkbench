/**
 * Rescue-Prime -- Algebraic Sponge Hash Function for Zero-Knowledge Proofs.
 *
 * Implements the Rescue-Prime sponge construction featuring alternating forward power S-box (x^alpha)
 * and inverse power S-box (x^(1/alpha)) interspersed with MDS matrix multiplications.
 */

import { BN254_PRIME, exp5 } from "./poseidon";

function expInv5(x: bigint, p: bigint): bigint {
  // alpha_inv = modInverse(5, p - 1)
  const phi = p - 1n;
  // Compute x^inv mod p using modular exponentiation
  const inv5 = modInversePrime(5n, phi);
  return modExp(x, inv5, p);
}

function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
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

function modInversePrime(a: bigint, m: bigint): bigint {
  let [m0, y, x] = [m, 0n, 1n];
  while (a > 1n) {
    const q = a / m0;
    let t = m0;
    m0 = a % m0;
    a = t;
    t = y;
    y = x - q * y;
    x = t;
  }
  if (x < 0n) x += m;
  return x;
}

/**
 * Rescue-Prime permutation step.
 */
export function rescuePrimePermute(state: bigint[], rounds: number = 8, p: bigint = BN254_PRIME): bigint[] {
  const m = state.length;
  let current = [...state];

  for (let r = 0; r < rounds; r++) {
    // Step 1: Forward S-box (x^5)
    for (let i = 0; i < m; i++) current[i] = exp5(current[i]!, p);
    // Linear layer 1
    current = mixLinear(current, m, p);

    // Step 2: Inverse S-box (x^(1/5))
    for (let i = 0; i < m; i++) current[i] = expInv5(current[i]!, p);
    // Linear layer 2
    current = mixLinear(current, m, p);
  }

  return current;
}

function mixLinear(state: bigint[], m: number, p: bigint): bigint[] {
  const next = new Array(m).fill(0n);
  for (let i = 0; i < m; i++) {
    let sum = 0n;
    for (let j = 0; j < m; j++) {
      const weight = BigInt((i + j + 2) * 17);
      sum = (sum + weight * state[j]!) % p;
    }
    next[i] = sum;
  }
  return next;
}

/**
 * Rescue-Prime hash of arbitrary byte input.
 */
export function rescuePrimeHashBytes(inputs: Uint8Array, outputLen: number = 32): Uint8Array {
  let elements: bigint[] = [0n, 0n, 0n];
  for (let offset = 0; offset < inputs.length; offset += 31) {
    const chunk = inputs.subarray(offset, Math.min(offset + 31, inputs.length));
    let val = 0n;
    for (let i = 0; i < chunk.length; i++) {
      val |= BigInt(chunk[i]!) << BigInt(8 * i);
    }
    elements[0] = (elements[0]! + val) % BN254_PRIME;
    elements = rescuePrimePermute(elements);
  }

  const outVal = elements[0]!;
  const out = new Uint8Array(outputLen);
  for (let i = 0; i < outputLen; i++) {
    out[i] = Number((outVal >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

export const rescuePrimeHash = (inputs: Uint8Array) => rescuePrimeHashBytes(inputs, 32);

