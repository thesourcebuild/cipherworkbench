/**
 * Poseidon2 Zero-Knowledge Hash Function (Horizen Labs / Ethereum Foundation 2023).
 *
 * An optimized variant of Poseidon with simplified linear layers and external/internal matrices
 * yielding up to 4x throughput improvement in recursive SNARK/STARK verifiers.
 */
import { BN254_PRIME, exp5 } from "./poseidon";

export interface Poseidon2Options {
  t?: number;
  fullRounds?: number;
  partialRounds?: number;
}

export function poseidon2Permute(
  state: bigint[],
  rf = 8,
  rp = 56,
): bigint[] {
  const t = state.length;
  const curr = state.map((v) => ((v % BN254_PRIME) + BN254_PRIME) % BN254_PRIME);

  const halfRf = Math.floor(rf / 2);

  // First half of full rounds
  for (let r = 0; r < halfRf; r++) {
    for (let i = 0; i < t; i++) {
      curr[i] = exp5(curr[i]!, BN254_PRIME);
    }
    // Poseidon2 linear layer: sum(state) + state[i]
    let sum = 0n;
    for (let i = 0; i < t; i++) sum = (sum + curr[i]!) % BN254_PRIME;
    for (let i = 0; i < t; i++) curr[i] = (curr[i]! + sum) % BN254_PRIME;
  }

  // Partial rounds (S-box only on first element)
  for (let r = 0; r < rp; r++) {
    curr[0] = exp5(curr[0]!, BN254_PRIME);
    let sum = 0n;
    for (let i = 0; i < t; i++) sum = (sum + curr[i]!) % BN254_PRIME;
    for (let i = 0; i < t; i++) curr[i] = (curr[i]! + sum) % BN254_PRIME;
  }

  // Second half of full rounds
  for (let r = 0; r < halfRf; r++) {
    for (let i = 0; i < t; i++) {
      curr[i] = exp5(curr[i]!, BN254_PRIME);
    }
    let sum = 0n;
    for (let i = 0; i < t; i++) sum = (sum + curr[i]!) % BN254_PRIME;
    for (let i = 0; i < t; i++) curr[i] = (curr[i]! + sum) % BN254_PRIME;
  }

  return curr;
}

export function poseidon2Hash(input: Uint8Array, outputLen = 32): Uint8Array {
  const elements: bigint[] = [1n, 0n, 0n, 0n]; // t=4
  let offset = 0;

  while (offset < input.length) {
    const chunk = input.subarray(offset, Math.min(offset + 31, input.length));
    let val = 0n;
    for (let i = 0; i < chunk.length; i++) {
      val = (val << 8n) | BigInt(chunk[i]!);
    }
    elements[1] = (elements[1]! + val) % BN254_PRIME;
    offset += chunk.length;
  }

  const permuted = poseidon2Permute(elements);
  const out = new Uint8Array(outputLen);
  let finalVal = permuted[0]!;

  for (let i = outputLen - 1; i >= 0; i--) {
    out[i] = Number(finalVal & 0xffn);
    finalVal >>= 8n;
  }

  return out;
}
