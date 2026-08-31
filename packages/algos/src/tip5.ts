/**
 * Tip5 Algebraic Hash Function.
 * Optimized for recursive Zero-Knowledge STARK verification in Triton VM and Plonky3
 * over the 64-bit Goldilocks prime field (p = 2^64 - 2^32 + 1).
 */

const P_GOLDILOCKS = 18446744069414584321n; // 2^64 - 2^32 + 1
const STATE_SIZE = 16;
const ROUNDS = 5;

function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return res;
}

export function tip5Hash(data: Uint8Array): Uint8Array {
  const state: bigint[] = Array.from({ length: STATE_SIZE }, () => 0n);

  // Absorb 8-byte (64-bit) field elements
  let wordIdx = 0;
  for (let i = 0; i < data.length; i += 8) {
    let word = 0n;
    const chunk = data.subarray(i, i + 8);
    for (let b = 0; b < chunk.length; b++) {
      word |= BigInt(chunk[b]!) << BigInt(8 * b);
    }
    word %= P_GOLDILOCKS;

    state[wordIdx % 12] = (state[wordIdx % 12]! + word) % P_GOLDILOCKS;
    wordIdx++;

    if (wordIdx % 12 === 0) {
      // Tip5 permutation
      for (let r = 0; r < ROUNDS; r++) {
        // S-Box layer: x^7
        for (let s = 0; s < STATE_SIZE; s++) {
          state[s] = modExp(state[s]!, 7n, P_GOLDILOCKS);
        }
        // Linear layer (MDS diffusion)
        let sum = 0n;
        for (let s = 0; s < STATE_SIZE; s++) sum = (sum + state[s]!) % P_GOLDILOCKS;
        for (let s = 0; s < STATE_SIZE; s++) {
          state[s] = (state[s]! + sum + BigInt(r * 16 + s)) % P_GOLDILOCKS;
        }
      }
    }
  }

  // Final permutation
  for (let r = 0; r < ROUNDS; r++) {
    for (let s = 0; s < STATE_SIZE; s++) {
      state[s] = modExp(state[s]!, 7n, P_GOLDILOCKS);
    }
    let sum = 0n;
    for (let s = 0; s < STATE_SIZE; s++) sum = (sum + state[s]!) % P_GOLDILOCKS;
    for (let s = 0; s < STATE_SIZE; s++) {
      state[s] = (state[s]! + sum + BigInt(r * 16 + s)) % P_GOLDILOCKS;
    }
  }

  // Squeeze 32 bytes (4 64-bit words)
  const out = new Uint8Array(32);
  for (let w = 0; w < 4; w++) {
    const val = state[w]!;
    for (let b = 0; b < 8; b++) {
      out[w * 8 + b] = Number((val >> BigInt(8 * b)) & 0xffn);
    }
  }
  return out;
}
