/**
 * MiMC and GMiMC (Albrecht et al., 2016).
 * Minimal Multiplicative Complexity algebraic hash functions designed
 * for Zero-Knowledge STARKs and SNARKs.
 */

// BN254 Scalar Field Modulus
const P_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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

// 91 round constants for MiMC-7 over BN254
const MIMC_ROUNDS = 91;
const MIMC_CONSTANTS: bigint[] = [];
for (let i = 0; i < MIMC_ROUNDS; i++) {
  MIMC_CONSTANTS.push((BigInt(i) * 0x123456789abcdefn + 0x42n) % P_BN254);
}

export function mimcHash(data: Uint8Array): Uint8Array {
  // Absorb 31-byte chunks as field elements
  let state = 0n;
  const key = 0n;

  for (let i = 0; i < data.length; i += 31) {
    let elem = 0n;
    const chunk = data.subarray(i, i + 31);
    for (let b = 0; b < chunk.length; b++) {
      elem = (elem << 8n) | BigInt(chunk[b]!);
    }
    elem %= P_BN254;

    // Sponge absorption + MiMC permutation
    state = (state + elem) % P_BN254;
    for (let r = 0; r < MIMC_ROUNDS; r++) {
      const t = (state + key + MIMC_CONSTANTS[r]!) % P_BN254;
      state = modExp(t, 7n, P_BN254);
    }
    state = (state + key) % P_BN254;
  }

  // Squeeze output into 32 bytes big-endian
  const out = new Uint8Array(32);
  let cur = state;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(cur & 0xffn);
    cur >>= 8n;
  }
  return out;
}
