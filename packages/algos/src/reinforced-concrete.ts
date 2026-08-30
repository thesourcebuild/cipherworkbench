/**
 * Reinforced Concrete -- Fast algebraic hash function designed for high throughput
 * in SNARK/STARK circuits over the BN254 scalar field.
 *
 * Implements the Bricks (power map x^5), Concrete (MDS linear diffusion),
 * and Bars (limb decomposition & non-linear substitution) round structure.
 */

export const RC_BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function exp5(x: bigint, p: bigint): bigint {
  const x2 = (x * x) % p;
  const x4 = (x2 * x2) % p;
  return (x4 * x) % p;
}

// 7-element Bars lookup table
function applyReinforcedBar(val: bigint, p: bigint): bigint {
  let acc = 0n;
  let multiplier = 1n;
  let remaining = val;

  // Decompose into 27 limbs of base B
  const base = 2048n;
  for (let i = 0; i < 23 && remaining > 0n; i++) {
    const limb = remaining % base;
    remaining /= base;
    // S-box: (limb^3 + limb + 5) mod base
    const sbox = (limb * limb * limb + limb + 5n) % base;
    acc = (acc + sbox * multiplier) % p;
    multiplier = (multiplier * base) % p;
  }
  return acc;
}

function applyConcreteMds(state: bigint[], p: bigint): bigint[] {
  const t = state.length;
  const next: bigint[] = new Array(t).fill(0n);
  const circulant = [2n, 1n, 1n];
  for (let i = 0; i < t; i++) {
    let sum = 0n;
    for (let j = 0; j < t; j++) {
      const coeff = circulant[(j - i + t) % t] ?? 1n;
      sum = (sum + coeff * (state[j] ?? 0n)) % p;
    }
    next[i] = sum;
  }
  return next;
}

export interface ReinforcedConcreteOptions {
  rounds?: number; // default 7
  stateSize?: number; // default 3 (rate 2, capacity 1)
}

export function reinforcedConcretePermute(
  inputState: bigint[],
  options: ReinforcedConcreteOptions = {},
): bigint[] {
  const p = RC_BN254_PRIME;
  const t = options.stateSize ?? 3;
  const rounds = options.rounds ?? 7;

  let state: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    state[i] = (inputState[i] ?? 0n) % p;
  }

  for (let r = 0; r < rounds; r++) {
    // 1. Add round constants
    for (let i = 0; i < t; i++) {
      const rc = BigInt(((r + 1) * 1000003 + (i + 1) * 31337) >>> 0) % p;
      state[i] = (state[i]! + rc) % p;
    }

    // 2. Bricks layer (x^5 mod p)
    for (let i = 0; i < t; i++) {
      state[i] = exp5(state[i]!, p);
    }

    // 3. Concrete layer (MDS diffusion)
    state = applyConcreteMds(state, p);

    // 4. Bars layer (Limb decomposition)
    for (let i = 0; i < t; i++) {
      state[i] = applyReinforcedBar(state[i]!, p);
    }

    // 5. Final Concrete layer in round
    state = applyConcreteMds(state, p);
  }

  return state;
}

export function reinforcedConcreteHash(
  data: Uint8Array,
  options: ReinforcedConcreteOptions = {},
): Uint8Array {
  const p = RC_BN254_PRIME;
  const width = options.stateSize ?? 3;
  const rate = Math.max(1, width - 1);

  const elements: bigint[] = [];
  for (let i = 0; i < data.length; i += 31) {
    let elem = 0n;
    for (let j = 0; j < 31 && i + j < data.length; j++) {
      elem = (elem << 8n) | BigInt(data[i + j]!);
    }
    elements.push(elem % p);
  }

  if (elements.length === 0) {
    elements.push(0n);
  }

  let state: bigint[] = new Array(width).fill(0n);
  let pos = 0;
  while (pos < elements.length) {
    for (let i = 0; i < rate && pos < elements.length; i++, pos++) {
      state[i] = (state[i]! + elements[pos]!) % p;
    }
    state = reinforcedConcretePermute(state, { ...options, stateSize: width });
  }

  const out = new Uint8Array(32);
  let val = state[0]!;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return out;
}
