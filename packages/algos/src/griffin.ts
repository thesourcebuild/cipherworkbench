/**
 * Griffin Algebraic Hash & Permutation -- Optimized for recursive STARK/Plonk circuits.
 *
 * Implements the Griffin non-linear map over prime fields with degree-d power maps and Feistel feedback.
 */

export const GRIFFIN_BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function exp5(x: bigint, p: bigint): bigint {
  const x2 = (x * x) % p;
  const x4 = (x2 * x2) % p;
  return (x4 * x) % p;
}

function applyGriffinNonLinear(state: bigint[], p: bigint): bigint[] {
  const t = state.length;
  const next = [...state];

  // state[0] = state[0]^5
  next[0] = exp5(state[0] ?? 0n, p);

  // state[1] = state[1] * (state[0]^2 + 1)
  const sq0 = ((state[0] ?? 0n) * (state[0] ?? 0n) + 1n) % p;
  next[1] = ((state[1] ?? 0n) * sq0) % p;

  // state[2..] = state[i] * (state[1]^2 + state[0] + i)
  const term = ((next[1] * next[1]) + next[0]) % p;
  for (let i = 2; i < t; i++) {
    next[i] = ((state[i] ?? 0n) * (term + BigInt(i))) % p;
  }

  return next;
}

function applyGriffinMds(state: bigint[], p: bigint): bigint[] {
  const t = state.length;
  const next: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    let sum = 0n;
    for (let j = 0; j < t; j++) {
      const coeff = BigInt((i + j + 1) * (i === j ? 2 : 1));
      sum = (sum + coeff * (state[j] ?? 0n)) % p;
    }
    next[i] = sum;
  }
  return next;
}

export interface GriffinOptions {
  rounds?: number; // default 8
  stateSize?: number; // default 4
}

export function griffinPermute(
  inputState: bigint[],
  options: GriffinOptions = {},
): bigint[] {
  const p = GRIFFIN_BN254_PRIME;
  const t = options.stateSize ?? (inputState.length > 0 ? inputState.length : 4);
  const rounds = options.rounds ?? 8;

  let state: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    state[i] = (inputState[i] ?? 0n) % p;
  }

  for (let r = 0; r < rounds; r++) {
    // 1. Add round constants
    for (let i = 0; i < t; i++) {
      const rc = BigInt(((r + 1) * 999983 + (i + 1) * 7919) >>> 0) % p;
      state[i] = (state[i]! + rc) % p;
    }

    // 2. Griffin Non-linear layer
    state = applyGriffinNonLinear(state, p);

    // 3. MDS linear diffusion
    state = applyGriffinMds(state, p);
  }

  return state;
}

export function griffinHash(
  data: Uint8Array,
  options: GriffinOptions = {},
): Uint8Array {
  const p = GRIFFIN_BN254_PRIME;
  const width = options.stateSize ?? 4;
  const rate = Math.max(1, width - 2);

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
    state = griffinPermute(state, { ...options, stateSize: width });
  }

  const out = new Uint8Array(32);
  let val = state[0]!;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return out;
}
