/**
 * Anemoi Algebraic Hash Function -- Designed for Plonk and Groth16 ZK-SNARK circuits.
 *
 * Implements the Flystel open-source S-box construction with linear diffusion matrix.
 */

export const ANEMOI_BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function exp5(x: bigint, p: bigint): bigint {
  const x2 = (x * x) % p;
  const x4 = (x2 * x2) % p;
  return (x4 * x) % p;
}

/**
 * Flystel non-linear layer over a pair of field elements (x, y)
 */
function applyFlystel(x: bigint, y: bigint, p: bigint): [bigint, bigint] {
  // 1. y_new = y - Q(x) mod p where Q(x) = x^2 + 5x + 7
  const qx = (x * x + 5n * x + 7n) % p;
  const y1 = (y - qx + p * 10n) % p;

  // 2. x_new = x - E(y_new) mod p where E(y) = y^5
  const ey = exp5(y1, p);
  const x1 = (x - ey + p * 10n) % p;

  // 3. y_final = y_new + Q(x_new)
  const qx1 = (x1 * x1 + 5n * x1 + 7n) % p;
  const y_final = (y1 + qx1) % p;

  return [x1, y_final];
}

function applyAnemoiMds(state: bigint[], p: bigint): bigint[] {
  const t = state.length;
  const next: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    let sum = 0n;
    for (let j = 0; j < t; j++) {
      const coeff = BigInt((i === j ? 3 : 1) * (i + 1));
      sum = (sum + coeff * (state[j] ?? 0n)) % p;
    }
    next[i] = sum;
  }
  return next;
}

export interface AnemoiOptions {
  rounds?: number; // default 10
  stateSize?: number; // default 4 (must be even: 2, 4, 6)
}

export function anemoiPermute(
  inputState: bigint[],
  options: AnemoiOptions = {},
): bigint[] {
  const p = ANEMOI_BN254_PRIME;
  const t = options.stateSize ?? 4;
  const rounds = options.rounds ?? 10;

  let state: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    state[i] = (inputState[i] ?? 0n) % p;
  }

  for (let r = 0; r < rounds; r++) {
    // 1. Add round constants
    for (let i = 0; i < t; i++) {
      const rc = BigInt(((r + 3) * 65537 + i * 4099) >>> 0) % p;
      state[i] = (state[i]! + rc) % p;
    }

    // 2. Apply Flystel S-box layer in pairs (state[2i], state[2i+1])
    for (let i = 0; i < t; i += 2) {
      if (i + 1 < t) {
        const [nx, ny] = applyFlystel(state[i]!, state[i + 1]!, p);
        state[i] = nx;
        state[i + 1] = ny;
      }
    }

    // 3. Linear MDS Diffusion
    state = applyAnemoiMds(state, p);
  }

  return state;
}

export function anemoiHash(
  data: Uint8Array,
  options: AnemoiOptions = {},
): Uint8Array {
  const p = ANEMOI_BN254_PRIME;
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
    state = anemoiPermute(state, { ...options, stateSize: width });
  }

  const out = new Uint8Array(32);
  let val = state[0]!;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return out;
}
