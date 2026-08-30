/**
 * Neptune Algebraic Hash Function -- ZK-friendly sponge hash over BN254 / BLS12-381 scalar field.
 *
 * Employs external full S-box rounds ($x^5 \pmod p$) and fast linear internal rounds.
 */

export const NEPTUNE_BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function exp5(x: bigint, p: bigint): bigint {
  const x2 = (x * x) % p;
  const x4 = (x2 * x2) % p;
  return (x4 * x) % p;
}

function generateNeptuneConstants(rounds: number, t: number, p: bigint): bigint[][] {
  const constants: bigint[][] = [];
  let seed = 0x1337c0den;
  for (let r = 0; r < rounds; r++) {
    const rc: bigint[] = [];
    for (let i = 0; i < t; i++) {
      seed = (seed * 6364136223846793005n + 1442695040888963407n) % p;
      rc.push(seed);
    }
    constants.push(rc);
  }
  return constants;
}

function applyNeptuneMds(state: bigint[], p: bigint): bigint[] {
  const t = state.length;
  const next: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    let sum = 0n;
    for (let j = 0; j < t; j++) {
      const coeff = BigInt((i === j ? 2 : 1) * (i + j + 1));
      sum = (sum + coeff * (state[j] ?? 0n)) % p;
    }
    next[i] = sum;
  }
  return next;
}

export interface NeptuneOptions {
  width?: number; // state size t, default 4 (rate 2, capacity 2)
  fullRounds?: number; // external rounds, default 8
  partialRounds?: number; // internal rounds, default 56
}

export function neptunePermute(
  inputState: bigint[],
  options: NeptuneOptions = {},
): bigint[] {
  const p = NEPTUNE_BN254_PRIME;
  const t = options.width ?? (inputState.length > 0 ? inputState.length : 4);
  const fullRounds = options.fullRounds ?? 8;
  const partialRounds = options.partialRounds ?? 56;
  const totalRounds = fullRounds + partialRounds;
  const roundConstants = generateNeptuneConstants(totalRounds, t, p);

  let state: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    state[i] = (inputState[i] ?? 0n) % p;
  }

  const halfFull = Math.floor(fullRounds / 2);

  // 1. First half full rounds
  for (let r = 0; r < halfFull; r++) {
    for (let i = 0; i < t; i++) {
      state[i] = exp5((state[i]! + roundConstants[r]![i]!) % p, p);
    }
    state = applyNeptuneMds(state, p);
  }

  // 2. Partial rounds (S-box only on first element)
  for (let r = halfFull; r < halfFull + partialRounds; r++) {
    for (let i = 0; i < t; i++) {
      state[i] = (state[i]! + roundConstants[r]![i]!) % p;
    }
    state[0] = exp5(state[0]!, p);
    state = applyNeptuneMds(state, p);
  }

  // 3. Second half full rounds
  for (let r = halfFull + partialRounds; r < totalRounds; r++) {
    for (let i = 0; i < t; i++) {
      state[i] = exp5((state[i]! + roundConstants[r]![i]!) % p, p);
    }
    state = applyNeptuneMds(state, p);
  }

  return state;
}

export function neptuneHash(
  data: Uint8Array,
  options: NeptuneOptions = {},
): Uint8Array {
  const p = NEPTUNE_BN254_PRIME;
  const width = options.width ?? 4;
  const rate = Math.max(1, width - 2); // capacity = 2

  // Chunk bytes into 31-byte field elements
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
    state = neptunePermute(state, { ...options, width });
  }

  // Squeeze 32-byte digest from state[0]
  const out = new Uint8Array(32);
  let val = state[0]!;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return out;
}
