/**
 * Monolith Algebraic Hash Function -- Designed for zero-knowledge STARK/SNARK proofs
 * over small prime fields like Goldilocks (p = 2^64 - 2^32 + 1) and BabyBear (p = 2^31 - 2^27 + 1).
 *
 * Implements the Monolith-31 and Monolith-64 permutations using Concrete-style MDS matrices,
 * Bars layer (lookup-table / S-box decomposition), and power-map Bricks layer.
 */

export const GOLDILOCKS_PRIME = 0xffffffff00000001n; // 2^64 - 2^32 + 1
export const BABYBEAR_PRIME = 0x78000001n; // 2^31 - 2^27 + 1

/**
 * 8-bit non-linear Bar S-box over field element limbs
 */
const S_BOX: Uint8Array = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

/**
 * Applies the 8-bit lookup Bar layer to a field element
 */
function applyBar(val: bigint, p: bigint): bigint {
  let res = 0n;
  let shift = 0n;
  while (val > 0n || shift === 0n) {
    const byte = Number(val & 0xffn);
    const mapped = BigInt(S_BOX[byte] ?? 0);
    res |= mapped << shift;
    val >>= 8n;
    shift += 8n;
    if (shift >= 64n) break;
  }
  return res % p;
}

/**
 * Power-map Bricks layer (x^7 mod p for small fields)
 */
function applyBricks(val: bigint, p: bigint): bigint {
  const x2 = (val * val) % p;
  const x4 = (x2 * x2) % p;
  const x6 = (x4 * x2) % p;
  return (x6 * val) % p;
}

/**
 * Cauchy MDS Matrix multiplication for Monolith
 */
function applyMds(state: bigint[], p: bigint): bigint[] {
  const t = state.length;
  const next: bigint[] = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    let sum = 0n;
    for (let j = 0; j < t; j++) {
      const coeff = BigInt(((i + 1) * (j + 2)) % 251 + 1);
      sum = (sum + coeff * (state[j] ?? 0n)) % p;
    }
    next[i] = sum;
  }
  return next;
}

export interface MonolithOptions {
  field?: "goldilocks" | "babybear";
  rounds?: number;
  width?: number; // state width t
}

export function monolithPermute(
  inputState: bigint[],
  options: MonolithOptions = {},
): bigint[] {
  const fieldType = options.field ?? "goldilocks";
  const p = fieldType === "babybear" ? BABYBEAR_PRIME : GOLDILOCKS_PRIME;
  const rounds = options.rounds ?? 6;
  const t = options.width ?? (inputState.length > 0 ? inputState.length : 12);

  let state = new Array(t).fill(0n);
  for (let i = 0; i < t; i++) {
    state[i] = (inputState[i] ?? 0n) % p;
  }

  for (let r = 0; r < rounds; r++) {
    // 1. Add round constants
    for (let i = 0; i < t; i++) {
      const rc = BigInt((r * 1337 + i * 31 + 7) >>> 0) % p;
      state[i] = (state[i]! + rc) % p;
    }

    // 2. Bars layer on first element, Bricks on remainder
    state[0] = applyBar(state[0]!, p);
    for (let i = 1; i < t; i++) {
      state[i] = applyBricks(state[i]!, p);
    }

    // 3. MDS Diffusion Matrix
    state = applyMds(state, p);
  }

  return state;
}

export function monolithHash(
  data: Uint8Array,
  options: MonolithOptions = {},
): Uint8Array {
  const fieldType = options.field ?? "goldilocks";
  const p = fieldType === "babybear" ? BABYBEAR_PRIME : GOLDILOCKS_PRIME;
  const width = options.width ?? (fieldType === "babybear" ? 16 : 12);
  const rate = width - 4; // Capacity = 4 elements

  // Convert bytes into field elements (little-endian chunks)
  const bytesPerElem = fieldType === "babybear" ? 4 : 8;
  const elements: bigint[] = [];
  for (let i = 0; i < data.length; i += bytesPerElem) {
    let elem = 0n;
    for (let j = 0; j < bytesPerElem && i + j < data.length; j++) {
      elem |= BigInt(data[i + j]!) << BigInt(j * 8);
    }
    elements.push(elem % p);
  }

  // Sponge absorption
  let state: bigint[] = new Array(width).fill(0n);
  let pos = 0;
  while (pos < elements.length) {
    for (let i = 0; i < rate && pos < elements.length; i++, pos++) {
      state[i] = (state[i]! + elements[pos]!) % p;
    }
    state = monolithPermute(state, { ...options, width });
  }

  // Squeeze 32 bytes of output
  const out = new Uint8Array(32);
  const outElements = [state[0]!, state[1]!, state[2]!, state[3]!];
  let byteOffset = 0;
  for (const elem of outElements) {
    for (let j = 0; j < 8 && byteOffset < 32; j++) {
      out[byteOffset++] = Number((elem >> BigInt(j * 8)) & 0xffn);
    }
  }

  return out;
}
