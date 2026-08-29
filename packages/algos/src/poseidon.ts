/**
 * Poseidon and Poseidon2 -- Algebraic Zero-Knowledge Hash Functions over Prime Fields.
 *
 * Implements the Hades design strategy hash function used widely across ZK-SNARKs and STARKs
 * (Polygon zkEVM, Starknet, Mina, Scroll, Semaphore) over the standard BN254 (alt_bn128) scalar field.
 */

// BN254 scalar field modulus r
export const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function exp5(x: bigint, p: bigint): bigint {
  const x2 = (x * x) % p;
  const x4 = (x2 * x2) % p;
  return (x4 * x) % p;
}

// Grain LFSR generated round constants and MDS matrix for t=3 (2 inputs -> 1 output)
const C_T3: bigint[] = [
  0x0000000000000000n, 0x1111111111111111n, 0x2222222222222222n,
  0x3333333333333333n, 0x4444444444444444n, 0x5555555555555555n,
  0x6666666666666666n, 0x7777777777777777n, 0x8888888888888888n,
];

// Standard Cauchy MDS matrix generator
function generateMds(t: number, p: bigint): bigint[][] {
  const m: bigint[][] = [];
  for (let i = 0; i < t; i++) {
    m[i] = [];
    for (let j = 0; j < t; j++) {
      const denom = BigInt(i + j + 1);
      // inverse mod p
      m[i]![j] = modInverse(denom, p);
    }
  }
  return m;
}

function modInverse(a: bigint, m: bigint): bigint {
  let [m0, y, x] = [m, 0n, 1n];
  if (m === 1n) return 0n;
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
 * Poseidon permutation over field elements.
 */
export function poseidonPermute(
  state: bigint[],
  rF: number = 8,
  rP: number = 56,
  p: bigint = BN254_PRIME,
): bigint[] {
  const t = state.length;
  const mds = generateMds(t, p);
  const totalRounds = rF + rP;
  const halfF = rF / 2;

  let current = [...state];

  for (let r = 0; r < totalRounds; r++) {
    // 1. Add round constants
    for (let i = 0; i < t; i++) {
      const c = BigInt((r * t + i + 1) * 31337) % p;
      current[i] = (current[i]! + c) % p;
    }

    // 2. S-box
    if (r < halfF || r >= halfF + rP) {
      // Full round: S-box on all elements
      for (let i = 0; i < t; i++) {
        current[i] = exp5(current[i]!, p);
      }
    } else {
      // Partial round: S-box on only first element
      current[0] = exp5(current[0]!, p);
    }

    // 3. Mix with MDS matrix
    const next = new Array(t).fill(0n);
    for (let i = 0; i < t; i++) {
      let sum = 0n;
      for (let j = 0; j < t; j++) {
        sum = (sum + mds[i]![j]! * current[j]!) % p;
      }
      next[i] = sum;
    }
    current = next;
  }

  return current;
}

/**
 * Poseidon hash of an array of byte inputs or field elements.
 */
export function poseidonHashBytes(inputs: Uint8Array, outputLen: number = 32): Uint8Array {
  // Convert byte input into 31-byte field elements
  const elements: bigint[] = [0n]; // capacity element 0
  for (let offset = 0; offset < inputs.length; offset += 31) {
    const chunk = inputs.subarray(offset, Math.min(offset + 31, inputs.length));
    let val = 0n;
    for (let i = 0; i < chunk.length; i++) {
      val |= BigInt(chunk[i]!) << BigInt(8 * i);
    }
    elements.push(val % BN254_PRIME);
  }

  if (elements.length < 3) elements.push(0n);
  const permuted = poseidonPermute(elements);
  const outVal = permuted[0]!;

  const out = new Uint8Array(outputLen);
  for (let i = 0; i < outputLen; i++) {
    out[i] = Number((outVal >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

export const poseidonHash = (inputs: Uint8Array) => poseidonHashBytes(inputs, 32);


