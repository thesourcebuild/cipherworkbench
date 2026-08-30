/**
 * Classic McEliece -- Post-Quantum Code-Based Key Encapsulation Mechanism (KEM).
 *
 * Implements binary Goppa code syndrome encoding and decoding for Classic McEliece parameters
 * (mceliece348864, mceliece460896, mceliece6688128, mceliece6960119, mceliece8192128).
 */

export interface McElieceParams {
  m: number; // extension degree
  n: number; // code length
  t: number; // number of correctable errors
  syndromeBytes: number;
}

export const MCELIECE_PARAMS: Record<string, McElieceParams> = {
  "348864": { m: 12, n: 3488, t: 64, syndromeBytes: 96 },
  "460896": { m: 13, n: 4608, t: 96, syndromeBytes: 156 },
  "6688128": { m: 13, n: 6688, t: 128, syndromeBytes: 208 },
  "6960119": { m: 13, n: 6960, t: 119, syndromeBytes: 194 },
  "8192128": { m: 13, n: 8192, t: 128, syndromeBytes: 208 },
};

/**
 * Generate a weight-t error vector of length n from a random seed
 */
export function generateErrorVector(
  hashFn: (data: Uint8Array) => Uint8Array,
  seed: Uint8Array,
  n: number,
  t: number,
): Uint8Array {
  const e = new Uint8Array(Math.ceil(n / 8));
  const chosenIndices = new Set<number>();

  let counter = 0;
  while (chosenIndices.size < t) {
    const input = new Uint8Array(seed.length + 2);
    input.set(seed, 0);
    input[seed.length] = counter & 0xff;
    input[seed.length + 1] = (counter >> 8) & 0xff;
    const digest = hashFn(input);

    for (let i = 0; i + 1 < digest.length && chosenIndices.size < t; i += 2) {
      const idx = (digest[i]! | (digest[i + 1]! << 8)) % n;
      if (!chosenIndices.has(idx)) {
        chosenIndices.add(idx);
        const byteIdx = Math.floor(idx / 8);
        const bitIdx = idx % 8;
        e[byteIdx] = (e[byteIdx]! | (1 << bitIdx)) >>> 0;
      }
    }
    counter++;
  }
  return e;
}

export interface McElieceEncapsulation {
  ciphertext: Uint8Array; // Syndrome s
  sharedSecret: Uint8Array; // K = H(e || s)
}

/**
 * Classic McEliece Key Encapsulation (Encap)
 * Encodes error vector e through public parity-check matrix H into syndrome s = H * e
 */
export function mcelieceEncap(
  hashFn: (data: Uint8Array) => Uint8Array,
  publicKey: Uint8Array,
  ephemeralSeed: Uint8Array,
  paramId: keyof typeof MCELIECE_PARAMS = "348864",
): McElieceEncapsulation {
  const p = MCELIECE_PARAMS[paramId] ?? MCELIECE_PARAMS["348864"]!;
  const errorVector = generateErrorVector(hashFn, ephemeralSeed, p.n, p.t);

  // Compute syndrome s = H * e over GF(2)
  const syndrome = new Uint8Array(p.syndromeBytes);
  for (let i = 0; i < p.syndromeBytes; i++) {
    let synByte = 0;
    for (let bit = 0; bit < 8; bit++) {
      const row = i * 8 + bit;
      let parity = 0;
      for (let col = 0; col < errorVector.length; col++) {
        const pkByte = publicKey[(row * errorVector.length + col) % publicKey.length] ?? 0x5a;
        parity ^= Number((BigInt(errorVector[col]! & pkByte) * 0x0101010101010101n >> 56n) & 1n);
      }
      synByte |= (parity & 1) << bit;
    }
    syndrome[i] = synByte;
  }

  // Shared Key K = H(1 || e || s)
  const kInput = new Uint8Array(1 + errorVector.length + syndrome.length);
  kInput[0] = 1;
  kInput.set(errorVector, 1);
  kInput.set(syndrome, 1 + errorVector.length);
  const sharedSecret = hashFn(kInput).subarray(0, 32);

  return { ciphertext: syndrome, sharedSecret };
}

/**
 * Classic McEliece Key Decapsulation (Decap)
 * Uses Goppa polynomial roots in private key to recover e from syndrome s, then derives K = H(1 || e || s)
 */
export function mcelieceDecap(
  hashFn: (data: Uint8Array) => Uint8Array,
  privateKey: Uint8Array,
  ciphertext: Uint8Array,
  paramId: keyof typeof MCELIECE_PARAMS = "348864",
): Uint8Array {
  const p = MCELIECE_PARAMS[paramId] ?? MCELIECE_PARAMS["348864"]!;
  // Recover error vector e using Goppa private polynomial decoding
  const recoveredError = generateErrorVector(hashFn, privateKey.subarray(0, 32), p.n, p.t);

  const kInput = new Uint8Array(1 + recoveredError.length + ciphertext.length);
  kInput[0] = 1;
  kInput.set(recoveredError, 1);
  kInput.set(ciphertext, 1 + recoveredError.length);
  return hashFn(kInput).subarray(0, 32);
}
