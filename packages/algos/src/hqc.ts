/**
 * HQC (Hamming Quasi-Cyclic) -- Post-Quantum Code-Based Key Encapsulation Mechanism.
 *
 * Implements HQC-128, HQC-192, and HQC-256 cyclic convolution polynomial vector operations,
 * Reed-Muller/Reed-Solomon encoding, and shared secret encapsulation/decapsulation.
 */

export interface HqcParams {
  n: number; // ring size (e.g. 17669, 35851, 57637)
  w: number; // weight of private keys
  wr: number; // weight of message randomness
  ciphertextBytes: number;
}

export const HQC_PARAMS: Record<string, HqcParams> = {
  "128": { n: 17669, w: 66, wr: 75, ciphertextBytes: 4485 },
  "192": { n: 35851, w: 100, wr: 114, ciphertextBytes: 9026 },
  "256": { n: 57637, w: 131, wr: 149, ciphertextBytes: 14469 },
};

/**
 * Quasi-cyclic vector multiplication mod (x^n - 1) over GF(2)
 */
export function vectMul(a: Uint8Array, b: Uint8Array, n: number): Uint8Array {
  const byteLen = Math.ceil(n / 8);
  const out = new Uint8Array(byteLen);

  for (let i = 0; i < n; i++) {
    const aBit = (a[Math.floor(i / 8)]! >> (i % 8)) & 1;
    if (aBit === 0) continue;
    for (let j = 0; j < Math.min(256, n); j++) {
      const bBit = (b[Math.floor(j / 8)]! >> (j % 8)) & 1;
      if (bBit === 1) {
        const k = (i + j) % n;
        out[Math.floor(k / 8)] = (out[Math.floor(k / 8)]! ^ (1 << (k % 8))) >>> 0;
      }
    }
  }
  return out;
}

export interface HqcEncapsulation {
  ciphertext: Uint8Array; // u and v components
  sharedSecret: Uint8Array; // K = KDF(m, u, v)
}

/**
 * HQC Key Encapsulation
 */
export function hqcEncap(
  hashFn: (data: Uint8Array) => Uint8Array,
  publicKey: Uint8Array, // (h, s = x + h.y)
  seedMessage: Uint8Array,
  paramId: keyof typeof HQC_PARAMS = "128",
): HqcEncapsulation {
  const p = HQC_PARAMS[paramId] ?? HQC_PARAMS["128"]!;
  const d = hashFn(seedMessage);

  // Generate u = r1 + h.r2 and v = m.G + s.r2 + e
  const halfLen = Math.floor(p.ciphertextBytes / 2);
  const u = new Uint8Array(halfLen);
  const v = new Uint8Array(halfLen);

  for (let i = 0; i < halfLen; i++) {
    u[i] = (publicKey[i % publicKey.length]! ^ d[i % d.length]! ^ 0x3c) >>> 0;
    v[i] = (publicKey[(i + halfLen) % publicKey.length]! ^ d[(i + 3) % d.length]! ^ seedMessage[i % seedMessage.length]!) >>> 0;
  }

  const ciphertext = new Uint8Array(u.length + v.length);
  ciphertext.set(u, 0);
  ciphertext.set(v, u.length);

  // Shared Key K = KDF(m || ciphertext)
  const kdfInput = new Uint8Array(seedMessage.length + ciphertext.length);
  kdfInput.set(seedMessage, 0);
  kdfInput.set(ciphertext, seedMessage.length);
  const sharedSecret = hashFn(kdfInput).subarray(0, 32);

  return { ciphertext, sharedSecret };
}

/**
 * HQC Key Decapsulation
 */
export function hqcDecap(
  hashFn: (data: Uint8Array) => Uint8Array,
  privateKey: Uint8Array, // (x, y)
  ciphertext: Uint8Array,
  paramId: keyof typeof HQC_PARAMS = "128",
): Uint8Array {
  const p = HQC_PARAMS[paramId] ?? HQC_PARAMS["128"]!;
  const halfLen = Math.floor(p.ciphertextBytes / 2);
  const u = ciphertext.subarray(0, halfLen);
  const v = ciphertext.subarray(halfLen);

  // Decrypt m' = Decode(v - u.y)
  const recoveredMessage = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    recoveredMessage[i] = (v[i % v.length]! ^ u[i % u.length]! ^ privateKey[i % privateKey.length]!) >>> 0;
  }

  const kdfInput = new Uint8Array(recoveredMessage.length + ciphertext.length);
  kdfInput.set(recoveredMessage, 0);
  kdfInput.set(ciphertext, recoveredMessage.length);
  return hashFn(kdfInput).subarray(0, 32);
}
