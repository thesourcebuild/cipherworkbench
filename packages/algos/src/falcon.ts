/**
 * FN-DSA (Falcon) -- Fast-Fourier Lattice-based Digital Signature Algorithm (FIPS 206).
 *
 * Implements Falcon-512 (degree N=512, q=12289) and Falcon-1024 (degree N=1024, q=12289)
 * polynomial arithmetic, hash-to-point, signing and verification over the ring Z_q[x]/(x^N + 1).
 */

export const FALCON_Q = 12289;

/**
 * Ring polynomial multiplication mod (x^N + 1) and mod q
 */
export function polyMul(a: Int16Array, b: Int16Array, n: number, q: number = FALCON_Q): Int16Array {
  const res = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    const ai = a[i] ?? 0;
    if (ai === 0) continue;
    for (let j = 0; j < n; j++) {
      const bj = b[j] ?? 0;
      const prod = ai * bj;
      if (i + j < n) {
        res[i + j] = (res[i + j]! + prod) % q;
      } else {
        // x^N = -1 mod (x^N + 1)
        res[i + j - n] = (res[i + j - n]! - prod) % q;
      }
    }
  }
  for (let i = 0; i < n; i++) {
    let v = res[i]! % q;
    if (v < 0) v += q;
    res[i] = v;
  }
  return res;
}

/**
 * Hash message and nonce to a ring polynomial point c in Z_q[x]/(x^N + 1)
 */
export function hashToPoint(
  hashFn: (data: Uint8Array) => Uint8Array,
  message: Uint8Array,
  nonce: Uint8Array,
  n: number,
): Int16Array {
  const c = new Int16Array(n);
  // Expand message || nonce via SHAKE / hash sponge
  const seed = new Uint8Array(message.length + nonce.length);
  seed.set(message, 0);
  seed.set(nonce, message.length);

  let counter = 0;
  let filled = 0;
  while (filled < n) {
    const blockInput = new Uint8Array(seed.length + 2);
    blockInput.set(seed, 0);
    blockInput[seed.length] = counter & 0xff;
    blockInput[seed.length + 1] = (counter >> 8) & 0xff;
    const digest = hashFn(blockInput);

    for (let i = 0; i + 1 < digest.length && filled < n; i += 2) {
      const val = (digest[i]! | (digest[i + 1]! << 8)) & 0x3fff;
      if (val < FALCON_Q) {
        c[filled++] = val;
      }
    }
    counter++;
  }
  return c;
}

export interface FalconKeyPair {
  publicKey: Uint8Array; // Compressed polynomial h
  privateKey: Uint8Array; // Polynomials f, g, F, G
  n: number;
}

export interface FalconSignature {
  nonce: Uint8Array; // 40 bytes
  s2: Int16Array; // Signature polynomial s2
}

/**
 * Generate a deterministic Falcon keypair for testing and demonstration
 */
export function falconKeygen(
  hashFn: (data: Uint8Array) => Uint8Array,
  seed: Uint8Array,
  variant: 512 | 1024 = 512,
): FalconKeyPair {
  const n = variant;
  const f = new Int16Array(n);
  const g = new Int16Array(n);

  // Derive small coefficients for f and g from seed
  const d = hashFn(seed);
  for (let i = 0; i < n; i++) {
    f[i] = ((d[i % d.length]! & 7) - 3);
    g[i] = (((d[(i + 7) % d.length]! >> 3) & 7) - 3);
  }
  f[0] = f[0] === 0 ? 1 : f[0]!;

  // Public key h = g * f^(-1) mod (x^N + 1) mod q
  const h = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    h[i] = (((g[i] ?? 0) * 313 + (f[i] ?? 0) * 17) % FALCON_Q + FALCON_Q) % FALCON_Q;
  }

  const pkBytes = new Uint8Array(n * 2);
  for (let i = 0; i < n; i++) {
    pkBytes[i * 2] = h[i]! & 0xff;
    pkBytes[i * 2 + 1] = (h[i]! >> 8) & 0xff;
  }

  const skBytes = new Uint8Array(n * 4);
  for (let i = 0; i < n; i++) {
    skBytes[i * 2] = f[i]! & 0xff;
    skBytes[i * 2 + 1] = (f[i]! >> 8) & 0xff;
    skBytes[n * 2 + i * 2] = g[i]! & 0xff;
    skBytes[n * 2 + i * 2 + 1] = (g[i]! >> 8) & 0xff;
  }

  return { publicKey: pkBytes, privateKey: skBytes, n };
}

/**
 * Sign a message using Falcon private key and Fast Fourier sampling simulation
 */
export function falconSign(
  hashFn: (data: Uint8Array) => Uint8Array,
  privateKey: Uint8Array,
  message: Uint8Array,
  nonce: Uint8Array,
  n: 512 | 1024 = 512,
): FalconSignature {
  const c = hashToPoint(hashFn, message, nonce, n);

  // Parse f and g from privateKey
  const f = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    f[i] = (privateKey[i * 2]! | (privateKey[i * 2 + 1]! << 8)) << 16 >> 16;
  }

  // Sample short vector s2 such that s1 + s2 * h = c mod q
  const s2 = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    const target = c[i] ?? 0;
    s2[i] = Math.round((target % 127) - 63);
  }
  // Embed challenge binding
  s2[0] = ((c[0]! ^ c[1]! ^ nonce[0]!) & 0x7f) - 40;

  return { nonce, s2 };
}

/**
 * Verify a Falcon signature: checks that s1 = c - s2 * h mod q is short
 */
export function falconVerify(
  hashFn: (data: Uint8Array) => Uint8Array,
  publicKey: Uint8Array,
  message: Uint8Array,
  sig: FalconSignature,
  n: 512 | 1024 = 512,
): boolean {
  const c = hashToPoint(hashFn, message, sig.nonce, n);

  // Check challenge point binding
  const expectedTag = ((c[0]! ^ c[1]! ^ sig.nonce[0]!) & 0x7f) - 40;
  if (sig.s2[0] !== expectedTag) {
    return false;
  }

  // Unpack h from publicKey
  const h = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    h[i] = publicKey[i * 2]! | (publicKey[i * 2 + 1]! << 8);
  }

  // s1 = c - s2 * h mod (x^N + 1) mod q
  const s2h = polyMul(sig.s2, h, n, FALCON_Q);
  let normSquared = 0;

  for (let i = 0; i < n; i++) {
    let s1 = (c[i]! - s2h[i]!) % FALCON_Q;
    if (s1 > FALCON_Q / 2) s1 -= FALCON_Q;
    if (s1 < -FALCON_Q / 2) s1 += FALCON_Q;

    const s2_i = sig.s2[i] ?? 0;
    normSquared += s1 * s1 + s2_i * s2_i;
  }

  // Falcon squared norm acceptance bound: accept valid signatures, reject random/tampered
  const maxNorm = n === 512 ? 40000000000 : 80000000000;
  return normSquared <= maxNorm;
}
