/**
 * Shamir's Secret Sharing (SSSS) -- Information-Theoretic (k, n) Threshold Cryptosystem.
 *
 * Implements polynomial secret sharing and Lagrange basis interpolation over Galois Field GF(256)
 * (using the standard AES/Rijndael irreducible polynomial x^8 + x^4 + x^3 + x + 1 = 0x11b).
 */

// GF(256) Log and Exp tables for multiplication and division
const EXP_TABLE: Uint8Array = new Uint8Array(512);
const LOG_TABLE: Uint8Array = new Uint8Array(256);

(function initGfTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    EXP_TABLE[i + 255] = x;
    LOG_TABLE[x] = i;
    let next = x ^ (x << 1);
    if (next >= 256) next ^= 0x11b;
    x = next;
  }
  LOG_TABLE[0] = 0;
})();

export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a]! + LOG_TABLE[b]!) % 255]!;
}

export function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error("Division by zero in GF(256)");
  if (a === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a]! - LOG_TABLE[b]! + 255) % 255]!;
}

export interface ShamirShare {
  x: number; // 1-indexed share coordinate (1..255)
  y: Uint8Array; // Polynomial evaluation at x for each byte of the secret
}

/**
 * Split a secret into N shares with threshold K
 */
export function shamirSplit(
  secret: Uint8Array,
  totalShares: number, // n
  threshold: number, // k
  rng: (len: number) => Uint8Array,
): ShamirShare[] {
  if (threshold < 1 || threshold > totalShares) {
    throw new Error(`Invalid threshold: ${threshold} (must be between 1 and ${totalShares})`);
  }
  if (totalShares > 255) {
    throw new Error("Maximum 255 shares in GF(256)");
  }

  // Coefficients for polynomial P(x) = secret + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1}
  // For each byte of the secret, generate (k-1) random coefficients
  const numCoeffs = threshold - 1;
  const randomBytes = rng(secret.length * numCoeffs);

  const shares: ShamirShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    shares.push({ x: i, y: new Uint8Array(secret.length) });
  }

  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    const s = secret[byteIdx]!;
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = s;
    for (let c = 0; c < numCoeffs; c++) {
      coeffs[c + 1] = randomBytes[byteIdx * numCoeffs + c]!;
    }

    // Evaluate polynomial at x = 1..totalShares using Horner's method
    for (let i = 0; i < totalShares; i++) {
      const x = shares[i]!.x;
      let val = 0;
      for (let c = threshold - 1; c >= 0; c--) {
        val = gfMul(val, x) ^ coeffs[c]!;
      }
      shares[i]!.y[byteIdx] = val;
    }
  }

  return shares;
}

/**
 * Reconstruct the original secret from K or more shares using Lagrange interpolation
 */
export function shamirCombine(shares: ShamirShare[]): Uint8Array {
  if (shares.length === 0) {
    throw new Error("Cannot combine zero shares");
  }

  // Ensure all share x coordinates are distinct
  const seenX = new Set<number>();
  for (const share of shares) {
    if (seenX.has(share.x)) {
      throw new Error(`Duplicate share x-coordinate: ${share.x}`);
    }
    seenX.add(share.x);
  }

  const k = shares.length;
  const secretLen = shares[0]!.y.length;
  const secret = new Uint8Array(secretLen);

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let sum = 0;
    for (let i = 0; i < k; i++) {
      const xi = shares[i]!.x;
      const yi = shares[i]!.y[byteIdx]!;

      // Compute Lagrange basis polynomial L_i(0) = \prod_{j \neq i} (0 - x_j) / (x_i - x_j)
      let num = 1;
      let den = 1;
      for (let j = 0; j < k; j++) {
        if (i === j) continue;
        const xj = shares[j]!.x;
        num = gfMul(num, xj); // (0 - x_j) = x_j in GF(256) where addition is XOR
        den = gfMul(den, xi ^ xj); // (x_i - x_j) = x_i ^ x_j
      }

      const li0 = gfDiv(num, den);
      sum ^= gfMul(yi, li0);
    }
    secret[byteIdx] = sum;
  }

  return secret;
}
