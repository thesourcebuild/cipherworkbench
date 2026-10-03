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

/**
 * Format a Shamir share into a portable token string (e.g. "SSSS-1-a1b2c3...")
 */
export function formatShamirShare(share: ShamirShare): string {
  let hex = "";
  for (let i = 0; i < share.y.length; i++) {
    hex += share.y[i]!.toString(16).padStart(2, "0");
  }
  return `SSSS-${share.x}-${hex}`;
}

/**
 * Parse a portable share token string (e.g. "SSSS-1-a1b2...", "1:a1b2...", "1-a1b2...")
 */
export function parseShamirShare(str: string): ShamirShare | null {
  const trimmed = str.trim();
  const match = trimmed.match(/^(?:SSSS-)?(\d+)[:-]([0-9a-fA-F]+)$/);
  if (!match) return null;
  const x = parseInt(match[1]!, 10);
  const hex = match[2]!;
  if (x < 1 || x > 255 || hex.length % 2 !== 0) return null;
  const y = new Uint8Array(hex.length / 2);
  for (let i = 0; i < y.length; i++) {
    y[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return { x, y };
}

export interface TamperDetectionResult {
  tampered: boolean;
  tamperedShareIndices?: number[];
  recoveredSecret?: Uint8Array;
}

/**
 * Given M shares (where M >= threshold K), checks if all subsets of size K agree on the reconstructed secret.
 * If M == K, returns the combined secret (no redundancy to detect tampering).
 * If M > K and a share is corrupted, identifies which share(s) cause inconsistency.
 */
export function detectTamperedShares(
  shares: ShamirShare[],
  threshold: number,
): TamperDetectionResult {
  if (shares.length < threshold) {
    throw new Error(`Need at least ${threshold} shares, got ${shares.length}`);
  }
  if (shares.length === threshold) {
    return {
      tampered: false,
      recoveredSecret: shamirCombine(shares),
    };
  }

  const subsets: ShamirShare[][] = [];
  function getSubsets(start: number, current: ShamirShare[]) {
    if (current.length === threshold) {
      subsets.push([...current]);
      return;
    }
    for (let i = start; i < shares.length; i++) {
      current.push(shares[i]!);
      getSubsets(i + 1, current);
      current.pop();
    }
  }
  getSubsets(0, []);

  const results = subsets.map((sub) => ({
    subset: sub,
    secret: shamirCombine(sub),
  }));

  const baseSecret = results[0]!.secret;
  let allMatch = true;
  for (let i = 1; i < results.length; i++) {
    const s = results[i]!.secret;
    let match = s.length === baseSecret.length;
    if (match) {
      for (let b = 0; b < s.length; b++) {
        if (s[b] !== baseSecret[b]) {
          match = false;
          break;
        }
      }
    }
    if (!match) {
      allMatch = false;
      break;
    }
  }

  if (allMatch) {
    return {
      tampered: false,
      recoveredSecret: baseSecret,
    };
  }

  const voteMap = new Map<string, { count: number; secret: Uint8Array; validSubsets: ShamirShare[][] }>();
  for (const res of results) {
    let hex = "";
    for (let b = 0; b < res.secret.length; b++) {
      hex += res.secret[b]!.toString(16).padStart(2, "0");
    }
    const entry = voteMap.get(hex) || { count: 0, secret: res.secret, validSubsets: [] };
    entry.count++;
    entry.validSubsets.push(res.subset);
    voteMap.set(hex, entry);
  }

  let bestEntry: { count: number; secret: Uint8Array; validSubsets: ShamirShare[][] } | undefined;
  for (const entry of voteMap.values()) {
    if (!bestEntry || entry.count > bestEntry.count) {
      bestEntry = entry;
    }
  }

  const validX = new Set<number>();
  if (bestEntry) {
    for (const sub of bestEntry.validSubsets) {
      for (const share of sub) {
        validX.add(share.x);
      }
    }
  }

  const tamperedIndices: number[] = [];
  for (const share of shares) {
    if (!validX.has(share.x)) {
      tamperedIndices.push(share.x);
    }
  }

  return {
    tampered: true,
    tamperedShareIndices: tamperedIndices.length > 0 ? tamperedIndices : undefined,
    recoveredSecret: bestEntry?.secret,
  };
}
