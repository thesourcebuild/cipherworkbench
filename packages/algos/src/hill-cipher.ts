/**
 * Hill Cipher -- Polygraphic substitution cipher based on linear algebra (Lester S. Hill, 1929).
 *
 * Implements 2x2 and 3x3 matrix multiplication modulo 26, modular determinant calculation,
 * and modular matrix inversion.
 */

function gcd(a: number, b: number): number {
  return b === 0 ? a : gcd(b, a % b);
}

function modInverse(a: number, m: number = 26): number {
  let [old_r, r] = [a % m, m];
  let [old_s, s] = [1, 0];
  while (r !== 0) {
    const q = Math.floor(old_r / r);
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return (old_s % m + m) % m;
}

export function det2x2(m: number[][]): number {
  return ((m[0]![0]! * m[1]![1]! - m[0]![1]! * m[1]![0]!) % 26 + 26) % 26;
}

export function invert2x2(m: number[][]): number[][] {
  const d = det2x2(m);
  if (gcd(d, 26) !== 1) {
    throw new Error(`Matrix is not invertible mod 26 (determinant = ${d})`);
  }
  const invDet = modInverse(d, 26);
  return [
    [((m[1]![1]! * invDet) % 26 + 26) % 26, ((-m[0]![1]! * invDet) % 26 + 26) % 26],
    [((-m[1]![0]! * invDet) % 26 + 26) % 26, ((m[0]![0]! * invDet) % 26 + 26) % 26],
  ];
}

export const DEFAULT_HILL_2X2: number[][] = [
  [3, 3],
  [2, 5],
]; // det = 15 - 6 = 9, gcd(9, 26) = 1

export function hillEncrypt(
  plaintext: string,
  matrix: number[][] = DEFAULT_HILL_2X2,
): string {
  const n = matrix.length;
  const clean = plaintext.toUpperCase().replace(/[^A-Z]/g, "");
  // Pad with 'X' to a multiple of n
  let padded = clean;
  while (padded.length % n !== 0) {
    padded += "X";
  }

  let ciphertext = "";
  for (let i = 0; i < padded.length; i += n) {
    for (let row = 0; row < n; row++) {
      let sum = 0;
      for (let col = 0; col < n; col++) {
        const charVal = padded.charCodeAt(i + col) - 65;
        sum += matrix[row]![col]! * charVal;
      }
      ciphertext += String.fromCharCode((sum % 26) + 65);
    }
  }

  return ciphertext;
}

export function hillDecrypt(
  ciphertext: string,
  matrix: number[][] = DEFAULT_HILL_2X2,
): string {
  const invMatrix = invert2x2(matrix);
  return hillEncrypt(ciphertext, invMatrix);
}
