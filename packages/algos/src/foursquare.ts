/**
 * Four-Square and Two-Square Ciphers -- Polygraphic Digram Substitution Ciphers (Felix Delastelle, 1902).
 *
 * Encrypts pairs of letters (digrams) using four 5x5 Polybius squares (I/J merged).
 */

export const ALPHABET_25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // 25 letters, J omitted / merged into I

export const DEFAULT_KEY_TOP_RIGHT = "ZGPTFOIHMKWDNERCQVYSULXAB";
export const DEFAULT_KEY_BOTTOM_LEFT = "MFNBZORVXYDGQJWHIKELPUSAC";

export function generateSquare(key: string): string {
  const clean = (key.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "") + ALPHABET_25);
  const seen = new Set<string>();
  let result = "";
  for (const ch of clean) {
    if (!seen.has(ch) && ALPHABET_25.includes(ch)) {
      seen.add(ch);
      result += ch;
    }
  }
  return result;
}

export function fourSquareEncrypt(
  plaintext: string,
  key1: string = DEFAULT_KEY_TOP_RIGHT,
  key2: string = DEFAULT_KEY_BOTTOM_LEFT,
): string {
  const sqTopRight = generateSquare(key1);
  const sqBottomLeft = generateSquare(key2);
  const clean = plaintext.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");

  let padded = clean;
  if (padded.length % 2 !== 0) padded += "X";

  let ciphertext = "";
  for (let i = 0; i < padded.length; i += 2) {
    const c1 = padded[i]!;
    const c2 = padded[i + 1]!;

    const idx1 = ALPHABET_25.indexOf(c1);
    const idx2 = ALPHABET_25.indexOf(c2);

    const row1 = Math.floor(idx1 / 5);
    const col1 = idx1 % 5;
    const row2 = Math.floor(idx2 / 5);
    const col2 = idx2 % 5;

    // c1' from sqTopRight (row1, col2)
    // c2' from sqBottomLeft (row2, col1)
    const c1Prime = sqTopRight[row1 * 5 + col2]!;
    const c2Prime = sqBottomLeft[row2 * 5 + col1]!;

    ciphertext += c1Prime + c2Prime;
  }

  return ciphertext;
}

export function fourSquareDecrypt(
  ciphertext: string,
  key1: string = DEFAULT_KEY_TOP_RIGHT,
  key2: string = DEFAULT_KEY_BOTTOM_LEFT,
): string {
  const sqTopRight = generateSquare(key1);
  const sqBottomLeft = generateSquare(key2);
  const clean = ciphertext.toUpperCase().replace(/[^A-Z]/g, "");

  let plaintext = "";
  for (let i = 0; i < clean.length; i += 2) {
    const c1Prime = clean[i]!;
    const c2Prime = clean[i + 1]!;

    const idx1 = sqTopRight.indexOf(c1Prime);
    const idx2 = sqBottomLeft.indexOf(c2Prime);

    const row1 = Math.floor(idx1 / 5);
    const col2 = idx1 % 5;
    const row2 = Math.floor(idx2 / 5);
    const col1 = idx2 % 5;

    const c1 = ALPHABET_25[row1 * 5 + col1]!;
    const c2 = ALPHABET_25[row2 * 5 + col2]!;

    plaintext += c1 + c2;
  }

  return plaintext;
}
