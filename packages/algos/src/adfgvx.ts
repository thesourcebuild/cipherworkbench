/**
 * ADFGX and ADFGVX Ciphers -- World War I German Field Ciphers (Fritz Nebel, 1918).
 *
 * Combines a Polybius-style fractionating substitution grid (ADFGX 5x5 or ADFGVX 6x6)
 * with a keyed columnar transposition.
 */

export const ADFGX_LETTERS = ["A", "D", "F", "G", "X"];
export const ADFGVX_LETTERS = ["A", "D", "F", "G", "V", "X"];

export const DEFAULT_ADFGX_GRID = "BTALPDHOZKQFVSNGICUXMREWY"; // 25 letters (I/J merged)
export const DEFAULT_ADFGVX_GRID = "NA1C3H8TB2OME5WRPD4F6G7I9J0KLQSUVXYZ"; // 36 alphanumeric

export function adfgvxEncrypt(
  plaintext: string,
  key: string,
  grid?: string,
  isAdfgvx: boolean = true,
): string {
  const actualGrid = grid ?? (isAdfgvx ? DEFAULT_ADFGVX_GRID : DEFAULT_ADFGX_GRID);
  const letters = isAdfgvx ? ADFGVX_LETTERS : ADFGX_LETTERS;
  const size = isAdfgvx ? 6 : 5;
  const cleanKey = key.toUpperCase().replace(/[^A-Z0-9]/g, "") || "KEY";
  const cleanInput = plaintext.toUpperCase().replace(/[^A-Z0-9]/g, "");

  // 1. Fractionation Substitution
  let fractionated = "";
  for (const ch of cleanInput) {
    let target = ch;
    if (!isAdfgvx && target === "J") target = "I";
    const idx = actualGrid.indexOf(target);
    if (idx !== -1) {
      const row = Math.floor(idx / size);
      const col = idx % size;
      fractionated += (letters[row] ?? "A") + (letters[col] ?? "A");
    }
  }

  // 2. Columnar Transposition
  const keyLen = cleanKey.length;
  const columns: string[] = new Array(keyLen).fill("");
  for (let i = 0; i < fractionated.length; i++) {
    columns[i % keyLen] += fractionated[i]!;
  }

  // Sort columns alphabetically by key letters
  const sortedIndices = Array.from({ length: keyLen }, (_, i) => i).sort((a, b) =>
    cleanKey.charAt(a).localeCompare(cleanKey.charAt(b)) || a - b
  );

  return sortedIndices.map((idx) => columns[idx]!).join("");
}

export function adfgvxDecrypt(
  ciphertext: string,
  key: string,
  grid?: string,
  isAdfgvx: boolean = true,
): string {
  const actualGrid = grid ?? (isAdfgvx ? DEFAULT_ADFGVX_GRID : DEFAULT_ADFGX_GRID);
  const letters = isAdfgvx ? ADFGVX_LETTERS : ADFGX_LETTERS;
  const size = isAdfgvx ? 6 : 5;
  const cleanKey = key.toUpperCase().replace(/[^A-Z0-9]/g, "") || "KEY";
  const cleanCipher = ciphertext.toUpperCase().replace(/[^A-Z]/g, "");

  const keyLen = cleanKey.length;
  const totalLen = cleanCipher.length;
  const baseColLen = Math.floor(totalLen / keyLen);
  const extraCols = totalLen % keyLen;

  // Determine lengths of each column in original order
  const colLengths: number[] = new Array(keyLen).fill(baseColLen);
  for (let i = 0; i < extraCols; i++) {
    colLengths[i] = (colLengths[i] ?? baseColLen) + 1;
  }

  // Sort indices by key letter
  const sortedIndices = Array.from({ length: keyLen }, (_, i) => i).sort((a, b) =>
    cleanKey.charAt(a).localeCompare(cleanKey.charAt(b)) || a - b
  );

  // Fill sorted columns
  const columns: string[] = new Array(keyLen).fill("");
  let pos = 0;
  for (const originalIdx of sortedIndices) {
    const len = colLengths[originalIdx]!;
    columns[originalIdx] = cleanCipher.slice(pos, pos + len);
    pos += len;
  }

  // Rebuild fractionated text row by row
  let fractionated = "";
  for (let row = 0; row < baseColLen + 1; row++) {
    for (let col = 0; col < keyLen; col++) {
      if (row < columns[col]!.length) {
        fractionated += columns[col]![row]!;
      }
    }
  }

  // Defractionate using grid
  let plaintext = "";
  for (let i = 0; i + 1 < fractionated.length; i += 2) {
    const row = letters.indexOf(fractionated[i]!);
    const col = letters.indexOf(fractionated[i + 1]!);
    if (row !== -1 && col !== -1) {
      const idx = row * size + col;
      plaintext += actualGrid[idx] ?? "";
    }
  }

  return plaintext;
}
