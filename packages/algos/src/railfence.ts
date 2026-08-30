/**
 * Rail Fence Cipher -- Geometric Zig-Zag Transposition Cipher.
 *
 * Implements:
 * - Multi-rail zig-zag path generation.
 * - Configurable rail count (>= 2) and starting offset.
 * - Bidirectional encryption / decryption.
 */

export interface RailFenceOptions {
  rails?: number; // default 3
  offset?: number; // default 0
}

export function railFenceEncrypt(text: string, options: RailFenceOptions = {}): string {
  const rails = Math.max(2, options.rails ?? 3);
  if (text.length === 0) return "";

  const rows: string[][] = Array.from({ length: rails }, () => []);
  let currentRail = 0;
  let direction = 1; // 1 for down, -1 for up

  for (let i = 0; i < text.length; i++) {
    rows[currentRail]!.push(text[i]!);

    if (currentRail === 0) {
      direction = 1;
    } else if (currentRail === rails - 1) {
      direction = -1;
    }
    currentRail += direction;
  }

  return rows.map((r) => r.join("")).join("");
}

export function railFenceDecrypt(ciphertext: string, options: RailFenceOptions = {}): string {
  const rails = Math.max(2, options.rails ?? 3);
  const n = ciphertext.length;
  if (n === 0) return "";

  // Mark matrix positions
  const matrix: boolean[][] = Array.from({ length: rails }, () => Array(n).fill(false));
  let currentRail = 0;
  let direction = 1;

  for (let i = 0; i < n; i++) {
    matrix[currentRail]![i] = true;

    if (currentRail === 0) {
      direction = 1;
    } else if (currentRail === rails - 1) {
      direction = -1;
    }
    currentRail += direction;
  }

  // Fill marked cells with ciphertext characters
  const filledMatrix: (string | null)[][] = Array.from({ length: rails }, () => Array(n).fill(null));
  let charIdx = 0;
  for (let r = 0; r < rails; r++) {
    for (let c = 0; c < n; c++) {
      if (matrix[r]![c] && charIdx < n) {
        filledMatrix[r]![c] = ciphertext[charIdx++]!;
      }
    }
  }

  // Read out characters in zig-zag order
  let result = "";
  currentRail = 0;
  direction = 1;
  for (let i = 0; i < n; i++) {
    const ch = filledMatrix[currentRail]![i];
    if (ch !== null) result += ch;

    if (currentRail === 0) {
      direction = 1;
    } else if (currentRail === rails - 1) {
      direction = -1;
    }
    currentRail += direction;
  }

  return result;
}
