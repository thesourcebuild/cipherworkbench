/**
 * Bifid Cipher -- Félix Delastelle's 2-Coordinate Fractionating Classical Cipher (1901).
 *
 * Implements:
 * - 5x5 Polybius square coordinate mapping.
 * - Periodic block fractionating transposition.
 * - Bidirectional encryption / decryption.
 */

export interface BifidOptions {
  key?: string;
  period?: number; // Block length (default 5)
}

function getBifidSquare(key: string = ""): string[][] {
  const cleanKey = key.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
  const seen = new Set<string>();
  const alphabet: string[] = [];

  for (const ch of cleanKey) {
    if (!seen.has(ch)) {
      seen.add(ch);
      alphabet.push(ch);
    }
  }

  for (let i = 0; i < 26; i++) {
    const ch = String.fromCharCode(65 + i);
    if (ch === "J") continue;
    if (!seen.has(ch)) {
      seen.add(ch);
      alphabet.push(ch);
    }
  }

  const square: string[][] = [];
  for (let r = 0; r < 5; r++) {
    square.push(alphabet.slice(r * 5, r * 5 + 5));
  }
  return square;
}

function findCoords(square: string[][], ch: string): [number, number] {
  for (let r = 0; r < 5; r++) {
    for (let c = 0; c < 5; c++) {
      if (square[r]![c] === ch) return [r + 1, c + 1];
    }
  }
  return [1, 1];
}

export function bifidEncrypt(text: string, options: BifidOptions = {}): string {
  const period = options.period ?? 5;
  const square = getBifidSquare(options.key ?? "BIFID");
  const clean = text.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");

  let result = "";
  for (let p = 0; p < clean.length; p += period) {
    const block = clean.slice(p, p + period);
    const rows: number[] = [];
    const cols: number[] = [];

    for (const ch of block) {
      const [r, c] = findCoords(square, ch);
      rows.push(r);
      cols.push(c);
    }

    const combined = [...rows, ...cols];
    for (let i = 0; i < combined.length; i += 2) {
      const r = combined[i]! - 1;
      const c = combined[i + 1]! - 1;
      result += square[r]![c]!;
    }
  }

  return result;
}

export function bifidDecrypt(text: string, options: BifidOptions = {}): string {
  const period = options.period ?? 5;
  const square = getBifidSquare(options.key ?? "BIFID");
  const clean = text.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");

  let result = "";
  for (let p = 0; p < clean.length; p += period) {
    const block = clean.slice(p, p + period);
    const combined: number[] = [];

    for (const ch of block) {
      const [r, c] = findCoords(square, ch);
      combined.push(r, c);
    }

    const half = block.length;
    const rows = combined.slice(0, half);
    const cols = combined.slice(half);

    for (let i = 0; i < half; i++) {
      const r = rows[i]! - 1;
      const c = cols[i]! - 1;
      result += square[r]![c]!;
    }
  }

  return result;
}
