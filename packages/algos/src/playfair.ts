/**
 * Playfair Cipher -- First practical digraph substitution cipher (Wheatstone & Playfair, 1854).
 *
 * Implements:
 * - 5x5 key matrix generation (merging 'J' into 'I' or omitting 'Q').
 * - Digraph pairing with duplicate-splitting filler letter (default 'X').
 * - Playfair transformation rules:
 *   1. Same row: shift right (encrypt) / shift left (decrypt).
 *   2. Same column: shift down (encrypt) / shift up (decrypt).
 *   3. Rectangle: swap column coordinates.
 */

export interface PlayfairOptions {
  key?: string;
  omitChar?: "J" | "Q"; // Default 'J' (replaced with 'I')
  fillerChar?: string; // Default 'X'
}

export function generatePlayfairMatrix(key: string = "PLAYFAIR", omitChar: "J" | "Q" = "J"): string[][] {
  const replaceWith = omitChar === "J" ? "I" : "K";
  const cleanKey = key
    .toUpperCase()
    .replace(new RegExp(omitChar, "g"), replaceWith)
    .replace(/[^A-Z]/g, "");

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
    if (ch === omitChar) continue;
    if (!seen.has(ch)) {
      seen.add(ch);
      alphabet.push(ch);
    }
  }

  const matrix: string[][] = [];
  for (let r = 0; r < 5; r++) {
    matrix.push(alphabet.slice(r * 5, r * 5 + 5));
  }
  return matrix;
}

function findPosition(matrix: string[][], ch: string): [number, number] {
  for (let r = 0; r < 5; r++) {
    for (let c = 0; c < 5; c++) {
      if (matrix[r]![c] === ch) return [r, c];
    }
  }
  return [0, 0];
}

export function playfairEncrypt(text: string, options: PlayfairOptions = {}): string {
  const omit = options.omitChar ?? "J";
  const replaceWith = omit === "J" ? "I" : "K";
  const filler = (options.fillerChar ?? "X").toUpperCase();
  const matrix = generatePlayfairMatrix(options.key ?? "PLAYFAIR", omit);

  const clean = text
    .toUpperCase()
    .replace(new RegExp(omit, "g"), replaceWith)
    .replace(/[^A-Z]/g, "");

  // Prepare digraphs
  const digraphs: [string, string][] = [];
  let i = 0;
  while (i < clean.length) {
    const a = clean[i]!;
    if (i + 1 < clean.length) {
      const b = clean[i + 1]!;
      if (a === b) {
        digraphs.push([a, filler]);
        i++;
      } else {
        digraphs.push([a, b]);
        i += 2;
      }
    } else {
      digraphs.push([a, filler]);
      i++;
    }
  }

  let result = "";
  for (const [a, b] of digraphs) {
    const [r1, c1] = findPosition(matrix, a);
    const [r2, c2] = findPosition(matrix, b);

    if (r1 === r2) {
      // Same row: shift right
      result += matrix[r1]![(c1 + 1) % 5]! + matrix[r2]![(c2 + 1) % 5]!;
    } else if (c1 === c2) {
      // Same column: shift down
      result += matrix[(r1 + 1) % 5]![c1]! + matrix[(r2 + 1) % 5]![c2]!;
    } else {
      // Rectangle: swap columns
      result += matrix[r1]![c2]! + matrix[r2]![c1]!;
    }
  }

  return result;
}

export function playfairDecrypt(text: string, options: PlayfairOptions = {}): string {
  const omit = options.omitChar ?? "J";
  const replaceWith = omit === "J" ? "I" : "K";
  const matrix = generatePlayfairMatrix(options.key ?? "PLAYFAIR", omit);

  const clean = text
    .toUpperCase()
    .replace(new RegExp(omit, "g"), replaceWith)
    .replace(/[^A-Z]/g, "");

  let result = "";
  for (let i = 0; i < clean.length; i += 2) {
    if (i + 1 >= clean.length) break;
    const a = clean[i]!;
    const b = clean[i + 1]!;

    const [r1, c1] = findPosition(matrix, a);
    const [r2, c2] = findPosition(matrix, b);

    if (r1 === r2) {
      // Same row: shift left
      result += matrix[r1]![(c1 + 4) % 5]! + matrix[r2]![(c2 + 4) % 5]!;
    } else if (c1 === c2) {
      // Same column: shift up
      result += matrix[(r1 + 4) % 5]![c1]! + matrix[(r2 + 4) % 5]![c2]!;
    } else {
      // Rectangle: swap columns
      result += matrix[r1]![c2]! + matrix[r2]![c1]!;
    }
  }

  return result;
}
