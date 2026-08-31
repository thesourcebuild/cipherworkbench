/**
 * Chaocipher (J.F. Byrne, 1953).
 * A dynamic substitution cipher using two interacting rotating alphabet wheels
 * that mutate after every letter enciphered/deciphered.
 */

const DEFAULT_LEFT = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";
const DEFAULT_RIGHT = "PTLNBQDEOYSFAVZKGJRIHWXUMC";

export interface ChaocipherOptions {
  leftAlphabet?: string;
  rightAlphabet?: string;
  direction?: "encrypt" | "decrypt";
}

export function chaocipherCrypt(text: string, options: ChaocipherOptions = {}): string {
  let left = (options.leftAlphabet ?? DEFAULT_LEFT).toUpperCase();
  let right = (options.rightAlphabet ?? DEFAULT_RIGHT).toUpperCase();
  const isDecrypt = options.direction === "decrypt";

  const clean = text.toUpperCase();
  let result = "";

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    if (isDecrypt) {
      const idx = left.indexOf(ch);
      if (idx === -1) {
        result += ch;
        continue;
      }
      const plainChar = right[idx]!;
      result += plainChar;

      // Permute alphabets
      left = permuteLeft(left, idx);
      right = permuteRight(right, idx);
    } else {
      const idx = right.indexOf(ch);
      if (idx === -1) {
        result += ch;
        continue;
      }
      const cipherChar = left[idx]!;
      result += cipherChar;

      // Permute alphabets
      left = permuteLeft(left, idx);
      right = permuteRight(right, idx);
    }
  }

  return result;
}

function permuteLeft(wheel: string, pos: number): string {
  // Rotate so pos is at zenith (index 0)
  const rotated = wheel.slice(pos) + wheel.slice(0, pos);
  // Extract index 1, insert at index 13
  const ch = rotated[1]!;
  const rest = rotated.slice(0, 1) + rotated.slice(2, 14) + ch + rotated.slice(14);
  return rest;
}

function permuteRight(wheel: string, pos: number): string {
  // Rotate so pos + 1 is at zenith (index 0)
  const shift = (pos + 1) % 26;
  const rotated = wheel.slice(shift) + wheel.slice(0, shift);
  // Extract index 2, insert at index 13
  const ch = rotated[2]!;
  const rest = rotated.slice(0, 2) + rotated.slice(3, 14) + ch + rotated.slice(14);
  return rest;
}
