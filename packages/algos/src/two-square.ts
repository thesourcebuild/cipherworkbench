/**
 * Two-Square Cipher (Double Playfair):
 * Digraphic substitution cipher using two 5x5 Polybius squares (horizontally or vertically aligned).
 */

function generateSquare(key: string): string {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  let square = "";
  const seen = new Set<string>();

  for (const ch of cleanKey) {
    if (!seen.has(ch)) {
      seen.add(ch);
      square += ch;
    }
  }

  const alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // 25 letters (I=J)
  for (const ch of alphabet) {
    if (!seen.has(ch)) {
      seen.add(ch);
      square += ch;
    }
  }
  return square;
}

export function twoSquareEncrypt(text: string, key1: string, key2: string): string {
  const sq1 = generateSquare(key1);
  const sq2 = generateSquare(key2);

  // Normalize plaintext: uppercase, I=J, paired
  const clean = text.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  const pairs: [string, string][] = [];
  for (let i = 0; i < clean.length; i += 2) {
    const a = clean[i]!;
    const b = (i + 1 < clean.length) ? clean[i + 1]! : "X";
    pairs.push([a, b]);
  }

  let result = "";
  for (const [a, b] of pairs) {
    const idxA = sq1.indexOf(a);
    const idxB = sq2.indexOf(b);

    const rA = Math.floor(idxA / 5), cA = idxA % 5;
    const rB = Math.floor(idxB / 5), cB = idxB % 5;

    // Horizontal two-square rule:
    // If different rows, form rectangle: (rA, cB) from sq2, (rB, cA) from sq1
    // If same row, keep row
    if (rA !== rB) {
      result += sq2[rA * 5 + cB]! + sq1[rB * 5 + cA]!;
    } else {
      result += sq2[rA * 5 + cA]! + sq1[rB * 5 + cB]!;
    }
  }
  return result;
}

export function twoSquareDecrypt(text: string, key1: string, key2: string): string {
  const sq1 = generateSquare(key1);
  const sq2 = generateSquare(key2);

  const clean = text.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  let result = "";

  for (let i = 0; i < clean.length; i += 2) {
    const c1 = clean[i]!;
    const c2 = (i + 1 < clean.length) ? clean[i + 1]! : "X";

    // c1 comes from sq2, c2 comes from sq1
    const idxC1 = sq2.indexOf(c1);
    const idxC2 = sq1.indexOf(c2);

    const r1 = Math.floor(idxC1 / 5), c1Col = idxC1 % 5;
    const r2 = Math.floor(idxC2 / 5), c2Col = idxC2 % 5;

    if (r1 !== r2) {
      result += sq1[r1 * 5 + c2Col]! + sq2[r2 * 5 + c1Col]!;
    } else {
      result += sq1[r1 * 5 + c1Col]! + sq2[r2 * 5 + c2Col]!;
    }
  }
  return result;
}

export function twoSquareCrypt(
  text: string,
  key1: string,
  key2: string,
  direction: "encrypt" | "decrypt" = "encrypt",
): string {
  return direction === "decrypt"
    ? twoSquareDecrypt(text, key1, key2)
    : twoSquareEncrypt(text, key1, key2);
}
