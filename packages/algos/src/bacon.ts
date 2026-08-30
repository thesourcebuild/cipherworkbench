/**
 * Bacon's Cipher -- Sir Francis Bacon's 5-bit Steganographic / Substitution Cipher (1605).
 *
 * Implements:
 * - 24-letter traditional alphabet (I=J and U=V).
 * - 26-letter full modern alphabet.
 * - Encoding letters to 'A'/'B' 5-character sequences and decoding back.
 */

export interface BaconOptions {
  variant?: "traditional" | "full"; // "traditional" (24 letters) or "full" (26 letters)
  aChar?: string; // default "A"
  bChar?: string; // default "B"
}

// 24-letter traditional Bacon code (I=J, U=V)
const BACON_TRADITIONAL: Record<string, string> = {
  A: "AAAAA", B: "AAAAB", C: "AAABA", D: "AAABB", E: "AABAA",
  F: "AABAB", G: "AABBA", H: "AABBB", I: "ABAAA", J: "ABAAA",
  K: "ABAAB", L: "ABABA", M: "ABABB", N: "ABBAA", O: "ABBAB",
  P: "ABBBA", Q: "ABBBB", R: "BAAAA", S: "BAAAB", T: "BAABA",
  U: "BAABB", V: "BAABB", W: "BABAA", X: "BABAB", Y: "BABBA",
  Z: "BABBB",
};

// 26-letter distinct Bacon code
const BACON_FULL: Record<string, string> = {
  A: "AAAAA", B: "AAAAB", C: "AAABA", D: "AAABB", E: "AABAA",
  F: "AABAB", G: "AABBA", H: "AABBB", I: "ABAAA", J: "ABAAB",
  K: "ABABA", L: "ABABB", M: "ABBAA", N: "ABBAB", O: "ABBBA",
  P: "ABBBB", Q: "BAAAA", R: "BAAAB", S: "BAABA", T: "BAABB",
  U: "BABAA", V: "BABAB", W: "BABBA", X: "BABBB", Y: "BBAAA",
  Z: "BBAAB",
};

export function baconEncrypt(text: string, options: BaconOptions = {}): string {
  const variant = options.variant ?? "full";
  const table = variant === "traditional" ? BACON_TRADITIONAL : BACON_FULL;
  const aChar = options.aChar ?? "A";
  const bChar = options.bChar ?? "B";

  const clean = text.toUpperCase().replace(/[^A-Z]/g, "");
  let result = "";

  for (const ch of clean) {
    const code = table[ch]!;
    if (code) {
      result += code.replace(/A/g, aChar).replace(/B/g, bChar) + " ";
    }
  }

  return result.trim();
}

export function baconDecrypt(text: string, options: BaconOptions = {}): string {
  const variant = options.variant ?? "full";
  const table = variant === "traditional" ? BACON_TRADITIONAL : BACON_FULL;
  const aChar = (options.aChar ?? "A").toUpperCase();
  const bChar = (options.bChar ?? "B").toUpperCase();

  // Invert table
  const reverse: Record<string, string> = {};
  for (const [letter, code] of Object.entries(table)) {
    if (!reverse[code]) reverse[code] = letter;
  }

  const clean = text
    .toUpperCase()
    .replace(new RegExp(`[^${aChar}${bChar}]`, "g"), "")
    .replace(new RegExp(aChar, "g"), "A")
    .replace(new RegExp(bChar, "g"), "B");

  let result = "";
  for (let i = 0; i + 5 <= clean.length; i += 5) {
    const chunk = clean.slice(i, i + 5);
    const letter = reverse[chunk];
    if (letter) result += letter;
  }

  return result;
}
