/**
 * Bacon's Cipher (Francis Bacon, 1605).
 * Steganographic 5-bit substitution encoding letters into sequences of 'A' and 'B'
 * or upper/lowercase font variations.
 */

const BACON_24: Record<string, string> = {
  A: "AAAAA", B: "AAAAB", C: "AAABA", D: "AAABB", E: "AABAA",
  F: "AABAB", G: "AABBA", H: "AABBB", I: "ABAAA", J: "ABAAA", // I = J
  K: "ABAAB", L: "ABABA", M: "ABABB", N: "ABBAA", O: "ABBAB",
  P: "ABBBA", Q: "ABBBB", R: "BAAAA", S: "BAAAB", T: "BAABA",
  U: "BAABB", V: "BAABB", // U = V
  W: "BABAA", X: "BABAB", Y: "BABBA", Z: "BABBB",
};

const REV_BACON_24: Record<string, string> = {
  AAAAA: "A", AAAAB: "B", AAABA: "C", AAABB: "D", AABAA: "E",
  AABAB: "F", AABBA: "G", AABBB: "H", ABAAA: "I", ABAAB: "K",
  ABABA: "L", ABABB: "M", ABBAA: "N", ABBAB: "O", ABBBA: "P",
  ABBBB: "Q", BAAAA: "R", BAAAB: "S", BAABA: "T", BAABB: "U",
  BABAA: "W", BABAB: "X", BABBA: "Y", BABBB: "Z",
};

export interface BaconOptions {
  direction?: "encrypt" | "decrypt";
}

export function baconCrypt(text: string, options: BaconOptions = {}): string {
  const isDecrypt = options.direction === "decrypt";

  if (!isDecrypt) {
    const clean = text.toUpperCase();
    const codes: string[] = [];
    for (const c of clean) {
      if (BACON_24[c]) {
        codes.push(BACON_24[c]!);
      }
    }
    return codes.join(" ");
  } else {
    // Clean to only A and B
    const clean = text.toUpperCase().replace(/[^AB]/g, "");
    let result = "";
    for (let i = 0; i + 5 <= clean.length; i += 5) {
      const chunk = clean.slice(i, i + 5);
      result += REV_BACON_24[chunk] ?? "?";
    }
    return result;
  }
}
