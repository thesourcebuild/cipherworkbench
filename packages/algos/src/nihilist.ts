/**
 * Nihilist Cipher -- 19th-Century Russian Nihilist Fractionating & Key-Addition Cipher.
 *
 * 1. Constructs a 5x5 Polybius square with key 1 (e.g. "RUSSIAN"), mapping letters A-Z (I/J merged) to 2-digit coordinates (11-55).
 * 2. Converts the additive key phrase (e.g. "SECRET") to coordinates.
 * 3. Converts the plaintext into coordinates and adds the key coordinates modulo 100 or directly as numbers.
 */

export interface NihilistOptions {
  /** Keyword for the 5x5 Polybius square matrix. */
  alphabetKey?: string;
  /** Additive key phrase added to plaintext coordinates. */
  keyPhrase?: string;
  direction?: "encrypt" | "decrypt";
}

export function buildNihilistSquare(alphabetKey = ""): string {
  const seen = new Set<string>();
  const clean = (alphabetKey + "ABCDEFGHIKLMNOPQRSTUVWXYZ").toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  let square = "";

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    if (!seen.has(ch)) {
      seen.add(ch);
      square += ch;
    }
  }
  return square;
}

export function nihilistEncrypt(text: string, options: NihilistOptions = {}): string {
  const square = buildNihilistSquare(options.alphabetKey ?? "RUSSIAN");
  const keyPhrase = (options.keyPhrase ?? "SECRET").toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I") || "KEY";

  // Convert key phrase to coordinates
  const keyCoords: number[] = [];
  for (let i = 0; i < keyPhrase.length; i++) {
    const idx = square.indexOf(keyPhrase[i]!);
    if (idx !== -1) {
      const r = Math.floor(idx / 5) + 1;
      const c = (idx % 5) + 1;
      keyCoords.push(r * 10 + c);
    }
  }

  const cleanText = text.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  const result: number[] = [];

  for (let i = 0; i < cleanText.length; i++) {
    const ch = cleanText[i]!;
    const idx = square.indexOf(ch);
    if (idx !== -1) {
      const r = Math.floor(idx / 5) + 1;
      const c = (idx % 5) + 1;
      const pCoord = r * 10 + c;
      const kCoord = keyCoords[i % keyCoords.length]!;
      result.push(pCoord + kCoord);
    }
  }

  return result.join(" ");
}

export function nihilistDecrypt(ciphertext: string, options: NihilistOptions = {}): string {
  const square = buildNihilistSquare(options.alphabetKey ?? "RUSSIAN");
  const keyPhrase = (options.keyPhrase ?? "SECRET").toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I") || "KEY";

  const keyCoords: number[] = [];
  for (let i = 0; i < keyPhrase.length; i++) {
    const idx = square.indexOf(keyPhrase[i]!);
    if (idx !== -1) {
      const r = Math.floor(idx / 5) + 1;
      const c = (idx % 5) + 1;
      keyCoords.push(r * 10 + c);
    }
  }

  // Split ciphertext by whitespace or comma
  const tokens = ciphertext.trim().split(/[\s,]+/);
  let plaintext = "";

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!;
    const sum = parseInt(token, 10);
    if (isNaN(sum)) continue;

    const kCoord = keyCoords[i % keyCoords.length]!;
    const pCoord = sum - kCoord;

    const r = Math.floor(pCoord / 10);
    const c = pCoord % 10;

    if (r >= 1 && r <= 5 && c >= 1 && c <= 5) {
      const idx = (r - 1) * 5 + (c - 1);
      plaintext += square[idx]!;
    }
  }

  return plaintext;
}
