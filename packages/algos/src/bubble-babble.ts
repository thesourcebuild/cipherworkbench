/**
 * Bubble Babble Binary Data Encoding (Antti Huima, 2001).
 * Encodes arbitrary byte sequences into pronounceable pseudo-words with built-in checksumming.
 */

const VOWELS = ["a", "e", "i", "o", "u", "y"] as const;
const CONSONANTS = [
  "b", "c", "d", "f", "g", "h", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z", "x",
] as const;

export function encodeBubbleBabble(data: Uint8Array): string {
  let out = "x";
  let checksum = 1;
  let i = 0;

  while (i < data.length) {
    const byte1 = data[i]!;
    if (i + 1 < data.length) {
      const byte2 = data[i + 1]!;
      const idx1 = (((byte1 >>> 6) & 3) + checksum) % 6;
      const idx2 = (byte1 >>> 2) & 15;
      const idx3 = ((byte1 & 3) + Math.floor(checksum / 6)) % 6;
      const idx4 = (byte2 >>> 4) & 15;
      const idx5 = byte2 & 15;

      out += VOWELS[idx1]!;
      out += CONSONANTS[idx2]!;
      out += VOWELS[idx3]!;
      out += CONSONANTS[idx4]!;
      out += "-";
      out += CONSONANTS[idx5]!;

      checksum = (checksum * 5 + byte1 * 7 + byte2) % 36;
      i += 2;
    } else {
      const idx1 = (((byte1 >>> 6) & 3) + checksum) % 6;
      const idx2 = (byte1 >>> 2) & 15;
      const idx3 = ((byte1 & 3) + Math.floor(checksum / 6)) % 6;

      out += VOWELS[idx1]!;
      out += CONSONANTS[idx2]!;
      out += VOWELS[idx3]!;
      i += 1;
      break;
    }
  }

  out += "x";
  return out;
}

export function decodeBubbleBabble(str: string): Uint8Array {
  const clean = str.replace(/[^a-z]/g, "");
  if (clean.length < 2 || !clean.startsWith("x") || !clean.endsWith("x")) {
    throw new Error("Invalid Bubble Babble format.");
  }

  const inner = clean.slice(1, -1);
  const bytes: number[] = [];
  let checksum = 1;
  let i = 0;

  while (i < inner.length) {
    if (i + 5 <= inner.length) {
      const c1 = inner[i]!;
      const c2 = inner[i + 1]!;
      const c3 = inner[i + 2]!;
      const c4 = inner[i + 3]!;
      const c5 = inner[i + 4]!;

      const idx1 = VOWELS.indexOf(c1 as (typeof VOWELS)[number]);
      const idx2 = CONSONANTS.indexOf(c2 as (typeof CONSONANTS)[number]);
      const idx3 = VOWELS.indexOf(c3 as (typeof VOWELS)[number]);
      const idx4 = CONSONANTS.indexOf(c4 as (typeof CONSONANTS)[number]);
      const idx5 = CONSONANTS.indexOf(c5 as (typeof CONSONANTS)[number]);

      if (idx1 === -1 || idx2 === -1 || idx3 === -1 || idx4 === -1 || idx5 === -1) {
        throw new Error("Invalid characters in Bubble Babble stream.");
      }

      const highBits = ((idx1 - (checksum % 6) + 6) % 6) & 3;
      const midBits = idx2 & 15;
      const lowBits = ((idx3 - Math.floor(checksum / 6) + 6) % 6) & 3;

      const byte1 = (highBits << 6) | (midBits << 2) | lowBits;
      const byte2 = (idx4 << 4) | idx5;

      bytes.push(byte1, byte2);
      checksum = (checksum * 5 + byte1 * 7 + byte2) % 36;
      i += 5;
    } else if (i + 3 <= inner.length) {
      const c1 = inner[i]!;
      const c2 = inner[i + 1]!;
      const c3 = inner[i + 2]!;

      const idx1 = VOWELS.indexOf(c1 as (typeof VOWELS)[number]);
      const idx2 = CONSONANTS.indexOf(c2 as (typeof CONSONANTS)[number]);
      const idx3 = VOWELS.indexOf(c3 as (typeof VOWELS)[number]);

      if (idx1 === -1 || idx2 === -1 || idx3 === -1) {
        throw new Error("Invalid characters in Bubble Babble stream.");
      }

      const highBits = ((idx1 - (checksum % 6) + 6) % 6) & 3;
      const midBits = idx2 & 15;
      const lowBits = ((idx3 - Math.floor(checksum / 6) + 6) % 6) & 3;

      const byte1 = (highBits << 6) | (midBits << 2) | lowBits;
      bytes.push(byte1);
      i += 3;
      break;
    } else {
      break;
    }
  }

  return new Uint8Array(bytes);
}
