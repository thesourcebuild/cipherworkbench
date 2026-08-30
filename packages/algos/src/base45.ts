/**
 * Base45 Encoding -- RFC 9285 (QR-Code Optimized Alphanumeric Encoding).
 *
 * Implements:
 * - 45-character alphabet: 0-9, A-Z, space, $, %, *, +, -, ., /, :.
 * - 2-byte to 3-character small-endian polynomial expansion.
 * - Single byte to 2-character trailing encoding.
 */

export const BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

export function base45Encode(data: Uint8Array): string {
  let result = "";

  for (let i = 0; i < data.length; i += 2) {
    if (i + 1 < data.length) {
      // 2 bytes -> 3 chars
      const val = (data[i]! << 8) | data[i + 1]!;
      const c0 = val % 45;
      const c1 = Math.floor(val / 45) % 45;
      const c2 = Math.floor(val / (45 * 45)) % 45;
      result += BASE45_ALPHABET[c0]! + BASE45_ALPHABET[c1]! + BASE45_ALPHABET[c2]!;
    } else {
      // 1 trailing byte -> 2 chars
      const val = data[i]!;
      const c0 = val % 45;
      const c1 = Math.floor(val / 45) % 45;
      result += BASE45_ALPHABET[c0]! + BASE45_ALPHABET[c1]!;
    }
  }

  return result;
}

export function base45Decode(text: string): Uint8Array {
  const bytes: number[] = [];

  for (let i = 0; i < text.length; i += 3) {
    const rem = text.length - i;
    if (rem === 1) {
      throw new Error("Invalid Base45 length: single dangling character");
    }

    if (rem >= 3) {
      const c0 = BASE45_ALPHABET.indexOf(text[i]!);
      const c1 = BASE45_ALPHABET.indexOf(text[i + 1]!);
      const c2 = BASE45_ALPHABET.indexOf(text[i + 2]!);
      if (c0 === -1 || c1 === -1 || c2 === -1) {
        throw new Error("Invalid character in Base45 string");
      }

      const val = c0 + c1 * 45 + c2 * 45 * 45;
      if (val > 65535) {
        throw new Error("Base45 overflow: triplet value exceeds 65535");
      }

      bytes.push((val >> 8) & 0xff);
      bytes.push(val & 0xff);
    } else {
      // rem === 2
      const c0 = BASE45_ALPHABET.indexOf(text[i]!);
      const c1 = BASE45_ALPHABET.indexOf(text[i + 1]!);
      if (c0 === -1 || c1 === -1) {
        throw new Error("Invalid character in Base45 string");
      }

      const val = c0 + c1 * 45;
      if (val > 255) {
        throw new Error("Base45 overflow: pair value exceeds 255");
      }
      bytes.push(val & 0xff);
    }
  }

  return new Uint8Array(bytes);
}
