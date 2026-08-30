/**
 * basE91 -- Advanced High-Density Binary-to-ASCII Encoding (Joachim Henke, 2005).
 *
 * Implements:
 * - 91 printable characters alphabet.
 * - 13/14-bit variable bit accumulation into 2-character words.
 * - 123% overhead efficiency (more compact than Base64's 133%).
 */

export const BASE91_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';

export function base91Encode(data: Uint8Array): string {
  let queue = 0;
  let nBits = 0;
  let result = "";

  for (let i = 0; i < data.length; i++) {
    queue |= (data[i]! & 0xff) << nBits;
    nBits += 8;

    if (nBits > 13) {
      let val = queue & 8191; // 13 bits (2^13 - 1)
      if (val > 88) {
        queue >>= 13;
        nBits -= 13;
      } else {
        val = queue & 16383; // 14 bits (2^14 - 1)
        queue >>= 14;
        nBits -= 14;
      }
      result += BASE91_ALPHABET[val % 91]! + BASE91_ALPHABET[Math.floor(val / 91)]!;
    }
  }

  if (nBits > 0) {
    result += BASE91_ALPHABET[queue % 91]!;
    if (nBits > 7 || queue > 90) {
      result += BASE91_ALPHABET[Math.floor(queue / 91)]!;
    }
  }

  return result;
}

export function base91Decode(text: string): Uint8Array {
  const bytes: number[] = [];
  let queue = 0;
  let nBits = 0;
  let val = -1;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const c = BASE91_ALPHABET.indexOf(ch);
    if (c === -1) continue; // Skip whitespace or unknown

    if (val === -1) {
      val = c;
    } else {
      val += c * 91;
      queue |= val << nBits;
      nBits += (val & 8191) > 88 ? 13 : 14;

      while (nBits >= 8) {
        bytes.push(queue & 0xff);
        queue >>= 8;
        nBits -= 8;
      }
      val = -1;
    }
  }

  if (val !== -1) {
    bytes.push((queue | (val << nBits)) & 0xff);
  }

  return new Uint8Array(bytes);
}
