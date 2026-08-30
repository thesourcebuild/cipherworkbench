/**
 * Proquints -- PRONounceable QUINTuplets (Daniel Wilkerson, 2009).
 *
 * Implements:
 * - 16-bit word to C-V-C-V-C pronounceable quintuplet conversion.
 * - Consonants (4 bits): b d f g h j k l m n p r s t v z
 * - Vowels (2 bits): a i o u
 * - Bidirectional binary to proquint string encoding and decoding.
 */

const CONSONANTS = "bdfghjklmnprstvz";
const VOWELS = "aiou";

export function uint16ToProquint(val: number): string {
  const c1 = CONSONANTS[(val >> 12) & 0x0f]!;
  const v1 = VOWELS[(val >> 10) & 0x03]!;
  const c2 = CONSONANTS[(val >> 6) & 0x0f]!;
  const v2 = VOWELS[(val >> 4) & 0x03]!;
  const c3 = CONSONANTS[val & 0x0f]!;

  return `${c1}${v1}${c2}${v2}${c3}`;
}

export function proquintToUint16(word: string): number {
  if (word.length !== 5) throw new Error(`Invalid proquint word length: "${word}" (expected 5 characters)`);

  const c1 = CONSONANTS.indexOf(word[0]!.toLowerCase());
  const v1 = VOWELS.indexOf(word[1]!.toLowerCase());
  const c2 = CONSONANTS.indexOf(word[2]!.toLowerCase());
  const v2 = VOWELS.indexOf(word[3]!.toLowerCase());
  const c3 = CONSONANTS.indexOf(word[4]!.toLowerCase());

  if (c1 === -1 || v1 === -1 || c2 === -1 || v2 === -1 || c3 === -1) {
    throw new Error(`Invalid proquint character in word: "${word}"`);
  }

  return (c1 << 12) | (v1 << 10) | (c2 << 6) | (v2 << 4) | c3;
}

export function proquintsEncode(data: Uint8Array): string {
  if (data.length === 0) return "";

  const words: string[] = [];
  for (let i = 0; i < data.length; i += 2) {
    const b0 = data[i]!;
    const b1 = i + 1 < data.length ? data[i + 1]! : 0;
    const val = (b0 << 8) | b1;
    words.push(uint16ToProquint(val));
  }

  return words.join("-");
}

export function proquintsDecode(text: string): Uint8Array {
  const clean = text.trim().toLowerCase();
  if (clean.length === 0) return new Uint8Array(0);

  const words = clean.split(/[-:\s]+/);
  const out = new Uint8Array(words.length * 2);

  for (let i = 0; i < words.length; i++) {
    const val = proquintToUint16(words[i]!);
    out[i * 2] = (val >> 8) & 0xff;
    out[i * 2 + 1] = val & 0xff;
  }

  return out;
}
