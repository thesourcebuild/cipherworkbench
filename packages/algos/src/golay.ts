/**
 * Extended Binary Golay Code G_24:
 * [24, 12, 8] linear error-correcting code.
 * Corrects up to 3 bit errors, detects 4 errors in every 24-bit codeword.
 * Historically used on NASA's Voyager 1 and 2 Jupiter flyby imaging (1979-1981).
 */

// 12x12 B matrix for Golay G_24 (symmetric circulant based on quadratic residues mod 11)
const GOLAY_B: number[] = [
  0x7ff, // 0111 1111 1111
  0xee2, // 1110 1110 0010
  0xdc5, // 1101 1100 0101
  0xb8b, // 1011 1000 1011
  0xf16, // 1111 0001 0110
  0xe2d, // 1110 0010 1101
  0xc5b, // 1100 0101 1011
  0x8b7, // 1000 1011 0111
  0x96f, // 1001 0110 1111
  0xade, // 1010 1101 1110
  0xdbd, // 1101 1011 1101
  0xb7b, // 1011 0111 1011
];

function popcount(n: number): number {
  let count = 0;
  let v = n >>> 0;
  while (v > 0) {
    count += v & 1;
    v >>>= 1;
  }
  return count;
}

export function golayEncodeWord(m12: number): number {
  const m = m12 & 0xfff;
  let parity = 0;
  for (let i = 0; i < 12; i++) {
    if ((m >>> (11 - i)) & 1) {
      parity ^= GOLAY_B[i]!;
    }
  }
  // Codeword is 24 bits: 12 data bits (high) + 12 parity bits (low)
  return ((m << 12) | parity) >>> 0;
}

export function golayDecodeWord(c24: number): { data: number; correctedErrors: number; valid: boolean } {
  const word = c24 & 0xffffff;
  const rm = (word >>> 12) & 0xfff;
  const rp = word & 0xfff;

  // Compute syndrome s = rm * B ^ rp
  let s = rp;
  for (let i = 0; i < 12; i++) {
    if ((rm >>> (11 - i)) & 1) {
      s ^= GOLAY_B[i]!;
    }
  }

  if (s === 0) {
    return { data: rm, correctedErrors: 0, valid: true };
  }

  // Check if weight(s) <= 3 (errors purely in parity bits)
  if (popcount(s) <= 3) {
    return { data: rm, correctedErrors: popcount(s), valid: true };
  }

  // Check if weight(s ^ B[i]) <= 2 (one error in data bit i)
  for (let i = 0; i < 12; i++) {
    const diff = s ^ GOLAY_B[i]!;
    if (popcount(diff) <= 2) {
      const correctedData = rm ^ (1 << (11 - i));
      return { data: correctedData, correctedErrors: 1 + popcount(diff), valid: true };
    }
  }

  // Compute second syndrome sB = s * B
  let sB = 0;
  for (let i = 0; i < 12; i++) {
    if ((s >>> (11 - i)) & 1) {
      sB ^= GOLAY_B[i]!;
    }
  }

  // Check if weight(sB) <= 3 (errors purely in message bits)
  if (popcount(sB) <= 3) {
    const correctedData = rm ^ sB;
    return { data: correctedData, correctedErrors: popcount(sB), valid: true };
  }

  // Check if weight(sB ^ B[i]) <= 2
  for (let i = 0; i < 12; i++) {
    const diff = sB ^ GOLAY_B[i]!;
    if (popcount(diff) <= 2) {
      const correctedData = rm ^ diff;
      return { data: correctedData, correctedErrors: 1 + popcount(diff), valid: true };
    }
  }

  // More than 3 bit errors (detectable up to 4 errors, but uncorrectable)
  return { data: rm, correctedErrors: -1, valid: false };
}

export function golayEncode(data: Uint8Array): Uint8Array {
  // Pack bytes into 12-bit nibbles -> encode to 24-bit (3-byte) words
  const words: number[] = [];
  let bitBuf = 0;
  let bitCount = 0;

  for (let i = 0; i < data.length; i++) {
    bitBuf = (bitBuf << 8) | data[i]!;
    bitCount += 8;
    while (bitCount >= 12) {
      bitCount -= 12;
      const m12 = (bitBuf >>> bitCount) & 0xfff;
      words.push(golayEncodeWord(m12));
    }
  }
  if (bitCount > 0) {
    const m12 = (bitBuf << (12 - bitCount)) & 0xfff;
    words.push(golayEncodeWord(m12));
  }

  const out = new Uint8Array(words.length * 3);
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    out[i * 3] = (w >>> 16) & 0xff;
    out[i * 3 + 1] = (w >>> 8) & 0xff;
    out[i * 3 + 2] = w & 0xff;
  }
  return out;
}

export function golayDecode(encoded: Uint8Array, originalLength?: number): Uint8Array {
  const numWords = Math.floor(encoded.length / 3);
  const dataWords: number[] = [];

  for (let i = 0; i < numWords; i++) {
    const w = (encoded[i * 3]! << 16) | (encoded[i * 3 + 1]! << 8) | encoded[i * 3 + 2]!;
    const decoded = golayDecodeWord(w);
    dataWords.push(decoded.data);
  }

  // Unpack 12-bit words into 8-bit bytes
  const out: number[] = [];
  let bitBuf = 0;
  let bitCount = 0;

  for (let i = 0; i < dataWords.length; i++) {
    bitBuf = (bitBuf << 12) | dataWords[i]!;
    bitCount += 12;
    while (bitCount >= 8) {
      bitCount -= 8;
      out.push((bitBuf >>> bitCount) & 0xff);
    }
  }

  if (originalLength !== undefined && out.length > originalLength) {
    return new Uint8Array(out.slice(0, originalLength));
  }
  return new Uint8Array(out);
}
