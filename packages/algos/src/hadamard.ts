/**
 * Walsh-Hadamard Error-Correcting Code:
 * [2^m, m+1, 2^(m-1)] linear error-correcting code.
 * Decoded via Fast Walsh-Hadamard Transform (FWHT) maximum-likelihood correlation.
 * Historically used on NASA's Mariner 9 Mars mission (1971) with order 32 [32, 6, 16].
 */

export function hadamardEncodeWord(msgBits: number, order = 16): Uint8Array {
  const codeword = new Uint8Array(order);
  const m = Math.log2(order);
  const data = msgBits & ((1 << (m + 1)) - 1);
  const invert = (data >>> m) & 1;
  const index = data & ((1 << m) - 1);

  for (let i = 0; i < order; i++) {
    // Sylvester matrix entry H[index, i]
    let dot = 0;
    for (let bit = 0; bit < m; bit++) {
      if (((index >>> bit) & 1) && ((i >>> bit) & 1)) {
        dot ^= 1;
      }
    }
    const val = dot ^ invert;
    codeword[i] = val ? 1 : 0;
  }
  return codeword;
}

export function hadamardDecodeWord(codeword: Uint8Array, order = 16): number {
  const m = Math.log2(order);
  // Fast Walsh-Hadamard Transform
  // Map 0 -> +1, 1 -> -1
  const a = new Float64Array(order);
  for (let i = 0; i < order; i++) {
    a[i] = codeword[i] ? -1 : 1;
  }

  for (let len = 1; len < order; len <<= 1) {
    for (let i = 0; i < order; i += 2 * len) {
      for (let j = 0; j < len; j++) {
        const u = a[i + j]!;
        const v = a[i + len + j]!;
        a[i + j] = u + v;
        a[i + len + j] = u - v;
      }
    }
  }

  // Find max correlation
  let maxVal = -1;
  let bestIndex = 0;
  let bestSign = 0;

  for (let i = 0; i < order; i++) {
    const val = Math.abs(a[i]!);
    if (val > maxVal) {
      maxVal = val;
      bestIndex = i;
      bestSign = a[i]! < 0 ? 1 : 0;
    }
  }

  return (bestSign << m) | bestIndex;
}

export function hadamardEncode(data: Uint8Array, order = 16): Uint8Array {
  const m = Math.log2(order);
  const k = m + 1; // bits per codeword
  const codewords: Uint8Array[] = [];

  let bitBuf = 0;
  let bitCount = 0;

  for (let i = 0; i < data.length; i++) {
    bitBuf = (bitBuf << 8) | data[i]!;
    bitCount += 8;
    while (bitCount >= k) {
      bitCount -= k;
      const msg = (bitBuf >>> bitCount) & ((1 << k) - 1);
      codewords.push(hadamardEncodeWord(msg, order));
    }
  }
  if (bitCount > 0) {
    const msg = (bitBuf << (k - bitCount)) & ((1 << k) - 1);
    codewords.push(hadamardEncodeWord(msg, order));
  }

  // Pack bit codewords into bytes
  const totalBits = codewords.length * order;
  const out = new Uint8Array(Math.ceil(totalBits / 8));
  let bitPos = 0;

  for (const cw of codewords) {
    for (let i = 0; i < order; i++) {
      if (cw[i]) {
        out[bitPos >>> 3]! |= 1 << (7 - (bitPos & 7));
      }
      bitPos++;
    }
  }

  return out;
}

export function hadamardDecode(encoded: Uint8Array, order = 16, originalLength?: number): Uint8Array {
  const m = Math.log2(order);
  const k = m + 1;
  const totalBits = encoded.length * 8;
  const numCodewords = Math.floor(totalBits / order);

  const decodedWords: number[] = [];
  let bitPos = 0;

  for (let c = 0; c < numCodewords; c++) {
    const cw = new Uint8Array(order);
    for (let i = 0; i < order; i++) {
      cw[i] = (encoded[bitPos >>> 3]! >>> (7 - (bitPos & 7))) & 1;
      bitPos++;
    }
    decodedWords.push(hadamardDecodeWord(cw, order));
  }

  // Unpack k-bit words to bytes
  const out: number[] = [];
  let bitBuf = 0;
  let bitCount = 0;

  for (const word of decodedWords) {
    bitBuf = (bitBuf << k) | word;
    bitCount += k;
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
