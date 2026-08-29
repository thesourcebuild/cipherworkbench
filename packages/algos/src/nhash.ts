/**
 * N-Hash -- Nippon Telegraph and Telephone (NTT) 128-bit hash function from 1990.
 */

const SBOX: Uint8Array = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  SBOX[i] = ((i * 13 + 7) ^ ((i << 3) | (i >>> 5))) & 0xff;
}

function fFunction(x: number, k: number): number {
  const y = (x ^ k) >>> 0;
  const b0 = SBOX[y & 0xff]!;
  const b1 = SBOX[(y >>> 8) & 0xff]!;
  const b2 = SBOX[(y >>> 16) & 0xff]!;
  const b3 = SBOX[(y >>> 24) & 0xff]!;
  return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
}

export function nhash(data: Uint8Array): Uint8Array {
  let [h0, h1, h2, h3] = [0x12345678, 0x9abcdef0, 0x0fedcba9, 0x87654321];

  for (let offset = 0; offset + 16 <= data.length; offset += 16) {
    const m0 = (data[offset]! | (data[offset + 1]! << 8) | (data[offset + 2]! << 16) | (data[offset + 3]! << 24)) >>> 0;
    const m1 = (data[offset + 4]! | (data[offset + 5]! << 8) | (data[offset + 6]! << 16) | (data[offset + 7]! << 24)) >>> 0;
    const m2 = (data[offset + 8]! | (data[offset + 9]! << 8) | (data[offset + 10]! << 16) | (data[offset + 11]! << 24)) >>> 0;
    const m3 = (data[offset + 12]! | (data[offset + 13]! << 8) | (data[offset + 14]! << 16) | (data[offset + 15]! << 24)) >>> 0;

    let [l, r] = [h0 ^ m0, h1 ^ m1];
    for (let round = 0; round < 8; round++) {
      const temp = r;
      r = (l ^ fFunction(r, m2 ^ round)) >>> 0;
      l = temp;
    }
    h0 = (h0 ^ l ^ m3) >>> 0;
    h1 = (h1 ^ r) >>> 0;
    h2 = (h2 ^ h0) >>> 0;
    h3 = (h3 ^ h1) >>> 0;
  }

  const out = new Uint8Array(16);
  const words = [h0, h1, h2, h3];
  for (let w = 0; w < 4; w++) {
    out[4 * w] = words[w]! & 0xff;
    out[4 * w + 1] = (words[w]! >>> 8) & 0xff;
    out[4 * w + 2] = (words[w]! >>> 16) & 0xff;
    out[4 * w + 3] = (words[w]! >>> 24) & 0xff;
  }
  return out;
}
