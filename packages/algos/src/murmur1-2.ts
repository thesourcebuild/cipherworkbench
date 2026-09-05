/**
 * MurmurHash1 & MurmurHash2:
 * 32-bit fast non-cryptographic hash functions designed by Austin Appleby.
 */

const u32 = (n: number) => n >>> 0;

export function murmurHash1(data: Uint8Array, seed = 0): number {
  const m = 0xc6a4a793;
  let h = u32(seed ^ Math.imul(data.length, m));

  const len = data.length;
  const nblocks = Math.floor(len / 4);

  const view = new DataView(data.buffer, data.byteOffset, data.length);
  for (let i = 0; i < nblocks; i++) {
    let k = view.getUint32(i * 4, true);
    k = Math.imul(k, m);
    k = u32(k ^ (k >>> 10));
    k = Math.imul(k, m);
    h = u32(Math.imul(h, m) ^ k);
  }

  const tail = len & 3;
  const offset = nblocks * 4;
  if (tail === 3) {
    h = u32(h ^ (data[offset + 2]! << 16));
  }
  if (tail >= 2) {
    h = u32(h ^ (data[offset + 1]! << 8));
  }
  if (tail >= 1) {
    h = u32(h ^ data[offset]!);
    h = Math.imul(h, m);
  }

  h = Math.imul(h, m);
  h = u32(h ^ (h >>> 10));
  h = Math.imul(h, m);
  h = u32(h ^ (h >>> 17));

  return u32(h);
}

export function murmurHash2(data: Uint8Array, seed = 0): number {
  const m = 0x5bd1e995;
  const r = 24;
  const len = data.length;
  let h = u32(seed ^ len);

  const nblocks = Math.floor(len / 4);
  const view = new DataView(data.buffer, data.byteOffset, data.length);

  for (let i = 0; i < nblocks; i++) {
    let k = view.getUint32(i * 4, true);
    k = Math.imul(k, m);
    k = u32(k ^ (k >>> r));
    k = Math.imul(k, m);

    h = Math.imul(h, m);
    h = u32(h ^ k);
  }

  const tail = len & 3;
  const offset = nblocks * 4;
  if (tail === 3) {
    h = u32(h ^ (data[offset + 2]! << 16));
  }
  if (tail >= 2) {
    h = u32(h ^ (data[offset + 1]! << 8));
  }
  if (tail >= 1) {
    h = u32(h ^ data[offset]!);
    h = Math.imul(h, m);
  }

  h = u32(h ^ (h >>> 13));
  h = Math.imul(h, m);
  h = u32(h ^ (h >>> 15));

  return u32(h);
}
