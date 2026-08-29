/**
 * Komihash -- Ultra-fast 64-bit non-cryptographic hash function by Aleksey Vaneev.
 */

function u64(n: bigint): bigint {
  return n & 0xffffffffffffffffn;
}

function komiRound(seed1: bigint, seed2: bigint, word1: bigint, word2: bigint): [bigint, bigint] {
  let s1 = u64(seed1 ^ word1);
  let s2 = u64(seed2 ^ word2);
  const p1 = s1 * 0x243f6a8885a308d3n;
  const p2 = s2 * 0x452821e638d01377n;
  s1 = u64(s1 ^ (p2 >> 32n));
  s2 = u64(s2 ^ (p1 >> 32n));
  return [s1, s2];
}

export function komihash64(data: Uint8Array, seed: bigint = 0n): bigint {
  let [s1, s2] = [u64(seed ^ 0x243f6a8885a308d3n), u64(seed ^ 0x452821e638d01377n)];

  let offset = 0;
  while (offset + 16 <= data.length) {
    let w1 = 0n, w2 = 0n;
    for (let i = 0; i < 8; i++) {
      w1 |= BigInt(data[offset + i]!) << BigInt(8 * i);
      w2 |= BigInt(data[offset + 8 + i]!) << BigInt(8 * i);
    }
    [s1, s2] = komiRound(s1, s2, w1, w2);
    offset += 16;
  }

  // Handle remaining bytes
  let rem1 = 0n, rem2 = 0n;
  const rem = data.length - offset;
  for (let i = 0; i < Math.min(8, rem); i++) {
    rem1 |= BigInt(data[offset + i]!) << BigInt(8 * i);
  }
  for (let i = 8; i < rem; i++) {
    rem2 |= BigInt(data[offset + i]!) << BigInt(8 * (i - 8));
  }
  [s1, s2] = komiRound(s1, s2, rem1, rem2);

  let finalHash = u64(s1 ^ s2 ^ BigInt(data.length));
  finalHash = u64(finalHash * 0x13198a2e03707344n);
  finalHash = u64(finalHash ^ (finalHash >> 32n));
  return finalHash;
}

export function komihash(data: Uint8Array, seed: bigint = 0n): Uint8Array {
  const h = komihash64(data, seed);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = Number((h >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}
