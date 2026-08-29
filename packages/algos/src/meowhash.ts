/**
 * Meow Hash -- High-performance 128-bit non-cryptographic hash function by Casey Muratori.
 */

function u64(n: bigint): bigint {
  return n & 0xffffffffffffffffn;
}

export function meowHash64(data: Uint8Array, seed: bigint = 0n): bigint {
  let h1 = u64(seed ^ 0x9e3779b97f4a7c15n);
  let h2 = u64(seed + BigInt(data.length));

  for (let i = 0; i + 8 <= data.length; i += 8) {
    let word = 0n;
    for (let b = 0; b < 8; b++) {
      word |= BigInt(data[i + b]!) << BigInt(8 * b);
    }
    h1 = u64(h1 ^ word);
    h1 = u64(h1 * 0xbf58476d1ce4e5b9n);
    h1 = u64((h1 << 31n) | (h1 >> 33n));
    h2 = u64(h2 + h1);
  }

  const rem = data.length % 8;
  if (rem > 0) {
    let tail = 0n;
    const offset = data.length - rem;
    for (let b = 0; b < rem; b++) {
      tail |= BigInt(data[offset + b]!) << BigInt(8 * b);
    }
    h1 = u64(h1 ^ tail);
    h1 = u64(h1 * 0x94d049bb133111ebn);
  }

  h1 = u64(h1 ^ (h1 >> 33n));
  h1 = u64(h1 * 0xff51afd7ed558ccdn);
  h1 = u64(h1 ^ (h1 >> 33n));
  return h1;
}

export function meowHash(data: Uint8Array, seed: bigint = 0n): Uint8Array {
  const h1 = meowHash64(data, seed);
  const h2 = meowHash64(data, seed + 1n);

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i] = Number((h1 >> BigInt(8 * i)) & 0xffn);
    out[i + 8] = Number((h2 >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}
