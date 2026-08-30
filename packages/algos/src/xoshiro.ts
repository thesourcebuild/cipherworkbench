/**
 * Xoshiro256++ and Xoroshiro128++ Fast High-Dimensional PRNGs (Blackman & Vigna, 2019).
 * Period 2^256-1 with excellent statistical properties across all tests (BigCrush).
 */
const MASK_64 = 0xffffffffffffffffn;

function readU64(b: Uint8Array, o = 0): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    const byte = o + i < b.length ? BigInt(b[o + i]!) : 0n;
    v = (v << 8n) | byte;
  }
  return v;
}

function rotl64(x: bigint, k: bigint): bigint {
  return ((x << k) | (x >> (64n - k))) & MASK_64;
}

export class Xoshiro256PlusPlus {
  private s: [bigint, bigint, bigint, bigint];

  constructor(seed?: Uint8Array) {
    if (seed && seed.length >= 32) {
      this.s = [
        readU64(seed, 0),
        readU64(seed, 8),
        readU64(seed, 16),
        readU64(seed, 24),
      ];
    } else {
      this.s = [
        0x1835677b1n,
        0x203598712n,
        0x381273918n,
        0x491823719n,
      ];
    }
  }

  public nextUint64(): bigint {
    const result = (rotl64((this.s[0] + this.s[3]) & MASK_64, 23n) + this.s[0]) & MASK_64;
    const t = (this.s[1] << 17n) & MASK_64;

    this.s[2] ^= this.s[0];
    this.s[3] ^= this.s[1];
    this.s[1] ^= this.s[2];
    this.s[0] ^= this.s[3];

    this.s[2] ^= t;
    this.s[3] = rotl64(this.s[3], 45n);

    return result;
  }

  public crypt(input: Uint8Array): Uint8Array {
    const out = new Uint8Array(input.length);
    let word = 0n;
    for (let i = 0; i < input.length; i++) {
      if ((i % 8) === 0) {
        word = this.nextUint64();
      }
      const byte = Number((word >> BigInt((i % 8) * 8)) & 0xffn);
      out[i] = input[i]! ^ byte;
    }
    return out;
  }
}

export function xoshiro256Crypt(key: Uint8Array, input: Uint8Array): Uint8Array {
  const gen = new Xoshiro256PlusPlus(key);
  return gen.crypt(input);
}
