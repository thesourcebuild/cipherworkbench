/**
 * PCG (Permuted Congruential Generator) - PCG64 / PCG-DXSM (Melissa O'Neill).
 * State-of-the-art fast statistical PRNG used in modern standard libraries (NumPy, etc.).
 */
const MASK_64 = 0xffffffffffffffffn;
const MULT_64 = 6364136223846793005n;

function readU64(b: Uint8Array, o = 0): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    const byte = o + i < b.length ? BigInt(b[o + i]!) : 0n;
    v = (v << 8n) | byte;
  }
  return v;
}

export class Pcg64 {
  private state = 0n;
  private inc = 1442695040888963407n | 1n; // Must be odd

  constructor(seed?: Uint8Array) {
    if (seed && seed.length >= 8) {
      this.state = readU64(seed, 0);
      if (seed.length >= 16) {
        this.inc = (readU64(seed, 8) << 1n) | 1n;
      }
    } else {
      this.state = 0x853c49e6748fea9bn;
    }
  }

  public nextUint64(): bigint {
    // Step state
    this.state = (this.state * MULT_64 + this.inc) & MASK_64;
    // DXSM output function
    const hi = this.state >> 32n;
    const lo = (this.state & 0xffffffffn) | 1n;
    let val = ((hi ^ (hi >> 16n)) * 0xda942042e4dd58b5n) & MASK_64;
    val = (val ^ (val >> 32n)) * lo;
    return val & MASK_64;
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

export function pcg64Crypt(key: Uint8Array, input: Uint8Array): Uint8Array {
  const pcg = new Pcg64(key);
  return pcg.crypt(input);
}
