/**
 * MurmurHash3: the 32-bit x86 variant and both 128-bit ones.
 *
 * Austin Appleby's 2011 hash, and still the default non-cryptographic choice in a great deal of
 * software -- Cassandra and Elasticsearch route on it, Hadoop partitions with it, and PHP exposes the
 * three variants as `murmur3a`, `murmur3c` and `murmur3f`, which is where the names used here come
 * from. Not in `@noble` and not in `hash-wasm`.
 *
 * Four things to know.
 *
 * **The three variants are different functions, not truncations.** `murmur3a` is
 * MurmurHash3_x86_32, `murmur3c` is x86_128 and `murmur3f` is x64_128. The two 128-bit ones produce
 * different values for the same input by design -- one is built from four 32-bit lanes for 32-bit
 * machines, the other from two 64-bit lanes -- so neither is "the" 128-bit MurmurHash3.
 *
 * **Input is read little-endian and output is written big-endian.** That asymmetry is not a mistake:
 * Murmur's blocks are little-endian integers by specification, and every tool that prints a Murmur
 * digest as hex prints the resulting integers most significant byte first. Getting the output order
 * wrong produces a byte-reversed value that looks plausible.
 *
 * **`Math.imul` is mandatory.** Murmur multiplies 32-bit values by large constants; `a * b` in
 * JavaScript is a double multiply, which silently loses the low bits once the product passes 2^53. The
 * 64-bit variant needs `mul64` for the same reason.
 *
 * **The tail is mixed but not chained.** The final partial block gets the same multiply-rotate-multiply
 * treatment and is XORed into the state, but the per-block state mixing that follows a full block is
 * skipped. An implementation that ran the whole block path on a padded tail agrees with itself and
 * nothing else.
 */
import { add64, copy64, mul64, rotl64, set64, shr64, u64, writeU64BE, xor64, type U64 } from "./u64";

export type Murmur3Variant = "murmur3a" | "murmur3c" | "murmur3f";

export interface Murmur3Hasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

const rotl32 = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

/** MurmurHash3's 32-bit finalisation mix. */
function fmix32(h: number): number {
  let x = h;
  x = (x ^ (x >>> 16)) >>> 0;
  x = Math.imul(x, 0x85ebca6b) >>> 0;
  x = (x ^ (x >>> 13)) >>> 0;
  x = Math.imul(x, 0xc2b2ae35) >>> 0;
  return (x ^ (x >>> 16)) >>> 0;
}

const FMIX64_C1 = u64(0xff51afd7, 0xed558ccd);
const FMIX64_C2 = u64(0xc4ceb9fe, 0x1a85ec53);

/** The 64-bit finalisation mix, in place. */
function fmix64(h: U64, scratch: U64): void {
  shr64(scratch, h, 33);
  xor64(h, h, scratch);
  mul64(h, h, FMIX64_C1);
  shr64(scratch, h, 33);
  xor64(h, h, scratch);
  mul64(h, h, FMIX64_C2);
  shr64(scratch, h, 33);
  xor64(h, h, scratch);
}

const readU32LE = (bytes: Uint8Array, at: number): number =>
  (bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24)) >>> 0;

/**
 * A hasher that buffers `blockSize` bytes, because Murmur's block step is not resumable.
 *
 * Every variant here shares this shape: fill a block, mix it, keep the count, and deal with whatever
 * is left over at `digest()`. The base class holds that so the three variants differ only in their
 * mixing.
 */
abstract class Murmur implements Murmur3Hasher {
  protected readonly buffer: Uint8Array;
  protected buffered = 0;
  protected length = 0;
  private done = false;

  protected constructor(protected readonly blockSize: number) {
    this.buffer = new Uint8Array(blockSize);
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("MurmurHash3: update after digest");
    this.length += chunk.length;

    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(this.blockSize - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === this.blockSize) {
        this.mixBlock(this.buffer, 0);
        this.buffered = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("MurmurHash3: digest called twice");
    this.done = true;
    return this.finish();
  }

  protected abstract mixBlock(bytes: Uint8Array, at: number): void;
  protected abstract finish(): Uint8Array;
}

const C1_32 = 0xcc9e2d51;
const C2_32 = 0x1b873593;

/** MurmurHash3_x86_32, PHP's `murmur3a`. */
class Murmur3A extends Murmur {
  private h = 0;

  constructor() {
    super(4);
  }

  protected mixBlock(bytes: Uint8Array, at: number): void {
    let k = readU32LE(bytes, at);
    k = Math.imul(k, C1_32) >>> 0;
    k = rotl32(k, 15);
    k = Math.imul(k, C2_32) >>> 0;
    this.h = (this.h ^ k) >>> 0;
    this.h = rotl32(this.h, 13);
    this.h = (Math.imul(this.h, 5) + 0xe6546b64) >>> 0;
  }

  protected finish(): Uint8Array {
    if (this.buffered > 0) {
      // Tail bytes, little-endian into the low end of k.
      let k = 0;
      for (let i = 0; i < this.buffered; i++) k |= this.buffer[i]! << (8 * i);
      k = Math.imul(k >>> 0, C1_32) >>> 0;
      k = rotl32(k, 15);
      k = Math.imul(k, C2_32) >>> 0;
      this.h = (this.h ^ k) >>> 0;
    }

    const h = fmix32((this.h ^ this.length) >>> 0);
    return Uint8Array.of((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff);
  }
}

const C1_128 = 0x239b961b;
const C2_128 = 0xab0e9789;
const C3_128 = 0x38b34ae5;
const C4_128 = 0xa1e38b93;

/** MurmurHash3_x86_128, PHP's `murmur3c`: four 32-bit lanes. */
class Murmur3C extends Murmur {
  private h1 = 0;
  private h2 = 0;
  private h3 = 0;
  private h4 = 0;

  constructor() {
    super(16);
  }

  protected mixBlock(bytes: Uint8Array, at: number): void {
    let k1 = readU32LE(bytes, at);
    let k2 = readU32LE(bytes, at + 4);
    let k3 = readU32LE(bytes, at + 8);
    let k4 = readU32LE(bytes, at + 12);

    k1 = Math.imul(rotl32(Math.imul(k1, C1_128) >>> 0, 15), C2_128) >>> 0;
    this.h1 = (this.h1 ^ k1) >>> 0;
    this.h1 = rotl32(this.h1, 19);
    this.h1 = (this.h1 + this.h2) >>> 0;
    this.h1 = (Math.imul(this.h1, 5) + 0x561ccd1b) >>> 0;

    k2 = Math.imul(rotl32(Math.imul(k2, C2_128) >>> 0, 16), C3_128) >>> 0;
    this.h2 = (this.h2 ^ k2) >>> 0;
    this.h2 = rotl32(this.h2, 17);
    this.h2 = (this.h2 + this.h3) >>> 0;
    this.h2 = (Math.imul(this.h2, 5) + 0x0bcaa747) >>> 0;

    k3 = Math.imul(rotl32(Math.imul(k3, C3_128) >>> 0, 17), C4_128) >>> 0;
    this.h3 = (this.h3 ^ k3) >>> 0;
    this.h3 = rotl32(this.h3, 15);
    this.h3 = (this.h3 + this.h4) >>> 0;
    this.h3 = (Math.imul(this.h3, 5) + 0x96cd1c35) >>> 0;

    k4 = Math.imul(rotl32(Math.imul(k4, C4_128) >>> 0, 18), C1_128) >>> 0;
    this.h4 = (this.h4 ^ k4) >>> 0;
    this.h4 = rotl32(this.h4, 13);
    this.h4 = (this.h4 + this.h1) >>> 0;
    this.h4 = (Math.imul(this.h4, 5) + 0x32ac3b17) >>> 0;
  }

  protected finish(): Uint8Array {
    const tail = this.buffered;
    if (tail > 0) {
      const word = (index: number): number => {
        let k = 0;
        for (let i = 0; i < 4; i++) {
          const at = index * 4 + i;
          if (at < tail) k |= this.buffer[at]! << (8 * i);
        }
        return k >>> 0;
      };

      if (tail > 12) {
        const k4 = Math.imul(rotl32(Math.imul(word(3), C4_128) >>> 0, 18), C1_128) >>> 0;
        this.h4 = (this.h4 ^ k4) >>> 0;
      }
      if (tail > 8) {
        const k3 = Math.imul(rotl32(Math.imul(word(2), C3_128) >>> 0, 17), C4_128) >>> 0;
        this.h3 = (this.h3 ^ k3) >>> 0;
      }
      if (tail > 4) {
        const k2 = Math.imul(rotl32(Math.imul(word(1), C2_128) >>> 0, 16), C3_128) >>> 0;
        this.h2 = (this.h2 ^ k2) >>> 0;
      }
      const k1 = Math.imul(rotl32(Math.imul(word(0), C1_128) >>> 0, 15), C2_128) >>> 0;
      this.h1 = (this.h1 ^ k1) >>> 0;
    }

    let { h1, h2, h3, h4 } = this;
    h1 = (h1 ^ this.length) >>> 0;
    h2 = (h2 ^ this.length) >>> 0;
    h3 = (h3 ^ this.length) >>> 0;
    h4 = (h4 ^ this.length) >>> 0;

    h1 = (h1 + h2 + h3 + h4) >>> 0;
    h2 = (h2 + h1) >>> 0;
    h3 = (h3 + h1) >>> 0;
    h4 = (h4 + h1) >>> 0;

    h1 = fmix32(h1);
    h2 = fmix32(h2);
    h3 = fmix32(h3);
    h4 = fmix32(h4);

    h1 = (h1 + h2 + h3 + h4) >>> 0;
    h2 = (h2 + h1) >>> 0;
    h3 = (h3 + h1) >>> 0;
    h4 = (h4 + h1) >>> 0;

    const out = new Uint8Array(16);
    for (const [index, value] of [h1, h2, h3, h4].entries()) {
      out[index * 4] = (value >>> 24) & 0xff;
      out[index * 4 + 1] = (value >>> 16) & 0xff;
      out[index * 4 + 2] = (value >>> 8) & 0xff;
      out[index * 4 + 3] = value & 0xff;
    }
    return out;
  }
}

const C1_64 = u64(0x87c37b91, 0x114253d5);
const C2_64 = u64(0x4cf5ad43, 0x2745937f);

const readU64LEWord = (out: U64, bytes: Uint8Array, at: number): U64 =>
  set64(out, readU32LE(bytes, at + 4), readU32LE(bytes, at));

/** MurmurHash3_x64_128, PHP's `murmur3f`: two 64-bit lanes. */
class Murmur3F extends Murmur {
  private readonly h1 = u64();
  private readonly h2 = u64();
  private readonly k1 = u64();
  private readonly k2 = u64();
  private readonly scratch = u64();
  private readonly five = u64(0, 5);

  constructor() {
    super(16);
  }

  private mixLane(h: U64, other: U64, k: U64, first: boolean): void {
    if (first) {
      mul64(k, k, C1_64);
      rotl64(this.scratch, k, 31);
      copy64(k, this.scratch);
      mul64(k, k, C2_64);
    } else {
      mul64(k, k, C2_64);
      rotl64(this.scratch, k, 33);
      copy64(k, this.scratch);
      mul64(k, k, C1_64);
    }
    xor64(h, h, k);
    rotl64(this.scratch, h, first ? 27 : 31);
    copy64(h, this.scratch);
    add64(h, h, other);
    mul64(h, h, this.five);
    add64(h, h, first ? u64(0, 0x52dce729) : u64(0, 0x38495ab5));
  }

  protected mixBlock(bytes: Uint8Array, at: number): void {
    readU64LEWord(this.k1, bytes, at);
    readU64LEWord(this.k2, bytes, at + 8);
    this.mixLane(this.h1, this.h2, this.k1, true);
    this.mixLane(this.h2, this.h1, this.k2, false);
  }

  protected finish(): Uint8Array {
    const tail = this.buffered;
    if (tail > 0) {
      const lane = (offset: number): U64 => {
        const value = u64();
        for (let i = 0; i < 8; i++) {
          const at = offset + i;
          if (at >= tail) break;
          const byte = this.buffer[at]!;
          if (i < 4) value.lo = (value.lo | (byte << (8 * i))) >>> 0;
          else value.hi = (value.hi | (byte << (8 * (i - 4)))) >>> 0;
        }
        return value;
      };

      if (tail > 8) {
        const k2 = lane(8);
        mul64(k2, k2, C2_64);
        rotl64(this.scratch, k2, 33);
        copy64(k2, this.scratch);
        mul64(k2, k2, C1_64);
        xor64(this.h2, this.h2, k2);
      }
      const k1 = lane(0);
      mul64(k1, k1, C1_64);
      rotl64(this.scratch, k1, 31);
      copy64(k1, this.scratch);
      mul64(k1, k1, C2_64);
      xor64(this.h1, this.h1, k1);
    }

    const len = u64(0, this.length >>> 0);
    xor64(this.h1, this.h1, len);
    xor64(this.h2, this.h2, len);
    add64(this.h1, this.h1, this.h2);
    add64(this.h2, this.h2, this.h1);
    fmix64(this.h1, this.scratch);
    fmix64(this.h2, this.scratch);
    add64(this.h1, this.h1, this.h2);
    add64(this.h2, this.h2, this.h1);

    const out = new Uint8Array(16);
    writeU64BE(out, 0, this.h1);
    writeU64BE(out, 8, this.h2);
    return out;
  }
}

export function createMurmur3(variant: Murmur3Variant): Murmur3Hasher {
  switch (variant) {
    case "murmur3a":
      return new Murmur3A();
    case "murmur3c":
      return new Murmur3C();
    case "murmur3f":
      return new Murmur3F();
    default:
      throw new Error(`Unknown MurmurHash3 variant: ${String(variant)}`);
  }
}

export function murmur3(data: Uint8Array, variant: Murmur3Variant): Uint8Array {
  const h = createMurmur3(variant);
  h.update(data);
  return h.digest();
}
