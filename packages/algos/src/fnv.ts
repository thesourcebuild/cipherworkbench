/**
 * FNV-1 and FNV-1a, 32- and 64-bit, and Jenkins's one-at-a-time.
 *
 * Three non-cryptographic hashes with one thing in common: they are what a great deal of software
 * actually uses for hash tables, `switch` dispatch and content ids, so people arrive wanting to
 * reproduce one. FNV appears in DNS libraries, in Redis, in the Rust and Go standard libraries; joaat
 * is Jenkins's original one-at-a-time hash and is what the Bethesda file formats and a number of game
 * engines index with.
 *
 * Three things to know.
 *
 * **FNV-1 and FNV-1a differ only in the order of two operations.** FNV-1 multiplies then XORs each
 * byte; FNV-1a XORs then multiplies. That is the whole difference, it changes every output, and 1a is
 * the one to prefer because it avalanches the low bits of short inputs far better. Both are here
 * because both are deployed.
 *
 * **The digest is big-endian.** FNV is defined as an integer, so how it is spelled as bytes is a
 * convention; PHP, which is what most people compare against, emits it most significant byte first.
 *
 * **The 64-bit multiply needs a 64-bit multiply.** `u64.ts`'s `mul64` exists for exactly this: a
 * `bigint` per byte of input would be an order of magnitude slower and the split-halves version is
 * written once, with its own tests.
 */
import { mul64, u64, writeU64BE, xor64, type U64 } from "./u64";

/** The published FNV constants -- the offset basis and the prime, per width. */
const FNV1_32_INIT = 0x811c9dc5;
const FNV_32_PRIME = 0x01000193;
const FNV1_64_INIT = u64(0xcbf29ce4, 0x84222325);
const FNV_64_PRIME = u64(0x00000100, 0x000001b3);

export type FnvVariant = "fnv132" | "fnv1a32" | "fnv164" | "fnv1a64";

export interface SimpleHasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

/**
 * 32-bit FNV. `alternate` selects FNV-1a.
 *
 * `Math.imul` rather than `*`: a 32-bit multiply whose result exceeds 2^53 loses low bits in a double,
 * which is the one way to get FNV subtly wrong -- it would agree with a naive implementation on short
 * inputs and diverge on longer ones.
 */
class Fnv32 implements SimpleHasher {
  private state = FNV1_32_INIT;
  private done = false;

  constructor(private readonly alternate: boolean) {}

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("FNV: update after digest");
    let h = this.state;
    if (this.alternate) {
      for (const byte of chunk) h = Math.imul(h ^ byte, FNV_32_PRIME) >>> 0;
    } else {
      for (const byte of chunk) h = (Math.imul(h, FNV_32_PRIME) >>> 0) ^ byte;
    }
    this.state = h >>> 0;
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("FNV: digest called twice");
    this.done = true;
    const h = this.state;
    return Uint8Array.of((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff);
  }
}

class Fnv64 implements SimpleHasher {
  private readonly state: U64 = u64(FNV1_64_INIT.hi, FNV1_64_INIT.lo);
  private readonly byteValue: U64 = u64();
  private done = false;

  constructor(private readonly alternate: boolean) {}

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("FNV: update after digest");
    for (const byte of chunk) {
      this.byteValue.hi = 0;
      this.byteValue.lo = byte;
      if (this.alternate) {
        xor64(this.state, this.state, this.byteValue);
        mul64(this.state, this.state, FNV_64_PRIME);
      } else {
        mul64(this.state, this.state, FNV_64_PRIME);
        xor64(this.state, this.state, this.byteValue);
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("FNV: digest called twice");
    this.done = true;
    const out = new Uint8Array(8);
    writeU64BE(out, 0, this.state);
    return out;
  }
}

export function createFnv(variant: FnvVariant): SimpleHasher {
  switch (variant) {
    case "fnv132":
      return new Fnv32(false);
    case "fnv1a32":
      return new Fnv32(true);
    case "fnv164":
      return new Fnv64(false);
    case "fnv1a64":
      return new Fnv64(true);
    default:
      throw new Error(`Unknown FNV variant: ${String(variant)}`);
  }
}

export function fnv(data: Uint8Array, variant: FnvVariant): Uint8Array {
  const h = createFnv(variant);
  h.update(data);
  return h.digest();
}

/**
 * Jenkins's one-at-a-time hash.
 *
 * Three operations per byte and a three-step avalanche at the end. The avalanche is not optional --
 * without it the top bits barely move, and every implementation that calls itself joaat includes it.
 */
class Joaat implements SimpleHasher {
  private state = 0;
  private done = false;

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("joaat: update after digest");
    let h = this.state;
    for (const byte of chunk) {
      h = (h + byte) >>> 0;
      h = (h + (h << 10)) >>> 0;
      h = (h ^ (h >>> 6)) >>> 0;
    }
    this.state = h;
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("joaat: digest called twice");
    this.done = true;
    let h = this.state;
    h = (h + (h << 3)) >>> 0;
    h = (h ^ (h >>> 11)) >>> 0;
    h = (h + (h << 15)) >>> 0;
    return Uint8Array.of((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff);
  }
}

export function createJoaat(): SimpleHasher {
  return new Joaat();
}

export function joaat(data: Uint8Array): Uint8Array {
  const h = createJoaat();
  h.update(data);
  return h.digest();
}
