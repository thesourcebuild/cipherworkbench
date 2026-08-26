import {
  add64,
  copy64,
  hex64,
  mul64,
  readU64LE,
  rotl64,
  set64,
  u64,
  writeU64BE,
  xor64,
  xorShr64,
  type U64,
} from "./u64";

/**
 * XXH64, from the xxHash reference implementation.
 *
 * Nothing on npm offers this in pure JavaScript with a streaming API — `xxhashjs` is
 * CommonJS from 2018 with a `cuint` dependency, and `js-xxhash` is XXH32 only. See
 * WHY-NOT-A-LIBRARY.md.
 *
 * Built on `./u64` rather than `BigInt`. xxHash exists to be fast, and a `BigInt`
 * implementation allocates on every one of the four multiplies per 32-byte stripe, which
 * would cost most of the point of choosing it. The 64-bit multiply lives in one tested
 * place instead of being open-coded here.
 *
 * Non-cryptographic. Fast, well-distributed, and trivially forgeable.
 */

const PRIME1 = /* @__PURE__ */ u64(0x9e3779b1, 0x85ebca87);
const PRIME2 = /* @__PURE__ */ u64(0xc2b2ae3d, 0x27d4eb4f);
const PRIME3 = /* @__PURE__ */ u64(0x165667b1, 0x9e3779f9);
const PRIME4 = /* @__PURE__ */ u64(0x85ebca77, 0xc2b2ae63);
const PRIME5 = /* @__PURE__ */ u64(0x27d4eb2f, 0x165667c5);

const STRIPE = 32;

// Scratch, reused across every call. Not reentrant, which is fine: an engine instance is
// single-threaded and none of these escape.
const t1: U64 = u64();
const t2: U64 = u64();
const lane: U64 = u64();

/** `acc = rotl64(acc + input * PRIME2, 31) * PRIME1` — the core mixing step. */
function round(acc: U64, input: U64): void {
  mul64(t1, input, PRIME2);
  add64(t1, acc, t1);
  rotl64(t1, t1, 31);
  mul64(acc, t1, PRIME1);
}

/**
 * `round(0, input)` — the mixing step with a zero accumulator, written into `out`.
 *
 * Its own function rather than a call to `round` with a zeroed target, because the two
 * share the `t1` scratch: zeroing `t1` and then passing it as the accumulator meant the
 * first multiply overwrote the zero, and `acc + input*P2` became `2 * input*P2`. Adding
 * zero is a no-op, so the correct version simply omits it.
 */
function roundFromZero(out: U64, input: U64): void {
  mul64(out, input, PRIME2);
  rotl64(out, out, 31);
  mul64(out, out, PRIME1);
}

/**
 * `acc = (acc ^ round(0, v)) * PRIME1 + PRIME4`.
 *
 * Only used when the input reached at least one full stripe. Folding each of the four
 * accumulators in separately is what stops two lanes swapping places from going unnoticed.
 */
function mergeRound(acc: U64, v: U64): void {
  roundFromZero(t2, v);
  xor64(acc, acc, t2);
  mul64(acc, acc, PRIME1);
  add64(acc, acc, PRIME4);
}

export interface XxHash64Engine {
  update(chunk: Uint8Array): void;
  /** The 64-bit result. `BigInt` at the boundary only — one allocation per digest. */
  digest(): bigint;
  digestBytes(): Uint8Array;
  digestHex(): string;
  reset(): void;
}

export function createXxHash64(seed: bigint | number = 0): XxHash64Engine {
  const seed64 = u64();
  const seedBig = typeof seed === "bigint" ? seed & 0xffffffffffffffffn : BigInt(seed >>> 0);
  seed64.hi = Number((seedBig >> 32n) & 0xffffffffn) >>> 0;
  seed64.lo = Number(seedBig & 0xffffffffn) >>> 0;

  const v1 = u64();
  const v2 = u64();
  const v3 = u64();
  const v4 = u64();
  const acc = u64();

  let total = 0;
  const buffer = new Uint8Array(STRIPE);
  let buffered = 0;

  function init(): void {
    // v1 = seed + P1 + P2; v2 = seed + P2; v3 = seed; v4 = seed - P1
    add64(v1, seed64, PRIME1);
    add64(v1, v1, PRIME2);
    add64(v2, seed64, PRIME2);
    copy64(v3, seed64);
    // Subtraction as two's-complement addition, so no sub64 is needed anywhere.
    set64(t1, ~PRIME1.hi >>> 0, ~PRIME1.lo >>> 0);
    add64(t1, t1, u64(0, 1));
    add64(v4, seed64, t1);

    total = 0;
    buffered = 0;
  }

  init();

  /** Reads one little-endian 64-bit word into the shared `lane` scratch, without allocating. */
  function loadLane(bytes: Uint8Array, offset: number): U64 {
    return set64(
      lane,
      (bytes[offset + 4]! |
        (bytes[offset + 5]! << 8) |
        (bytes[offset + 6]! << 16) |
        (bytes[offset + 7]! << 24)) >>>
        0,
      (bytes[offset]! |
        (bytes[offset + 1]! << 8) |
        (bytes[offset + 2]! << 16) |
        (bytes[offset + 3]! << 24)) >>>
        0,
    );
  }

  function absorb(bytes: Uint8Array, offset: number): void {
    round(v1, loadLane(bytes, offset));
    round(v2, loadLane(bytes, offset + 8));
    round(v3, loadLane(bytes, offset + 16));
    round(v4, loadLane(bytes, offset + 24));
  }

  return {
    update(chunk: Uint8Array): void {
      total += chunk.length;
      let offset = 0;

      if (buffered > 0) {
        const take = Math.min(STRIPE - buffered, chunk.length);
        buffer.set(chunk.subarray(0, take), buffered);
        buffered += take;
        offset = take;
        if (buffered < STRIPE) return;
        absorb(buffer, 0);
        buffered = 0;
      }

      while (offset + STRIPE <= chunk.length) {
        absorb(chunk, offset);
        offset += STRIPE;
      }

      if (offset < chunk.length) {
        buffered = chunk.length - offset;
        buffer.set(chunk.subarray(offset), 0);
      }
    },

    digest(): bigint {
      if (total >= STRIPE) {
        // acc = rotl(v1,1) + rotl(v2,7) + rotl(v3,12) + rotl(v4,18)
        rotl64(acc, v1, 1);
        rotl64(t1, v2, 7);
        add64(acc, acc, t1);
        rotl64(t1, v3, 12);
        add64(acc, acc, t1);
        rotl64(t1, v4, 18);
        add64(acc, acc, t1);

        mergeRound(acc, v1);
        mergeRound(acc, v2);
        mergeRound(acc, v3);
        mergeRound(acc, v4);
      } else {
        // Short inputs never touch the accumulators — a different function, not a
        // shortcut, and the branch everything under 32 bytes depends on.
        add64(acc, seed64, PRIME5);
      }

      add64(acc, acc, set64(t1, Math.floor(total / 0x100000000) >>> 0, total >>> 0));

      let offset = 0;
      let remaining = buffered;

      // Tail: 8-byte words, then a 4-byte word, then single bytes. Each stage has its own
      // rotation and prime pair.
      while (remaining >= 8) {
        roundFromZero(t2, readU64LE(buffer, offset));
        xor64(acc, acc, t2);
        rotl64(acc, acc, 27);
        mul64(acc, acc, PRIME1);
        add64(acc, acc, PRIME4);

        offset += 8;
        remaining -= 8;
      }

      if (remaining >= 4) {
        const word =
          (buffer[offset]! |
            (buffer[offset + 1]! << 8) |
            (buffer[offset + 2]! << 16) |
            (buffer[offset + 3]! << 24)) >>>
          0;
        // Zero-extended to 64 bits before the multiply.
        mul64(t1, set64(t1, 0, word), PRIME1);
        xor64(acc, acc, t1);
        rotl64(acc, acc, 23);
        mul64(acc, acc, PRIME2);
        add64(acc, acc, PRIME3);

        offset += 4;
        remaining -= 4;
      }

      while (remaining > 0) {
        mul64(t1, set64(t1, 0, buffer[offset]!), PRIME5);
        xor64(acc, acc, t1);
        rotl64(acc, acc, 11);
        mul64(acc, acc, PRIME1);

        offset += 1;
        remaining -= 1;
      }

      // Final avalanche.
      xorShr64(acc, acc, 33);
      mul64(acc, acc, PRIME2);
      xorShr64(acc, acc, 29);
      mul64(acc, acc, PRIME3);
      xorShr64(acc, acc, 32);

      return (BigInt(acc.hi) << 32n) | BigInt(acc.lo);
    },

    digestBytes(): Uint8Array {
      const value = this.digest();
      const out = new Uint8Array(8);
      writeU64BE(out, 0, {
        hi: Number((value >> 32n) & 0xffffffffn) >>> 0,
        lo: Number(value & 0xffffffffn) >>> 0,
      });
      return out;
    },

    digestHex(): string {
      const value = this.digest();
      return hex64({
        hi: Number((value >> 32n) & 0xffffffffn) >>> 0,
        lo: Number(value & 0xffffffffn) >>> 0,
      });
    },

    reset(): void {
      init();
    },
  };
}

export function xxhash64(data: Uint8Array, seed: bigint | number = 0): bigint {
  const engine = createXxHash64(seed);
  engine.update(data);
  return engine.digest();
}

export const XXHASH64_OUTPUT_LEN = 8;
