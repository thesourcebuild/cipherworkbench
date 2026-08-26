/**
 * XXH32, from the xxHash reference implementation (Yann Collet).
 *
 * A non-cryptographic hash. It is fast because it does almost nothing per byte — four
 * independent accumulators, one multiply-rotate-multiply each — and it offers no
 * resistance whatsoever to someone choosing an input. Collisions can be constructed
 * directly by inverting the mixing steps.
 *
 * `js-xxhash` implements XXH32 too, but one-shot only, which cannot back a streaming file
 * hash. See WHY-NOT-A-LIBRARY.md.
 */

const PRIME1 = 0x9e3779b1 | 0;
const PRIME2 = 0x85ebca77 | 0;
const PRIME3 = 0xc2b2ae3d | 0;
const PRIME4 = 0x27d4eb2f | 0;
const PRIME5 = 0x165667b1 | 0;

const STRIPE = 16;

/**
 * `Math.imul` rather than `*`.
 *
 * A 32-bit multiply overflows a double's 53-bit mantissa the moment both operands exceed
 * about 2^27, and xxHash's primes are all above 2^31 — so `a * PRIME1` silently produces
 * a rounded result and every subsequent bit is wrong. `Math.imul` performs the multiply
 * with C semantics and truncates to 32 bits, which is what the reference does.
 */
const mul = Math.imul;

const rotl = (v: number, bits: number): number => ((v << bits) | (v >>> (32 - bits))) | 0;

/** One accumulator lane absorbing one 32-bit input word. */
const round = (acc: number, input: number): number => mul(rotl((acc + mul(input, PRIME2)) | 0, 13), PRIME1);

export interface XxHash32Engine {
  update(chunk: Uint8Array): void;
  /** Unsigned 32-bit result. */
  digest(): number;
  digestBytes(): Uint8Array;
  reset(): void;
}

export function createXxHash32(seed = 0): XxHash32Engine {
  let v1 = 0;
  let v2 = 0;
  let v3 = 0;
  let v4 = 0;
  /** Total bytes seen. xxHash mixes the length in at finalisation, so it must be tracked. */
  let total = 0;
  const buffer = new Uint8Array(STRIPE);
  let buffered = 0;

  function init(): void {
    v1 = (seed + PRIME1 + PRIME2) | 0;
    v2 = (seed + PRIME2) | 0;
    v3 = seed | 0;
    v4 = (seed - PRIME1) | 0;
    total = 0;
    buffered = 0;
  }

  init();

  const readLE = (bytes: Uint8Array, offset: number): number =>
    (bytes[offset]! | (bytes[offset + 1]! << 8) | (bytes[offset + 2]! << 16) | (bytes[offset + 3]! << 24)) | 0;

  function absorb(bytes: Uint8Array, offset: number): void {
    v1 = round(v1, readLE(bytes, offset));
    v2 = round(v2, readLE(bytes, offset + 4));
    v3 = round(v3, readLE(bytes, offset + 8));
    v4 = round(v4, readLE(bytes, offset + 12));
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

    digest(): number {
      /**
       * Inputs shorter than one stripe skip the four accumulators entirely and start from
       * `seed + PRIME5`. That is not an optimisation — it is a different function for
       * short inputs, and getting the branch wrong makes everything under 16 bytes wrong
       * while everything above it stays correct.
       */
      let acc =
        total >= STRIPE
          ? (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) | 0
          : (seed + PRIME5) | 0;

      acc = (acc + total) | 0;

      // Tail: whole 4-byte words first, then single bytes.
      let offset = 0;
      let remaining = buffered;

      while (remaining >= 4) {
        acc = mul(rotl((acc + mul(readLE(buffer, offset), PRIME3)) | 0, 17), PRIME4);
        offset += 4;
        remaining -= 4;
      }

      while (remaining > 0) {
        acc = mul(rotl((acc + mul(buffer[offset]!, PRIME5)) | 0, 11), PRIME1);
        offset += 1;
        remaining -= 1;
      }

      // Final avalanche.
      acc = (acc ^ (acc >>> 15)) | 0;
      acc = mul(acc, PRIME2);
      acc = (acc ^ (acc >>> 13)) | 0;
      acc = mul(acc, PRIME3);
      acc = (acc ^ (acc >>> 16)) | 0;

      return acc >>> 0;
    },

    digestBytes(): Uint8Array {
      const value = this.digest();
      // Big-endian, matching how xxhsum prints it and how every other digest in this app
      // is laid out.
      return new Uint8Array([
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
      ]);
    },

    reset(): void {
      init();
    },
  };
}

export function xxhash32(data: Uint8Array, seed = 0): number {
  const engine = createXxHash32(seed);
  engine.update(data);
  return engine.digest();
}

export const XXHASH32_OUTPUT_LEN = 4;
