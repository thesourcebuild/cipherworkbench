/**
 * Adler-32, from RFC 1950 §9 (zlib).
 *
 * Not a CRC and not a hash — two running sums mod 65521, chosen in 1995 because it
 * was faster than a CRC on the hardware of the day. It is weaker than CRC-32 at the
 * job both are used for: on short inputs the low half barely mixes, so Adler-32 has
 * poor collision behaviour on a few hundred bytes, which is exactly the regime a lot
 * of code uses it in.
 */

/** Largest prime below 2^16. */
const MOD_ADLER = 65521;

/**
 * How many bytes can be summed before a reduction is needed.
 *
 * `b` grows by up to `a` per byte and `a` by up to 255, so with both starting under
 * 65521 the pair stays inside a double's exact-integer range for 5552 bytes. This is
 * zlib's own constant, and it is what makes the inner loop division-free.
 */
const NMAX = 5552;

export interface Adler32Engine {
  update(chunk: Uint8Array): void;
  digest(): number;
  digestBytes(): Uint8Array;
  reset(): void;
}

export function createAdler32(): Adler32Engine {
  let a = 1;
  let b = 0;

  return {
    update(chunk: Uint8Array): void {
      let offset = 0;
      let remaining = chunk.length;

      while (remaining > 0) {
        const block = Math.min(remaining, NMAX);
        const end = offset + block;
        for (let i = offset; i < end; i++) {
          a += chunk[i]!;
          b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
        offset = end;
        remaining -= block;
      }
    },

    digest(): number {
      // `* 65536` rather than `<< 16`: b can reach 65520, and shifting that left by
      // 16 overflows into the sign bit.
      return (b * 65536 + a) >>> 0;
    },

    digestBytes(): Uint8Array {
      const value = this.digest();
      return new Uint8Array([
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
      ]);
    },

    reset(): void {
      a = 1;
      b = 0;
    },
  };
}

export function adler32(data: Uint8Array): number {
  const engine = createAdler32();
  engine.update(data);
  return engine.digest();
}
