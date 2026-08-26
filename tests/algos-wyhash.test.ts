import { describe, expect, it } from "vitest";

import { WYHASH_SECRET, wyhash, wyhashBytes } from "../packages/algos/src/index";

const ascii = (text: string): Uint8Array => Uint8Array.from([...text].map((c) => c.charCodeAt(0)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/**
 * wyhash final 3. Its successor rapidhash has its own file, `tests/algos-rapidhash.test.ts`, because
 * that turned out to be four published versions rather than one.
 */

/**
 * The reference's own seven, via Zig's standard library.
 *
 * Seed is the row index, which is what `test_vector.cpp` does. The lengths cross all four of wyhash's
 * branches -- under 4 bytes, 4 to 16, the 16-byte tail loop, and the three-lane 48-byte body -- which
 * is why seven values are worth more here than seventy at one length.
 */
const WYHASH_VECTORS: readonly { seed: bigint; expected: bigint; input: string }[] = [
  { seed: 0n, expected: 0x409638ee2bde459n, input: "" },
  { seed: 1n, expected: 0xa8412d091b5fe0a9n, input: "a" },
  { seed: 2n, expected: 0x32dd92e4b2915153n, input: "abc" },
  { seed: 3n, expected: 0x8619124089a3a16bn, input: "message digest" },
  { seed: 4n, expected: 0x7a43afb61d7f5f40n, input: "abcdefghijklmnopqrstuvwxyz" },
  {
    seed: 5n,
    expected: 0xff42329b90e50d58n,
    input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  },
  {
    seed: 6n,
    expected: 0xc39cab13b115aad3n,
    input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
  },
];

describe("wyhash final 3", () => {
  it.each(WYHASH_VECTORS)(
    "matches the reference vector at seed $seed",
    ({ seed, expected, input }) => {
      expect(wyhash(ascii(input), seed)).toBe(expected);
    },
  );

  /**
   * The seven vectors reach every branch, and this asserts that rather than leaving it as a claim in
   * a comment -- if someone trims the fixture, the coverage argument should fail with it.
   */
  it("covers all four length branches", () => {
    const lengths = WYHASH_VECTORS.map((v) => v.input.length);
    expect(lengths.some((n) => n < 4), "the under-4 path").toBe(true);
    expect(lengths.some((n) => n >= 4 && n <= 16), "the 4-to-16 path").toBe(true);
    expect(lengths.some((n) => n > 16 && n <= 48), "the 16-byte tail loop").toBe(true);
    expect(lengths.some((n) => n > 48), "the three-lane body").toBe(true);
  });

  it("declares final 3's secret, not final 4's", () => {
    // Final 4 begins 0x2d358dccaa6c78a5 and produces unrelated output. The two are different
    // functions and only this one has a reachable published vector.
    expect(WYHASH_SECRET[0]).toBe(0xa0761d6478bd642fn);
    expect(WYHASH_SECRET).toHaveLength(4);
  });

  it("changes with the seed", () => {
    const message = ascii("the same message");
    expect(wyhash(message, 0n)).not.toBe(wyhash(message, 1n));
    // And a large seed is not silently truncated, which a number-typed control would do.
    expect(wyhash(message, 0xffffffffffffffffn)).not.toBe(wyhash(message, 0n));
  });

  it("returns eight bytes, most significant first", () => {
    const value = wyhash(ascii("abc"), 2n);
    expect(hex(wyhashBytes(ascii("abc"), 2n))).toBe(value.toString(16).padStart(16, "0"));
  });

  /**
   * The three-byte read double-counts a byte for a two-byte input, and that is the reference's own
   * definition rather than the bug this repo records elsewhere.
   *
   * `read3` is `p[0] << 16 | p[k >> 1] << 8 | p[k - 1]`, so at k = 2 the middle and last term are both
   * `p[1]`. That means the two-byte inputs `ab` and `a` + anything share structure but not a value --
   * what it must *not* do is collide two distinct two-byte messages.
   */
  it("does not collide two-byte messages despite the overlapping tail read", () => {
    const seen = new Set<string>();
    for (let a = 0; a < 16; a++) {
      for (let b = 0; b < 16; b++) {
        seen.add(wyhash(Uint8Array.of(a * 17, b * 17)).toString(16));
      }
    }
    expect(seen.size).toBe(256);
  });
});
