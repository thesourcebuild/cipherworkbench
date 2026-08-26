import { describe, expect, it } from "vitest";

import {
  randomBelow,
  randomBytes,
  randomFloat,
  randomHex,
  randomInt,
  randomIntSample,
  shuffled,
} from "../packages/cipher-engine/src/index";

/**
 * The random samplers, and this file has to carry more weight than most because **there is nothing to
 * compare against**.
 *
 * Every other correctness claim in this repo ends at a published vector or a second implementation. A
 * uniform draw has neither: any particular output is as likely as any other, so no output is evidence.
 * What stands in is *distribution* -- enough draws that a biased sampler cannot look uniform -- plus the
 * structural properties that are exactly true and can be asserted outright: the endpoints are
 * reachable, a sample without replacement has no repeats, a shuffle is a permutation.
 *
 * Two things follow from that and shape every test here.
 *
 * **The bands are chosen so a modulo fails them.** The point of `randomBelow` is that it rejects
 * rather than taking a modulo, so the tests are calibrated against what a modulo would actually
 * produce: at bound 70, `byte % 70` puts the low 46 buckets near 2,057 draws and the rest near 1,928,
 * so a band of 1,800 to 2,200 around 2,000 catches it while leaving room for ordinary variance. A
 * looser band would pass the bug; a tighter one would flake.
 *
 * **Nothing here is seeded, so nothing here is deterministic.** That is unavoidable -- the whole point
 * is that the source is `crypto.getRandomValues` -- and it is why every band has a stated margin
 * rather than an exact figure. A test that flakes once a year is worse than no test, so the margins
 * are wide in absolute terms and narrow in terms of the bug they exist to catch.
 */

const MODULO_NOTE = "a modulo would land outside this band";

describe("randomBelow", () => {
  it("is uniform over its buckets, which a modulo would not be", () => {
    // 70 buckets, because that is the password generator's alphabet size and the case a modulo is
    // worst at: 256 = 3 * 70 + 46, so 46 of the 70 values would be over-represented.
    const bound = 70;
    const expected = 2000;
    const counts = new Array<number>(bound).fill(0);
    for (let i = 0; i < bound * expected; i++) counts[randomBelow(bound)]! += 1;
    for (const [value, count] of counts.entries()) {
      expect(count, `bucket ${value} came up ${count} times; ${MODULO_NOTE}`).toBeGreaterThan(1800);
      expect(count, `bucket ${value} came up ${count} times; ${MODULO_NOTE}`).toBeLessThan(2200);
    }
  });

  it("stays inside its range for every bound from 1 to 40", () => {
    for (let bound = 1; bound <= 40; bound++) {
      for (let draw = 0; draw < 200; draw++) {
        const value = randomBelow(bound);
        expect(Number.isInteger(value), `bound ${bound} produced ${value}`).toBe(true);
        expect(value, `bound ${bound}`).toBeGreaterThanOrEqual(0);
        expect(value, `bound ${bound}`).toBeLessThan(bound);
      }
    }
  });

  it("reaches both ends of a small bound", () => {
    // A sampler that never produces 0, or never the top value, is the classic off-by-one and is
    // invisible in any single output. 400 draws over 4 buckets makes a missing one conclusive.
    const seen = new Set<number>();
    for (let i = 0; i < 400; i++) seen.add(randomBelow(4));
    expect([...seen].sort()).toEqual([0, 1, 2, 3]);
  });

  it("returns 0 for a bound of 1 without drawing", () => {
    for (let i = 0; i < 10; i++) expect(randomBelow(1)).toBe(0);
  });

  /**
   * Bounds that cross a byte boundary, where the draw width changes.
   *
   * `byteCount` comes from the bit length, so 256 and 257 draw one byte and two. Getting that
   * arithmetic wrong is not subtle in its effect -- a bound of 257 drawn at one byte can never return
   * 256 -- but it is invisible without asking for the top of the range specifically.
   */
  it("spans bounds either side of a byte boundary", () => {
    for (const bound of [255, 256, 257, 65535, 65536, 65537]) {
      let max = -1;
      let min = Number.MAX_SAFE_INTEGER;
      for (let i = 0; i < 4000; i++) {
        const value = randomBelow(bound);
        expect(value, `bound ${bound}`).toBeLessThan(bound);
        if (value > max) max = value;
        if (value < min) min = value;
      }
      // Within 4000 draws the extremes should be close to the ends for the small bounds, and the
      // assertion that matters for the large ones is simply that nothing exceeded the bound.
      if (bound <= 257) {
        expect(max, `bound ${bound} never produced anything above ${max}`).toBeGreaterThan(bound - 20);
        expect(min, `bound ${bound} never produced anything below ${min}`).toBeLessThan(20);
      }
    }
  });

  /**
   * A range past 2^32, which is why this is `bigint` inside.
   *
   * Building the value in a `number` from seven bytes crosses 2^53 and loses the low bits, so a
   * sampler written that way returns multiples of a power of two and nothing else. 500 draws over a
   * 10^15 range must all be distinct and must not all be even.
   */
  it("works past 2^32, without losing the low bits", () => {
    const bound = 1_000_000_000_000_000;
    const draws = Array.from({ length: 500 }, () => randomBelow(bound));
    for (const value of draws) {
      expect(Number.isSafeInteger(value)).toBe(true);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(bound);
    }
    expect(new Set(draws).size, "500 draws from 10^15 collided").toBe(500);
    // A 32-bit-arithmetic mistake shows up as low bits that are always zero.
    expect(draws.some((value) => value % 2 === 1), "no odd value in 500 draws").toBe(true);
  });

  it("refuses a bound it cannot sample", () => {
    expect(() => randomBelow(0)).toThrow(/safe positive integer bound/);
    expect(() => randomBelow(-5)).toThrow(/safe positive integer bound/);
    expect(() => randomBelow(1.5)).toThrow(/safe positive integer bound/);
    expect(() => randomBelow(Number.MAX_SAFE_INTEGER + 10)).toThrow(/safe positive integer bound/);
  });
});

describe("randomInt", () => {
  it("is inclusive at both ends", () => {
    // "Between 1 and 6" means six outcomes. An exclusive upper bound is the single most likely
    // mistake here and a die that never rolls a 6 reads as luck rather than as a bug.
    const seen = new Set<number>();
    for (let i = 0; i < 600; i++) seen.add(randomInt(1, 6));
    expect([...seen].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it("handles a single-value range and a negative range", () => {
    for (let i = 0; i < 10; i++) expect(randomInt(7, 7)).toBe(7);
    const seen = new Set<number>();
    for (let i = 0; i < 400; i++) seen.add(randomInt(-3, -1));
    expect([...seen].sort((a, b) => a - b)).toEqual([-3, -2, -1]);
  });

  it("is uniform across a negative-to-positive range", () => {
    const counts = new Map<number, number>();
    for (let i = 0; i < 10_000; i++) {
      const value = randomInt(-2, 2);
      counts.set(value, (counts.get(value) ?? 0) + 1);
    }
    expect([...counts.keys()].sort((a, b) => a - b)).toEqual([-2, -1, 0, 1, 2]);
    for (const [value, count] of counts) {
      expect(count, `value ${value} came up ${count} times`).toBeGreaterThan(1700);
      expect(count, `value ${value} came up ${count} times`).toBeLessThan(2300);
    }
  });

  it("refuses an inverted or unspannable range", () => {
    expect(() => randomInt(5, 4)).toThrow(/max >= min/);
    expect(() => randomInt(1.5, 4)).toThrow(/safe integer bounds/);
    expect(() => randomInt(-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)).toThrow(
      /more than 9007199254740991 values/,
    );
  });
});

describe("randomFloat", () => {
  it("stays in [0, 1)", () => {
    for (let i = 0; i < 20_000; i++) {
      const value = randomFloat();
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(1);
    }
  });

  /**
   * Ten buckets, and the assertion that catches the constructions that are *nearly* right.
   *
   * `byte / 256` passes a range check and gives 256 distinct values; using only the high bytes gives a
   * coarse grid. Both look fine in a range check and fail a bucket count at this resolution.
   */
  it("is uniform across the interval", () => {
    const buckets = new Array<number>(10).fill(0);
    const draws = 100_000;
    for (let i = 0; i < draws; i++) buckets[Math.floor(randomFloat() * 10)]! += 1;
    for (const [bucket, count] of buckets.entries()) {
      expect(count, `bucket ${bucket} held ${count}`).toBeGreaterThan(draws / 10 - 700);
      expect(count, `bucket ${bucket} held ${count}`).toBeLessThan(draws / 10 + 700);
    }
  });

  it("uses the whole mantissa rather than a coarse grid", () => {
    // With all 53 bits random, 5,000 draws are distinct with overwhelming probability. A construction
    // that only randomises the top 8 or 16 bits collides constantly.
    const draws = new Set<number>();
    for (let i = 0; i < 5000; i++) draws.add(randomFloat());
    expect(draws.size).toBe(5000);
    // And the values are not all multiples of some power of two, which is what dropping the low bits
    // of the mantissa produces.
    expect([...draws].some((value) => (value * 2 ** 53) % 2 === 1)).toBe(true);
  });
});

describe("shuffled", () => {
  it("returns a permutation and leaves the input alone", () => {
    const input = [1, 2, 3, 4, 5, 6, 7, 8];
    const out = shuffled(input);
    expect(out).not.toBe(input);
    expect([...out].sort((a, b) => a - b)).toEqual(input);
    expect(input).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  /**
   * All six orderings of three elements, each about a sixth of the time.
   *
   * This is the test that separates Fisher-Yates from the two ways of getting it wrong. Drawing `j`
   * from the whole length rather than from `[0, i]`, or iterating upwards, both still produce
   * permutations -- they just produce some of them more often than others, which no single shuffle
   * can show. The naive `j = randomBelow(length)` version puts one of these six near 1.6x another.
   */
  it("is uniform over permutations", () => {
    const draws = 60_000;
    const counts = new Map<string, number>();
    for (let i = 0; i < draws; i++) {
      const key = shuffled([1, 2, 3]).join("");
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    expect([...counts.keys()].sort()).toEqual(["123", "132", "213", "231", "312", "321"]);
    for (const [order, count] of counts) {
      expect(count, `order ${order} came up ${count} times`).toBeGreaterThan(draws / 6 - 700);
      expect(count, `order ${order} came up ${count} times`).toBeLessThan(draws / 6 + 700);
    }
  });

  it("handles empty and single-element arrays", () => {
    expect(shuffled([])).toEqual([]);
    expect(shuffled(["only"])).toEqual(["only"]);
  });
});

describe("randomIntSample", () => {
  it("draws distinct values in a wide range, through the rejection branch", () => {
    const out = randomIntSample(1, 1_000_000, 100);
    expect(out).toHaveLength(100);
    expect(new Set(out).size).toBe(100);
    for (const value of out) {
      expect(value).toBeGreaterThanOrEqual(1);
      expect(value).toBeLessThanOrEqual(1_000_000);
    }
  });

  /**
   * The whole range at once, which is where rejection degenerates.
   *
   * Asking for all 100 values of 1..100 by redrawing duplicates is a coupon-collector problem: the
   * last few draws wait for one specific number, and the expected number of draws is about 519. It
   * terminates, so a test that only checked the output would pass -- which is why the branch exists
   * and why this case is here to exercise it rather than to prove it eventually finishes.
   */
  it("draws a whole small range, through the shuffle branch", () => {
    const out = randomIntSample(1, 100, 100);
    expect(out).toHaveLength(100);
    expect([...out].sort((a, b) => a - b)).toEqual(Array.from({ length: 100 }, (_, i) => i + 1));
  });

  it("is uniform about which values it leaves out", () => {
    // 4 drawn from 5, 20,000 times: each value should be omitted about a fifth of the time. A partial
    // shuffle that reused an index would omit some values far more often than others.
    const omissions = new Map<number, number>();
    for (let i = 0; i < 20_000; i++) {
      const drawn = new Set(randomIntSample(1, 5, 4));
      for (let value = 1; value <= 5; value++) {
        if (!drawn.has(value)) omissions.set(value, (omissions.get(value) ?? 0) + 1);
      }
    }
    for (const [value, count] of omissions) {
      expect(count, `value ${value} was left out ${count} times`).toBeGreaterThan(3600);
      expect(count, `value ${value} was left out ${count} times`).toBeLessThan(4400);
    }
  });

  it("crosses the branch threshold without changing its contract", () => {
    // count * 4 is the switch, so a count of 10 uses the shuffle at span 40 and rejection at 41.
    for (const max of [39, 40, 41, 42]) {
      const out = randomIntSample(1, max, 10);
      expect(out, `span ${max}`).toHaveLength(10);
      expect(new Set(out).size, `span ${max}`).toBe(10);
    }
  });

  it("refuses to draw more distinct values than exist", () => {
    expect(() => randomIntSample(1, 5, 6)).toThrow(/Cannot draw 6 distinct values from 5/);
    expect(() => randomIntSample(5, 1, 1)).toThrow(/max >= min/);
    expect(() => randomIntSample(1, 5, -1)).toThrow(/non-negative integer count/);
    expect(randomIntSample(1, 5, 0)).toEqual([]);
  });
});

describe("randomBytes and randomHex", () => {
  it("fills past the 65536-byte getRandomValues limit", () => {
    // The chunking loop exists for this; without it the call throws QuotaExceededError, and a version
    // that silently left the tail zeroed would be far worse.
    const bytes = randomBytes(70_000);
    expect(bytes).toHaveLength(70_000);
    const tail = bytes.subarray(65_536);
    expect(tail.some((byte) => byte !== 0), "the tail past 65536 bytes was all zero").toBe(true);
  });

  it("produces every byte value across enough draws", () => {
    const seen = new Set(randomBytes(20_000));
    expect(seen.size).toBe(256);
  });

  it("spells hex at two characters a byte, zero-padded", () => {
    expect(randomHex(0)).toBe("");
    expect(randomHex(16)).toMatch(/^[0-9a-f]{32}$/);
    expect(new Set(Array.from({ length: 50 }, () => randomHex(8))).size).toBe(50);
  });

  it("refuses a negative or fractional length", () => {
    expect(() => randomBytes(-1)).toThrow(/non-negative integer length/);
    expect(() => randomBytes(1.5)).toThrow(/non-negative integer length/);
  });
});
