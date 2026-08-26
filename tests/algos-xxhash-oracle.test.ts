import { beforeAll, describe, expect, it } from "vitest";
import xxhashWasm from "xxhash-wasm";
import { createXxHash32, createXxHash64, xxhash32, xxhash64 } from "@ocs/algos";

/**
 * Differential test against the reference xxHash implementation.
 *
 * `xxhash-wasm` compiles Yann Collet's own C to WebAssembly, so it is an independent
 * oracle rather than a second opinion from the same lineage. It is a **devDependency and
 * a test-only import** — nothing in `packages/` or `apps/` touches it. See
 * `packages/algos/WHY-NOT-A-LIBRARY.md` for why it is not the shipped implementation:
 * WASM would need `'wasm-unsafe-eval'` added to the desktop CSP, and its API cannot back
 * the synchronous streaming path.
 *
 * This suite exists because the fixed vectors in `algos-hash.test.ts` cannot carry the
 * weight alone. Four published values pin down the short-input branch and two lengths of
 * the striped path; they say nothing about the other several hundred length-and-seed
 * combinations, and xxHash has a distinct code path for every tail remainder. Writing
 * those vectors by hand is also how the first version of that suite ended up asserting
 * four values that were simply wrong — the implementation was right and the expectations
 * were invented. An oracle does not have that failure mode.
 */

type Oracle = Awaited<ReturnType<typeof xxhashWasm>>;
let oracle: Oracle;

beforeAll(async () => {
  oracle = await xxhashWasm();
});

/** Deterministic bytes, so a failure names a reproducible input. */
function pseudoRandom(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed >>> 0 || 1;
  for (let i = 0; i < length; i++) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[i] = state & 0xff;
  }
  return out;
}

describe("XXH32 against the reference implementation", () => {
  it("agrees on every length from 0 to 300", () => {
    // Covers both branches and all four tail remainders many times over, including the
    // 15/16/17 and 31/32/33 boundaries the fixed vectors only sample.
    for (let length = 0; length <= 300; length++) {
      const input = pseudoRandom(length, length + 1);
      expect(xxhash32(input, 0), `length ${length}`).toBe(oracle.h32Raw(input, 0) >>> 0);
    }
  });

  it("agrees across seeds", () => {
    // The seed feeds all four accumulator initialisers and the short-input path, so a
    // sign or width mistake there would pass at seed 0 and fail everywhere else.
    const seeds = [0, 1, 42, 0x7fffffff, 0x80000000, 0xdeadbeef, 0xffffffff];
    for (const seed of seeds) {
      for (const length of [0, 1, 4, 5, 15, 16, 17, 32, 100]) {
        const input = pseudoRandom(length, length + 7);
        expect(xxhash32(input, seed), `seed ${seed}, length ${length}`).toBe(
          oracle.h32Raw(input, seed) >>> 0,
        );
      }
    }
  });

  it("agrees when fed incrementally", () => {
    const input = pseudoRandom(1000, 99);
    for (const chunkSize of [1, 5, 16, 17, 63, 128]) {
      const mine = createXxHash32(0);
      const theirs = oracle.create32(0);
      for (let o = 0; o < input.length; o += chunkSize) {
        const slice = input.subarray(o, o + chunkSize);
        mine.update(slice);
        theirs.update(slice);
      }
      expect(mine.digest(), `chunk ${chunkSize}`).toBe(theirs.digest() >>> 0);
    }
  });

  it("agrees on all-zero and all-ones inputs", () => {
    // Degenerate inputs are where a missing `>>> 0` shows up: an accumulator that goes
    // negative indexes and shifts differently.
    for (const length of [16, 17, 64, 65]) {
      for (const fill of [0x00, 0xff]) {
        const input = new Uint8Array(length).fill(fill);
        expect(xxhash32(input, 0), `${length} x ${fill}`).toBe(oracle.h32Raw(input, 0) >>> 0);
      }
    }
  });
});

describe("XXH64 against the reference implementation", () => {
  it("agrees on every length from 0 to 300", () => {
    for (let length = 0; length <= 300; length++) {
      const input = pseudoRandom(length, length + 2);
      expect(xxhash64(input, 0), `length ${length}`).toBe(oracle.h64Raw(input, 0n));
    }
  });

  it("agrees across seeds, including ones that use the high 32 bits", () => {
    // A 64-bit seed is where a hi/lo mix-up hides. Seeds below 2^32 would pass with the
    // halves swapped in the initialiser.
    const seeds = [
      0n,
      1n,
      42n,
      0xffffffffn,
      0x100000000n,
      0xdeadbeefcafebaben,
      0xffffffffffffffffn,
    ];
    for (const seed of seeds) {
      for (const length of [0, 1, 4, 8, 31, 32, 33, 100]) {
        const input = pseudoRandom(length, length + 11);
        expect(xxhash64(input, seed), `seed ${seed}, length ${length}`).toBe(
          oracle.h64Raw(input, seed),
        );
      }
    }
  });

  it("agrees when fed incrementally", () => {
    const input = pseudoRandom(2000, 123);
    for (const chunkSize of [1, 4, 8, 31, 32, 33, 256]) {
      const mine = createXxHash64(0);
      const theirs = oracle.create64(0n);
      for (let o = 0; o < input.length; o += chunkSize) {
        const slice = input.subarray(o, o + chunkSize);
        mine.update(slice);
        theirs.update(slice);
      }
      expect(mine.digest(), `chunk ${chunkSize}`).toBe(theirs.digest());
    }
  });

  it("agrees on inputs that exercise each tail stage in turn", () => {
    // 32 bytes of stripe plus 0..15 bytes of tail walks the 8-byte, 4-byte and
    // single-byte stages through every combination.
    for (let tail = 0; tail <= 15; tail++) {
      const input = pseudoRandom(32 + tail, tail + 500);
      expect(xxhash64(input, 0), `tail ${tail}`).toBe(oracle.h64Raw(input, 0n));
    }
  });

  it("agrees on all-zero and all-ones inputs", () => {
    for (const length of [32, 33, 64, 65]) {
      for (const fill of [0x00, 0xff]) {
        const input = new Uint8Array(length).fill(fill);
        expect(xxhash64(input, 0), `${length} x ${fill}`).toBe(oracle.h64Raw(input, 0n));
      }
    }
  });
});

describe("the oracle covers what it claims", () => {
  it("provides XXH32 and XXH64 only — not XXH3 or XXH128", () => {
    /**
     * Recorded as an assertion rather than a comment because it is the reason
     * `xxhash-wasm` cannot be the oracle for XXH3/XXH128. Nothing in JavaScript
     * implements those, WASM included, so if they are ever added here they will need
     * vectors from the xxHash repository rather than a differential test.
     */
    expect(typeof oracle.h32Raw).toBe("function");
    expect(typeof oracle.h64Raw).toBe("function");
    expect("h3Raw" in oracle).toBe(false);
    expect("h128Raw" in oracle).toBe(false);
  });
});
