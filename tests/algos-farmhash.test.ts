import { describe, expect, it } from "vitest";

import {
  FARMHASH_VARIANTS,
  farmhash,
  farmhashBytes,
  farmhashna,
  farmhashnaWithSeed,
  farmhashnaWithSeeds,
  farmhashuo,
  farmhashuoWithSeed,
  farmhashuoWithSeeds,
  farmhashxo,
  farmhashxoWithSeed,
  farmhashxoWithSeeds,
} from "../packages/algos/src/index";
import { cityhash64 } from "../packages/algos/src/cityhash";
import { FARMHASH_SELF_TEST } from "./farmhash-vectors";

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const K0 = 0xc3a5c85c97cb3127n;

/**
 * FarmHash's own self-test, reproduced: 5,792 assertions across three namespaces.
 *
 * The public `farmhash::Hash64` is not implemented and must not be -- it dispatches on CPU features,
 * so two machines disagree on the same input. The namespaces are deterministic and the reference's
 * self-test checks *them*, which is exactly what makes this possible. See `farmhash.ts`.
 */

/** CityHash's 1 MB pseudorandom buffer, which FarmHash's self-test reuses verbatim. */
const DATA_SIZE = 1 << 20;
const data = new Uint8Array(DATA_SIZE);
{
  let a = 9n;
  let b = 777n;
  for (let i = 0; i < DATA_SIZE; i++) {
    a = add(a, b);
    b = add(b, a);
    a = mul(a ^ (a >> 41n), K0);
    b = add(mul(b ^ (b >> 41n), K0), BigInt(i));
    data[i] = Number((b >> 37n) & 0xffn);
  }
}

/** FarmHash's `CreateSeed`: six Murmur3 rounds with the offset folded in halfway. */
const C1 = 0xcc9e2d51;
function createSeed(offset: number, salt: number): bigint {
  let h = salt >>> 0;
  for (let i = 0; i < 3; i++) {
    h = Math.imul(h, C1) >>> 0;
    h = (h ^ (h >>> 17)) >>> 0;
  }
  h = (h + (offset >>> 0)) >>> 0;
  for (let i = 0; i < 3; i++) {
    h = Math.imul(h, C1) >>> 0;
    h = (h ^ (h >>> 17)) >>> 0;
  }
  return BigInt(h >>> 0);
}

/**
 * The reference's three-loop driver.
 *
 * 299 quadratic cases, then a growth loop, then the whole buffer. CityHash's driver has only the first
 * and last, which is why its self-test is 300 cases and this is 362 -- and why the count is asserted
 * before any value is compared.
 */
function selfTestCases(): readonly [number, number][] {
  const out: [number, number][] = [];
  let i = 0;
  for (; i < 299; i++) out.push([i * i, i]);
  for (; i < DATA_SIZE; i += Math.floor(i / 7)) out.push([0, i]);
  out.push([0, DATA_SIZE]);
  return out;
}

const CASES = selfTestCases();

type Hasher = (s: Uint8Array, o: number, len: number, ...rest: bigint[]) => bigint;

const IMPLEMENTATIONS: Record<string, Record<string, Hasher>> = {
  na: {
    Hash64WithSeeds: farmhashnaWithSeeds as Hasher,
    Hash64WithSeed: farmhashnaWithSeed as Hasher,
    Hash64: farmhashna as Hasher,
  },
  uo: {
    Hash64WithSeeds: farmhashuoWithSeeds as Hasher,
    Hash64WithSeed: farmhashuoWithSeed as Hasher,
    Hash64: farmhashuo as Hasher,
  },
  xo: {
    Hash64WithSeeds: farmhashxoWithSeeds as Hasher,
    Hash64WithSeed: farmhashxoWithSeed as Hasher,
    Hash64: farmhashxo as Hasher,
  },
};

describe("FarmHash", () => {
  it("reproduces the reference's three-loop driver, which is 362 cases and not 300", () => {
    expect(CASES).toHaveLength(362);
    // The first loop is quadratic in the offset and linear in the length.
    expect(CASES[0]).toEqual([0, 0]);
    expect(CASES[298]).toEqual([298 * 298, 298]);
    // The growth loop hashes from the start at increasing lengths, and the last case is the megabyte.
    expect(CASES[299]).toEqual([0, 299]);
    expect(CASES[CASES.length - 1]).toEqual([0, DATA_SIZE]);
  });

  for (const set of FARMHASH_SELF_TEST) {
    it(`farmhash${set.namespace} matches all ${set.expected.length} of its self-test values`, () => {
      const impl = IMPLEMENTATIONS[set.namespace]!;
      expect(set.expected).toHaveLength(CASES.length * set.calls.length * 2);
      let index = 0;
      for (const [offset, len] of CASES) {
        const seed = createSeed(offset, 0xffffffff);
        const seed0 = createSeed(offset, 0);
        const seed1 = createSeed(offset, 1);
        for (const call of set.calls) {
          const fn = impl[call]!;
          const h =
            call === "Hash64WithSeeds"
              ? fn(data, offset, len, seed0, seed1)
              : call === "Hash64WithSeed"
                ? fn(data, offset, len, seed)
                : fn(data, offset, len);
          expect(Number(h >> 32n), `${set.namespace} (${offset},${len}) ${call} high`).toBe(
            set.expected[index++],
          );
          expect(Number(h & 0xffffffffn), `${set.namespace} (${offset},${len}) ${call} low`).toBe(
            set.expected[index++],
          );
        }
      }
    });
  }

  it("covers exactly the three namespaces the public Hash64 dispatches between", () => {
    expect(FARMHASH_SELF_TEST.map((s) => s.namespace)).toEqual(["na", "uo", "xo"]);
    expect(FARMHASH_VARIANTS.map((v) => v.id)).toEqual(["na", "uo", "xo"]);
  });

  /**
   * `na` is CityHash64's descendant and shares its short paths exactly -- so up to 32 bytes the two
   * agree, and above that they must not. That is a real check on the import from `cityhash.ts`: if
   * those shared functions were subtly re-declared rather than shared, the first half would break.
   */
  it("agrees with CityHash64 up to 32 bytes and diverges above it", () => {
    for (let len = 0; len <= 32; len++) {
      expect(farmhashna(data, 0, len), `${len} bytes`).toBe(cityhash64(data, 0, len));
    }
    for (const len of [33, 40, 64, 65, 100, 200, 1000]) {
      expect(farmhashna(data, 0, len), `${len} bytes`).not.toBe(cityhash64(data, 0, len));
    }
  });

  /**
   * The three namespaces must be three functions, and the boundaries are where to look.
   *
   * `uo` delegates to `na` at 64 bytes and below, and `xo` delegates to `na` up to 32 and again from 97
   * to 256, so the lengths where all three differ are narrow. Asserting agreement where it is required
   * is as much the point as asserting difference where it is.
   */
  it("delegates exactly where the reference delegates", () => {
    for (const len of [0, 16, 32, 64]) {
      expect(farmhashuo(data, 0, len), `uo at ${len} delegates to na`).toBe(farmhashna(data, 0, len));
    }
    for (const len of [0, 16, 32]) {
      expect(farmhashxo(data, 0, len), `xo at ${len} delegates to na`).toBe(farmhashna(data, 0, len));
    }
    for (const len of [97, 150, 256]) {
      expect(farmhashxo(data, 0, len), `xo at ${len} delegates to na`).toBe(farmhashna(data, 0, len));
    }
    for (const len of [257, 500, 4096]) {
      expect(farmhashxo(data, 0, len), `xo at ${len} delegates to uo`).toBe(farmhashuo(data, 0, len));
    }
    // And where none delegates, all three differ.
    for (const len of [65, 80, 96]) {
      const values = [farmhashna(data, 0, len), farmhashuo(data, 0, len), farmhashxo(data, 0, len)];
      expect(new Set(values.map(String)).size, `at ${len} bytes`).toBe(3);
    }
  });

  /**
   * An unseeded call is not a zero-seeded one, and that distinction has to survive to the tool.
   *
   * `na`'s seeded form is `HashLen16(Hash64 - k2, seed)`, so seeding with zero still folds `k2` in.
   * The hash family leaves `seed64` undefined for an empty field so that `farmhash()` can tell them
   * apart -- if that ever regressed, an empty Seed box would silently produce the seeded value.
   */
  it("distinguishes an absent seed from a zero seed", () => {
    for (const variant of FARMHASH_VARIANTS) {
      const message = data.subarray(0, 100);
      expect(farmhash(message, variant.id), variant.id).not.toBe(farmhash(message, variant.id, 0n));
      expect(farmhash(message, variant.id, 0n), variant.id).not.toBe(farmhash(message, variant.id, 1n));
    }
  });

  it("returns eight bytes, most significant first", () => {
    for (const variant of FARMHASH_VARIANTS) {
      const value = farmhash(data.subarray(0, 50), variant.id);
      expect(
        [...farmhashBytes(data.subarray(0, 50), variant.id)]
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
        variant.id,
      ).toBe(value.toString(16).padStart(16, "0"));
    }
  });
});
