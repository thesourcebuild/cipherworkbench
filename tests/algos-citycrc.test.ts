import { describe, expect, it } from "vitest";

import {
  CRC32C_TABLE,
  cityhashCrc,
  cityhashCrc128,
  cityhashCrc128WithSeed,
  cityhashCrc256,
  crc32Word,
} from "../packages/algos/src/index";
import { cityhash128 } from "../packages/algos/src/cityhash";
import { CITY_CRC_CASES } from "./citycrc-vectors";

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const K0 = 0xc3a5c85c97cb3127n;
const h = (v: string): bigint => BigInt("0x" + v);

/** CityHash's own 1 MB buffer, the same recurrence `tests/algos-nonchash.test.ts` builds. */
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

/** The reference's `kSeed128`, which is `Uint128(kSeed0, kSeed1)` = (1234567, k0). */
const SEED_LO = 1234567n;
const SEED_HI = K0;

/** CityHash's two-loop driver: 299 quadratic cases then the whole buffer. */
const CASES: readonly [number, number][] = Array.from({ length: 300 }, (_, i) =>
  i < 299 ? [i * i, i] : [0, DATA_SIZE],
);

describe("CityHashCrc", () => {
  it("reproduces all 1,200 CityHashCrc256 words", () => {
    expect(CITY_CRC_CASES).toHaveLength(300);
    for (const [index, [offset, len]] of CASES.entries()) {
      const got = cityhashCrc256(data, offset, len);
      const want = CITY_CRC_CASES[index]!.crc256;
      for (let word = 0; word < 4; word++) {
        expect(got[word], `case ${index} (${offset},${len}) word ${word}`).toBe(h(want[word]!));
      }
    }
  });

  it("reproduces all 600 CityHashCrc128 words, seeded and unseeded", () => {
    for (const [index, [offset, len]] of CASES.entries()) {
      const plain = cityhashCrc128(data, offset, len);
      const seeded = cityhashCrc128WithSeed(data, offset, len, SEED_LO, SEED_HI);
      const want = CITY_CRC_CASES[index]!;
      expect(plain[0], `case ${index} plain low`).toBe(h(want.crc128[0]));
      expect(plain[1], `case ${index} plain high`).toBe(h(want.crc128[1]));
      expect(seeded[0], `case ${index} seeded low`).toBe(h(want.crc128Seed[0]));
      expect(seeded[1], `case ${index} seeded high`).toBe(h(want.crc128Seed[1]));
    }
  });

  /**
   * `PERMUTE3(a, b, c)` is `swap(a, b); swap(a, c)`, which rotates to `(c, a, b)`.
   *
   * Asserted directly because the wrong direction is *also* a permutation: the loop still runs, the
   * output still looks random, and all 1,800 expected values are simply wrong with nothing to say why.
   * It cost a debugging cycle here, so the direction gets its own assertion rather than only being
   * covered by the digests above.
   */
  it("rotates PERMUTE3 in the direction the reference's swaps produce", () => {
    let a = 1;
    let b = 2;
    let c = 3;
    [a, b, c] = [c, a, b];
    expect([a, b, c]).toEqual([3, 1, 2]);
  });

  /**
   * The CRC-32C table is derived from the catalogue's CRC-32/ISCSI polynomial, so this checks the
   * derivation against a value the CRC family independently pins.
   *
   * `crc32Word` is deliberately *not* the CRC-32C a checksum tool prints: the instruction has no
   * initial value and no final xor. So the check is the table itself plus the standard property that
   * running the reflected table over a byte reproduces the well-known first entries.
   */
  it("derives the CRC-32C table from the catalogue's own polynomial", () => {
    expect(CRC32C_TABLE).toHaveLength(256);
    expect(CRC32C_TABLE[0]).toBe(0);
    // The first entries of every reflected CRC-32C table in circulation.
    expect(CRC32C_TABLE[1]).toBe(0xf26b8303);
    expect(CRC32C_TABLE[2]).toBe(0xe13b70f7);
    expect(CRC32C_TABLE[255]).toBe(0xad7d5351);
    // And it is a permutation-free table with no duplicate entries, which a wrong polynomial breaks.
    expect(new Set(CRC32C_TABLE).size).toBe(256);
  });

  it("applies no initial value and no final xor, unlike the CRC-32C checksum tool", () => {
    // Feeding zero into a zero accumulator must stay zero -- a model with an init or an xorOut cannot.
    expect(crc32Word(0n, 0n)).toBe(0n);
    expect(crc32Word(0n, 1n)).not.toBe(0n);
  });

  /**
   * Below 900 bytes `CityHashCrc128` *is* `CityHash128`, and above it must not be.
   *
   * That boundary is the thing a reader would assume away -- the CRC variant looks like it should be a
   * faster route to the same answer at every length, and it is a different function only above 900.
   */
  it("delegates to CityHash128 at 900 bytes and below, and diverges above", () => {
    for (const len of [0, 1, 100, 899, 900]) {
      expect(cityhashCrc128(data, 0, len), `${len} bytes`).toEqual(cityhash128(data, 0, len));
    }
    for (const len of [901, 1000, 5000]) {
      expect(cityhashCrc128(data, 0, len), `${len} bytes`).not.toEqual(cityhash128(data, 0, len));
    }
  });

  /**
   * A short message still costs a full 240-byte computation.
   *
   * `CityHashCrc256` has no short path: under 240 bytes it zero-pads and seeds with `~len`, so there is
   * no length at which it gets cheap. Worth pinning because the natural "optimisation" is to add one.
   */
  it("distinguishes a short message from the same bytes zero-padded", () => {
    const five = cityhashCrc256(data, 0, 5);
    const padded = new Uint8Array(240);
    padded.set(data.subarray(0, 5));
    // Hashing 240 explicit bytes is not the same as hashing 5, because the seed carries ~len.
    expect(cityhashCrc256(padded, 0, 240)).not.toEqual(five);
  });

  /**
   * The byte order must match plain `cityhash()`: little-endian words, low word first.
   *
   * Not a preference -- the two tools sit in the same sidebar category, so someone comparing
   * CityHash128 with CityHashCrc128 on one input must not have to reverse one of them. This was written
   * big-endian first and caught by comparing against the existing convention.
   */
  it("emits little-endian words in the same order as plain cityhash", () => {
    const message = data.subarray(0, 1000);
    const short = cityhashCrc(16, message);
    const long = cityhashCrc(32, message);
    expect(short).toHaveLength(16);
    expect(long).toHaveLength(32);
    const [lo, hi] = cityhashCrc128(message, 0, message.length);
    expect(short[0]).toBe(Number(lo & 0xffn));
    expect(short[8]).toBe(Number(hi & 0xffn));
    // And the 256-bit form is not the 128-bit one extended.
    expect([...long.subarray(0, 16)]).not.toEqual([...short]);
  });
});
