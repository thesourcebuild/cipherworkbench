/**
 * MetroHash128CRC, at both of its constant sets.
 *
 * `not-a-mac`. Its 32-bit seed is not a key.
 *
 * **A different function from MetroHash128, not a faster one.** Like `citycrc.ts`, this uses
 * `_mm_crc32_u64` as a *mixing* step -- so the CRC variant's output has no relationship to plain
 * MetroHash128's, and the reference's `testvector.h` lists them as separate entries. Anyone reaching
 * for it because "CRC" suggests hardware acceleration of the same answer is reaching for the wrong
 * tool; `metrohash` is the one that matches MetroHash128.
 *
 * Only the 128-bit width exists. There is no MetroHash64CRC, so unlike `metrohash` this has no output
 * length control -- just the variant.
 *
 * ## The two variants, and what actually differs
 *
 * Variant 1 and variant 2 have **different constants and different rotation amounts and nothing else**:
 * the same four-lane 32-byte loop, the same tail cascade at 16, 8, 4, 2 and 1 bytes, and the same
 * four-step finalisation. So they are a table, not two implementations -- which is why `VARIANTS` below
 * is data and the body is written once. Getting one rotation wrong produces a function that looks
 * perfectly random and matches neither.
 *
 * ## Where the CRC actually appears, which is not everywhere
 *
 * Three of the six input paths use it and three do not: the 32-byte main loop mixes with
 * `_mm_crc32_u64`, and so do the 4-byte, 2-byte and 1-byte tails -- but the 16-byte and 8-byte tails
 * are plain multiply-and-rotate, identical in shape to non-CRC MetroHash. That asymmetry is why the
 * reference's test key is 63 bytes: its own comment says the length is chosen to "properly exercise
 * every internal branch", and 63 is 32 + 16 + 8 + 4 + 2 + 1.
 *
 * Note the narrow reads are fed to the *64-bit* intrinsic, so a 4-byte read is zero-extended to eight
 * bytes and four zero bytes go through the CRC with it. Passing only the four bytes gives a different
 * answer.
 *
 * Verified against all four of the reference's own published vectors -- both variants at seeds 0 and 1.
 */

import { crc32Word } from "./crc32c";

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const ror = (x: bigint, n: number): bigint =>
  n === 0 ? x : ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;

const read = (s: Uint8Array, o: number, bytes: number): bigint => {
  let v = 0n;
  for (let i = bytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(s[o + i]!);
  return v;
};

export type MetrohashCrcVariant = "1" | "2";

interface Params {
  readonly k: readonly [bigint, bigint, bigint, bigint];
  /** The four rotations closing the 32-byte loop. */
  readonly bulk: readonly [number, number, number, number];
  /** The 16-byte tail: two identical rotations then two mixing ones. */
  readonly tail16: readonly [number, number, number];
  /** The 8-byte tail: a rotation then a mixing one. */
  readonly tail8: readonly [number, number];
  /** The 4-, 2- and 1-byte tails, one rotation each. */
  readonly tail4: number;
  readonly tail2: number;
  readonly tail1: number;
  /** The finalisation, two rotations applied twice. */
  readonly final: readonly [number, number];
}

const VARIANTS: Readonly<Record<MetrohashCrcVariant, Params>> = {
  "1": {
    k: [0xc83a91e1n, 0x8648dbdbn, 0x7bdec03bn, 0x2f5870a5n],
    bulk: [34, 37, 34, 37],
    tail16: [34, 30, 30],
    tail8: [36, 23],
    tail4: 19,
    tail2: 13,
    tail1: 17,
    final: [11, 26],
  },
  "2": {
    k: [0xee783e2fn, 0xad07c493n, 0x797a90bbn, 0x2e4b2e1bn],
    bulk: [12, 19, 12, 19],
    tail16: [41, 10, 10],
    tail8: [34, 22],
    tail4: 14,
    tail2: 15,
    tail1: 18,
    final: [15, 27],
  },
};

/** MetroHash128CRC, as [low, high] 64-bit words. */
export function metrohashCrc128(
  message: Uint8Array,
  variant: MetrohashCrcVariant = "1",
  seed = 0,
): [bigint, bigint] {
  const params = VARIANTS[variant];
  if (!params) throw new Error(`MetroHash128CRC: unknown variant "${String(variant)}"`);
  const [k0, k1, k2, k3] = params.k;
  const len = message.length;
  const lenBig = BigInt(len);
  const seedBig = BigInt(seed >>> 0);
  let p = 0;
  const end = len;

  const v: bigint[] = [0n, 0n, 0n, 0n];
  v[0] = add(mul(sub(seedBig, k0), k3), lenBig);
  v[1] = add(mul(add(seedBig, k1), k2), lenBig);

  if (len >= 32) {
    v[2] = add(mul(add(seedBig, k0), k2), lenBig);
    v[3] = add(mul(sub(seedBig, k1), k3), lenBig);
    do {
      // The only place the CRC touches all four lanes.
      v[0] = v[0]! ^ crc32Word(v[0]!, read(message, p, 8));
      p += 8;
      v[1] = v[1]! ^ crc32Word(v[1]!, read(message, p, 8));
      p += 8;
      v[2] = v[2]! ^ crc32Word(v[2]!, read(message, p, 8));
      p += 8;
      v[3] = v[3]! ^ crc32Word(v[3]!, read(message, p, 8));
      p += 8;
    } while (p <= end - 32);

    const [r0, r1, r2, r3] = params.bulk;
    v[2] = v[2]! ^ mul(ror(add(mul(add(v[0]!, v[3]!), k0), v[1]!), r0), k1);
    v[3] = v[3]! ^ mul(ror(add(mul(add(v[1]!, v[2]!), k1), v[0]!), r1), k0);
    v[0] = v[0]! ^ mul(ror(add(mul(add(v[0]!, v[2]!), k0), v[3]!), r2), k1);
    v[1] = v[1]! ^ mul(ror(add(mul(add(v[1]!, v[3]!), k1), v[2]!), r3), k0);
  }

  if (end - p >= 16) {
    const [rA, rB, rC] = params.tail16;
    v[0] = add(v[0]!, mul(read(message, p, 8), k2));
    p += 8;
    v[0] = mul(ror(v[0]!, rA), k3);
    v[1] = add(v[1]!, mul(read(message, p, 8), k2));
    p += 8;
    v[1] = mul(ror(v[1]!, rA), k3);
    v[0] = v[0]! ^ mul(ror(add(mul(v[0]!, k2), v[1]!), rB), k1);
    v[1] = v[1]! ^ mul(ror(add(mul(v[1]!, k3), v[0]!), rC), k0);
  }

  if (end - p >= 8) {
    const [rA, rB] = params.tail8;
    v[0] = add(v[0]!, mul(read(message, p, 8), k2));
    p += 8;
    v[0] = mul(ror(v[0]!, rA), k3);
    v[0] = v[0]! ^ mul(ror(add(mul(v[0]!, k2), v[1]!), rB), k1);
  }

  // The narrow tails feed the *64-bit* intrinsic, so the read is zero-extended to eight bytes.
  if (end - p >= 4) {
    v[1] = v[1]! ^ crc32Word(v[0]!, read(message, p, 4));
    p += 4;
    v[1] = v[1]! ^ mul(ror(add(mul(v[1]!, k3), v[0]!), params.tail4), k0);
  }

  if (end - p >= 2) {
    v[0] = v[0]! ^ crc32Word(v[1]!, read(message, p, 2));
    p += 2;
    v[0] = v[0]! ^ mul(ror(add(mul(v[0]!, k2), v[1]!), params.tail2), k1);
  }

  if (end - p >= 1) {
    v[1] = v[1]! ^ crc32Word(v[0]!, read(message, p, 1));
    v[1] = v[1]! ^ mul(ror(add(mul(v[1]!, k3), v[0]!), params.tail1), k0);
  }

  const [f0, f1] = params.final;
  v[0] = add(v[0]!, ror(add(mul(v[0]!, k0), v[1]!), f0));
  v[1] = add(v[1]!, ror(add(mul(v[1]!, k1), v[0]!), f1));
  v[0] = add(v[0]!, ror(add(mul(v[0]!, k0), v[1]!), f0));
  v[1] = add(v[1]!, ror(add(mul(v[1]!, k1), v[0]!), f1));
  return [v[0]!, v[1]!];
}

/**
 * Sixteen bytes, in the reference's own order: `v[0]` then `v[1]`, each **little-endian**.
 *
 * That is `memcpy(out, v, 16)` on x86, and it is what the reference's published hex strings are -- so
 * the byte order here is not a choice, it is what makes those four vectors comparable.
 */
export function metrohashCrc128Bytes(
  message: Uint8Array,
  variant: MetrohashCrcVariant = "1",
  seed = 0,
): Uint8Array {
  const [lo, hi] = metrohashCrc128(message, variant, seed);
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i] = Number((lo >> BigInt(8 * i)) & 0xffn);
    out[8 + i] = Number((hi >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}
