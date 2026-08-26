/**
 * MetroHash, at 64 and 128 bits, variants 1 and 2. Non-cryptographic.
 *
 * J. Andrew Rogers' family, designed by an automated search over hash constructions rather than by
 * hand -- which is why the four members share a skeleton and differ only in their constants and their
 * rotation counts. Four functions, one implementation, parameterised by `(width, variant)`.
 *
 * Three things to preserve.
 *
 * **The rotation counts differ per variant *and* per tail branch.** Variant 1's 8-byte branch rotates
 * by 33 where variant 2's rotates by 36; the 16-byte branch differs, the 2-byte branch differs, the
 * finaliser differs. Sharing one table across the two variants gives a hash that is self-consistent,
 * inverts nothing (there is nothing to invert) and matches no published value. The `ROT` records
 * below are the whole difference between the variants beyond their constants, so they are written out
 * rather than derived.
 *
 * **The 16-byte branch also differs in which constants multiply the two words.** Variant 1 uses k0 and
 * k1; variant 2 uses k2 for both. That is a difference in the *structure*, not just a rotation, and it
 * is easy to miss while transcribing four near-identical blocks.
 *
 * **The output is little-endian, and for the 128-bit forms it is two words in order.** The published
 * vectors print bytes, so a big-endian write reverses every one of them.
 *
 * No oracle: MetroHash is in no dependency here and OpenSSL has never had it. What stands behind it is
 * the author's own eight published vectors -- four functions at two seeds -- over a 63-byte key chosen
 * precisely because 63 = 32 + 16 + 8 + 4 + 2 + 1 exercises every branch of every variant. That is a
 * small fixture doing an unusual amount of work, and it is why no wider sweep was written.
 *
 * The `metrohash128crc` variants are deliberately absent: they use the SSE4.2 CRC-32C instruction as a
 * mixing primitive, which makes them a different algorithm from the two here rather than a faster
 * version of them.
 */

const MASK = (1n << 64n) - 1n;
const add = (a: bigint, b: bigint): bigint => (a + b) & MASK;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK;
const mul = (a: bigint, b: bigint): bigint => (a * b) & MASK;
const ror = (x: bigint, n: number): bigint => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;

/** Read `n` bytes little-endian. */
const rd = (b: Uint8Array, o: number, n: number): bigint => {
  let v = 0n;
  for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]!);
  return v;
};

const K: Record<string, readonly bigint[]> = {
  "1": [0xc83a91e1n, 0x8648dbdbn, 0x7bdec03bn, 0x2f5870a5n],
  "2": [0xd6d018f5n, 0xa2aa033bn, 0x62992fc1n, 0x30bc5b29n],
};

export type MetroVariant = 1 | 2;

/** Variant 1's and variant 2's rotation schedules for the 64-bit form. */
const ROT64: Record<string, Record<string, number>> = {
  "1": { fold: 33, s16a: 33, s16b: 35, s8: 33, s4: 15, s2: 13, s1: 25, f1: 33, f2: 33 },
  "2": { fold: 30, s16a: 29, s16b: 34, s8: 36, s4: 15, s2: 15, s1: 23, f1: 28, f2: 29 },
};

export function metrohash64(variant: MetroVariant, key: Uint8Array, seed: number): Uint8Array {
  const [k0, k1, k2, k3] = K[String(variant)]! as [bigint, bigint, bigint, bigint];
  const r = ROT64[String(variant)]!;
  const len = key.length;
  let p = 0;
  let hash = add(mul(add(BigInt(seed >>> 0), k2), k0), BigInt(len));

  if (len >= 32) {
    const v = [hash, hash, hash, hash];
    do {
      v[0] = add(v[0]!, mul(rd(key, p, 8), k0)); p += 8; v[0] = add(ror(v[0]!, 29), v[2]!);
      v[1] = add(v[1]!, mul(rd(key, p, 8), k1)); p += 8; v[1] = add(ror(v[1]!, 29), v[3]!);
      v[2] = add(v[2]!, mul(rd(key, p, 8), k2)); p += 8; v[2] = add(ror(v[2]!, 29), v[0]!);
      v[3] = add(v[3]!, mul(rd(key, p, 8), k3)); p += 8; v[3] = add(ror(v[3]!, 29), v[1]!);
    } while (p <= len - 32);
    v[2] = v[2]! ^ mul(ror(add(mul(add(v[0]!, v[3]!), k0), v[1]!), r.fold!), k1);
    v[3] = v[3]! ^ mul(ror(add(mul(add(v[1]!, v[2]!), k1), v[0]!), r.fold!), k0);
    v[0] = v[0]! ^ mul(ror(add(mul(add(v[0]!, v[2]!), k0), v[3]!), r.fold!), k1);
    v[1] = v[1]! ^ mul(ror(add(mul(add(v[1]!, v[3]!), k1), v[2]!), r.fold!), k0);
    hash = add(hash, v[0]! ^ v[1]!);
  }
  if (len - p >= 16) {
    // Variant 1 multiplies the two words by k0 and k1; variant 2 uses k2 for both.
    const ka = variant === 1 ? k0 : k2;
    const kb = variant === 1 ? k1 : k2;
    const kc = variant === 1 ? k1 : k3;
    const kd = variant === 1 ? k2 : k3;
    let v0 = add(hash, mul(rd(key, p, 8), ka)); p += 8; v0 = mul(ror(v0, r.s16a!), kc);
    let v1 = add(hash, mul(rd(key, p, 8), kb)); p += 8; v1 = mul(ror(v1, r.s16a!), kd);
    v0 ^= add(ror(mul(v0, k0), r.s16b!), v1);
    v1 ^= add(ror(mul(v1, k3), r.s16b!), v0);
    hash = add(hash, v1);
  }
  if (len - p >= 8) {
    hash = add(hash, mul(rd(key, p, 8), k3)); p += 8;
    hash ^= mul(ror(hash, r.s8!), k1);
  }
  if (len - p >= 4) {
    hash = add(hash, mul(rd(key, p, 4), k3)); p += 4;
    hash ^= mul(ror(hash, r.s4!), k1);
  }
  if (len - p >= 2) {
    hash = add(hash, mul(rd(key, p, 2), k3)); p += 2;
    hash ^= mul(ror(hash, r.s2!), k1);
  }
  if (len - p >= 1) {
    hash = add(hash, mul(rd(key, p, 1), k3));
    hash ^= mul(ror(hash, r.s1!), k1);
  }
  hash ^= ror(hash, r.f1!);
  hash = mul(hash, k0);
  hash ^= ror(hash, r.f2!);
  return writeLe([hash]);
}

/** The 128-bit form's schedule. Note variant 1's four folding rotations are not all equal. */
const ROT128: Record<string, { fold: readonly number[]; s: number; x: readonly number[]; fin: readonly number[] }> = {
  // `s` is one number because all five tail branches happen to share it within a variant.
  "1": { fold: [26, 26, 26, 30], s: 33, x: [17, 17, 20, 18, 24, 24], fin: [13, 37, 13, 37] },
  "2": { fold: [33, 33, 33, 33], s: 29, x: [29, 29, 29, 25, 30, 18], fin: [33, 33, 33, 33] },
};

export function metrohash128(variant: MetroVariant, key: Uint8Array, seed: number): Uint8Array {
  const [k0, k1, k2, k3] = K[String(variant)]! as [bigint, bigint, bigint, bigint];
  const r = ROT128[String(variant)]!;
  const len = key.length;
  let p = 0;
  const s = BigInt(seed >>> 0);
  const v = [add(mul(sub(s, k0), k3), BigInt(len)), add(mul(add(s, k1), k2), BigInt(len)), 0n, 0n];

  if (len >= 32) {
    v[2] = add(mul(add(s, k0), k2), BigInt(len));
    v[3] = add(mul(sub(s, k1), k3), BigInt(len));
    do {
      v[0] = add(v[0]!, mul(rd(key, p, 8), k0)); p += 8; v[0] = add(ror(v[0]!, 29), v[2]!);
      v[1] = add(v[1]!, mul(rd(key, p, 8), k1)); p += 8; v[1] = add(ror(v[1]!, 29), v[3]!);
      v[2] = add(v[2]!, mul(rd(key, p, 8), k2)); p += 8; v[2] = add(ror(v[2]!, 29), v[0]!);
      v[3] = add(v[3]!, mul(rd(key, p, 8), k3)); p += 8; v[3] = add(ror(v[3]!, 29), v[1]!);
    } while (p <= len - 32);
    v[2] = v[2]! ^ mul(ror(add(mul(add(v[0]!, v[3]!), k0), v[1]!), r.fold[0]!), k1);
    v[3] = v[3]! ^ mul(ror(add(mul(add(v[1]!, v[2]!), k1), v[0]!), r.fold[1]!), k0);
    v[0] = v[0]! ^ mul(ror(add(mul(add(v[0]!, v[2]!), k0), v[3]!), r.fold[2]!), k1);
    v[1] = v[1]! ^ mul(ror(add(mul(add(v[1]!, v[3]!), k1), v[2]!), r.fold[3]!), k0);
  }
  if (len - p >= 16) {
    v[0] = add(v[0]!, mul(rd(key, p, 8), k2)); p += 8; v[0] = mul(ror(v[0]!, r.s), k3);
    v[1] = add(v[1]!, mul(rd(key, p, 8), k2)); p += 8; v[1] = mul(ror(v[1]!, r.s), k3);
    v[0] = v[0]! ^ mul(ror(add(mul(v[0]!, k2), v[1]!), r.x[0]!), k1);
    v[1] = v[1]! ^ mul(ror(add(mul(v[1]!, k3), v[0]!), r.x[1]!), k0);
  }
  if (len - p >= 8) {
    v[0] = add(v[0]!, mul(rd(key, p, 8), k2)); p += 8; v[0] = mul(ror(v[0]!, r.s), k3);
    v[0] = v[0]! ^ mul(ror(add(mul(v[0]!, k2), v[1]!), r.x[2]!), k1);
  }
  if (len - p >= 4) {
    v[1] = add(v[1]!, mul(rd(key, p, 4), k2)); p += 4; v[1] = mul(ror(v[1]!, r.s), k3);
    v[1] = v[1]! ^ mul(ror(add(mul(v[1]!, k3), v[0]!), r.x[3]!), k0);
  }
  if (len - p >= 2) {
    v[0] = add(v[0]!, mul(rd(key, p, 2), k2)); p += 2; v[0] = mul(ror(v[0]!, r.s), k3);
    v[0] = v[0]! ^ mul(ror(add(mul(v[0]!, k2), v[1]!), r.x[4]!), k1);
  }
  if (len - p >= 1) {
    v[1] = add(v[1]!, mul(rd(key, p, 1), k2)); v[1] = mul(ror(v[1]!, r.s), k3);
    v[1] = v[1]! ^ mul(ror(add(mul(v[1]!, k3), v[0]!), r.x[5]!), k0);
  }
  v[0] = add(v[0]!, ror(add(mul(v[0]!, k0), v[1]!), r.fin[0]!));
  v[1] = add(v[1]!, ror(add(mul(v[1]!, k1), v[0]!), r.fin[1]!));
  v[0] = add(v[0]!, ror(add(mul(v[0]!, k2), v[1]!), r.fin[2]!));
  v[1] = add(v[1]!, ror(add(mul(v[1]!, k3), v[0]!), r.fin[3]!));
  return writeLe([v[0]!, v[1]!]);
}

/** MetroHash writes its state words little-endian, which is what the published byte strings show. */
function writeLe(words: readonly bigint[]): Uint8Array {
  const out = new Uint8Array(words.length * 8);
  for (let w = 0; w < words.length; w++) {
    for (let i = 0; i < 8; i++) out[8 * w + i] = Number((words[w]! >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

/** MetroHash at either width. `outputLen` is 8 or 16 bytes. */
export function metrohash(
  outputLen: 8 | 16,
  variant: MetroVariant,
  message: Uint8Array,
  seed = 0,
): Uint8Array {
  return outputLen === 8 ? metrohash64(variant, message, seed) : metrohash128(variant, message, seed);
}
