/**
 * rapidhash, at all four published versions: v1.0, v2.0, v2.2 and v3.0.
 *
 * `not-a-mac`. The seed is not a key.
 *
 * wyhash's successor, and the current default hash of several language runtimes. Like wyhash its whole
 * diffusion is a 128-bit multiply with both halves folded together -- no S-box, no round constants, no
 * permutation -- so `bigint` is unavoidable here: JavaScript cannot reach the high half of a 64x64
 * product any other way. See `wyhash.ts` for the shared primitive.
 *
 * ## The four versions are four different functions
 *
 * They are not refinements that agree on any input. Each changed the structure, and the differences are
 * small enough to be worth listing so that nobody "simplifies" one into another:
 *
 * | | v1.0 | v2.0 | v2.2 | v3.0 |
 * |---|---|---|---|---|
 * | default seed | `0xbdd89aa982704029` | 0 | 0 | 0 |
 * | secret words | 3 | 8 | 8 | 8 |
 * | length folded into the seed | yes | yes | yes | **no** |
 * | main body stride | 96, then 48 | 112, then 48 twice | 112, then 48 twice | 112 only |
 * | medium branch | none | `len <= 56` | `len <= 64` | none |
 * | 1-to-3-byte read | `readSmall` | `readSmall` | `readBytes`, plus `b` | `readSmallV3`, plus `b` |
 *
 * Two of those are one token apart and change every output: **v1.0 folds `secret[0]` into the mix where
 * v2 onwards folds `secret[2]`**, and **v2.0's third medium-branch mix uses `secret[0]` where v2.2's
 * uses `secret[1]`**. v2.0 and v2.2 are otherwise nearly identical, which is exactly why both are
 * offered rather than one being treated as a fix for the other -- someone holding a value from either
 * needs the one that produced it.
 *
 * ## What stands behind this, and it is now strong
 *
 * All four are checked against `komiya-atsushi/rapidhash-js`'s generated test vectors, which its
 * `packages/gen-test/` produces by **compiling the reference C at a named git revision** and hashing a
 * fixed corpus. Each version's fixture records the revision it came from. That makes this a
 * differential check against the reference implementation rather than a self-consistency test, and it
 * replaces the earlier position -- recorded in `NO_PUBLISHED_VECTOR` and now deleted -- that rapidhash
 * had no reachable published value at all. It did; it was in a JavaScript port nobody had looked at.
 *
 * The coverage is 32 short vectors per version across four seeds (byte lengths 0, 1, 2, 3, 13 and 27,
 * including multi-byte UTF-8) plus 43 long ones at every branch boundary and its neighbours -- 4, 8,
 * 16, 32, 48, 56, 64, 80, 96, 112, 224 and 336, each at -1, exact and +1. Those +/-1 pairs are the
 * point: every one of the differences in the table above is a boundary, and only a length either side
 * of it can see them.
 *
 * ## Two things deliberately not done
 *
 * **`protected` is implemented and not offered.** `RAPIDHASH_PROTECTED` swaps `rapid_mum` for a form
 * that XORs its operands back in, resisting a multiply-by-zero collapse. It is a compile-time flag that
 * is not the default anywhere, it produces unrelated output, and offering it would double a dropdown to
 * cover a case almost nobody has a value from. `rapidMumBehaviour` below reaches it, so registering it
 * later is a metadata edit.
 *
 * **None of the four streams.** Every version reads `p + i - 16` and `p + i - 8` -- the last sixteen
 * bytes -- in its final step, so the answer depends on the end of the message and no incremental API
 * can produce it without buffering the whole input. The Rust crate exposes a `Hasher`, which is Rust's
 * streaming trait, but it buffers internally for exactly this reason; there is no version of rapidhash
 * that is genuinely a streaming construction. The tool therefore uses `bufferedHasher`, like the other
 * read-from-the-end families here.
 */

const MASK = (1n << 64n) - 1n;
const u64 = (x: bigint): bigint => x & MASK;

/** The `fast` rapid_mum: the 128-bit product with its halves XORed together. */
const mixFast = (a: bigint, b: bigint): bigint => {
  const m = a * b;
  return u64(u64(m) ^ (m >> 64n));
};

/** The `protected` rapid_mum: the same, with both operands folded back in. */
const mixProtected = (a: bigint, b: bigint): bigint => {
  const m = a * b;
  return u64(u64(m) ^ (m >> 64n) ^ a ^ b);
};

export type RapidMumBehaviour = "fast" | "protected";

const read64 = (p: Uint8Array, at: number): bigint => {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(p[at + i]!);
  return v;
};

const read32 = (p: Uint8Array, at: number): bigint => {
  let v = 0n;
  for (let i = 3; i >= 0; i--) v = (v << 8n) | BigInt(p[at + i]!);
  return v;
};

/** Two 32-bit reads packed high/low. v1.0 only. */
const read32x2 = (p: Uint8Array, a: number, b: number): bigint => u64((read32(p, a) << 32n) | read32(p, b));

/** v1.0 and v2.0's 1-to-3-byte gather: three bytes at bits 56, 32 and 0. */
const readSmall = (p: Uint8Array, at: number, k: number): bigint =>
  u64((BigInt(p[at]!) << 56n) | (BigInt(p[at + (k >> 1)]!) << 32n) | BigInt(p[at + k - 1]!));

/** v2.2's: two bytes at bits 56 and 0. */
const readBytes = (p: Uint8Array, a: number, b: number): bigint =>
  u64((BigInt(p[a]!) << 56n) | BigInt(p[b]!));

/** v3.0's: the first byte at bit 45, which is the same value the reference's byte-splicing produces. */
const readSmallV3 = (p: Uint8Array, len: number): bigint =>
  u64((BigInt(p[0]!) << 45n) | BigInt(p[len - 1]!));

const SECRET_V1: readonly bigint[] = [0x2d358dccaa6c78a5n, 0x8bb84b93962eacc9n, 0x4b33a62ed433d4a3n];

/** v2.0, v2.2 and v3.0 share this. */
const SECRET_V2: readonly bigint[] = [
  0x2d358dccaa6c78a5n,
  0x8bb84b93962eacc9n,
  0x4b33a62ed433d4a3n,
  0x4d5a2da51de1aa47n,
  0xa0761d6478bd642fn,
  0xe7037ed1a0b428dbn,
  0x90ed1765281c388cn,
  0xaaaaaaaaaaaaaaaan,
];

export type RapidhashVersion = "v1.0" | "v2.0" | "v2.2" | "v3.0";

export interface RapidhashVersionMeta {
  readonly id: RapidhashVersion;
  readonly label: string;
  /** The seed used when none is supplied. v1.0's is not zero. */
  readonly defaultSeed: bigint;
  readonly secretWords: number;
}

export const RAPIDHASH_VERSIONS: readonly RapidhashVersionMeta[] = [
  { id: "v1.0", label: "rapidhash v1.0", defaultSeed: 0xbdd89aa982704029n, secretWords: 3 },
  { id: "v2.0", label: "rapidhash v2.0", defaultSeed: 0n, secretWords: 8 },
  { id: "v2.2", label: "rapidhash v2.2", defaultSeed: 0n, secretWords: 8 },
  { id: "v3.0", label: "rapidhash v3.0", defaultSeed: 0n, secretWords: 8 },
];

export const RAPIDHASH_DEFAULT_VERSION: RapidhashVersion = "v3.0";

/** v1.0 and v2's epilogue: length into the first factor. */
function epilogueV1V2(
  a: bigint,
  b: bigint,
  secretA: bigint,
  secretB: bigint,
  len: bigint,
  behaviour: RapidMumBehaviour,
): bigint {
  const m0 = a * b;
  if (behaviour === "protected") {
    const a1 = u64(u64(m0) ^ secretA ^ len ^ a);
    const b1 = u64((m0 >> 64n) ^ secretB ^ b);
    const m1 = a1 * b1;
    return u64(u64(m1) ^ (m1 >> 64n) ^ a1 ^ b1);
  }
  const m1 = u64(u64(m0) ^ secretA ^ len) * u64((m0 >> 64n) ^ secretB);
  return u64(u64(m1) ^ (m1 >> 64n));
}

/** v3.0's: `secret[7]` alone in the first factor, and the length in the second. */
function epilogueV3(
  a: bigint,
  b: bigint,
  secret: readonly bigint[],
  i: bigint,
  behaviour: RapidMumBehaviour,
): bigint {
  const m0 = a * b;
  if (behaviour === "protected") {
    const a1 = u64(u64(m0) ^ secret[7]! ^ a);
    const b1 = u64((m0 >> 64n) ^ secret[1]! ^ i ^ b);
    const m1 = a1 * b1;
    return u64(u64(m1) ^ (m1 >> 64n) ^ a1 ^ b1);
  }
  const m1 = u64(u64(m0) ^ secret[7]!) * u64((m0 >> 64n) ^ secret[1]! ^ i);
  return u64(u64(m1) ^ (m1 >> 64n));
}

function rapidhashV1(p: Uint8Array, seedIn: bigint, behaviour: RapidMumBehaviour): bigint {
  const mix = behaviour === "protected" ? mixProtected : mixFast;
  const s = SECRET_V1;
  const len = p.length;
  const lenBI = BigInt(len);
  let seed = u64(seedIn ^ mix(u64(seedIn ^ s[0]!), s[1]!) ^ lenBI);
  let a: bigint;
  let b: bigint;

  if (len <= 16) {
    if (len >= 4) {
      const last = len - 4;
      a = read32x2(p, 0, last);
      // The one place a shift amount is itself computed from the length.
      const delta = (len & 24) >> (len >> 3);
      b = read32x2(p, delta, last - delta);
    } else if (len > 0) {
      a = readSmall(p, 0, len);
      b = 0n;
    } else {
      a = 0n;
      b = 0n;
    }
  } else {
    let i = len;
    let at = 0;
    if (i > 48) {
      let see1 = seed;
      let see2 = seed;
      while (i >= 96) {
        seed = mix(u64(read64(p, at) ^ s[0]!), u64(read64(p, at + 8) ^ seed));
        see1 = mix(u64(read64(p, at + 16) ^ s[1]!), u64(read64(p, at + 24) ^ see1));
        see2 = mix(u64(read64(p, at + 32) ^ s[2]!), u64(read64(p, at + 40) ^ see2));
        seed = mix(u64(read64(p, at + 48) ^ s[0]!), u64(read64(p, at + 56) ^ seed));
        see1 = mix(u64(read64(p, at + 64) ^ s[1]!), u64(read64(p, at + 72) ^ see1));
        see2 = mix(u64(read64(p, at + 80) ^ s[2]!), u64(read64(p, at + 88) ^ see2));
        at += 96;
        i -= 96;
      }
      if (i >= 48) {
        seed = mix(u64(read64(p, at) ^ s[0]!), u64(read64(p, at + 8) ^ seed));
        see1 = mix(u64(read64(p, at + 16) ^ s[1]!), u64(read64(p, at + 24) ^ see1));
        see2 = mix(u64(read64(p, at + 32) ^ s[2]!), u64(read64(p, at + 40) ^ see2));
        at += 48;
        i -= 48;
      }
      seed = u64(seed ^ see1 ^ see2);
    }
    if (i > 16) {
      // Note the extra `^ s[1]` on the second operand -- v1.0 only.
      seed = mix(u64(read64(p, at) ^ s[2]!), u64(read64(p, at + 8) ^ seed ^ s[1]!));
      if (i > 32) {
        seed = mix(u64(read64(p, at + 16) ^ s[2]!), u64(read64(p, at + 24) ^ seed));
      }
    }
    a = read64(p, at + i - 16);
    b = read64(p, at + i - 8);
  }
  a = u64(a ^ s[1]!);
  b = u64(b ^ seed);
  return epilogueV1V2(a, b, s[0]!, s[1]!, lenBI, behaviour);
}

/** v2.0 and v2.2, which differ in three places -- all flagged inline. */
function rapidhashV2(
  p: Uint8Array,
  seedIn: bigint,
  behaviour: RapidMumBehaviour,
  point2: boolean,
): bigint {
  const mix = behaviour === "protected" ? mixProtected : mixFast;
  const s = SECRET_V2;
  const len = p.length;
  const lenBI = BigInt(len);
  let seed = u64(seedIn ^ mix(u64(seedIn ^ s[2]!), s[1]!) ^ lenBI);
  let a: bigint;
  let b: bigint;

  // Difference 1: the medium branch's upper bound. 56 at v2.0, 64 at v2.2.
  const mediumLimit = point2 ? 64 : 56;

  if (len <= 16) {
    if (len >= 4) {
      if (len >= 8) {
        a = read64(p, 0);
        b = read64(p, len - 8);
      } else {
        a = read32(p, 0);
        b = read32(p, len - 4);
      }
    } else if (len > 0) {
      // Difference 2: v2.2 reads two bytes and sets `b`; v2.0 reads three and leaves `b` zero.
      if (point2) {
        a = readBytes(p, 0, len - 1);
        b = BigInt(p[len >> 1]!);
      } else {
        a = readSmall(p, 0, len);
        b = 0n;
      }
    } else {
      a = 0n;
      b = 0n;
    }
  } else if (len > mediumLimit) {
    let i = len;
    let at = 0;
    let see1 = seed;
    let see2 = seed;
    let see3456 = 0n;
    if (i >= 112) {
      let see3 = seed;
      let see4 = seed;
      let see5 = seed;
      let see6 = seed;
      do {
        seed = mix(u64(read64(p, at) ^ s[0]!), u64(read64(p, at + 8) ^ seed));
        see1 = mix(u64(read64(p, at + 16) ^ s[1]!), u64(read64(p, at + 24) ^ see1));
        see2 = mix(u64(read64(p, at + 32) ^ s[2]!), u64(read64(p, at + 40) ^ see2));
        see3 = mix(u64(read64(p, at + 48) ^ s[3]!), u64(read64(p, at + 56) ^ see3));
        see4 = mix(u64(read64(p, at + 64) ^ s[4]!), u64(read64(p, at + 72) ^ see4));
        see5 = mix(u64(read64(p, at + 80) ^ s[5]!), u64(read64(p, at + 88) ^ see5));
        see6 = mix(u64(read64(p, at + 96) ^ s[6]!), u64(read64(p, at + 104) ^ see6));
        at += 112;
        i -= 112;
      } while (i >= 112);
      see3456 = u64(see3 ^ see4 ^ see5 ^ see6);
    }
    // Up to two 48-byte blocks, not a loop -- the length is already under 112 here.
    if (i >= 48) {
      seed = mix(u64(read64(p, at) ^ s[0]!), u64(read64(p, at + 8) ^ seed));
      see1 = mix(u64(read64(p, at + 16) ^ s[1]!), u64(read64(p, at + 24) ^ see1));
      see2 = mix(u64(read64(p, at + 32) ^ s[2]!), u64(read64(p, at + 40) ^ see2));
      at += 48;
      i -= 48;
      if (i >= 48) {
        seed = mix(u64(read64(p, at) ^ s[0]!), u64(read64(p, at + 8) ^ seed));
        see1 = mix(u64(read64(p, at + 16) ^ s[1]!), u64(read64(p, at + 24) ^ see1));
        see2 = mix(u64(read64(p, at + 32) ^ s[2]!), u64(read64(p, at + 40) ^ see2));
        at += 48;
        i -= 48;
      }
    }
    seed = u64(seed ^ see1 ^ see2 ^ see3456);
    if (i > 16) {
      seed = mix(u64(read64(p, at) ^ s[2]!), u64(read64(p, at + 8) ^ seed));
      if (i > 32) {
        seed = mix(u64(read64(p, at + 16) ^ s[2]!), u64(read64(p, at + 24) ^ seed));
      }
    }
    a = read64(p, at + i - 16);
    b = read64(p, at + i - 8);
  } else {
    seed = mix(u64(read64(p, 0) ^ s[0]!), u64(read64(p, 8) ^ seed));
    if (len > 32) {
      seed = mix(u64(read64(p, 16) ^ s[1]!), u64(read64(p, 24) ^ seed));
      if (len > 48) {
        // Difference 3: v2.0 uses secret[0] here and v2.2 uses secret[1]. One index, every output.
        seed = mix(u64(read64(p, 32) ^ (point2 ? s[1]! : s[0]!)), u64(read64(p, 40) ^ seed));
      }
    }
    a = read64(p, len - 16);
    b = read64(p, len - 8);
  }
  a = u64(a ^ s[1]!);
  b = u64(b ^ seed);
  return epilogueV1V2(a, b, s[7]!, s[1]!, lenBI, behaviour);
}

function rapidhashV3(p: Uint8Array, seedIn: bigint, behaviour: RapidMumBehaviour): bigint {
  const mix = behaviour === "protected" ? mixProtected : mixFast;
  const s = SECRET_V2;
  const len = p.length;
  const lenBI = BigInt(len);
  // v3.0 does *not* fold the length in here, unlike v1 and v2.
  let seed = u64(seedIn ^ mix(u64(seedIn ^ s[2]!), s[1]!));
  let a: bigint;
  let b: bigint;
  let i = len;
  let counted: bigint;

  if (len <= 16) {
    counted = lenBI;
    if (len >= 4) {
      seed = u64(seed ^ lenBI);
      if (len >= 8) {
        a = read64(p, 0);
        b = read64(p, len - 8);
      } else {
        a = read32(p, 0);
        b = read32(p, len - 4);
      }
    } else if (len > 0) {
      a = readSmallV3(p, len);
      b = BigInt(p[len >> 1]!);
    } else {
      a = 0n;
      b = 0n;
    }
  } else {
    let at = 0;
    if (i > 112) {
      let see1 = seed;
      let see2 = seed;
      let see3 = seed;
      let see4 = seed;
      let see5 = seed;
      let see6 = seed;
      do {
        seed = mix(u64(read64(p, at) ^ s[0]!), u64(read64(p, at + 8) ^ seed));
        see1 = mix(u64(read64(p, at + 16) ^ s[1]!), u64(read64(p, at + 24) ^ see1));
        see2 = mix(u64(read64(p, at + 32) ^ s[2]!), u64(read64(p, at + 40) ^ see2));
        see3 = mix(u64(read64(p, at + 48) ^ s[3]!), u64(read64(p, at + 56) ^ see3));
        see4 = mix(u64(read64(p, at + 64) ^ s[4]!), u64(read64(p, at + 72) ^ see4));
        see5 = mix(u64(read64(p, at + 80) ^ s[5]!), u64(read64(p, at + 88) ^ see5));
        see6 = mix(u64(read64(p, at + 96) ^ s[6]!), u64(read64(p, at + 104) ^ see6));
        at += 112;
        i -= 112;
      } while (i > 112);
      // The six lanes fold in a specific order rather than a straight reduction.
      seed = u64(seed ^ see1);
      see2 = u64(see2 ^ see3);
      see4 = u64(see4 ^ see5);
      seed = u64(seed ^ see6);
      see2 = u64(see2 ^ see4);
      seed = u64(seed ^ see2);
    }
    counted = BigInt(i);
    if (i > 16) {
      seed = mix(u64(read64(p, at) ^ s[2]!), u64(read64(p, at + 8) ^ seed));
      if (i > 32) {
        seed = mix(u64(read64(p, at + 16) ^ s[2]!), u64(read64(p, at + 24) ^ seed));
        if (i > 48) {
          seed = mix(u64(read64(p, at + 32) ^ s[1]!), u64(read64(p, at + 40) ^ seed));
          if (i > 64) {
            seed = mix(u64(read64(p, at + 48) ^ s[1]!), u64(read64(p, at + 56) ^ seed));
            if (i > 80) {
              seed = mix(u64(read64(p, at + 64) ^ s[2]!), u64(read64(p, at + 72) ^ seed));
              if (i > 96) {
                seed = mix(u64(read64(p, at + 80) ^ s[1]!), u64(read64(p, at + 88) ^ seed));
              }
            }
          }
        }
      }
    }
    a = u64(read64(p, at + i - 16) ^ counted);
    b = read64(p, at + i - 8);
  }
  a = u64(a ^ s[1]!);
  b = u64(b ^ seed);
  return epilogueV3(a, b, s, counted, behaviour);
}

export function requireRapidhashVersion(id: string): RapidhashVersionMeta {
  const found = RAPIDHASH_VERSIONS.find((v) => v.id === id);
  if (!found) throw new Error(`rapidhash: unknown version "${id}"`);
  return found;
}

/**
 * rapidhash at the given version.
 *
 * The seed defaults to the version's own default, which is **not zero for v1.0** -- passing zero there
 * gives a different answer from calling the reference with no seed at all.
 */
export function rapidhash(
  message: Uint8Array,
  version: RapidhashVersion = RAPIDHASH_DEFAULT_VERSION,
  seed?: bigint,
  behaviour: RapidMumBehaviour = "fast",
): bigint {
  const meta = requireRapidhashVersion(version);
  const s = seed ?? meta.defaultSeed;
  switch (version) {
    case "v1.0":
      return rapidhashV1(message, s, behaviour);
    case "v2.0":
      return rapidhashV2(message, s, behaviour, false);
    case "v2.2":
      return rapidhashV2(message, s, behaviour, true);
    case "v3.0":
      return rapidhashV3(message, s, behaviour);
    default: {
      const never: never = version;
      throw new Error(`rapidhash: no implementation for ${String(never)}`);
    }
  }
}

/** Eight bytes, most significant first -- the spelling a digest is compared in. */
export function rapidhashBytes(
  message: Uint8Array,
  version: RapidhashVersion = RAPIDHASH_DEFAULT_VERSION,
  seed?: bigint,
  behaviour: RapidMumBehaviour = "fast",
): Uint8Array {
  const out = new Uint8Array(8);
  let value = rapidhash(message, version, seed, behaviour);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}
