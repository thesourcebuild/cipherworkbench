/**
 * Camellia, RFC 3713. A 128-bit block cipher with 128-, 192- and 256-bit keys.
 *
 * Here for the same reason DES is: no pure-ESM library this project can use offers it, and it is not
 * obscure. Camellia is a NESSIE selection and a CRYPTREC standard, `openssl enc -camellia-256-cbc`
 * has existed for twenty years, and the TLS cipher suites in RFC 5932 mean it turns up in captured
 * sessions and in older Japanese and European deployments.
 *
 * Four things to know before touching this.
 *
 * **The tables were parsed out of the RFC, not typed in.** SBOX1 and both subkey schedules were
 * extracted from RFC 3713's own text by a script and pasted here once, on the same principle as the
 * RSA `DigestInfo` prefixes: a 256-entry table typed by hand produces a cipher that round-trips
 * perfectly and matches nothing in the world, and no round-trip test can see it. What checks them on
 * every run is `tests/algos-camellia-aria.test.ts`, which compares all five modes against OpenSSL's
 * `camellia-128/192/256-*` and reproduces the three vectors in the RFC's appendix A.
 *
 * **The other three S-boxes are derived.** RFC 3713 defines SBOX2, SBOX3 and SBOX4 as rotations of
 * SBOX1 rather than as separate tables, so they are computed at module load. Three fewer tables to
 * get wrong.
 *
 * **The 128-bit schedule really is asymmetric.** `k9` is the top half of `KA <<< 45` while `k10` is
 * the *bottom* half of `KL <<< 60` -- every other pair in that listing takes both halves of one
 * rotation. It looks like a typo in the RFC and is not; the reference implementation does the same.
 * Because the schedule is parsed from the RFC text, this repo cannot quietly "fix" it.
 *
 * **Decryption is the same routine with the subkeys reversed.** Section 2.3.3 spells out the swaps;
 * `reverseSchedule` performs them, so there is one Feistel loop rather than two.
 */
import type { BlockCipher } from "./blockmodes";

export const CAMELLIA_BLOCK_SIZE = 16;

/** From RFC 3713 section 2.4.1, parsed from the RFC's decimal table. SBOX1[0x3d] is 86. */
const SBOX1 = new Uint8Array([
  0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
  0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
  0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
  0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
  0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
  0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
  0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
  0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
  0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
  0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
  0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
  0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
  0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
  0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
  0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
  0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e,
]);

const rotl8 = (x: number, n: number): number => ((x << n) | (x >>> (8 - n))) & 0xff;

/** SBOX2[x] = SBOX1[x] <<< 1, SBOX3[x] = SBOX1[x] <<< 7, SBOX4[x] = SBOX1[x <<< 1]. */
const SBOX2 = new Uint8Array(256);
const SBOX3 = new Uint8Array(256);
const SBOX4 = new Uint8Array(256);
for (let x = 0; x < 256; x++) {
  SBOX2[x] = rotl8(SBOX1[x]!, 1);
  SBOX3[x] = rotl8(SBOX1[x]!, 7);
  SBOX4[x] = SBOX1[rotl8(x, 1)]!;
}

/**
 * Sigma1..Sigma6, the constants the key schedule feeds to F as if they were subkeys.
 *
 * Each is a 64-bit value written as its two 32-bit halves, which is how every 64-bit quantity is
 * carried here -- see the note on `f`.
 */
const SIGMA: readonly (readonly [number, number])[] = [
  [0xa09e667f, 0x3bcc908b],
  [0xb67ae858, 0x4caa73b2],
  [0xc6ef372f, 0xe94f82be],
  [0x54ff53a5, 0xf1d36f1c],
  [0x10e527fa, 0xde682d1d],
  [0xb05688c2, 0xb3e6c1fd],
];

/**
 * A 64-bit value as `[high 32 bits, low 32 bits]`.
 *
 * `bigint` was the other option and is what `xxhash3.ts` uses. It is not the right trade here:
 * Camellia's F-function decomposes its input into bytes and recombines them, which is native work
 * for two 32-bit words and allocation-plus-masking for a bigint, and unlike a hash a cipher is
 * asked to process the whole input twice in a round trip.
 */
type Word64 = readonly [number, number];

/** The F-function, RFC 3713 section 2.4.1. */
function f(xhi: number, xlo: number, khi: number, klo: number): Word64 {
  const hi = xhi ^ khi;
  const lo = xlo ^ klo;

  const t1 = SBOX1[(hi >>> 24) & 0xff]!;
  const t2 = SBOX2[(hi >>> 16) & 0xff]!;
  const t3 = SBOX3[(hi >>> 8) & 0xff]!;
  const t4 = SBOX4[hi & 0xff]!;
  const t5 = SBOX2[(lo >>> 24) & 0xff]!;
  const t6 = SBOX3[(lo >>> 16) & 0xff]!;
  const t7 = SBOX4[(lo >>> 8) & 0xff]!;
  const t8 = SBOX1[lo & 0xff]!;

  const y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
  const y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
  const y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
  const y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
  const y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
  const y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
  const y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
  const y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

  return [
    ((y1 << 24) | (y2 << 16) | (y3 << 8) | y4) >>> 0,
    ((y5 << 24) | (y6 << 16) | (y7 << 8) | y8) >>> 0,
  ];
}

const rotl32 = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

/** FL, section 2.4.2. */
function fl(xhi: number, xlo: number, khi: number, klo: number): Word64 {
  const x2 = (xlo ^ rotl32(xhi & khi, 1)) >>> 0;
  const x1 = (xhi ^ (x2 | klo)) >>> 0;
  return [x1, x2];
}

/** FLINV, the inverse of FL. The two statements are the same as FL's, in the other order. */
function flinv(yhi: number, ylo: number, khi: number, klo: number): Word64 {
  const y1 = (yhi ^ (ylo | klo)) >>> 0;
  const y2 = (ylo ^ rotl32(y1 & khi, 1)) >>> 0;
  return [y1, y2];
}

/** One entry of the RFC's subkey listing: which 128-bit value, rotated how far, and which half. */
interface SubkeySpec {
  name: string;
  from: "KL" | "KR" | "KA" | "KB";
  rot: number;
  half: "hi" | "lo";
}

const SCHEDULE_128: readonly SubkeySpec[] = [
  { name: "kw1", from: "KL", rot: 0, half: "hi" },
  { name: "kw2", from: "KL", rot: 0, half: "lo" },
  { name: "k1", from: "KA", rot: 0, half: "hi" },
  { name: "k2", from: "KA", rot: 0, half: "lo" },
  { name: "k3", from: "KL", rot: 15, half: "hi" },
  { name: "k4", from: "KL", rot: 15, half: "lo" },
  { name: "k5", from: "KA", rot: 15, half: "hi" },
  { name: "k6", from: "KA", rot: 15, half: "lo" },
  { name: "ke1", from: "KA", rot: 30, half: "hi" },
  { name: "ke2", from: "KA", rot: 30, half: "lo" },
  { name: "k7", from: "KL", rot: 45, half: "hi" },
  { name: "k8", from: "KL", rot: 45, half: "lo" },
  { name: "k9", from: "KA", rot: 45, half: "hi" },
  { name: "k10", from: "KL", rot: 60, half: "lo" },
  { name: "k11", from: "KA", rot: 60, half: "hi" },
  { name: "k12", from: "KA", rot: 60, half: "lo" },
  { name: "ke3", from: "KL", rot: 77, half: "hi" },
  { name: "ke4", from: "KL", rot: 77, half: "lo" },
  { name: "k13", from: "KL", rot: 94, half: "hi" },
  { name: "k14", from: "KL", rot: 94, half: "lo" },
  { name: "k15", from: "KA", rot: 94, half: "hi" },
  { name: "k16", from: "KA", rot: 94, half: "lo" },
  { name: "k17", from: "KL", rot: 111, half: "hi" },
  { name: "k18", from: "KL", rot: 111, half: "lo" },
  { name: "kw3", from: "KA", rot: 111, half: "hi" },
  { name: "kw4", from: "KA", rot: 111, half: "lo" },
];

const SCHEDULE_192_256: readonly SubkeySpec[] = [
  { name: "kw1", from: "KL", rot: 0, half: "hi" },
  { name: "kw2", from: "KL", rot: 0, half: "lo" },
  { name: "k1", from: "KB", rot: 0, half: "hi" },
  { name: "k2", from: "KB", rot: 0, half: "lo" },
  { name: "k3", from: "KR", rot: 15, half: "hi" },
  { name: "k4", from: "KR", rot: 15, half: "lo" },
  { name: "k5", from: "KA", rot: 15, half: "hi" },
  { name: "k6", from: "KA", rot: 15, half: "lo" },
  { name: "ke1", from: "KR", rot: 30, half: "hi" },
  { name: "ke2", from: "KR", rot: 30, half: "lo" },
  { name: "k7", from: "KB", rot: 30, half: "hi" },
  { name: "k8", from: "KB", rot: 30, half: "lo" },
  { name: "k9", from: "KL", rot: 45, half: "hi" },
  { name: "k10", from: "KL", rot: 45, half: "lo" },
  { name: "k11", from: "KA", rot: 45, half: "hi" },
  { name: "k12", from: "KA", rot: 45, half: "lo" },
  { name: "ke3", from: "KL", rot: 60, half: "hi" },
  { name: "ke4", from: "KL", rot: 60, half: "lo" },
  { name: "k13", from: "KR", rot: 60, half: "hi" },
  { name: "k14", from: "KR", rot: 60, half: "lo" },
  { name: "k15", from: "KB", rot: 60, half: "hi" },
  { name: "k16", from: "KB", rot: 60, half: "lo" },
  { name: "k17", from: "KL", rot: 77, half: "hi" },
  { name: "k18", from: "KL", rot: 77, half: "lo" },
  { name: "ke5", from: "KA", rot: 77, half: "hi" },
  { name: "ke6", from: "KA", rot: 77, half: "lo" },
  { name: "k19", from: "KR", rot: 94, half: "hi" },
  { name: "k20", from: "KR", rot: 94, half: "lo" },
  { name: "k21", from: "KA", rot: 94, half: "hi" },
  { name: "k22", from: "KA", rot: 94, half: "lo" },
  { name: "k23", from: "KL", rot: 111, half: "hi" },
  { name: "k24", from: "KL", rot: 111, half: "lo" },
  { name: "kw3", from: "KB", rot: 111, half: "hi" },
  { name: "kw4", from: "KB", rot: 111, half: "lo" },
];

/** A 128-bit value as four 32-bit words, most significant first. */
type Word128 = readonly [number, number, number, number];

/** Left-rotates a 128-bit value. The four words are treated as one cyclic register. */
function rotl128(w: Word128, n: number): Word128 {
  const words = n >>> 5;
  const bits = n & 31;
  const out: number[] = [];
  for (let i = 0; i < 4; i++) {
    const a = w[(i + words) & 3]!;
    if (bits === 0) {
      out.push(a >>> 0);
    } else {
      const b = w[(i + words + 1) & 3]!;
      out.push(((a << bits) | (b >>> (32 - bits))) >>> 0);
    }
  }
  return out as unknown as Word128;
}

function readWord(bytes: Uint8Array, at: number): number {
  return (
    ((bytes[at]! << 24) | (bytes[at + 1]! << 16) | (bytes[at + 2]! << 8) | bytes[at + 3]!) >>> 0
  );
}

/**
 * KL and KR, RFC 3713 section 2.2.
 *
 * The 192-bit case is the interesting one: KR's lower half is the bit-complement of its upper half,
 * which is how a 24-byte key fills a 32-byte schedule. Getting that wrong leaves 128- and 256-bit
 * keys perfectly correct, which is why the tests carry a vector for all three sizes rather than one.
 */
function keyHalves(key: Uint8Array): { KL: Word128; KR: Word128 } {
  const KL: Word128 = [readWord(key, 0), readWord(key, 4), readWord(key, 8), readWord(key, 12)];

  if (key.length === 16) return { KL, KR: [0, 0, 0, 0] };
  if (key.length === 32) {
    return {
      KL,
      KR: [readWord(key, 16), readWord(key, 20), readWord(key, 24), readWord(key, 28)],
    };
  }

  const hi = readWord(key, 16);
  const lo = readWord(key, 20);
  return { KL, KR: [hi, lo, ~hi >>> 0, ~lo >>> 0] };
}

interface Schedule {
  rounds: 18 | 24;
  /** k1..k18 or k1..k24, zero-indexed. */
  k: readonly Word64[];
  /** ke1..ke4 or ke1..ke6. */
  ke: readonly Word64[];
  /** kw1..kw4. */
  kw: readonly Word64[];
}

function expandKey(key: Uint8Array): Schedule {
  const { KL, KR } = keyHalves(key);

  // KA, then KB. Both are four F-applications over the halves of KL ^ KR.
  let d1hi = (KL[0] ^ KR[0]) >>> 0;
  let d1lo = (KL[1] ^ KR[1]) >>> 0;
  let d2hi = (KL[2] ^ KR[2]) >>> 0;
  let d2lo = (KL[3] ^ KR[3]) >>> 0;

  let out = f(d1hi, d1lo, SIGMA[0]![0], SIGMA[0]![1]);
  d2hi = (d2hi ^ out[0]) >>> 0;
  d2lo = (d2lo ^ out[1]) >>> 0;
  out = f(d2hi, d2lo, SIGMA[1]![0], SIGMA[1]![1]);
  d1hi = (d1hi ^ out[0]) >>> 0;
  d1lo = (d1lo ^ out[1]) >>> 0;

  d1hi = (d1hi ^ KL[0]) >>> 0;
  d1lo = (d1lo ^ KL[1]) >>> 0;
  d2hi = (d2hi ^ KL[2]) >>> 0;
  d2lo = (d2lo ^ KL[3]) >>> 0;

  out = f(d1hi, d1lo, SIGMA[2]![0], SIGMA[2]![1]);
  d2hi = (d2hi ^ out[0]) >>> 0;
  d2lo = (d2lo ^ out[1]) >>> 0;
  out = f(d2hi, d2lo, SIGMA[3]![0], SIGMA[3]![1]);
  d1hi = (d1hi ^ out[0]) >>> 0;
  d1lo = (d1lo ^ out[1]) >>> 0;

  const KA: Word128 = [d1hi, d1lo, d2hi, d2lo];

  d1hi = (KA[0] ^ KR[0]) >>> 0;
  d1lo = (KA[1] ^ KR[1]) >>> 0;
  d2hi = (KA[2] ^ KR[2]) >>> 0;
  d2lo = (KA[3] ^ KR[3]) >>> 0;

  out = f(d1hi, d1lo, SIGMA[4]![0], SIGMA[4]![1]);
  d2hi = (d2hi ^ out[0]) >>> 0;
  d2lo = (d2lo ^ out[1]) >>> 0;
  out = f(d2hi, d2lo, SIGMA[5]![0], SIGMA[5]![1]);
  d1hi = (d1hi ^ out[0]) >>> 0;
  d1lo = (d1lo ^ out[1]) >>> 0;

  // KB is used only for 192- and 256-bit keys, and computing it regardless costs two F-calls.
  const KB: Word128 = [d1hi, d1lo, d2hi, d2lo];

  const parts: Record<SubkeySpec["from"], Word128> = { KL, KR, KA, KB };
  const specs = key.length === 16 ? SCHEDULE_128 : SCHEDULE_192_256;
  const named = new Map<string, Word64>();
  for (const spec of specs) {
    const rotated = rotl128(parts[spec.from], spec.rot);
    named.set(
      spec.name,
      spec.half === "hi" ? [rotated[0], rotated[1]] : [rotated[2], rotated[3]],
    );
  }

  const take = (prefix: string, count: number): Word64[] => {
    const list: Word64[] = [];
    for (let i = 1; i <= count; i++) {
      const value = named.get(`${prefix}${i}`);
      if (!value) throw new Error(`Camellia schedule is missing ${prefix}${i}`);
      list.push(value);
    }
    return list;
  };

  const rounds: 18 | 24 = key.length === 16 ? 18 : 24;
  return {
    rounds,
    k: take("k", rounds),
    ke: take("ke", rounds === 18 ? 4 : 6),
    kw: take("kw", 4),
  };
}

/**
 * The decryption schedule, RFC 3713 section 2.3.3.
 *
 * The RFC lists the swaps pair by pair -- k1 with k18, ke1 with ke4, kw1 with kw3 -- which is a
 * reversal of each list plus a swap of the two whitening pairs. Writing it as the reversal keeps it
 * correct for both round counts at once; the enumerated form would be two tables to maintain.
 */
function reverseSchedule(s: Schedule): Schedule {
  return {
    rounds: s.rounds,
    k: [...s.k].reverse(),
    ke: [...s.ke].reverse(),
    kw: [s.kw[2]!, s.kw[3]!, s.kw[0]!, s.kw[1]!],
  };
}

function crypt(src: Uint8Array, s: Schedule, dst: Uint8Array): void {
  let d1hi = readWord(src, 0);
  let d1lo = readWord(src, 4);
  let d2hi = readWord(src, 8);
  let d2lo = readWord(src, 12);

  // Prewhitening.
  d1hi = (d1hi ^ s.kw[0]![0]) >>> 0;
  d1lo = (d1lo ^ s.kw[0]![1]) >>> 0;
  d2hi = (d2hi ^ s.kw[1]![0]) >>> 0;
  d2lo = (d2lo ^ s.kw[1]![1]) >>> 0;

  for (let round = 0; round < s.rounds; round++) {
    // FL and FLINV sit between every sixth round and the next, never after the last.
    if (round > 0 && round % 6 === 0) {
      const pair = round / 6 - 1;
      const ke1 = s.ke[pair * 2]!;
      const ke2 = s.ke[pair * 2 + 1]!;
      const left = fl(d1hi, d1lo, ke1[0], ke1[1]);
      const right = flinv(d2hi, d2lo, ke2[0], ke2[1]);
      d1hi = left[0];
      d1lo = left[1];
      d2hi = right[0];
      d2lo = right[1];
    }

    const rk = s.k[round]!;
    if (round % 2 === 0) {
      const out = f(d1hi, d1lo, rk[0], rk[1]);
      d2hi = (d2hi ^ out[0]) >>> 0;
      d2lo = (d2lo ^ out[1]) >>> 0;
    } else {
      const out = f(d2hi, d2lo, rk[0], rk[1]);
      d1hi = (d1hi ^ out[0]) >>> 0;
      d1lo = (d1lo ^ out[1]) >>> 0;
    }
  }

  // Postwhitening, and note the halves come out swapped: C = (D2 << 64) | D1.
  const c0 = (d2hi ^ s.kw[2]![0]) >>> 0;
  const c1 = (d2lo ^ s.kw[2]![1]) >>> 0;
  const c2 = (d1hi ^ s.kw[3]![0]) >>> 0;
  const c3 = (d1lo ^ s.kw[3]![1]) >>> 0;

  for (const [i, word] of [c0, c1, c2, c3].entries()) {
    dst[i * 4] = (word >>> 24) & 0xff;
    dst[i * 4 + 1] = (word >>> 16) & 0xff;
    dst[i * 4 + 2] = (word >>> 8) & 0xff;
    dst[i * 4 + 3] = word & 0xff;
  }
}

export const CAMELLIA_KEY_SIZES: readonly number[] = [16, 24, 32];

export function createCamellia(key: Uint8Array): BlockCipher {
  if (!CAMELLIA_KEY_SIZES.includes(key.length)) {
    throw new Error(`Camellia takes a 16, 24 or 32-byte key; this one is ${key.length}.`);
  }
  const forward = expandKey(key);
  const backward = reverseSchedule(forward);
  return {
    blockSize: CAMELLIA_BLOCK_SIZE,
    encryptBlock: (src, dst) => crypt(src, forward, dst),
    decryptBlock: (src, dst) => crypt(src, backward, dst),
  };
}
