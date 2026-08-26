/**
 * Phase 6: MISTY1, HIGHT, CLEFIA, MARS and Rabbit.
 *
 * Filed together because they arrived together, not because they share anything. The four block
 * ciphers plug into `blockmodes.ts` through the `BlockCipher` interface, so ECB, CBC, CFB, OFB and
 * CTR come for free; Rabbit is a stream cipher and has its own keystream interface.
 *
 * All five needed a vector source Bouncy Castle does not carry -- see the section of `CLAUDE.md`
 * that names the two that replaced it. MISTY1, CLEFIA and Rabbit each have their whole
 * specification *and* their vectors in one RFC, which is the best case this repo has found.
 *
 * ## MISTY1
 *
 * Mitsuru Matsui's design, and the *provably* differential- and linear-resistant one: its round
 * function is built from two S-boxes chosen so that the maximum differential and linear
 * probabilities are bounded, which was novel in 1995. It is a recursive Feistel -- FO calls FI calls
 * the S-boxes -- with FL "key-dependent linear" layers between the even rounds. 3GPP's KASUMI is a
 * modified MISTY1.
 *
 * Everything here comes from RFC 2994, which carries the whole specification *and* its own worked
 * examples. Three things worth knowing.
 *
 * **The halves swap on the way out and not on the way in.** The RFC writes
 * `C = (D1 << 32) | D0` after loading `D0` from the leftmost 32 bits. So the output's first four
 * bytes are `D1`. Reading that as a symmetric Feistel gives a cipher that inverts against itself
 * perfectly and reproduces nothing.
 *
 * **`d7` is masked back to seven bits mid-FI, and the RFC brackets that line.** `S7TABLE[d7] ^ d9`
 * can set bits above 7 because `d9` is nine bits wide; the mask is what keeps `d7` a 7-bit value.
 * The parenthesised line in the RFC reads as optional and is not.
 *
 * **FL and FLINV are the same two statements in the opposite order**, and the key indices differ
 * between the even and odd cases. They are written out rather than derived because getting either
 * wrong leaves encryption correct and only breaks the inverse -- which a round trip cannot see, and
 * which is why the RFC's own ciphertext is decrypted back in the tests rather than just re-encrypted.
 *
 * Verified against RFC 2994's Appendix A in three ways: its two-block ECB example, the same example
 * decrypted back, and its CBC example -- which additionally exercises this repo's mode layer against
 * a published value rather than against itself.
 *
 * ## HIGHT
 *
 * KISA's lightweight cipher, ISO/IEC 18033-3 and a Korean national standard. Eight bytes of state,
 * 32 rounds of add/XOR/rotate over byte lanes, and a 128-bit key. Designed for hardware small enough
 * that a table lookup is expensive -- which is why **nothing here is stored**:
 *
 * - `F0(x) = x<<<1 ^ x<<<2 ^ x<<<7` and `F1(x) = x<<<3 ^ x<<<4 ^ x<<<6`. The reference ships them as
 *   two 256-byte tables; they are three rotations each.
 * - `DELTA`'s 128 bytes come from a 7-bit LFSR seeded `0101101`, stepping `s[i+7] = s[i+3] ^ s[i]`.
 *
 * A test asserts both derivations against the reference's literal tables, which is what makes
 * deriving them safe rather than merely shorter -- 384 bytes of constants is 384 chances to mistype.
 *
 * **The eight lanes rotate one slot per round, so every index is relative to the round number.** The
 * reference writes all 32 rounds out longhand with the indices permuted per line; here it is
 * `first = (9 - round) mod 8` and each of the eight positions counts down from there. Getting that
 * generalisation wrong is what the first attempt did, and it produced a cipher that inverted
 * perfectly and matched nothing -- the usual signature.
 *
 * Verified against Crypto++'s `hight.txt`, which takes its values from KISA's own reference archive:
 * nine ECB vectors, each checked in both directions against the published plaintext rather than
 * through a round trip.
 *
 * Neither has an oracle. OpenSSL implemented neither, and no dependency in this tree has either.
 */

import type { BlockCipher } from "./blockmodes";

const u32 = (v: number): number => v >>> 0;

/** MISTY1's 7-bit S-box, RFC 2994 section 2.3. Checked to be a permutation at load. */
const S7 = new Uint8Array([
  0x1b, 0x32, 0x33, 0x5a, 0x3b, 0x10, 0x17, 0x54, 0x5b, 0x1a, 0x72, 0x73, 0x6b, 0x2c, 0x66, 0x49,
  0x1f, 0x24, 0x13, 0x6c, 0x37, 0x2e, 0x3f, 0x4a, 0x5d, 0x0f, 0x40, 0x56, 0x25, 0x51, 0x1c, 0x04,
  0x0b, 0x46, 0x20, 0x0d, 0x7b, 0x35, 0x44, 0x42, 0x2b, 0x1e, 0x41, 0x14, 0x4b, 0x79, 0x15, 0x6f,
  0x0e, 0x55, 0x09, 0x36, 0x74, 0x0c, 0x67, 0x53, 0x28, 0x0a, 0x7e, 0x38, 0x02, 0x07, 0x60, 0x29,
  0x19, 0x12, 0x65, 0x2f, 0x30, 0x39, 0x08, 0x68, 0x5f, 0x78, 0x2a, 0x4c, 0x64, 0x45, 0x75, 0x3d,
  0x59, 0x48, 0x03, 0x57, 0x7c, 0x4f, 0x62, 0x3c, 0x1d, 0x21, 0x5e, 0x27, 0x6a, 0x70, 0x4d, 0x3a,
  0x01, 0x6d, 0x6e, 0x63, 0x18, 0x77, 0x23, 0x05, 0x26, 0x76, 0x00, 0x31, 0x2d, 0x7a, 0x7f, 0x61,
  0x50, 0x22, 0x11, 0x06, 0x47, 0x16, 0x52, 0x4e, 0x71, 0x3e, 0x69, 0x43, 0x34, 0x5c, 0x58, 0x7d,
]);

/** And the 9-bit one, from the same section. */
const S9 = new Uint16Array([
  0x1c3, 0x0cb, 0x153, 0x19f, 0x1e3, 0x0e9, 0x0fb, 0x035, 0x181, 0x0b9, 0x117, 0x1eb, 0x133, 0x009, 0x02d, 0x0d3,
  0x0c7, 0x14a, 0x037, 0x07e, 0x0eb, 0x164, 0x193, 0x1d8, 0x0a3, 0x11e, 0x055, 0x02c, 0x01d, 0x1a2, 0x163, 0x118,
  0x14b, 0x152, 0x1d2, 0x00f, 0x02b, 0x030, 0x13a, 0x0e5, 0x111, 0x138, 0x18e, 0x063, 0x0e3, 0x0c8, 0x1f4, 0x01b,
  0x001, 0x09d, 0x0f8, 0x1a0, 0x16d, 0x1f3, 0x01c, 0x146, 0x07d, 0x0d1, 0x082, 0x1ea, 0x183, 0x12d, 0x0f4, 0x19e,
  0x1d3, 0x0dd, 0x1e2, 0x128, 0x1e0, 0x0ec, 0x059, 0x091, 0x011, 0x12f, 0x026, 0x0dc, 0x0b0, 0x18c, 0x10f, 0x1f7,
  0x0e7, 0x16c, 0x0b6, 0x0f9, 0x0d8, 0x151, 0x101, 0x14c, 0x103, 0x0b8, 0x154, 0x12b, 0x1ae, 0x017, 0x071, 0x00c,
  0x047, 0x058, 0x07f, 0x1a4, 0x134, 0x129, 0x084, 0x15d, 0x19d, 0x1b2, 0x1a3, 0x048, 0x07c, 0x051, 0x1ca, 0x023,
  0x13d, 0x1a7, 0x165, 0x03b, 0x042, 0x0da, 0x192, 0x0ce, 0x0c1, 0x06b, 0x09f, 0x1f1, 0x12c, 0x184, 0x0fa, 0x196,
  0x1e1, 0x169, 0x17d, 0x031, 0x180, 0x10a, 0x094, 0x1da, 0x186, 0x13e, 0x11c, 0x060, 0x175, 0x1cf, 0x067, 0x119,
  0x065, 0x068, 0x099, 0x150, 0x008, 0x007, 0x17c, 0x0b7, 0x024, 0x019, 0x0de, 0x127, 0x0db, 0x0e4, 0x1a9, 0x052,
  0x109, 0x090, 0x19c, 0x1c1, 0x028, 0x1b3, 0x135, 0x16a, 0x176, 0x0df, 0x1e5, 0x188, 0x0c5, 0x16e, 0x1de, 0x1b1,
  0x0c3, 0x1df, 0x036, 0x0ee, 0x1ee, 0x0f0, 0x093, 0x049, 0x09a, 0x1b6, 0x069, 0x081, 0x125, 0x00b, 0x05e, 0x0b4,
  0x149, 0x1c7, 0x174, 0x03e, 0x13b, 0x1b7, 0x08e, 0x1c6, 0x0ae, 0x010, 0x095, 0x1ef, 0x04e, 0x0f2, 0x1fd, 0x085,
  0x0fd, 0x0f6, 0x0a0, 0x16f, 0x083, 0x08a, 0x156, 0x09b, 0x13c, 0x107, 0x167, 0x098, 0x1d0, 0x1e9, 0x003, 0x1fe,
  0x0bd, 0x122, 0x089, 0x0d2, 0x18f, 0x012, 0x033, 0x06a, 0x142, 0x0ed, 0x170, 0x11b, 0x0e2, 0x14f, 0x158, 0x131,
  0x147, 0x05d, 0x113, 0x1cd, 0x079, 0x161, 0x1a5, 0x179, 0x09e, 0x1b4, 0x0cc, 0x022, 0x132, 0x01a, 0x0e8, 0x004,
  0x187, 0x1ed, 0x197, 0x039, 0x1bf, 0x1d7, 0x027, 0x18b, 0x0c6, 0x09c, 0x0d0, 0x14e, 0x06c, 0x034, 0x1f2, 0x06e,
  0x0ca, 0x025, 0x0ba, 0x191, 0x0fe, 0x013, 0x106, 0x02f, 0x1ad, 0x172, 0x1db, 0x0c0, 0x10b, 0x1d6, 0x0f5, 0x1ec,
  0x10d, 0x076, 0x114, 0x1ab, 0x075, 0x10c, 0x1e4, 0x159, 0x054, 0x11f, 0x04b, 0x0c4, 0x1be, 0x0f7, 0x029, 0x0a4,
  0x00e, 0x1f0, 0x077, 0x04d, 0x17a, 0x086, 0x08b, 0x0b3, 0x171, 0x0bf, 0x10e, 0x104, 0x097, 0x15b, 0x160, 0x168,
  0x0d7, 0x0bb, 0x066, 0x1ce, 0x0fc, 0x092, 0x1c5, 0x06f, 0x016, 0x04a, 0x0a1, 0x139, 0x0af, 0x0f1, 0x190, 0x00a,
  0x1aa, 0x143, 0x17b, 0x056, 0x18d, 0x166, 0x0d4, 0x1fb, 0x14d, 0x194, 0x19a, 0x087, 0x1f8, 0x123, 0x0a7, 0x1b8,
  0x141, 0x03c, 0x1f9, 0x140, 0x02a, 0x155, 0x11a, 0x1a1, 0x198, 0x0d5, 0x126, 0x1af, 0x061, 0x12e, 0x157, 0x1dc,
  0x072, 0x18a, 0x0aa, 0x096, 0x115, 0x0ef, 0x045, 0x07b, 0x08d, 0x145, 0x053, 0x05f, 0x178, 0x0b2, 0x02e, 0x020,
  0x1d5, 0x03f, 0x1c9, 0x1e7, 0x1ac, 0x044, 0x038, 0x014, 0x0b1, 0x16b, 0x0ab, 0x0b5, 0x05a, 0x182, 0x1c8, 0x1d4,
  0x018, 0x177, 0x064, 0x0cf, 0x06d, 0x100, 0x199, 0x130, 0x15a, 0x005, 0x120, 0x1bb, 0x1bd, 0x0e0, 0x04f, 0x0d6,
  0x13f, 0x1c4, 0x12a, 0x015, 0x006, 0x0ff, 0x19b, 0x0a6, 0x043, 0x088, 0x050, 0x15f, 0x1e8, 0x121, 0x073, 0x17e,
  0x0bc, 0x0c2, 0x0c9, 0x173, 0x189, 0x1f5, 0x074, 0x1cc, 0x1e6, 0x1a8, 0x195, 0x01f, 0x041, 0x00d, 0x1ba, 0x032,
  0x03d, 0x1d1, 0x080, 0x0a8, 0x057, 0x1b9, 0x162, 0x148, 0x0d9, 0x105, 0x062, 0x07a, 0x021, 0x1ff, 0x112, 0x108,
  0x1c0, 0x0a9, 0x11d, 0x1b0, 0x1a6, 0x0cd, 0x0f3, 0x05c, 0x102, 0x05b, 0x1d9, 0x144, 0x1f6, 0x0ad, 0x0a5, 0x03a,
  0x1cb, 0x136, 0x17f, 0x046, 0x0e1, 0x01e, 0x1dd, 0x0e6, 0x137, 0x1fa, 0x185, 0x08c, 0x08f, 0x040, 0x1b5, 0x0be,
  0x078, 0x000, 0x0ac, 0x110, 0x15e, 0x124, 0x002, 0x1bc, 0x0a2, 0x0ea, 0x070, 0x1fc, 0x116, 0x15c, 0x04c, 0x1c2,
]);

// Both S-boxes are permutations; the RFC's tables are transcribed by script and this is the check
// that nothing was dropped or duplicated on the way in.
for (const [name, table, size] of [
  ["S7", S7, 128],
  ["S9", S9, 512],
] as const) {
  const seen = new Set<number>(table);
  if (seen.size !== size) throw new Error(`MISTY1 ${name} is not a permutation`);
}

/** Exported so a test can pin the transcription against RFC 2994's own first row. */
export const MISTY1_S7_FIRST: number = S7[0]!;
export const MISTY1_S9_FIRST: number = S9[0]!;

const fi = (input: number, key: number): number => {
  let d9 = input >>> 7;
  let d7 = input & 0x7f;
  d9 = S9[d9]! ^ d7;
  d7 = S7[d7]! ^ d9;
  // Not optional, though the RFC brackets it: `S7[d7] ^ d9` can set bits above 7.
  d7 &= 0x7f;
  d7 ^= key >>> 9;
  d9 ^= key & 0x1ff;
  d9 = S9[d9]! ^ d7;
  return ((d7 << 9) | d9) & 0xffff;
};

const fo = (ek: readonly number[], input: number, k: number): number => {
  let t0 = input >>> 16;
  let t1 = input & 0xffff;
  t0 ^= ek[k]!;
  t0 = fi(t0, ek[((k + 5) % 8) + 8]!);
  t0 ^= t1;
  t1 ^= ek[(k + 2) % 8]!;
  t1 = fi(t1, ek[((k + 1) % 8) + 8]!);
  t1 ^= t0;
  t0 ^= ek[(k + 7) % 8]!;
  t0 = fi(t0, ek[((k + 3) % 8) + 8]!);
  t0 ^= t1;
  t1 ^= ek[(k + 4) % 8]!;
  return u32((t1 << 16) | t0);
};

const fl = (ek: readonly number[], input: number, k: number): number => {
  let d0 = input >>> 16;
  let d1 = input & 0xffff;
  if (k % 2 === 0) {
    d1 ^= d0 & ek[k / 2]!;
    d0 ^= (d1 | ek[((k / 2 + 6) % 8) + 8]!) & 0xffff;
  } else {
    d1 ^= d0 & ek[(((k - 1) / 2 + 2) % 8) + 8]!;
    d0 ^= (d1 | ek[((k - 1) / 2 + 4) % 8]!) & 0xffff;
  }
  return u32((d0 << 16) | d1);
};

/** The same two statements as `fl`, in the opposite order. */
const flinv = (ek: readonly number[], input: number, k: number): number => {
  let d0 = input >>> 16;
  let d1 = input & 0xffff;
  if (k % 2 === 0) {
    d0 ^= (d1 | ek[((k / 2 + 6) % 8) + 8]!) & 0xffff;
    d1 ^= d0 & ek[k / 2]!;
  } else {
    d0 ^= (d1 | ek[((k - 1) / 2 + 4) % 8]!) & 0xffff;
    d1 ^= d0 & ek[(((k - 1) / 2 + 2) % 8) + 8]!;
  }
  return u32((d0 << 16) | d1);
};

const loadBE = (b: Uint8Array, o: number): number =>
  u32((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!);
const storeBE = (b: Uint8Array, o: number, v: number): void => {
  b[o] = (v >>> 24) & 0xff;
  b[o + 1] = (v >>> 16) & 0xff;
  b[o + 2] = (v >>> 8) & 0xff;
  b[o + 3] = v & 0xff;
};

/** MISTY1 over a 16-byte key. */
export function createMisty1(key: Uint8Array): BlockCipher {
  if (key.length !== 16) {
    throw new Error(`MISTY1's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const ek: number[] = new Array<number>(32).fill(0);
  for (let i = 0; i < 8; i++) ek[i] = (key[2 * i]! << 8) | key[2 * i + 1]!;
  for (let i = 0; i < 8; i++) {
    ek[i + 8] = fi(ek[i]!, ek[(i + 1) % 8]!);
    ek[i + 16] = ek[i + 8]! & 0x1ff;
    ek[i + 24] = ek[i + 8]! >>> 9;
  }

  return {
    blockSize: 8,
    encryptBlock(src, dst) {
      let d0 = loadBE(src, 0);
      let d1 = loadBE(src, 4);
      for (let r = 0; r < 4; r++) {
        d0 = fl(ek, d0, 2 * r);
        d1 = fl(ek, d1, 2 * r + 1);
        d1 = u32(d1 ^ fo(ek, d0, 2 * r));
        d0 = u32(d0 ^ fo(ek, d1, 2 * r + 1));
      }
      d0 = fl(ek, d0, 8);
      d1 = fl(ek, d1, 9);
      // The halves swap here and not on the way in -- see the header.
      storeBE(dst, 0, d1);
      storeBE(dst, 4, d0);
    },
    decryptBlock(src, dst) {
      let d1 = loadBE(src, 0);
      let d0 = loadBE(src, 4);
      d0 = flinv(ek, d0, 8);
      d1 = flinv(ek, d1, 9);
      for (let r = 3; r >= 0; r--) {
        d0 = u32(d0 ^ fo(ek, d1, 2 * r + 1));
        d1 = u32(d1 ^ fo(ek, d0, 2 * r));
        d0 = flinv(ek, d0, 2 * r);
        d1 = flinv(ek, d1, 2 * r + 1);
      }
      storeBE(dst, 0, d0);
      storeBE(dst, 4, d1);
    },
  };
}

// ---- HIGHT ----

const rotl8 = (x: number, n: number): number => ((x << n) | (x >>> (8 - n))) & 0xff;

/** `F0(x) = x<<<1 ^ x<<<2 ^ x<<<7`. The reference ships this as a 256-byte table. */
const HIGHT_F0 = new Uint8Array(256);
/** `F1(x) = x<<<3 ^ x<<<4 ^ x<<<6`. */
const HIGHT_F1 = new Uint8Array(256);
for (let x = 0; x < 256; x++) {
  HIGHT_F0[x] = rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 7);
  HIGHT_F1[x] = rotl8(x, 3) ^ rotl8(x, 4) ^ rotl8(x, 6);
}

/**
 * The 128 round constants, from the 7-bit LFSR the standard specifies.
 *
 * Seed `s0..s6 = 0,1,0,1,1,0,1`, which makes `DELTA[0] = 0x5a`; then `s[i+7] = s[i+3] ^ s[i]`, and
 * `DELTA[i]` is `s[i+6] .. s[i]` read as a 7-bit value with `s[i]` least significant.
 */
const HIGHT_DELTA = new Uint8Array(128);
{
  const s: number[] = [0, 1, 0, 1, 1, 0, 1];
  for (let i = 0; i < 128; i++) {
    let d = 0;
    for (let b = 0; b < 7; b++) d |= s[i + b]! << b;
    HIGHT_DELTA[i] = d;
    s.push(s[i + 3]! ^ s[i]!);
  }
}

/** Exported so a test can check the two derivations against the reference's literal tables. */
export const HIGHT_TABLES = {
  f0: HIGHT_F0,
  f1: HIGHT_F1,
  delta: HIGHT_DELTA,
} as const;

/**
 * Which lane each of the eight sub-steps touches, for one round.
 *
 * Round 2 starts at lane 7 and each later round starts one lower, wrapping every eight -- so the
 * whole 32-round schedule is this one expression rather than 32 permuted argument lists.
 */
const hightOrder = (round: number): number[] => {
  const first = (((9 - round) % 8) + 8) % 8;
  return [0, 1, 2, 3, 4, 5, 6, 7].map((j) => (first - j + 8) % 8);
};

/** HIGHT over a 16-byte key. */
export function createHight(key: Uint8Array): BlockCipher {
  if (key.length !== 16) {
    throw new Error(`HIGHT's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const rk = new Uint8Array(136);
  for (let i = 0; i < 4; i++) {
    rk[i] = key[i + 12]!;
    rk[i + 4] = key[i]!;
  }
  for (let i = 0; i < 8; i++) {
    for (let j = 0; j < 8; j++) {
      rk[8 + 16 * i + j] = (key[(j - i) & 7]! + HIGHT_DELTA[16 * i + j]!) & 0xff;
      rk[8 + 16 * i + j + 8] = (key[(((j - i) & 7) + 8)]! + HIGHT_DELTA[16 * i + j + 8]!) & 0xff;
    }
  }

  const x = new Uint8Array(8);

  return {
    blockSize: 8,
    encryptBlock(src, dst) {
      x[1] = src[1]!;
      x[3] = src[3]!;
      x[5] = src[5]!;
      x[7] = src[7]!;
      x[0] = (src[0]! + rk[0]!) & 0xff;
      x[2] = src[2]! ^ rk[1]!;
      x[4] = (src[4]! + rk[2]!) & 0xff;
      x[6] = src[6]! ^ rk[3]!;

      for (let k = 2; k <= 33; k++) {
        const [i0, i1, i2, i3, i4, i5, i6, i7] = hightOrder(k) as [
          number, number, number, number, number, number, number, number,
        ];
        x[i0] = x[i0]! ^ ((HIGHT_F0[x[i1]!]! + rk[4 * k + 3]!) & 0xff);
        x[i2] = (x[i2]! + (HIGHT_F1[x[i3]!]! ^ rk[4 * k + 2]!)) & 0xff;
        x[i4] = x[i4]! ^ ((HIGHT_F0[x[i5]!]! + rk[4 * k + 1]!) & 0xff);
        x[i6] = (x[i6]! + (HIGHT_F1[x[i7]!]! ^ rk[4 * k + 0]!)) & 0xff;
      }

      dst[1] = x[2]!;
      dst[3] = x[4]!;
      dst[5] = x[6]!;
      dst[7] = x[0]!;
      dst[0] = (x[1]! + rk[4]!) & 0xff;
      dst[2] = x[3]! ^ rk[5]!;
      dst[4] = (x[5]! + rk[6]!) & 0xff;
      dst[6] = x[7]! ^ rk[7]!;
    },
    decryptBlock(src, dst) {
      x[2] = src[1]!;
      x[4] = src[3]!;
      x[6] = src[5]!;
      x[0] = src[7]!;
      x[1] = (src[0]! - rk[4]!) & 0xff;
      x[3] = src[2]! ^ rk[5]!;
      x[5] = (src[4]! - rk[6]!) & 0xff;
      x[7] = src[6]! ^ rk[7]!;

      for (let k = 33; k >= 2; k--) {
        const [i0, i1, i2, i3, i4, i5, i6, i7] = hightOrder(k) as [
          number, number, number, number, number, number, number, number,
        ];
        // The four sub-steps undo in reverse, and only the two additions become subtractions.
        x[i6] = (x[i6]! - (HIGHT_F1[x[i7]!]! ^ rk[4 * k + 0]!)) & 0xff;
        x[i4] = x[i4]! ^ ((HIGHT_F0[x[i5]!]! + rk[4 * k + 1]!) & 0xff);
        x[i2] = (x[i2]! - (HIGHT_F1[x[i3]!]! ^ rk[4 * k + 2]!)) & 0xff;
        x[i0] = x[i0]! ^ ((HIGHT_F0[x[i1]!]! + rk[4 * k + 3]!) & 0xff);
      }

      dst[1] = x[1]!;
      dst[3] = x[3]!;
      dst[5] = x[5]!;
      dst[7] = x[7]!;
      dst[0] = (x[0]! - rk[0]!) & 0xff;
      dst[2] = x[2]! ^ rk[1]!;
      dst[4] = (x[4]! - rk[2]!) & 0xff;
      dst[6] = x[6]! ^ rk[3]!;
    },
  };
}

/** CLEFIA's S0, RFC 6114 Table 1. Checked to be a permutation at load. */
const CLEFIA_S0 = new Uint8Array([
  0x57, 0x49, 0xd1, 0xc6, 0x2f, 0x33, 0x74, 0xfb, 0x95, 0x6d, 0x82, 0xea, 0x0e, 0xb0, 0xa8, 0x1c,
  0x28, 0xd0, 0x4b, 0x92, 0x5c, 0xee, 0x85, 0xb1, 0xc4, 0x0a, 0x76, 0x3d, 0x63, 0xf9, 0x17, 0xaf,
  0xbf, 0xa1, 0x19, 0x65, 0xf7, 0x7a, 0x32, 0x20, 0x06, 0xce, 0xe4, 0x83, 0x9d, 0x5b, 0x4c, 0xd8,
  0x42, 0x5d, 0x2e, 0xe8, 0xd4, 0x9b, 0x0f, 0x13, 0x3c, 0x89, 0x67, 0xc0, 0x71, 0xaa, 0xb6, 0xf5,
  0xa4, 0xbe, 0xfd, 0x8c, 0x12, 0x00, 0x97, 0xda, 0x78, 0xe1, 0xcf, 0x6b, 0x39, 0x43, 0x55, 0x26,
  0x30, 0x98, 0xcc, 0xdd, 0xeb, 0x54, 0xb3, 0x8f, 0x4e, 0x16, 0xfa, 0x22, 0xa5, 0x77, 0x09, 0x61,
  0xd6, 0x2a, 0x53, 0x37, 0x45, 0xc1, 0x6c, 0xae, 0xef, 0x70, 0x08, 0x99, 0x8b, 0x1d, 0xf2, 0xb4,
  0xe9, 0xc7, 0x9f, 0x4a, 0x31, 0x25, 0xfe, 0x7c, 0xd3, 0xa2, 0xbd, 0x56, 0x14, 0x88, 0x60, 0x0b,
  0xcd, 0xe2, 0x34, 0x50, 0x9e, 0xdc, 0x11, 0x05, 0x2b, 0xb7, 0xa9, 0x48, 0xff, 0x66, 0x8a, 0x73,
  0x03, 0x75, 0x86, 0xf1, 0x6a, 0xa7, 0x40, 0xc2, 0xb9, 0x2c, 0xdb, 0x1f, 0x58, 0x94, 0x3e, 0xed,
  0xfc, 0x1b, 0xa0, 0x04, 0xb8, 0x8d, 0xe6, 0x59, 0x62, 0x93, 0x35, 0x7e, 0xca, 0x21, 0xdf, 0x47,
  0x15, 0xf3, 0xba, 0x7f, 0xa6, 0x69, 0xc8, 0x4d, 0x87, 0x3b, 0x9c, 0x01, 0xe0, 0xde, 0x24, 0x52,
  0x7b, 0x0c, 0x68, 0x1e, 0x80, 0xb2, 0x5a, 0xe7, 0xad, 0xd5, 0x23, 0xf4, 0x46, 0x3f, 0x91, 0xc9,
  0x6e, 0x84, 0x72, 0xbb, 0x0d, 0x18, 0xd9, 0x96, 0xf0, 0x5f, 0x41, 0xac, 0x27, 0xc5, 0xe3, 0x3a,
  0x81, 0x6f, 0x07, 0xa3, 0x79, 0xf6, 0x2d, 0x38, 0x1a, 0x44, 0x5e, 0xb5, 0xd2, 0xec, 0xcb, 0x90,
  0x9a, 0x36, 0xe5, 0x29, 0xc3, 0x4f, 0xab, 0x64, 0x51, 0xf8, 0x10, 0xd7, 0xbc, 0x02, 0x7d, 0x8e,
]);

/** And S1, Table 2 -- based on the inverse function over GF(2^8) where S0 is four 4-bit boxes. */
const CLEFIA_S1 = new Uint8Array([
  0x6c, 0xda, 0xc3, 0xe9, 0x4e, 0x9d, 0x0a, 0x3d, 0xb8, 0x36, 0xb4, 0x38, 0x13, 0x34, 0x0c, 0xd9,
  0xbf, 0x74, 0x94, 0x8f, 0xb7, 0x9c, 0xe5, 0xdc, 0x9e, 0x07, 0x49, 0x4f, 0x98, 0x2c, 0xb0, 0x93,
  0x12, 0xeb, 0xcd, 0xb3, 0x92, 0xe7, 0x41, 0x60, 0xe3, 0x21, 0x27, 0x3b, 0xe6, 0x19, 0xd2, 0x0e,
  0x91, 0x11, 0xc7, 0x3f, 0x2a, 0x8e, 0xa1, 0xbc, 0x2b, 0xc8, 0xc5, 0x0f, 0x5b, 0xf3, 0x87, 0x8b,
  0xfb, 0xf5, 0xde, 0x20, 0xc6, 0xa7, 0x84, 0xce, 0xd8, 0x65, 0x51, 0xc9, 0xa4, 0xef, 0x43, 0x53,
  0x25, 0x5d, 0x9b, 0x31, 0xe8, 0x3e, 0x0d, 0xd7, 0x80, 0xff, 0x69, 0x8a, 0xba, 0x0b, 0x73, 0x5c,
  0x6e, 0x54, 0x15, 0x62, 0xf6, 0x35, 0x30, 0x52, 0xa3, 0x16, 0xd3, 0x28, 0x32, 0xfa, 0xaa, 0x5e,
  0xcf, 0xea, 0xed, 0x78, 0x33, 0x58, 0x09, 0x7b, 0x63, 0xc0, 0xc1, 0x46, 0x1e, 0xdf, 0xa9, 0x99,
  0x55, 0x04, 0xc4, 0x86, 0x39, 0x77, 0x82, 0xec, 0x40, 0x18, 0x90, 0x97, 0x59, 0xdd, 0x83, 0x1f,
  0x9a, 0x37, 0x06, 0x24, 0x64, 0x7c, 0xa5, 0x56, 0x48, 0x08, 0x85, 0xd0, 0x61, 0x26, 0xca, 0x6f,
  0x7e, 0x6a, 0xb6, 0x71, 0xa0, 0x70, 0x05, 0xd1, 0x45, 0x8c, 0x23, 0x1c, 0xf0, 0xee, 0x89, 0xad,
  0x7a, 0x4b, 0xc2, 0x2f, 0xdb, 0x5a, 0x4d, 0x76, 0x67, 0x17, 0x2d, 0xf4, 0xcb, 0xb1, 0x4a, 0xa8,
  0xb5, 0x22, 0x47, 0x3a, 0xd5, 0x10, 0x4c, 0x72, 0xcc, 0x00, 0xf9, 0xe0, 0xfd, 0xe2, 0xfe, 0xae,
  0xf8, 0x5f, 0xab, 0xf1, 0x1b, 0x42, 0x81, 0xd6, 0xbe, 0x44, 0x29, 0xa6, 0x57, 0xb9, 0xaf, 0xf2,
  0xd4, 0x75, 0x66, 0xbb, 0x68, 0x9f, 0x50, 0x02, 0x01, 0x3c, 0x7f, 0x8d, 0x1a, 0x88, 0xbd, 0xac,
  0xf7, 0xe4, 0x79, 0x96, 0xa2, 0xfc, 0x6d, 0xb2, 0x6b, 0x03, 0xe1, 0x2e, 0x7d, 0x14, 0x95, 0x1d,
]);

/**
 * MARS's 512-word S-box, from the AES submission.
 *
 * The one table in this file that is neither derived nor in an RFC. It is stored because the
 * submission generates it from SHA-1 over a seed, and reproducing that would mean a second SHA-1
 * path in `@ocs/algos` for one table -- so the values are parsed from the reference by script and the
 * ten published vectors are what check them.
 */
const MARS_SBOX = new Uint32Array([
  0x09d0c479, 0x28c8ffe0, 0x84aa6c39, 0x9dad7287,
  0x7dff9be3, 0xd4268361, 0xc96da1d4, 0x7974cc93,
  0x85d0582e, 0x2a4b5705, 0x1ca16a62, 0xc3bd279d,
  0x0f1f25e5, 0x5160372f, 0xc695c1fb, 0x4d7ff1e4,
  0xae5f6bf4, 0x0d72ee46, 0xff23de8a, 0xb1cf8e83,
  0xf14902e2, 0x3e981e42, 0x8bf53eb6, 0x7f4bf8ac,
  0x83631f83, 0x25970205, 0x76afe784, 0x3a7931d4,
  0x4f846450, 0x5c64c3f6, 0x210a5f18, 0xc6986a26,
  0x28f4e826, 0x3a60a81c, 0xd340a664, 0x7ea820c4,
  0x526687c5, 0x7eddd12b, 0x32a11d1d, 0x9c9ef086,
  0x80f6e831, 0xab6f04ad, 0x56fb9b53, 0x8b2e095c,
  0xb68556ae, 0xd2250b0d, 0x294a7721, 0xe21fb253,
  0xae136749, 0xe82aae86, 0x93365104, 0x99404a66,
  0x78a784dc, 0xb69ba84b, 0x04046793, 0x23db5c1e,
  0x46cae1d6, 0x2fe28134, 0x5a223942, 0x1863cd5b,
  0xc190c6e3, 0x07dfb846, 0x6eb88816, 0x2d0dcc4a,
  0xa4ccae59, 0x3798670d, 0xcbfa9493, 0x4f481d45,
  0xeafc8ca8, 0xdb1129d6, 0xb0449e20, 0x0f5407fb,
  0x6167d9a8, 0xd1f45763, 0x4daa96c3, 0x3bec5958,
  0xababa014, 0xb6ccd201, 0x38d6279f, 0x02682215,
  0x8f376cd5, 0x092c237e, 0xbfc56593, 0x32889d2c,
  0x854b3e95, 0x05bb9b43, 0x7dcd5dcd, 0xa02e926c,
  0xfae527e5, 0x36a1c330, 0x3412e1ae, 0xf257f462,
  0x3c4f1d71, 0x30a2e809, 0x68e5f551, 0x9c61ba44,
  0x5ded0ab8, 0x75ce09c8, 0x9654f93e, 0x698c0cca,
  0x243cb3e4, 0x2b062b97, 0x0f3b8d9e, 0x00e050df,
  0xfc5d6166, 0xe35f9288, 0xc079550d, 0x0591aee8,
  0x8e531e74, 0x75fe3578, 0x2f6d829a, 0xf60b21ae,
  0x95e8eb8d, 0x6699486b, 0x901d7d9b, 0xfd6d6e31,
  0x1090acef, 0xe0670dd8, 0xdab2e692, 0xcd6d4365,
  0xe5393514, 0x3af345f0, 0x6241fc4d, 0x460da3a3,
  0x7bcf3729, 0x8bf1d1e0, 0x14aac070, 0x1587ed55,
  0x3afd7d3e, 0xd2f29e01, 0x29a9d1f6, 0xefb10c53,
  0xcf3b870f, 0xb414935c, 0x664465ed, 0x024acac7,
  0x59a744c1, 0x1d2936a7, 0xdc580aa6, 0xcf574ca8,
  0x040a7a10, 0x6cd81807, 0x8a98be4c, 0xaccea063,
  0xc33e92b5, 0xd1e0e03d, 0xb322517e, 0x2092bd13,
  0x386b2c4a, 0x52e8dd58, 0x58656dfb, 0x50820371,
  0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6,
  0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
  0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073,
  0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1,
  0xa64fc9c6, 0xf6957d49, 0x38b06a75, 0xdd805fcd,
  0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294,
  0xce9f8e99, 0xbffcd770, 0xc7c275cc, 0x378453a7,
  0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98,
  0x5915ea51, 0x99f861b7, 0xc9980a88, 0x1d74fd5f,
  0xb0a495f8, 0x614deed0, 0xb5778eea, 0x5941792d,
  0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550,
  0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48,
  0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149,
  0x16a45272, 0x532459a0, 0x8e5f4872, 0xf966c7d9,
  0x07128dc0, 0x0d44db62, 0xafc8d52d, 0x06316131,
  0xd838e7ce, 0x1bc41d00, 0x3a2e8c0f, 0xea83837e,
  0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3,
  0xa215cdce, 0x8359838b, 0x6bd1aa31, 0xf579dd52,
  0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76,
  0x2b38fd54, 0x431de1da, 0xab394825, 0x9ad3048f,
  0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59,
  0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8,
  0x8d421fc0, 0x9b0ed10c, 0x88f1a1e9, 0x54c1f029,
  0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca,
  0x1a9a5f08, 0xfcd651b9, 0x25605182, 0xe11fc6c3,
  0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030,
  0x6b57e354, 0xad913cf7, 0x7e16688d, 0x58872a69,
  0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734,
  0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b,
  0x73f9a978, 0x73398d32, 0x0f59573e, 0xe9df2b03,
  0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3,
  0x684f259a, 0x943ba848, 0xa6370152, 0x863b5ea3,
  0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf,
  0x8e6a0829, 0x8695bc14, 0xe35b3447, 0x933ac568,
  0x8894b022, 0x2f511c27, 0xddfbcc3c, 0x006662b6,
  0x117c83fe, 0x4e12b414, 0xc2bca766, 0x3a2fec10,
  0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce,
  0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047,
  0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f,
  0x23becb64, 0xa075f3a3, 0x088f8ead, 0x07adf158,
  0x7796943c, 0xfacabf3d, 0xc09730cd, 0xf7679969,
  0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f,
  0x690624f8, 0x1cb0bafd, 0x7b0dbdc6, 0x810f23bb,
  0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05,
  0x010e65c4, 0x86a3d963, 0xf907b5a0, 0xd0042bd3,
  0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33,
  0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650,
  0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd,
  0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e,
  0xcd67eb2f, 0xe2eb6dc2, 0x97338b02, 0x06c9f246,
  0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089,
  0x160bead7, 0x5d494656, 0x35f8a74b, 0x1e4e6c9e,
  0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2,
  0xca815ab3, 0x5a6395e7, 0x302a67c5, 0x8bdb446b,
  0x108f8fa4, 0x10223eda, 0x92b8b48b, 0x7f38d0ee,
  0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba,
  0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c,
  0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5,
  0x01e87da6, 0x6ce91e6a, 0xbb7bcc84, 0xc7922c20,
  0x9d3b71fd, 0x060e41c6, 0xd7590f15, 0x4e03bb47,
  0x183c198e, 0x63eeb240, 0x2ddbf49a, 0x6d5cba54,
  0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72,
  0x81b66760, 0xbb2926c1, 0x48a0ce0d, 0xa6c0496d,
  0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6,
  0x054356dc, 0xde7ced35, 0xd51a138b, 0x62088cc9,
  0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68,
  0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2,
  0x72698d7d, 0x5e368c31, 0xf7d95e2e, 0xa1d3493f,
  0xdcd9433e, 0x896f1552, 0x4bc4ca7a, 0xa6d1baf4,
  0xa5a96dcc, 0x0bef8b46, 0xa169fda7, 0x74df40b7,
  0x4e208804, 0x9a756607, 0x038e87c8, 0x20211e44,
  0x8b7ad4bf, 0xc6403f35, 0x1848e36d, 0x80bdb038,
  0x1e62891c, 0x643d2107, 0xbf04d6f8, 0x21092c8c,
  0xf644f389, 0x0778404e, 0x7b78adb8, 0xa2c52d53,
  0x42157abe, 0xa2253e2e, 0x7bf3f4ae, 0x80f594f9,
  0x953194e7, 0x77eb92ed, 0xb3816930, 0xda8d9336,
  0xbf447469, 0xf26d9483, 0xee6faed5, 0x71371235,
  0xde425f73, 0xb4e59f43, 0x7dbe2d4e, 0x2d37b185,
  0x49dc9a63, 0x98c39d98, 0x1301c9a2, 0x389b1bbf,
  0x0c18588d, 0xa421c1ba, 0x7aa3865c, 0x71e08558,
  0x3c5cfcaa, 0x7d239ca4, 0x0297d9dd, 0xd7dc2830,
  0x4b37802b, 0x7428ab54, 0xaeee0347, 0x4b3fbb85,
  0x692f2f08, 0x134e578e, 0x36d9e0bf, 0xae8b5fcf,
  0xedb93ecf, 0x2b27248e, 0x170eb1ef, 0x7dc57fd6,
  0x1e760f16, 0xb1136601, 0x864e1b9b, 0xd7ea7319,
  0x3ab871bd, 0xcfa4d76f, 0xe31bd782, 0x0dbeb469,
  0xabb96061, 0x5370f85d, 0xffb07e37, 0xda30d0fb,
  0xebc977b6, 0x0b98b40f, 0x3a4d0fe6, 0xdf4fc26b,
  0x159cf22a, 0xc298d6e2, 0x2b78ef6a, 0x61a94ac0,
  0xab561187, 0x14eea0f0, 0xdf0d4164, 0x19af70ee,
]);

{
  const seen = new Set<number>(CLEFIA_S0);
  if (seen.size !== 256) throw new Error("CLEFIA S0 is not a permutation");
  const seen1 = new Set<number>(CLEFIA_S1);
  if (seen1.size !== 256) throw new Error("CLEFIA S1 is not a permutation");
}

/** Exported so a test can pin the transcriptions against RFC 6114's own first entries. */
export const CLEFIA_SBOX_FIRST: readonly [number, number] = [CLEFIA_S0[0]!, CLEFIA_S1[0]!];

// ---- CLEFIA ----

/** GF(2^8) under CLEFIA's polynomial z^8 + z^4 + z^3 + z^2 + 1 = 0x11d -- not AES's 0x11b. */
const clefiaMul = (a: number, b: number): number => {
  let r = 0;
  let x = a;
  let y = b;
  while (y !== 0) {
    if ((y & 1) !== 0) r ^= x;
    x = ((x << 1) ^ (x & 0x80 ? 0x11d : 0)) & 0xff;
    y >>= 1;
  }
  return r & 0xff;
};

const M0: readonly (readonly number[])[] = [
  [0x01, 0x02, 0x04, 0x06],
  [0x02, 0x01, 0x06, 0x04],
  [0x04, 0x06, 0x01, 0x02],
  [0x06, 0x04, 0x02, 0x01],
];
const M1: readonly (readonly number[])[] = [
  [0x01, 0x08, 0x02, 0x0a],
  [0x08, 0x01, 0x0a, 0x02],
  [0x02, 0x0a, 0x01, 0x08],
  [0x0a, 0x02, 0x08, 0x01],
];

const word = (b: readonly number[]): number => u32((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!);
const quad = (w: number): number[] => [(w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff];

const diffuse = (m: readonly (readonly number[])[], t: readonly number[]): number =>
  word([0, 1, 2, 3].map((r) => t.reduce((acc, v, c) => acc ^ clefiaMul(m[r]![c]!, v), 0)));

/** F0: S0, S1, S0, S1 then M0. */
const clefiaF0 = (rk: number, x: number): number => {
  const t = quad(u32(rk ^ x));
  return diffuse(M0, [CLEFIA_S0[t[0]!]!, CLEFIA_S1[t[1]!]!, CLEFIA_S0[t[2]!]!, CLEFIA_S1[t[3]!]!]);
};
/** F1: the same S-boxes in the other order, then M1. */
const clefiaF1 = (rk: number, x: number): number => {
  const t = quad(u32(rk ^ x));
  return diffuse(M1, [CLEFIA_S1[t[0]!]!, CLEFIA_S0[t[1]!]!, CLEFIA_S1[t[2]!]!, CLEFIA_S0[t[3]!]!]);
};

/** The 4-branch generalised Feistel network, r rounds. */
function gfn4(rk: readonly number[], x: readonly number[], r: number): number[] {
  let [t0, t1, t2, t3] = x as [number, number, number, number];
  for (let i = 0; i < r; i++) {
    t1 = u32(t1 ^ clefiaF0(rk[2 * i]!, t0));
    t3 = u32(t3 ^ clefiaF1(rk[2 * i + 1]!, t2));
    [t0, t1, t2, t3] = [t1, t2, t3, t0];
  }
  return [t3, t0, t1, t2];
}

/** Its inverse: the round keys run backwards and the word rotation reverses. */
function gfn4Inv(rk: readonly number[], x: readonly number[], r: number): number[] {
  let [t0, t1, t2, t3] = x as [number, number, number, number];
  for (let i = 0; i < r; i++) {
    t1 = u32(t1 ^ clefiaF0(rk[2 * (r - i) - 2]!, t0));
    t3 = u32(t3 ^ clefiaF1(rk[2 * (r - i) - 1]!, t2));
    [t0, t1, t2, t3] = [t3, t0, t1, t2];
  }
  return [t1, t2, t3, t0];
}

/** The 8-branch network, used only by the 192- and 256-bit key schedules. */
function gfn8(rk: readonly number[], x: readonly number[], r: number): number[] {
  let t = [...x];
  for (let i = 0; i < r; i++) {
    t[1] = u32(t[1]! ^ clefiaF0(rk[4 * i]!, t[0]!));
    t[3] = u32(t[3]! ^ clefiaF1(rk[4 * i + 1]!, t[2]!));
    t[5] = u32(t[5]! ^ clefiaF0(rk[4 * i + 2]!, t[4]!));
    t[7] = u32(t[7]! ^ clefiaF1(rk[4 * i + 3]!, t[6]!));
    t = [t[1]!, t[2]!, t[3]!, t[4]!, t[5]!, t[6]!, t[7]!, t[0]!];
  }
  return [t[7]!, t[0]!, t[1]!, t[2]!, t[3]!, t[4]!, t[5]!, t[6]!];
}

/**
 * DoubleSwap: `Y = X[7-63] | X[121-127] | X[0-6] | X[64-120]`, bit 0 most significant.
 *
 * Done in a 128-bit `bigint` because that is the only spelling that matches the RFC's bit indices
 * without four hand-derived cross-word shifts. It runs nine times per key schedule, not per block.
 */
function doubleSwap(l: readonly number[]): number[] {
  let x = 0n;
  for (const w of l) x = (x << 32n) | BigInt(w >>> 0);
  const slice = (a: number, b: number): bigint =>
    (x >> BigInt(127 - b)) & ((1n << BigInt(b - a + 1)) - 1n);
  const y =
    (slice(7, 63) << 71n) | (slice(121, 127) << 64n) | (slice(0, 6) << 57n) | slice(64, 120);
  const out: number[] = [];
  for (let i = 3; i >= 0; i--) out.push(Number((y >> BigInt(32 * i)) & 0xffffffffn) >>> 0);
  return out;
}

/**
 * The round constants, derived from IV_k rather than stored.
 *
 * `T_k[i+1] = T_k[i] * z^-1` in GF(2^16) under `z^16 + z^15 + z^13 + z^11 + z^5 + z^4 + 1` = 0x1a831.
 * Halving is a right shift; an odd value has the polynomial added first, which makes it even -- and
 * getting that fold wrong is what the first attempt did, which the RFC's own T and CON tables caught.
 */
function clefiaConstants(iv: number, count: number): { con: number[]; t: number[] } {
  const P = 0xb7e1;
  const Q = 0x243f;
  const rotl16 = (v: number, n: number): number => ((v << n) | (v >>> (16 - n))) & 0xffff;
  const con: number[] = [];
  const t: number[] = [];
  let cur = iv;
  while (con.length < count) {
    t.push(cur);
    con.push(u32((((cur ^ P) & 0xffff) << 16) | rotl16(~cur & 0xffff, 1)));
    con.push(u32(((((~cur) ^ Q) & 0xffff) << 16) | rotl16(cur, 8)));
    cur = (cur & 1) !== 0 ? (cur ^ 0x1a831) >>> 1 : cur >>> 1;
  }
  return { con: con.slice(0, count), t };
}

const CLEFIA_CON: Record<string, { con: number[]; t: number[] }> = {
  "128": clefiaConstants(0x428a, 60),
  "192": clefiaConstants(0x7137, 84),
  "256": clefiaConstants(0xb5c0, 92),
};

/** Exported so a test can check the derivation against RFC 6114's Tables 4-9. */
export const CLEFIA_CONSTANTS = CLEFIA_CON;

const loadBE32 = (b: Uint8Array, o: number): number =>
  u32((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!);
const storeBE32 = (b: Uint8Array, o: number, v: number): void => {
  b[o] = (v >>> 24) & 0xff;
  b[o + 1] = (v >>> 16) & 0xff;
  b[o + 2] = (v >>> 8) & 0xff;
  b[o + 3] = v & 0xff;
};

/** CLEFIA over a 16-, 24- or 32-byte key. */
export function createClefia(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`CLEFIA's key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }
  const bits = key.length * 8;
  const con = CLEFIA_CON[String(bits)]!.con;
  const words: number[] = [];
  for (let i = 0; i < key.length / 4; i++) words.push(loadBE32(key, 4 * i));

  let wk: number[];
  const rk: number[] = [];
  let rounds: number;

  if (bits === 128) {
    let l = gfn4(con.slice(0, 24), words, 12);
    wk = [...words];
    for (let i = 0; i < 9; i++) {
      const t = [0, 1, 2, 3].map((j) => u32(l[j]! ^ con[24 + 4 * i + j]!));
      l = doubleSwap(l);
      if (i % 2 === 1) for (let j = 0; j < 4; j++) t[j] = u32(t[j]! ^ words[j]!);
      rk.push(...t);
    }
    rounds = 18;
  } else {
    const kl = words.slice(0, 4);
    // A 192-bit key completes KR with the complement of its first two words; a 256-bit one does not.
    const kr =
      bits === 192
        ? [words[4]!, words[5]!, u32(~words[0]!), u32(~words[1]!)]
        : words.slice(4, 8);
    const l = gfn8(con.slice(0, 40), [...kl, ...kr], 10);
    let ll = l.slice(0, 4);
    let lr = l.slice(4, 8);
    wk = [0, 1, 2, 3].map((j) => u32(kl[j]! ^ kr[j]!));
    const iterations = bits === 192 ? 11 : 13;
    for (let i = 0; i < iterations; i++) {
      // Two iterations from LL, then two from LR, alternating.
      const useLl = i % 4 === 0 || i % 4 === 1;
      const src = useLl ? ll : lr;
      const t = [0, 1, 2, 3].map((j) => u32(src[j]! ^ con[40 + 4 * i + j]!));
      if (useLl) ll = doubleSwap(ll);
      else lr = doubleSwap(lr);
      if (i % 2 === 1) {
        const other = useLl ? kr : kl;
        for (let j = 0; j < 4; j++) t[j] = u32(t[j]! ^ other[j]!);
      }
      rk.push(...t);
    }
    rounds = bits === 192 ? 22 : 26;
  }

  return {
    blockSize: 16,
    encryptBlock(src, dst) {
      const p = [loadBE32(src, 0), loadBE32(src, 4), loadBE32(src, 8), loadBE32(src, 12)];
      const t = gfn4(rk, [p[0]!, u32(p[1]! ^ wk[0]!), p[2]!, u32(p[3]! ^ wk[1]!)], rounds);
      storeBE32(dst, 0, t[0]!);
      storeBE32(dst, 4, u32(t[1]! ^ wk[2]!));
      storeBE32(dst, 8, t[2]!);
      storeBE32(dst, 12, u32(t[3]! ^ wk[3]!));
    },
    decryptBlock(src, dst) {
      const c = [loadBE32(src, 0), loadBE32(src, 4), loadBE32(src, 8), loadBE32(src, 12)];
      const t = gfn4Inv(rk, [c[0]!, u32(c[1]! ^ wk[2]!), c[2]!, u32(c[3]! ^ wk[3]!)], rounds);
      storeBE32(dst, 0, t[0]!);
      storeBE32(dst, 4, u32(t[1]! ^ wk[0]!));
      storeBE32(dst, 8, t[2]!);
      storeBE32(dst, 12, u32(t[3]! ^ wk[1]!));
    },
  };
}

// ---- MARS ----

const marsRotl = (x: number, n: number): number => (n === 0 ? u32(x) : u32((x << n) | (x >>> (32 - n))));
const marsRotr = (x: number, n: number): number => (n === 0 ? u32(x) : u32((x >>> n) | (x << (32 - n))));
const marsRotlMod = (x: number, n: number): number => marsRotl(x, n & 31);

const MS = (a: number): number => MARS_SBOX[a & 0x1ff]!;
const MS0 = (a: number): number => MARS_SBOX[a & 0xff]!;
const MS1 = (a: number): number => MARS_SBOX[(a & 0xff) + 256]!;

const loadLE32 = (b: Uint8Array, o: number): number =>
  u32(b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24));
const storeLE32 = (b: Uint8Array, o: number, v: number): void => {
  b[o] = v & 0xff;
  b[o + 1] = (v >>> 8) & 0xff;
  b[o + 2] = (v >>> 16) & 0xff;
  b[o + 3] = (v >>> 24) & 0xff;
};

/** MARS over a 16-, 24- or 32-byte key. */
export function createMars(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`MARS's key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }
  const T = new Uint32Array(15);
  const words = key.length / 4;
  for (let i = 0; i < words; i++) T[i] = loadLE32(key, 4 * i);
  T[words] = words;

  const k = new Uint32Array(40);
  for (let j = 0; j < 4; j++) {
    for (let i = 0; i < 15; i++) {
      T[i] = u32(T[i]! ^ marsRotl(T[(i + 8) % 15]! ^ T[(i + 13) % 15]!, 3) ^ (4 * i + j));
    }
    for (let c = 0; c < 4; c++) {
      for (let i = 0; i < 15; i++) {
        T[i] = marsRotl(u32(T[i]! + MARS_SBOX[T[(i + 14) % 15]! % 512]!), 9);
      }
    }
    for (let i = 0; i < 10; i++) k[10 * j + i] = T[(4 * i) % 15]!;
  }

  /**
   * The multiplication keys are fixed up so none is weak.
   *
   * The low two bits are forced, and any run of ten or more identical bits is broken by XORing in a
   * rotated S-box entry. This is the one part of MARS with no analogue in any other cipher here.
   */
  for (let i = 5; i < 37; i += 2) {
    let w = u32(k[i]! | 3);
    let m = u32((~w ^ (w << 1)) & (~w ^ (w >>> 1)) & 0x7ffffffe);
    m = u32(m & (m >>> 1));
    m = u32(m & (m >>> 2));
    m = u32(m & (m >>> 4));
    m = u32(m | (m << 1));
    m = u32(m | (m << 2));
    m = u32(m | (m << 4));
    m = u32(m & 0x7ffffffc);
    w = u32(w ^ (marsRotlMod(MARS_SBOX[265 + (k[i]! & 3)]!, k[i - 1]!) & m));
    k[i] = w;
  }

  /** Eight unkeyed rounds of forward mixing. Runs in both directions unchanged. */
  const forwardMix = (s: number[]): number[] => {
    let [a, b, c, d] = s as [number, number, number, number];
    for (let i = 0; i < 8; i++) {
      b = u32(u32(b ^ MS0(a)) + MS1(a >>> 8));
      c = u32(c + MS0(a >>> 16));
      a = marsRotr(a, 24);
      d = u32(d ^ MS1(a));
      if (i % 4 === 0) a = u32(a + d);
      if (i % 4 === 1) a = u32(a + b);
      const t = a;
      a = b;
      b = c;
      c = d;
      d = t;
    }
    return [a, b, c, d];
  };

  /** And eight of backward mixing. */
  const backwardMix = (s: number[]): number[] => {
    let [a, b, c, d] = s as [number, number, number, number];
    for (let i = 0; i < 8; i++) {
      if (i % 4 === 2) a = u32(a - d);
      if (i % 4 === 3) a = u32(a - b);
      b = u32(b ^ MS1(a));
      c = u32(c - MS0(a >>> 24));
      const t = marsRotl(a, 24);
      d = u32(u32(d - MS1(a >>> 16)) ^ MS0(t));
      a = b;
      b = c;
      c = d;
      d = t;
    }
    return [a, b, c, d];
  };

  return {
    blockSize: 16,
    encryptBlock(src, dst) {
      let a = u32(loadLE32(src, 0) + k[0]!);
      let b = u32(loadLE32(src, 4) + k[1]!);
      let c = u32(loadLE32(src, 8) + k[2]!);
      let d = u32(loadLE32(src, 12) + k[3]!);
      [a, b, c, d] = forwardMix([a, b, c, d]) as [number, number, number, number];
      for (let i = 0; i < 16; i++) {
        const t = marsRotl(a, 13);
        // `t * k` exceeds 32 bits; the reference relies on the wrap, so `Math.imul` is required.
        const r = marsRotl(Math.imul(t, k[2 * i + 5]!), 10);
        const m = u32(a + k[2 * i + 4]!);
        const l = marsRotlMod(u32(MS(m) ^ marsRotr(r, 5) ^ r), r);
        c = u32(c + marsRotlMod(m, marsRotr(r, 5)));
        if (i < 8) {
          b = u32(b + l);
          d = u32(d ^ r);
        } else {
          d = u32(d + l);
          b = u32(b ^ r);
        }
        a = b;
        b = c;
        c = d;
        d = t;
      }
      [a, b, c, d] = backwardMix([a, b, c, d]) as [number, number, number, number];
      storeLE32(dst, 0, u32(a - k[36]!));
      storeLE32(dst, 4, u32(b - k[37]!));
      storeLE32(dst, 8, u32(c - k[38]!));
      storeLE32(dst, 12, u32(d - k[39]!));
    },
    decryptBlock(src, dst) {
      // The words load and store in reverse, which is what lets the mixing phases run unchanged.
      let d = u32(loadLE32(src, 0) + k[36]!);
      let c = u32(loadLE32(src, 4) + k[37]!);
      let b = u32(loadLE32(src, 8) + k[38]!);
      let a = u32(loadLE32(src, 12) + k[39]!);
      [a, b, c, d] = forwardMix([a, b, c, d]) as [number, number, number, number];
      for (let i = 0; i < 16; i++) {
        const t = marsRotr(a, 13);
        const r = marsRotl(Math.imul(a, k[35 - 2 * i]!), 10);
        const m = u32(t + k[34 - 2 * i]!);
        const l = marsRotlMod(u32(MS(m) ^ marsRotr(r, 5) ^ r), r);
        c = u32(c - marsRotlMod(m, marsRotr(r, 5)));
        if (i < 8) {
          b = u32(b - l);
          d = u32(d ^ r);
        } else {
          d = u32(d - l);
          b = u32(b ^ r);
        }
        a = b;
        b = c;
        c = d;
        d = t;
      }
      [a, b, c, d] = backwardMix([a, b, c, d]) as [number, number, number, number];
      storeLE32(dst, 0, u32(d - k[0]!));
      storeLE32(dst, 4, u32(c - k[1]!));
      storeLE32(dst, 8, u32(b - k[2]!));
      storeLE32(dst, 12, u32(a - k[3]!));
    },
  };
}

// ---- Rabbit ----

const RABBIT_A = [
  0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3,
] as const;

interface RabbitState {
  x: number[];
  c: number[];
  b: number;
}

/**
 * `g(u,v) = LSW(square(u+v)) ^ MSW(square(u+v))`, the whole of Rabbit's nonlinearity.
 *
 * The square is a full 64-bit product of a 32-bit value, so `bigint` rather than `Math.imul`: both
 * halves are needed, not just the low one.
 */
const rabbitG = (x: number, c: number): number => {
  const s = BigInt(u32(x + c));
  const sq = s * s;
  return u32(Number(sq & 0xffffffffn) ^ Number((sq >> 32n) & 0xffffffffn));
};

function rabbitCounterUpdate(st: RabbitState): void {
  let b = st.b;
  for (let j = 0; j < 8; j++) {
    const t = st.c[j]! + RABBIT_A[j]! + b;
    b = t >= 0x100000000 ? 1 : 0;
    st.c[j] = u32(t);
  }
  st.b = b;
}

function rabbitNextState(st: RabbitState): void {
  const g: number[] = [];
  for (let j = 0; j < 8; j++) g.push(rabbitG(st.x[j]!, st.c[j]!));
  const x = st.x;
  x[0] = u32(g[0]! + marsRotl(g[7]!, 16) + marsRotl(g[6]!, 16));
  x[1] = u32(g[1]! + marsRotl(g[0]!, 8) + g[7]!);
  x[2] = u32(g[2]! + marsRotl(g[1]!, 16) + marsRotl(g[0]!, 16));
  x[3] = u32(g[3]! + marsRotl(g[2]!, 8) + g[1]!);
  x[4] = u32(g[4]! + marsRotl(g[3]!, 16) + marsRotl(g[2]!, 16));
  x[5] = u32(g[5]! + marsRotl(g[4]!, 8) + g[3]!);
  x[6] = u32(g[6]! + marsRotl(g[5]!, 16) + marsRotl(g[4]!, 16));
  x[7] = u32(g[7]! + marsRotl(g[6]!, 8) + g[5]!);
}

/**
 * Rabbit's keystream generator.
 *
 * The IV is optional and RFC 4503 publishes vectors for both cases -- so an empty nonce means "no IV
 * setup" rather than "an IV of eight zero bytes", and the two give different keystreams. That is the
 * one thing about this cipher a caller can get wrong without any error.
 */
export function createRabbit(key: Uint8Array, iv: Uint8Array): {
  keystream(length: number): Uint8Array;
} {
  if (key.length !== 16) {
    throw new Error(`Rabbit's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  if (iv.length !== 0 && iv.length !== 8) {
    throw new Error(`Rabbit's IV is 8 bytes, or empty for no IV setup; this one is ${iv.length}.`);
  }

  // The key is an integer (RFC 4503 says OS2IP), so subkey j is the j-th 16-bit slice from the low end.
  const K: number[] = [];
  for (let j = 0; j < 8; j++) K.push((key[14 - 2 * j]! << 8) | key[15 - 2 * j]!);

  const st: RabbitState = { x: new Array<number>(8).fill(0), c: new Array<number>(8).fill(0), b: 0 };
  for (let j = 0; j < 8; j++) {
    if (j % 2 === 0) {
      st.x[j] = u32((K[(j + 1) % 8]! << 16) | K[j]!);
      st.c[j] = u32((K[(j + 4) % 8]! << 16) | K[(j + 5) % 8]!);
    } else {
      st.x[j] = u32((K[(j + 5) % 8]! << 16) | K[(j + 4) % 8]!);
      st.c[j] = u32((K[j]! << 16) | K[(j + 1) % 8]!);
    }
  }
  for (let i = 0; i < 4; i++) {
    rabbitCounterUpdate(st);
    rabbitNextState(st);
  }
  for (let j = 0; j < 8; j++) st.c[j] = u32(st.c[j]! ^ st.x[(j + 4) % 8]!);

  if (iv.length === 8) {
    const i16: number[] = [];
    for (let j = 0; j < 4; j++) i16.push((iv[6 - 2 * j]! << 8) | iv[7 - 2 * j]!);
    const lo = u32((i16[1]! << 16) | i16[0]!);
    const hi = u32((i16[3]! << 16) | i16[2]!);
    const midA = u32((i16[3]! << 16) | i16[1]!);
    const midB = u32((i16[2]! << 16) | i16[0]!);
    const mask = [lo, midA, hi, midB, lo, midA, hi, midB];
    for (let j = 0; j < 8; j++) st.c[j] = u32(st.c[j]! ^ mask[j]!);
    for (let n = 0; n < 4; n++) {
      rabbitCounterUpdate(st);
      rabbitNextState(st);
    }
  }

  const block = new Uint8Array(16);
  let ptr = 16;

  const fill = (): void => {
    rabbitCounterUpdate(st);
    rabbitNextState(st);
    const x = st.x;
    const lo16 = (v: number): number => v & 0xffff;
    const hi16 = (v: number): number => v >>> 16;
    const s = [
      lo16(x[0]!) ^ hi16(x[5]!),
      hi16(x[0]!) ^ lo16(x[3]!),
      lo16(x[2]!) ^ hi16(x[7]!),
      hi16(x[2]!) ^ lo16(x[5]!),
      lo16(x[4]!) ^ hi16(x[1]!),
      hi16(x[4]!) ^ lo16(x[7]!),
      lo16(x[6]!) ^ hi16(x[3]!),
      hi16(x[6]!) ^ lo16(x[1]!),
    ];
    // Slice j is S[16j+15 .. 16j], and I2OSP writes the most significant byte first.
    for (let j = 0; j < 8; j++) {
      block[14 - 2 * j] = (s[j]! >>> 8) & 0xff;
      block[15 - 2 * j] = s[j]! & 0xff;
    }
    ptr = 0;
  };

  return {
    keystream(length) {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        if (ptr === 16) fill();
        out[i] = block[ptr++]!;
      }
      return out;
    },
  };
}

/** Rabbit is its own inverse, so one function serves both directions. */
export function rabbitCrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const gen = createRabbit(key, iv);
  const ks = gen.keystream(data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ ks[i]!;
  return out;
}
