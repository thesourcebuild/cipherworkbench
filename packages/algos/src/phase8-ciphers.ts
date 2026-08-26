/**
 * Trivium, KASUMI and Khazad -- three algorithms whose vectors took a third source to find.
 *
 * Bouncy Castle has none of them and Crypto++ has none of them. What did: **Botan 2.19.3**, whose
 * `src/tests/data/block/` carries `kasumi.vec` and `misty.vec`; and **avr-crypto-lib**, which mirrors
 * the eSTREAM and NESSIE submission test-vector files that `ecrypt.eu.org` no longer serves. Both are
 * recorded in `CLAUDE.md` alongside the RFC and Crypto++ routes, because a fourth batch will want them.
 *
 * ## Trivium
 *
 * eSTREAM's hardware-profile winner and the smallest cipher in this repo by a wide margin: 288 bits of
 * state in three coupled nonlinear feedback registers, and no tables, constants or key schedule at all.
 * Its whole specification fits in the twelve lines of `round` below.
 *
 * **The bit-loading convention is the only hard part, and no summary of the algorithm states it.** The
 * paper says `(s1..s93) <- (K1..K80, 0...0)` and leaves what `K1` means to the API. eSTREAM's vectors
 * are hex, and the bit that becomes `s[1]` is the **most significant bit of the last key byte** -- so
 * the bytes are consumed in reverse and the bits within each byte most significant first. Three of the
 * four plausible orderings produce a keystream that looks perfectly random and matches nothing; this
 * one was settled by reading avr-crypto-lib's reference rather than by guessing, after the guesses
 * failed.
 *
 * The output byte assembles **least significant bit first**, which is the opposite convention to the
 * input. That asymmetry is real and is what the reference does.
 *
 * ## KASUMI
 *
 * 3GPP's modification of MISTY1, and the cipher behind A5/3, GEA3, f8 and f9 -- so it is what GSM, GPRS
 * and 3G confidentiality actually ran on. `security: "broken"` and it is not close: Biham, Dunkelman and
 * Keller's related-key attack recovers the full 128-bit key with four related keys, 2^26 data and 2^32
 * time, which is minutes on a laptop. It is here to reproduce values, and the metadata says so.
 *
 * **Its S-boxes are not MISTY1's**, and neither is its FI. MISTY1's FI applies S9, S7, S9; KASUMI's
 * applies S9, S7, S9, S7 and mixes the key in the middle rather than after the first pair. Sharing
 * either with `phase6-ciphers.ts` would give a cipher that is self-consistent and matches nothing.
 *
 * **Its round structure processes two rounds at a time**, which is why the subkey window below is
 * sixteen wide and the loop steps by two. The FL layers sit at the outside of each pair rather than
 * between every round.
 *
 * ## Khazad
 *
 * Barreto and Rijmen's NESSIE submission -- the same pair as AES, and an involutional design: the
 * cipher and its inverse are the same circuit, because the S-box and the diffusion matrix are both
 * their own inverses. Only the key schedule runs backwards.
 *
 * **Nothing is stored but sixteen bytes.** The 8-bit S-box is three layers of a pair of 4-bit boxes
 * with a nibble crossover between them, and both 4-bit boxes pack into one 16-byte table -- P in the
 * high nibble, Q in the low. That is the derive-don't-transcribe rule at its strongest: there is no
 * 256-entry table to mistype, and the permutation property is checked at load.
 *
 * **The decryption here XORs the round key *before* theta rather than applying theta to the key.** By
 * linearity those are the same thing, and doing it this way means the round keys are stored once. It
 * looks wrong against the standard write-up, which is why this note exists.
 *
 * ## Verification
 *
 * No oracle for any of the three -- OpenSSL has none and no dependency here does either.
 *
 *  - **Trivium**: 984 assertions from eSTREAM's own verified vector files, across all three IV widths
 *    (32, 64 and 80 bits). Each vector checks four separate windows of the keystream, including one at
 *    offset 448, so a state that drifted after the first block could not pass.
 *  - **KASUMI**: Botan's three vectors, each in both directions against the published plaintext.
 *  - **Khazad**: 450 NESSIE vectors -- 1,800 assertions, because each carries a plaintext, a
 *    ciphertext, and the result of encrypting 100 and 1,000 times over. The iterated values are the
 *    valuable part: they catch a fault that only shows after the state has been through itself.
 */

import type { BlockCipher } from "./blockmodes";

const u16 = (v: number): number => v & 0xffff;
const rotl16 = (x: number, n: number): number => u16((x << n) | (x >>> (16 - n)));

/**
 * KASUMI's 7-bit S-box. NOT MISTY1's -- 3GPP replaced both boxes when it derived this.
 *
 * Checked to be a permutation at load, which is the only cheap guard on a transcribed table.
 */
const KASUMI_S7 = new Uint8Array([
  0x36, 0x32, 0x3e, 0x38, 0x16, 0x22, 0x5e, 0x60, 0x26, 0x06, 0x3f, 0x5d, 0x02, 0x12, 0x7b, 0x21,
  0x37, 0x71, 0x27, 0x72, 0x15, 0x43, 0x41, 0x0c, 0x2f, 0x49, 0x2e, 0x1b, 0x19, 0x6f, 0x7c, 0x51,
  0x35, 0x09, 0x79, 0x4f, 0x34, 0x3c, 0x3a, 0x30, 0x65, 0x7f, 0x28, 0x78, 0x68, 0x46, 0x47, 0x2b,
  0x14, 0x7a, 0x48, 0x3d, 0x17, 0x6d, 0x0d, 0x64, 0x4d, 0x01, 0x10, 0x07, 0x52, 0x0a, 0x69, 0x62,
  0x75, 0x74, 0x4c, 0x0b, 0x59, 0x6a, 0x00, 0x7d, 0x76, 0x63, 0x56, 0x45, 0x1e, 0x39, 0x7e, 0x57,
  0x70, 0x33, 0x11, 0x05, 0x5f, 0x0e, 0x5a, 0x54, 0x5b, 0x08, 0x23, 0x67, 0x20, 0x61, 0x1c, 0x42,
  0x66, 0x1f, 0x1a, 0x2d, 0x4b, 0x04, 0x55, 0x5c, 0x25, 0x4a, 0x50, 0x31, 0x44, 0x1d, 0x73, 0x2c,
  0x40, 0x6b, 0x6c, 0x18, 0x6e, 0x53, 0x24, 0x4e, 0x2a, 0x13, 0x0f, 0x29, 0x58, 0x77, 0x3b, 0x03,
]);

/** And KASUMI's 9-bit box, also its own. */
const KASUMI_S9 = new Uint16Array([
  0x0a7, 0x0ef, 0x0a1, 0x17b, 0x187, 0x14e, 0x009, 0x152, 0x026, 0x0e2, 0x030, 0x166, 0x1c4, 0x181, 0x05a, 0x18d,
  0x0b7, 0x0fd, 0x093, 0x14b, 0x19f, 0x154, 0x033, 0x16a, 0x132, 0x1f4, 0x106, 0x052, 0x0d8, 0x09f, 0x164, 0x0b1,
  0x0af, 0x0f1, 0x1e9, 0x025, 0x0ce, 0x011, 0x000, 0x14d, 0x02c, 0x0fe, 0x17a, 0x03a, 0x08f, 0x0dc, 0x051, 0x190,
  0x05f, 0x003, 0x13b, 0x0f5, 0x036, 0x0eb, 0x0da, 0x195, 0x1d8, 0x108, 0x0ac, 0x1ee, 0x173, 0x122, 0x18f, 0x04c,
  0x0a5, 0x0c5, 0x18b, 0x079, 0x101, 0x1e0, 0x1a7, 0x0d4, 0x0f0, 0x01c, 0x1ce, 0x0b0, 0x196, 0x1fb, 0x120, 0x0df,
  0x1f5, 0x197, 0x0f9, 0x109, 0x059, 0x0ba, 0x0dd, 0x1ac, 0x0a4, 0x04a, 0x1b8, 0x0c4, 0x1ca, 0x1a5, 0x15e, 0x0a3,
  0x0e8, 0x09e, 0x086, 0x162, 0x00d, 0x0fa, 0x1eb, 0x08e, 0x0bf, 0x045, 0x0c1, 0x1a9, 0x098, 0x0e3, 0x16e, 0x087,
  0x158, 0x12c, 0x114, 0x0f2, 0x1b5, 0x140, 0x071, 0x116, 0x00b, 0x0f3, 0x057, 0x13d, 0x024, 0x05d, 0x1f0, 0x01b,
  0x1e7, 0x1be, 0x1e2, 0x029, 0x044, 0x09c, 0x1c9, 0x083, 0x146, 0x193, 0x153, 0x014, 0x027, 0x073, 0x1ba, 0x07c,
  0x1db, 0x180, 0x1fc, 0x035, 0x070, 0x0aa, 0x1df, 0x097, 0x07e, 0x0a9, 0x049, 0x10c, 0x117, 0x141, 0x0a8, 0x16c,
  0x16b, 0x124, 0x02e, 0x1f3, 0x189, 0x147, 0x144, 0x018, 0x1c8, 0x10b, 0x09d, 0x1cc, 0x1e8, 0x1aa, 0x135, 0x0e5,
  0x1b7, 0x1fa, 0x0d0, 0x10f, 0x15d, 0x191, 0x1b2, 0x0ec, 0x010, 0x0d1, 0x167, 0x034, 0x038, 0x078, 0x0c7, 0x115,
  0x1d1, 0x1a0, 0x0fc, 0x11f, 0x0f6, 0x006, 0x053, 0x131, 0x1a4, 0x159, 0x099, 0x1f6, 0x041, 0x03d, 0x0f4, 0x11a,
  0x0ad, 0x0de, 0x1a2, 0x043, 0x182, 0x170, 0x105, 0x065, 0x1dc, 0x123, 0x0c3, 0x1ae, 0x031, 0x04f, 0x0a6, 0x14a,
  0x118, 0x17f, 0x175, 0x080, 0x17e, 0x198, 0x09b, 0x1ef, 0x16f, 0x184, 0x112, 0x06b, 0x1cb, 0x1a1, 0x03e, 0x1c6,
  0x084, 0x0e1, 0x0cb, 0x13c, 0x0ea, 0x00e, 0x12d, 0x05b, 0x1f7, 0x11e, 0x1a8, 0x0d3, 0x15b, 0x133, 0x08c, 0x176,
  0x023, 0x067, 0x07d, 0x1ab, 0x013, 0x0d6, 0x1c5, 0x092, 0x1f2, 0x13a, 0x1bc, 0x0e6, 0x100, 0x149, 0x0c6, 0x11d,
  0x032, 0x074, 0x04e, 0x19a, 0x00a, 0x0cd, 0x1fe, 0x0ab, 0x0e7, 0x02d, 0x08b, 0x1d3, 0x01d, 0x056, 0x1f9, 0x020,
  0x048, 0x01a, 0x156, 0x096, 0x139, 0x1ea, 0x1af, 0x0ee, 0x19b, 0x145, 0x095, 0x1d9, 0x028, 0x077, 0x0ae, 0x163,
  0x0b9, 0x0e9, 0x185, 0x047, 0x1c0, 0x111, 0x174, 0x037, 0x06e, 0x0b2, 0x142, 0x00c, 0x1d5, 0x188, 0x171, 0x0be,
  0x001, 0x06d, 0x177, 0x089, 0x0b5, 0x058, 0x04b, 0x134, 0x104, 0x1e4, 0x062, 0x110, 0x172, 0x113, 0x19c, 0x06f,
  0x150, 0x13e, 0x004, 0x1f8, 0x1ec, 0x103, 0x130, 0x04d, 0x151, 0x1b3, 0x015, 0x165, 0x12f, 0x14c, 0x1e3, 0x012,
  0x02f, 0x055, 0x019, 0x1f1, 0x1da, 0x121, 0x064, 0x10d, 0x128, 0x1de, 0x10e, 0x06a, 0x01f, 0x068, 0x1b1, 0x054,
  0x19e, 0x1e6, 0x18a, 0x060, 0x063, 0x09a, 0x1ff, 0x094, 0x19d, 0x169, 0x199, 0x0ff, 0x0a2, 0x0d7, 0x12e, 0x0c9,
  0x10a, 0x15f, 0x157, 0x090, 0x1b9, 0x16d, 0x06c, 0x12a, 0x0fb, 0x022, 0x0b6, 0x1fd, 0x08a, 0x0d2, 0x14f, 0x085,
  0x137, 0x160, 0x148, 0x08d, 0x18c, 0x15a, 0x07b, 0x13f, 0x1c2, 0x119, 0x1ad, 0x0e4, 0x1bb, 0x1e1, 0x05c, 0x194,
  0x1e5, 0x1a6, 0x0f8, 0x129, 0x017, 0x0d5, 0x082, 0x1d2, 0x016, 0x0d9, 0x11b, 0x046, 0x126, 0x168, 0x1a3, 0x07f,
  0x138, 0x179, 0x007, 0x1d4, 0x0c2, 0x002, 0x075, 0x127, 0x1cf, 0x102, 0x0e0, 0x1bf, 0x0f7, 0x0bb, 0x050, 0x18e,
  0x11c, 0x161, 0x069, 0x186, 0x12b, 0x1d7, 0x1d6, 0x0b8, 0x039, 0x0c8, 0x15c, 0x03f, 0x0cc, 0x0bc, 0x021, 0x1c3,
  0x061, 0x01e, 0x136, 0x0db, 0x05e, 0x0a0, 0x081, 0x1ed, 0x040, 0x0b3, 0x107, 0x066, 0x0bd, 0x0cf, 0x072, 0x192,
  0x1b6, 0x1dd, 0x183, 0x07a, 0x0c0, 0x02a, 0x17d, 0x005, 0x091, 0x076, 0x0b4, 0x1c1, 0x125, 0x143, 0x088, 0x17c,
  0x02b, 0x042, 0x03c, 0x1c7, 0x155, 0x1bd, 0x0ca, 0x1b0, 0x008, 0x0ed, 0x00f, 0x178, 0x1b4, 0x1d0, 0x03b, 0x1cd,
]);

{
  const seen7 = new Set<number>(KASUMI_S7);
  if (seen7.size !== 128) throw new Error("KASUMI S7 is not a permutation");
  const seen9 = new Set<number>(KASUMI_S9);
  if (seen9.size !== 512) throw new Error("KASUMI S9 is not a permutation");
}

/** Exported so a test can pin the transcription, and confirm it differs from MISTY1's. */
export const KASUMI_SBOX_FIRST: readonly [number, number] = [KASUMI_S7[0]!, KASUMI_S9[0]!];

/**
 * KASUMI's FI. Four substitutions, not three, and the key enters between the second and third.
 *
 * MISTY1's is S9, S7, S9 with the key after the first pair. Reusing either for the other gives a
 * cipher that inverts perfectly and reproduces nothing.
 */
const kasumiFi = (input: number, key: number): number => {
  let d9 = input >>> 7;
  let d7 = input & 0x7f;
  d9 = KASUMI_S9[d9]! ^ d7;
  d7 = KASUMI_S7[d7]! ^ (d9 & 0x7f);
  d7 ^= key >>> 9;
  d9 = KASUMI_S9[d9 ^ (key & 0x1ff)]! ^ d7;
  d7 = KASUMI_S7[d7]! ^ (d9 & 0x7f);
  return u16((d7 << 9) | d9);
};

/** The eight round constants, and the whole key schedule is one rotation of each word. */
const KASUMI_RC = [0x0123, 0x4567, 0x89ab, 0xcdef, 0xfedc, 0xba98, 0x7654, 0x3210] as const;

/** KASUMI over a 16-byte key. 64-bit block, eight rounds taken two at a time. */
export function createKasumi(key: Uint8Array): BlockCipher {
  if (key.length !== 16) {
    throw new Error(`KASUMI's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const k: number[] = new Array<number>(16).fill(0);
  for (let i = 0; i < 8; i++) {
    k[i] = (key[2 * i]! << 8) | key[2 * i + 1]!;
    k[i + 8] = k[i]! ^ KASUMI_RC[i]!;
  }
  const ek: number[] = new Array<number>(64).fill(0);
  for (let i = 0; i < 8; i++) {
    ek[8 * i] = rotl16(k[(i + 0) % 8]!, 2);
    ek[8 * i + 1] = rotl16(k[((i + 2) % 8) + 8]!, 1);
    ek[8 * i + 2] = rotl16(k[(i + 1) % 8]!, 5);
    ek[8 * i + 3] = k[((i + 4) % 8) + 8]!;
    ek[8 * i + 4] = rotl16(k[(i + 5) % 8]!, 8);
    ek[8 * i + 5] = k[((i + 3) % 8) + 8]!;
    ek[8 * i + 6] = rotl16(k[(i + 6) % 8]!, 13);
    ek[8 * i + 7] = k[((i + 7) % 8) + 8]!;
  }

  const rd = (b: Uint8Array, o: number): number => (b[o]! << 8) | b[o + 1]!;
  const wr = (b: Uint8Array, o: number, v: number): void => {
    b[o] = (v >>> 8) & 0xff;
    b[o + 1] = v & 0xff;
  };

  return {
    blockSize: 8,
    encryptBlock(src, dst) {
      let b0 = rd(src, 0);
      let b1 = rd(src, 2);
      let b2 = rd(src, 4);
      let b3 = rd(src, 6);
      // Two rounds per iteration, so the subkey window is sixteen wide.
      for (let j = 0; j < 8; j += 2) {
        const w = ek.slice(8 * j, 8 * j + 16);
        let r = b1 ^ (rotl16(b0, 1) & w[0]!);
        let l = b0 ^ (rotl16(r, 1) | w[1]!);
        l = kasumiFi(l ^ w[2]!, w[3]!) ^ r;
        r = kasumiFi(r ^ w[4]!, w[5]!) ^ l;
        l = kasumiFi(l ^ w[6]!, w[7]!) ^ r;
        b2 = u16(b2 ^ r);
        r = b2;
        b3 = u16(b3 ^ l);
        l = b3;
        r = kasumiFi(r ^ w[10]!, w[11]!) ^ l;
        l = kasumiFi(l ^ w[12]!, w[13]!) ^ r;
        r = kasumiFi(r ^ w[14]!, w[15]!) ^ l;
        r = u16(r ^ (rotl16(l, 1) & w[8]!));
        l = u16(l ^ (rotl16(r, 1) | w[9]!));
        b0 = u16(b0 ^ l);
        b1 = u16(b1 ^ r);
      }
      wr(dst, 0, b0);
      wr(dst, 2, b1);
      wr(dst, 4, b2);
      wr(dst, 6, b3);
    },
    decryptBlock(src, dst) {
      let b0 = rd(src, 0);
      let b1 = rd(src, 2);
      let b2 = rd(src, 4);
      let b3 = rd(src, 6);
      for (let j = 0; j < 8; j += 2) {
        const w = ek.slice(8 * (6 - j), 8 * (6 - j) + 16);
        let l = b2;
        let r = b3;
        l = kasumiFi(l ^ w[10]!, w[11]!) ^ r;
        r = kasumiFi(r ^ w[12]!, w[13]!) ^ l;
        l = kasumiFi(l ^ w[14]!, w[15]!) ^ r;
        l = u16(l ^ (rotl16(r, 1) & w[8]!));
        r = u16(r ^ (rotl16(l, 1) | w[9]!));
        b0 = u16(b0 ^ r);
        r = b0;
        b1 = u16(b1 ^ l);
        l = b1;
        l = u16(l ^ (rotl16(r, 1) & w[0]!));
        r = u16(r ^ (rotl16(l, 1) | w[1]!));
        r = kasumiFi(r ^ w[2]!, w[3]!) ^ l;
        l = kasumiFi(l ^ w[4]!, w[5]!) ^ r;
        r = kasumiFi(r ^ w[6]!, w[7]!) ^ l;
        b2 = u16(b2 ^ l);
        b3 = u16(b3 ^ r);
      }
      wr(dst, 0, b0);
      wr(dst, 2, b1);
      wr(dst, 4, b2);
      wr(dst, 6, b3);
    },
  };
}

// ---- Khazad ----

/**
 * Both 4-bit boxes in sixteen bytes: P in the high nibble, Q in the low.
 *
 * This is the entire substitution layer. The 8-bit box below is three layers of (P, Q) with a nibble
 * crossover between them, so there is no 256-entry table to mistype -- and `KHAZAD_SBOX` is checked to
 * be a permutation at load, which is the property the whole construction rests on.
 */
const KHAZAD_PQ = [
  0x39, 0xfe, 0xe5, 0x06, 0x5a, 0x42, 0xb3, 0xcc, 0xdf, 0xa0, 0x94, 0x6d, 0x77, 0x8b, 0x21, 0x18,
] as const;

const khazadSboxByte = (a: number): number => {
  let b = KHAZAD_PQ[a >> 4]! & 0xf0;
  let c = KHAZAD_PQ[a & 0xf]! & 0x0f;
  let d = (b >> 2) & 0x0c;
  let e = (c << 2) & 0x30;
  b = (b & 0xc0) | e;
  c = (c & 0x03) | d;
  b = (KHAZAD_PQ[b >> 4]! << 4) & 0xff;
  c = KHAZAD_PQ[c & 0xf]! >> 4;
  d = (b >> 2) & 0x0c;
  e = (c << 2) & 0x30;
  b = (b & 0xc0) | e;
  c = (c & 0x03) | d;
  b = KHAZAD_PQ[b >> 4]! & 0xf0;
  c = KHAZAD_PQ[c & 0xf]! & 0x0f;
  return b | c;
};

/**
 * Khazad's S-box, derived below from sixteen packed bytes.
 *
 * Exported because **Anubis-tweaked's S-box is this one entry for entry** -- the two ciphers were
 * designed together and revised together -- so `anubis.ts` imports it rather than storing a second
 * copy. That also means Khazad's 450 NESSIE vectors already pin Anubis's substitution layer.
 */
export const KHAZAD_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) KHAZAD_SBOX[i] = khazadSboxByte(i);
{
  const seen = new Set<number>(KHAZAD_SBOX);
  if (seen.size !== 256) throw new Error("Khazad's derived S-box is not a permutation");
}

/** Exported so a test can pin the derivation against a value from the submission. */
export const KHAZAD_SBOX_FIRST: number = KHAZAD_SBOX[0]!;

/** GF(2^8) under Khazad's polynomial x^8 + x^4 + x^3 + x^2 + 1 = 0x11d. */
const khazadMul = (a: number, b: number): number => {
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

/**
 * The diffusion matrix H, stored as nibble pairs the way the reference does.
 *
 * It is *involutory* -- H times H is the identity -- which together with the S-box being its own
 * inverse is what makes Khazad one circuit for both directions.
 */
const KHAZAD_H_PACKED = [
  [0x13, 0x45, 0x68, 0xb7],
  [0x31, 0x54, 0x86, 0x7b],
  [0x45, 0x13, 0xb7, 0x68],
  [0x54, 0x31, 0x7b, 0x86],
  [0x68, 0xb7, 0x13, 0x45],
  [0x86, 0x7b, 0x31, 0x54],
  [0xb7, 0x68, 0x45, 0x13],
  [0x7b, 0x86, 0x54, 0x31],
] as const;

const KHAZAD_H: readonly (readonly number[])[] = KHAZAD_H_PACKED.map((row) =>
  row.flatMap((pair) => [pair >> 4, pair & 0xf]),
);

/** Exported so a test can assert the involution rather than trusting the transcription. */
export const KHAZAD_MATRIX: readonly (readonly number[])[] = KHAZAD_H;

const khazadGamma = (a: Uint8Array): void => {
  for (let i = 0; i < 8; i++) a[i] = KHAZAD_SBOX[a[i]!]!;
};

const khazadTheta = (a: Uint8Array): void => {
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let acc = 0;
    for (let j = 0; j < 8; j++) acc ^= khazadMul(a[j]!, KHAZAD_H[i]![j]!);
    out[i] = acc;
  }
  a.set(out);
};

const khazadXor = (a: Uint8Array, b: Uint8Array | ArrayLike<number>, offset = 0): void => {
  for (let i = 0; i < 8; i++) a[i] = a[i]! ^ b[offset + i]!;
};

/** Khazad over a 16-byte key. 64-bit block, eight rounds. */
export function createKhazad(key: Uint8Array): BlockCipher {
  if (key.length !== 16) {
    throw new Error(`Khazad's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const rk: Uint8Array[] = [];
  for (let r = 0; r < 9; r++) rk.push(new Uint8Array(8));
  const c = new Uint8Array(8);

  const roundOn = (a: Uint8Array, k: Uint8Array): void => {
    khazadGamma(a);
    khazadTheta(a);
    khazadXor(a, k);
  };

  /**
   * The key schedule is the round function itself, with the round constants taken from the S-box.
   *
   * Constant `i` of round `r` is `S[8r + i]` -- so the eight constants of the last round are
   * `S[64..71]`, and nothing beyond the S-box is stored.
   */
  for (let i = 0; i < 8; i++) c[i] = KHAZAD_SBOX[i]!;
  rk[0]!.set(key.subarray(8, 16));
  roundOn(rk[0]!, c);
  khazadXor(rk[0]!, key, 0);

  for (let i = 0; i < 8; i++) c[i] = KHAZAD_SBOX[8 + i]!;
  rk[1]!.set(rk[0]!);
  roundOn(rk[1]!, c);
  khazadXor(rk[1]!, key, 8);

  for (let r = 2; r < 9; r++) {
    for (let i = 0; i < 8; i++) c[i] = KHAZAD_SBOX[r * 8 + i]!;
    rk[r]!.set(rk[r - 1]!);
    roundOn(rk[r]!, c);
    khazadXor(rk[r]!, rk[r - 2]!);
  }

  return {
    blockSize: 8,
    encryptBlock(src, dst) {
      const a = Uint8Array.from(src.subarray(0, 8));
      khazadXor(a, rk[0]!);
      for (let r = 1; r < 8; r++) roundOn(a, rk[r]!);
      khazadGamma(a);
      khazadXor(a, rk[8]!);
      dst.set(a);
    },
    decryptBlock(src, dst) {
      const a = Uint8Array.from(src.subarray(0, 8));
      khazadXor(a, rk[8]!);
      khazadGamma(a);
      /**
       * The round key is XORed *before* theta rather than theta being applied to the key.
       *
       * By linearity those are identical, and doing it this way means the schedule is stored once
       * instead of twice. It reads as wrong against the standard write-up, which is why this is here.
       */
      for (let r = 7; r >= 1; r--) {
        khazadXor(a, rk[r]!);
        khazadTheta(a);
        khazadGamma(a);
      }
      khazadXor(a, rk[0]!);
      dst.set(a);
    },
  };
}

// ---- Trivium ----

/**
 * Trivium's keystream generator: 288 bits in three coupled registers, indexed from 1 as the paper does.
 *
 * Index 0 of the array is unused. That wastes one byte and keeps every tap below readable against the
 * specification, which for a cipher whose entire definition is fifteen tap positions is the right
 * trade.
 */
export function createTrivium(
  key: Uint8Array,
  iv: Uint8Array,
): { keystream(length: number): Uint8Array } {
  if (key.length !== 10) {
    throw new Error(`Trivium's key is exactly 10 bytes; this one is ${key.length}.`);
  }
  if (iv.length !== 4 && iv.length !== 8 && iv.length !== 10) {
    throw new Error(`Trivium's IV is 4, 8 or 10 bytes; this one is ${iv.length}.`);
  }
  const s = new Uint8Array(289);

  /**
   * Bit `i` of a loaded region is byte `last - i/8`, bit `7 - i%8`.
   *
   * The bytes are consumed in reverse and the bits within each byte most significant first. Three of
   * the four plausible orderings give a keystream that looks random and matches nothing.
   */
  const load = (bytes: Uint8Array, at: number): void => {
    for (let i = 0; i < bytes.length * 8; i++) {
      const byte = bytes[bytes.length - 1 - (i >> 3)]!;
      s[at + i] = (byte >> (7 - (i & 7))) & 1;
    }
  };
  load(key, 1);
  load(iv, 94);
  s[286] = 1;
  s[287] = 1;
  s[288] = 1;

  const round = (): number => {
    let t1 = s[66]! ^ s[93]!;
    let t2 = s[162]! ^ s[177]!;
    let t3 = s[243]! ^ s[288]!;
    const z = t1 ^ t2 ^ t3;
    t1 ^= (s[91]! & s[92]!) ^ s[171]!;
    t2 ^= (s[175]! & s[176]!) ^ s[264]!;
    t3 ^= (s[286]! & s[287]!) ^ s[69]!;
    // Each register shifts up one place and the feedback bit enters at its low end.
    for (let i = 93; i > 1; i--) s[i] = s[i - 1]!;
    s[1] = t3;
    for (let i = 177; i > 94; i--) s[i] = s[i - 1]!;
    s[94] = t1;
    for (let i = 288; i > 178; i--) s[i] = s[i - 1]!;
    s[178] = t2;
    return z;
  };

  // 4 * 288 warm-up rounds with the output discarded, which is what mixes the IV into the key.
  for (let i = 0; i < 4 * 288; i++) round();

  return {
    keystream(length) {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        let byte = 0;
        // Least significant bit first, which is the opposite convention to the loading above.
        for (let b = 0; b < 8; b++) byte |= round() << b;
        out[i] = byte;
      }
      return out;
    },
  };
}

/** Trivium is its own inverse, so one function serves both directions. */
export function triviumCrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const gen = createTrivium(key, iv);
  const ks = gen.keystream(data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ ks[i]!;
  return out;
}
