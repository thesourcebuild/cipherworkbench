/**
 * Romulus -- SKINNY-128-384+ as a tweakable block cipher, in three modes plus a hash. A NIST finalist.
 *
 * The only finalist built on a *tweakable* block cipher, and the only one offering three genuinely
 * different security profiles from one primitive:
 *
 * | Mode | Property | Cost |
 * |---|---|---|
 * | Romulus-N | nonce-respecting, one pass | one cipher call per block |
 * | Romulus-M | nonce-*misuse* resistant | two passes over the message |
 * | Romulus-T | leakage-resilient | a hash over the ciphertext, plus a per-block rekey |
 *
 * Plus Romulus-H, a Hirose double-block-length hash over the same cipher -- what Romulus-T uses
 * internally, and a hash tool in its own right.
 *
 * Ported from the designers' own reference C rather than from an optimised port: the mode logic is
 * intricate enough that a buffering abstraction obscures it. Verified against 1089 known-answer vectors
 * per mode in both directions plus 1025 hash vectors -- 7559 assertions, all first run.
 *
 * ## The counter is a GF(2^56) LFSR, and it is part of the tweak
 *
 * Every cipher call takes `counter || domain || tweak || key` as a 48-byte tweakey. The counter advances
 * by an LFSR rather than by addition, so no two blocks share a tweak, and the domain byte separates the
 * phases. That is the whole of Romulus's structure -- there is no chaining value in the usual sense.
 *
 * ## Where each mode goes wrong
 *
 * **Romulus-N** absorbs associated data in *pairs* of blocks: the odd block by XOR into the state, the
 * even block through the cipher as a tweak. The final domain byte then depends on which of four cases
 * the length fell into -- odd or even block, complete or incomplete.
 *
 * **Romulus-M**'s domain byte is a table over `(adlen mod 32, mlen mod 32)` and has to be computed
 * *before* anything is absorbed, because bit 3 of it decides whether the message's first block goes
 * through `ad2msg` or through the ordinary pair loop.
 *
 * **Romulus-T** hashes `(AD, ciphertext, nonce, counter)`, and the hash's block boundaries interact with
 * where the nonce is injected: five branches, and which one runs decides whether the final compression
 * takes the nonce or only the counter.
 *
 * **`rho` writes a whole block even for a partial one**, zeroing the tail, and the caller takes only the
 * bytes it wanted. `irho` reconstructs the state from the padded ciphertext *and* the recovered
 * plaintext, which is not `rho`'s expression rearranged -- inverting one into the other by hand is how a
 * decrypt path ends up self-consistent and wrong.
 */

import { eagerAbsorber, type LwcHasher } from "./lwc-hash";

/**
 * SKINNY's 8-bit S-box, its tweakey permutation and Romulus's forty round constants.
 *
 * Exported because `skinny.ts` implements the whole SKINNY family and must not keep a second copy: these
 * are already pinned by Romulus's 7,559 known-answer assertions, so a failure in SKINNY's own vectors
 * points at the round count, the 4-bit path or the decryption rather than at a table. `SKINNY_RC_40` is
 * the first forty entries of the specification's LFSR sequence, which `skinny.ts` derives and checks
 * against these.
 */
export const SKINNY_SBOX8 = new Uint8Array([
  0x65,0x4c,0x6a,0x42,0x4b,0x63,0x43,0x6b,0x55,0x75,0x5a,0x7a,0x53,0x73,0x5b,0x7b,
  0x35,0x8c,0x3a,0x81,0x89,0x33,0x80,0x3b,0x95,0x25,0x98,0x2a,0x90,0x23,0x99,0x2b,
  0xe5,0xcc,0xe8,0xc1,0xc9,0xe0,0xc0,0xe9,0xd5,0xf5,0xd8,0xf8,0xd0,0xf0,0xd9,0xf9,
  0xa5,0x1c,0xa8,0x12,0x1b,0xa0,0x13,0xa9,0x05,0xb5,0x0a,0xb8,0x03,0xb0,0x0b,0xb9,
  0x32,0x88,0x3c,0x85,0x8d,0x34,0x84,0x3d,0x91,0x22,0x9c,0x2c,0x94,0x24,0x9d,0x2d,
  0x62,0x4a,0x6c,0x45,0x4d,0x64,0x44,0x6d,0x52,0x72,0x5c,0x7c,0x54,0x74,0x5d,0x7d,
  0xa1,0x1a,0xac,0x15,0x1d,0xa4,0x14,0xad,0x02,0xb1,0x0c,0xbc,0x04,0xb4,0x0d,0xbd,
  0xe1,0xc8,0xec,0xc5,0xcd,0xe4,0xc4,0xed,0xd1,0xf1,0xdc,0xfc,0xd4,0xf4,0xdd,0xfd,
  0x36,0x8e,0x38,0x82,0x8b,0x30,0x83,0x39,0x96,0x26,0x9a,0x28,0x93,0x20,0x9b,0x29,
  0x66,0x4e,0x68,0x41,0x49,0x60,0x40,0x69,0x56,0x76,0x58,0x78,0x50,0x70,0x59,0x79,
  0xa6,0x1e,0xaa,0x11,0x19,0xa3,0x10,0xab,0x06,0xb6,0x08,0xba,0x00,0xb3,0x09,0xbb,
  0xe6,0xce,0xea,0xc2,0xcb,0xe3,0xc3,0xeb,0xd6,0xf6,0xda,0xfa,0xd3,0xf3,0xdb,0xfb,
  0x31,0x8a,0x3e,0x86,0x8f,0x37,0x87,0x3f,0x92,0x21,0x9e,0x2e,0x97,0x27,0x9f,0x2f,
  0x61,0x48,0x6e,0x46,0x4f,0x67,0x47,0x6f,0x51,0x71,0x5e,0x7e,0x57,0x77,0x5f,0x7f,
  0xa2,0x18,0xae,0x16,0x1f,0xa7,0x17,0xaf,0x01,0xb2,0x0e,0xbe,0x07,0xb7,0x0f,0xbf,
  0xe2,0xca,0xee,0xc6,0xcf,0xe7,0xc7,0xef,0xd2,0xf2,0xde,0xfe,0xd7,0xf7,0xdf,0xff,
]);
export const SKINNY_TWEAKEY_P = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] as const;

/** The private aliases the rest of this file was written against. */
const SBOX = SKINNY_SBOX8;
const TWEAKEY_P = SKINNY_TWEAKEY_P;
export const SKINNY_RC_40 = [
  0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,0x0e,
  0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,0x1c,0x38,
  0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a,
] as const;

const RC = SKINNY_RC_40;

/**
 * SKINNY-128-384+ encryption, in place over `block`, under a 48-byte tweakey. Forty rounds.
 *
 * The "+" is the round count: SKINNY-128-384 runs 56, and Romulus uses the 40-round reduction the
 * designers proposed alongside it. Only encryption is written -- none of the modes inverts the cipher.
 */
export function skinny128384plus(block: Uint8Array, tweakey: Uint8Array): void {
  const state = block;
  const kc = new Uint8Array(48);
  const kt = new Uint8Array(48);
  kc.set(tweakey);
  for (let round = 0; round < 40; round++) {
    for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]!]!;
    state[0] = state[0]! ^ (RC[round]! & 0xf);
    state[4] = state[4]! ^ ((RC[round]! >>> 4) & 0x3);
    state[8] = state[8]! ^ 0x02;
    for (let i = 0; i < 8; i++) state[i] = state[i]! ^ kc[i]! ^ kc[16 + i]! ^ kc[32 + i]!;
    // The tweakey schedule: one permutation shared by all three lanes, then an LFSR on lanes 2 and 3.
    for (let i = 0; i < 16; i++) {
      const pos = TWEAKEY_P[i]!;
      kt[i] = kc[pos]!;
      kt[16 + i] = kc[16 + pos]!;
      kt[32 + i] = kc[32 + pos]!;
    }
    for (let i = 0; i < 8; i++) {
      kc[i] = kt[i]!;
      let tmp = kt[16 + i]!;
      kc[16 + i] = ((tmp << 1) & 0xfe) ^ ((tmp >>> 7) & 0x01) ^ ((tmp >>> 5) & 0x01);
      tmp = kt[32 + i]!;
      kc[32 + i] = ((tmp >>> 1) & 0x7f) ^ ((tmp << 7) & 0x80) ^ ((tmp << 1) & 0x80);
    }
    for (let i = 8; i < 16; i++) {
      kc[i] = kt[i]!;
      kc[16 + i] = kt[16 + i]!;
      kc[32 + i] = kt[32 + i]!;
    }
    // ShiftRows: row 1 by one, row 2 by two, row 3 by three.
    let tmp = state[7]!;
    state[7] = state[6]!;
    state[6] = state[5]!;
    state[5] = state[4]!;
    state[4] = tmp;
    tmp = state[8]!; state[8] = state[10]!; state[10] = tmp;
    tmp = state[9]!; state[9] = state[11]!; state[11] = tmp;
    tmp = state[12]!;
    state[12] = state[13]!;
    state[13] = state[14]!;
    state[14] = state[15]!;
    state[15] = tmp;
    for (let j = 0; j < 4; j++) {
      state[4 + j] = state[4 + j]! ^ state[8 + j]!;
      state[8 + j] = state[8 + j]! ^ state[j]!;
      state[12 + j] = state[12 + j]! ^ state[8 + j]!;
      const t = state[12 + j]!;
      state[12 + j] = state[8 + j]!;
      state[8 + j] = state[4 + j]!;
      state[4 + j] = state[j]!;
      state[j] = t;
    }
  }
}

/** Romulus's padding: the block, then zeroes, with the length in the low nibble of the last byte. */
const pad16 = (m: Uint8Array, off: number, len: number, l = 16): Uint8Array => {
  const mp = new Uint8Array(16);
  for (let i = 0; i < l; i++) {
    if (i < len) mp[i] = m[off + i]!;
    else if (i === l - 1) mp[i] = len & 0x0f;
  }
  return mp;
};

/** G: a one-bit rotation of every byte with the top bit held. Romulus's whole "key schedule". */
const g8A = (s: Uint8Array): Uint8Array => {
  const c = new Uint8Array(16);
  for (let i = 0; i < 16; i++) c[i] = ((s[i]! >>> 1) ^ (s[i]! & 0x80) ^ ((s[i]! & 0x01) << 7)) & 0xff;
  return c;
};

const resetCnt = (cnt: Uint8Array): void => {
  cnt.fill(0);
  cnt[0] = 0x01;
};

/** The GF(2^56) LFSR that indexes every tweak. */
function lfsr(cnt: Uint8Array): void {
  const fb = cnt[6]! >>> 7;
  cnt[6] = ((cnt[6]! << 1) | (cnt[5]! >>> 7)) & 0xff;
  cnt[5] = ((cnt[5]! << 1) | (cnt[4]! >>> 7)) & 0xff;
  cnt[4] = ((cnt[4]! << 1) | (cnt[3]! >>> 7)) & 0xff;
  cnt[3] = ((cnt[3]! << 1) | (cnt[2]! >>> 7)) & 0xff;
  cnt[2] = ((cnt[2]! << 1) | (cnt[1]! >>> 7)) & 0xff;
  cnt[1] = ((cnt[1]! << 1) | (cnt[0]! >>> 7)) & 0xff;
  cnt[0] = (fb === 1 ? (cnt[0]! << 1) ^ 0x95 : cnt[0]! << 1) & 0xff;
}

function blockCipher(
  s: Uint8Array,
  key: Uint8Array,
  tweak: Uint8Array,
  tweakOff: number,
  cnt: Uint8Array,
  domain: number,
): void {
  const kt = new Uint8Array(48);
  kt.set(cnt.subarray(0, 7), 0);
  kt[7] = domain;
  for (let i = 0; i < 16; i++) kt[16 + i] = tweak[tweakOff + i]!;
  for (let i = 0; i < 16; i++) kt[32 + i] = key[i]!;
  skinny128384plus(s, kt);
}

const nonceEncryption = (
  nonce: Uint8Array,
  cnt: Uint8Array,
  s: Uint8Array,
  key: Uint8Array,
  domain: number,
): void => blockCipher(s, key, nonce, 0, cnt, domain);

function rho(m: Uint8Array, mOff: number, len: number, s: Uint8Array): Uint8Array {
  const mp = pad16(m, mOff, len);
  const c = g8A(s);
  for (let i = 0; i < 16; i++) {
    s[i] = s[i]! ^ mp[i]!;
    c[i] = i < len ? c[i]! ^ mp[i]! : 0;
  }
  return c;
}

function irho(c: Uint8Array, cOff: number, len: number, s: Uint8Array): Uint8Array {
  const cp = pad16(c, cOff, len);
  const m = g8A(s);
  for (let i = 0; i < 16; i++) {
    // The state absorbs the recovered plaintext where it exists and the pad where it does not, and
    // `m[i]` is read *before* it is overwritten -- see the header.
    s[i] = s[i]! ^ (i < len ? cp[i]! ^ m[i]! : cp[i]!);
    m[i] = i < len ? m[i]! ^ cp[i]! : 0;
  }
  return m;
}

/** Absorbs one odd block by XOR and, when there is one, one even block through the cipher. */
function adEncryption(
  a: Uint8Array,
  aOff: number,
  adlen: number,
  s: Uint8Array,
  key: Uint8Array,
  cnt: Uint8Array,
  domain: number,
): { rest: number; off: number } {
  let len = Math.min(adlen, 16);
  let rest = adlen - len;
  const mp = pad16(a, aOff, len);
  for (let i = 0; i < 16; i++) s[i] = s[i]! ^ mp[i]!;
  let off = aOff + len;
  lfsr(cnt);
  if (rest !== 0) {
    len = Math.min(rest, 16);
    rest -= len;
    const t = pad16(a, off, len);
    off += len;
    blockCipher(s, key, t, 0, cnt, domain);
    lfsr(cnt);
  }
  return { rest, off };
}

export type RomulusMode = "n" | "m" | "t";

// ---------------------------------------------------------------- Romulus-N

function romulusN(
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  aad: Uint8Array,
  encrypting: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  const s = new Uint8Array(16);
  const cnt = new Uint8Array(7);
  resetCnt(cnt);

  if (aad.length === 0) {
    lfsr(cnt);
    nonceEncryption(nonce, cnt, s, key, 0x1a);
  } else {
    let adlen = aad.length;
    let off = 0;
    while (adlen > 0) {
      // The four cases: an odd or even final block, complete or incomplete. 0x18 for complete.
      const domainAfter =
        adlen < 16 ? 0x1a : adlen === 16 ? 0x18 : adlen < 32 ? 0x1a : adlen === 32 ? 0x18 : null;
      const step = adEncryption(aad, off, adlen, s, key, cnt, 0x08);
      adlen = step.rest;
      off = step.off;
      if (domainAfter !== null) nonceEncryption(nonce, cnt, s, key, domainAfter);
    }
  }

  resetCnt(cnt);
  const out = new Uint8Array(input.length);
  if (input.length === 0) {
    lfsr(cnt);
    nonceEncryption(nonce, cnt, s, key, 0x15);
  } else {
    let mlen = input.length;
    let off = 0;
    while (mlen > 0) {
      const len = Math.min(mlen, 16);
      const domain = mlen < 16 ? 0x15 : mlen === 16 ? 0x14 : 0x04;
      const block = encrypting ? rho(input, off, len, s) : irho(input, off, len, s);
      out.set(block.subarray(0, len), off);
      off += len;
      mlen -= len;
      lfsr(cnt);
      nonceEncryption(nonce, cnt, s, key, domain);
    }
  }
  return { out, tag: g8A(s) };
}

// ---------------------------------------------------------------- Romulus-M

/**
 * Romulus-M's domain byte, over `(adlen mod 32, mlen mod 32)`.
 *
 * Bit 3 is the one with a consequence beyond the value: it decides whether the message's first block
 * goes through `ad2msg` -- straight into the cipher as a tweak -- or through the ordinary pair loop.
 * Which is why this is computed before any absorbing starts.
 */
function romulusMDomain(adlen: number, xlen: number): number {
  const pair = 32;
  let w = 48;
  if (adlen === 0) w ^= 2;
  else if (adlen % pair === 0) w ^= 8;
  else if (adlen % pair < 16) w ^= 2;
  else if (adlen % pair === 16) w ^= 0;
  else w ^= 10;

  if (xlen === 0) w ^= 1;
  else if (xlen % pair === 0) w ^= 4;
  else if (xlen % pair < 16) w ^= 1;
  else if (xlen % pair === 16) w ^= 0;
  else w ^= 5;
  return w;
}

function romulusMAuth(
  key: Uint8Array,
  nonce: Uint8Array,
  message: Uint8Array,
  aad: Uint8Array,
  w: number,
): Uint8Array {
  const s = new Uint8Array(16);
  const cnt = new Uint8Array(7);
  resetCnt(cnt);

  if (aad.length === 0) {
    lfsr(cnt);
  } else {
    let adlen = aad.length;
    let off = 0;
    while (adlen > 0) {
      const step = adEncryption(aad, off, adlen, s, key, cnt, 40);
      adlen = step.rest;
      off = step.off;
    }
  }

  let xlen = message.length;
  let off = 0;
  if ((w & 8) === 0) {
    // ad2msg: one block of the message goes straight through the cipher as a tweak.
    const len = Math.min(xlen, 16);
    xlen -= len;
    blockCipher(s, key, pad16(message, off, len), 0, cnt, 44);
    lfsr(cnt);
    off += len;
  } else if (message.length === 0) {
    lfsr(cnt);
  }
  while (xlen > 0) {
    const step = adEncryption(message, off, xlen, s, key, cnt, 44);
    xlen = step.rest;
    off = step.off;
  }
  nonceEncryption(nonce, cnt, s, key, w);
  return g8A(s);
}

function romulusMCrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  tag: Uint8Array,
  encrypting: boolean,
): Uint8Array {
  // The tag *is* the initial state for the second pass, which is what makes the mode misuse-resistant.
  const s = new Uint8Array(16);
  s.set(tag.subarray(0, 16));
  const cnt = new Uint8Array(7);
  resetCnt(cnt);
  const out = new Uint8Array(input.length);
  if (input.length > 0) {
    nonceEncryption(nonce, cnt, s, key, 36);
    let mlen = input.length;
    let off = 0;
    while (mlen > 16) {
      const block = encrypting ? rho(input, off, 16, s) : irho(input, off, 16, s);
      out.set(block, off);
      off += 16;
      mlen -= 16;
      lfsr(cnt);
      nonceEncryption(nonce, cnt, s, key, 36);
    }
    const block = encrypting ? rho(input, off, mlen, s) : irho(input, off, mlen, s);
    out.set(block.subarray(0, mlen), off);
  }
  return out;
}

// ---------------------------------------------------------------- Romulus-H and Romulus-T

const ipad = (m: Uint8Array, off: number, len: number, l: number, mask: number): Uint8Array => {
  const mp = new Uint8Array(32);
  for (let i = 0; i < l; i++) {
    if (i < len) mp[i] = m[off + i]!;
    else if (i === l - 1) mp[i] = len & mask;
  }
  return mp;
};

/**
 * The Hirose double-block-length compression function over SKINNY.
 *
 * Two cipher calls under the same tweakey, one of which has its input's first byte flipped, and both
 * feed forward the *original* h. That is what gives a 256-bit chaining value from a 128-bit cipher, and
 * the flipped bit is what stops the two halves from being equal.
 */
function hirose(h: Uint8Array, g: Uint8Array, m: Uint8Array, mOff: number): void {
  const key = new Uint8Array(48);
  const hh = h.slice();
  key.set(g.subarray(0, 16), 0);
  g.set(h.subarray(0, 16), 0);
  g[0] = g[0]! ^ 0x01;
  for (let i = 0; i < 32; i++) key[16 + i] = m[mOff + i]!;
  skinny128384plus(h, key);
  skinny128384plus(g, key);
  for (let i = 0; i < 16; i++) {
    h[i] = h[i]! ^ hh[i]!;
    g[i] = g[i]! ^ hh[i]!;
  }
  g[0] = g[0]! ^ 0x01;
}

/**
 * Romulus-H: a 256-bit hash, rate 32 bytes, from the same cipher the AEAD modes use.
 *
 * **Eager**, not hold-back, and that is the one thing to get right: the reference absorbs while at
 * least 32 bytes remain and then pads whatever is left -- including nothing at all. Holding a block back
 * would add a compression for every message whose length is a multiple of 32.
 */
export function createRomulusH(): LwcHasher {
  const h = new Uint8Array(16);
  const g = new Uint8Array(16);
  return eagerAbsorber(
    32,
    (block, off) => hirose(h, g, block, off),
    (tail, tailLen) => {
      const p = ipad(tail, 0, tailLen, 32, 0x1f);
      h[0] = h[0]! ^ 2;
      hirose(h, g, p, 0);
      const out = new Uint8Array(32);
      out.set(h, 0);
      out.set(g, 16);
      return out;
    },
  );
}

export function romulusH(message: Uint8Array): Uint8Array {
  const hasher = createRomulusH();
  hasher.update(message);
  return hasher.digest();
}

/** Romulus-T's hash over `(AD, ciphertext, nonce, counter)`. Returns the 32-byte L || R. */
function romulusTHash(
  aad: Uint8Array,
  ct: Uint8Array,
  nonce: Uint8Array,
  cnt: Uint8Array,
): Uint8Array {
  const h = new Uint8Array(16);
  const g = new Uint8Array(16);
  let n = 16;
  const adEmpty = aad.length === 0;
  let ctEmpty = ct.length === 0;
  let adlen = aad.length;
  let aOff = 0;
  let clen = ct.length;
  let cOff = 0;
  resetCnt(cnt);

  while (adlen >= 32) {
    hirose(h, g, aad, aOff);
    aOff += 32;
    adlen -= 32;
  }
  if (adlen >= 16) {
    hirose(h, g, ipad(aad, aOff, adlen, 32, 0x0f), 0);
  } else if (!adEmpty) {
    // A short tail of AD shares its compression block with the head of the ciphertext -- or, if there
    // is none, with the nonce. This is the branch that decides `n`, and therefore the final block.
    const p = ipad(aad, aOff, adlen, 16, 0x0f);
    adlen = 0;
    if (clen >= 16) {
      for (let i = 0; i < 16; i++) p[16 + i] = ct[cOff + i]!;
      hirose(h, g, p, 0);
      lfsr(cnt);
      clen -= 16;
      cOff += 16;
    } else if (clen > 0) {
      const tail = ipad(ct, cOff, clen, 16, 0x0f);
      for (let i = 0; i < 16; i++) p[16 + i] = tail[i]!;
      hirose(h, g, p, 0);
      clen = 0;
      ctEmpty = true;
      cOff += 16;
      lfsr(cnt);
    } else {
      for (let i = 0; i < 16; i++) p[16 + i] = nonce[i]!;
      hirose(h, g, p, 0);
      n = 0;
    }
  }

  while (clen >= 32) {
    hirose(h, g, ct, cOff);
    cOff += 32;
    clen -= 32;
    lfsr(cnt);
    lfsr(cnt);
  }
  if (clen > 16) {
    hirose(h, g, ipad(ct, cOff, clen, 32, 0x0f), 0);
    lfsr(cnt);
    lfsr(cnt);
  } else if (clen === 16) {
    hirose(h, g, ipad(ct, cOff, clen, 32, 0x0f), 0);
    lfsr(cnt);
  } else if (!ctEmpty) {
    const p = ipad(ct, cOff, clen, 16, 0x0f);
    if (clen > 0) lfsr(cnt);
    for (let i = 0; i < 16; i++) p[16 + i] = nonce[i]!;
    hirose(h, g, p, 0);
    n = 0;
  }

  let p: Uint8Array;
  if (n === 16) {
    const buf = new Uint8Array(32);
    buf.set(nonce.subarray(0, 16), 0);
    for (let i = 16; i < 23; i++) buf[i] = cnt[i - 16]!;
    p = ipad(buf, 0, 23, 32, 0x1f);
  } else {
    p = ipad(cnt, 0, 7, 32, 0x1f);
  }
  h[0] = h[0]! ^ 2;
  hirose(h, g, p, 0);
  const lr = new Uint8Array(32);
  lr.set(h, 0);
  lr.set(g, 16);
  return lr;
}

/**
 * Romulus-T's keystream. The session key Z is *rekeyed every block*, which is the leakage resilience.
 *
 * Two cipher calls per block: one to produce the keystream and one to advance Z. The second is skipped
 * on the final block, since nothing would read the new Z.
 */
function romulusTKeystream(key: Uint8Array, nonce: Uint8Array, length: number): Uint8Array {
  const cnt = new Uint8Array(7);
  const cntZ = new Uint8Array(7);
  resetCnt(cnt);
  const z = new Uint8Array(16);
  z.set(nonce.subarray(0, 16));
  blockCipher(z, key, new Uint8Array(16), 0, cntZ, 66);

  const stream = new Uint8Array(Math.ceil(length / 16) * 16);
  let produced = 0;
  let remaining = length;
  while (remaining !== 0) {
    const len = Math.min(remaining, 16);
    remaining -= len;
    const s = new Uint8Array(16);
    s.set(nonce.subarray(0, 16));
    blockCipher(s, z, new Uint8Array(16), 0, cnt, 64);
    stream.set(s, produced);
    produced += 16;
    if (remaining !== 0) {
      const next = new Uint8Array(16);
      next.set(nonce.subarray(0, 16));
      blockCipher(next, z, new Uint8Array(16), 0, cnt, 65);
      z.set(next);
    }
    lfsr(cnt);
  }
  return stream;
}

function romulusTTag(
  key: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  const cnt = new Uint8Array(7);
  const lr = romulusTHash(aad, ct, nonce, cnt);
  const cntZ = new Uint8Array(7);
  const l = lr.subarray(0, 16);
  blockCipher(l, key, lr, 16, cntZ, 68);
  return l.slice();
}

// ---------------------------------------------------------------- public API

export function romulusEncrypt(
  mode: RomulusMode,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== 16) throw new Error(`Romulus needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== 16) throw new Error(`Romulus needs a 16-byte nonce; got ${nonce.length}.`);
  if (mode === "n") {
    const { out, tag } = romulusN(key, nonce, plaintext, aad, true);
    const result = new Uint8Array(out.length + 16);
    result.set(out, 0);
    result.set(tag, out.length);
    return result;
  }
  if (mode === "m") {
    const w = romulusMDomain(aad.length, plaintext.length);
    const tag = romulusMAuth(key, nonce, plaintext, aad, w);
    const out = romulusMCrypt(key, nonce, plaintext, tag, true);
    const result = new Uint8Array(out.length + 16);
    result.set(out, 0);
    result.set(tag, out.length);
    return result;
  }
  const stream = romulusTKeystream(key, nonce, plaintext.length);
  const out = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) out[i] = plaintext[i]! ^ stream[i]!;
  const tag = romulusTTag(key, aad, out, nonce);
  const result = new Uint8Array(out.length + 16);
  result.set(out, 0);
  result.set(tag, out.length);
  return result;
}

export function romulusDecrypt(
  mode: RomulusMode,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (key.length !== 16) throw new Error(`Romulus needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== 16) throw new Error(`Romulus needs a 16-byte nonce; got ${nonce.length}.`);
  if (data.length < 16) return null;
  const body = data.subarray(0, data.length - 16);
  const given = data.subarray(data.length - 16);
  const equal = (a: Uint8Array, b: Uint8Array): boolean => {
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= a[i]! ^ b[i]!;
    return diff === 0;
  };
  if (mode === "n") {
    const { out, tag } = romulusN(key, nonce, body, aad, false);
    return equal(tag, given) ? out : null;
  }
  if (mode === "m") {
    // Misuse resistance costs a pass: the plaintext has to exist before the tag can be recomputed.
    const out = romulusMCrypt(key, nonce, body, given, false);
    const tag = romulusMAuth(key, nonce, out, aad, romulusMDomain(aad.length, out.length));
    return equal(tag, given) ? out : null;
  }
  const tag = romulusTTag(key, aad, body, nonce);
  if (!equal(tag, given)) return null;
  const stream = romulusTKeystream(key, nonce, body.length);
  const out = new Uint8Array(body.length);
  for (let i = 0; i < body.length; i++) out[i] = body[i]! ^ stream[i]!;
  return out;
}
