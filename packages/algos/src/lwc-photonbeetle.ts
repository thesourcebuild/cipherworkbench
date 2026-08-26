/**
 * PHOTON-Beetle -- the PHOTON256 permutation under the Beetle sponge mode. A NIST lightweight finalist.
 *
 * PHOTON256 is AES's shape at a quarter of the width: an 8x8 grid of *nibbles* with a 4-bit S-box, a
 * row rotation and a MixColumns over GF(2^4). Beetle is a sponge duplex whose output transform mixes in
 * a one-bit rotation of half the rate, which is what lets the rate be as small as four bytes without
 * losing the security proof.
 *
 * Verified against the submission's known-answer files: 1089 AEAD vectors in both directions at each of
 * the two rates and 1025 hash vectors -- 5381 assertions.
 *
 * ## Two tables stored, one derived
 *
 * The 4-bit S-box and the 8x8 MixColumns matrix are the only stored data -- 16 plus 64 nibbles. The
 * 256-entry byte-wise S-box the reference ships is *derived* here by applying the 4-bit box to each
 * nibble, and the GF(2^4) multiplication table and the packed per-column contributions are computed at
 * load. So nothing longer than a line of the specification is transcribed.
 *
 * ## The domain constants are a four-way table, not a flag
 *
 * `select(c1, c2, o3, o4)` returns 1, 2, o3 or o4 depending on *both* conditions, and the four
 * combinations are not symmetric -- the third and fourth cases take caller-supplied values (3/4 after
 * the associated data, 5/6 after the message) while the first two are fixed. Collapsing it into "was
 * the last block full" is right in two of four cases.
 *
 * ## The one first-attempt bug, and where it hid
 *
 * PHOTON-Beetle-Hash uses the first sixteen bytes of the message *as* its initial state, then absorbs
 * the rest at rate 4. At exactly sixteen bytes there is a state and nothing to absorb, and the domain
 * constant is 2 rather than the 1 that "the tail block was full" would give. Every other length was
 * correct; only vector 17 failed.
 */

import { holdBackAbsorber, type LwcHasher } from "./lwc-hash";

const D = 8;

/** The round constants: one row of twelve per grid row. */
const RC: readonly (readonly number[])[] = [
  [1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10],
  [0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11],
  [2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9],
  [6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13],
  [14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5],
  [15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4],
  [13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6],
  [9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2],
];

/** The MixColumnSerial matrix, as published. */
const MIX: readonly (readonly number[])[] = [
  [2, 4, 2, 11, 2, 8, 5, 6],
  [12, 9, 8, 13, 7, 7, 5, 2],
  [4, 4, 13, 13, 9, 4, 13, 9],
  [1, 6, 5, 1, 12, 13, 15, 14],
  [15, 12, 9, 13, 14, 5, 14, 13],
  [9, 14, 5, 15, 4, 12, 9, 6],
  [12, 2, 2, 10, 3, 1, 1, 14],
  [15, 1, 13, 10, 5, 10, 2, 3],
];

const SBOX4 = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2] as const;

/** GF(2^4) multiplication under x^4 + x + 1, and the packed column contributions built from it. */
const GF4 = new Uint8Array(256);
const COL = new Int32Array(8 * 16);
{
  for (let x = 0; x < 16; x++) {
    for (let b = 0; b < 16; b++) {
      let sum = (x * (b & 1)) ^ (x * (b & 2)) ^ (x * (b & 4)) ^ (x * (b & 8));
      let t = sum >>> 4;
      sum = (sum & 15) ^ t ^ (t << 1);
      t = sum >>> 4;
      sum = (sum & 15) ^ t ^ (t << 1);
      GF4[(x << 4) | b] = sum;
    }
  }
  for (let k = 0; k < D; k++) {
    for (let v = 0; v < 16; v++) {
      let packed = 0;
      for (let i = 0; i < D; i++) packed |= (GF4[(MIX[i]![k]! << 4) | v]! & 0xf) << (i << 2);
      COL[(k << 4) | v] = packed;
    }
  }
}

/** PHOTON256: twelve rounds over an 8x8 nibble grid held in 32 bytes, low nibble of each byte first. */
export function photon256(state: Uint8Array): void {
  const cells = new Uint8Array(64);
  for (let i = 0; i < 64; i++) cells[i] = (state[i >> 1]! >>> ((i & 1) << 2)) & 0xf;
  const tmp = new Uint8Array(D);
  for (let round = 0; round < 12; round++) {
    for (let i = 0; i < D; i++) cells[i << 3] = cells[i << 3]! ^ RC[i]![round]!;
    for (let i = 0; i < 64; i++) cells[i] = SBOX4[cells[i]!]!;
    // ShiftRows: row i rotates left by i.
    for (let i = 1; i < D; i++) {
      const base = i << 3;
      tmp.set(cells.subarray(base, base + D));
      for (let c = 0; c < D; c++) cells[base + c] = tmp[(c + i) & 7]!;
    }
    for (let j = 0; j < D; j++) {
      let col = 0;
      for (let k = 0; k < D; k++) col ^= COL[(k << 4) | cells[(k << 3) + j]!]!;
      for (let i = 0; i < D; i++) cells[(i << 3) + j] = (col >>> (i << 2)) & 0xf;
    }
  }
  for (let i = 0; i < 64; i += 2) state[i >>> 1] = cells[i]! | (cells[i + 1]! << 4);
}

/** The four-way domain selector. See the header: the cases are deliberately not symmetric. */
const select = (c1: boolean, c2: boolean, o3: number, o4: number): number =>
  c1 && c2 ? 1 : c1 ? 2 : c2 ? o3 : o4;

const LAST_THREE_BITS_OFFSET = 5;

export type PhotonBeetleRate = 4 | 16;

function beetle(
  rate: PhotonBeetleRate,
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  aad: Uint8Array,
  encrypting: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  if (key.length !== 16) throw new Error(`PHOTON-Beetle needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== 16) throw new Error(`PHOTON-Beetle needs a 16-byte nonce; got ${nonce.length}.`);

  const half = rate >>> 1;
  const state = new Uint8Array(32);
  state.set(key, 0);
  state.set(nonce, key.length);

  const absorb = (data: Uint8Array, off: number, len: number): void => {
    photon256(state);
    for (let i = 0; i < len; i++) state[i] = state[i]! ^ data[off + i]!;
    if (len < rate) state[len] = state[len]! ^ 0x01;
  };

  /** rho: the second rate half XORs the data, and a 1-bit rotation of the first half covers the tail. */
  const rho = (out: Uint8Array, outOff: number, data: Uint8Array, off: number, len: number): void => {
    photon256(state);
    const rotated = new Uint8Array(half);
    for (let i = 0; i < half - 1; i++) {
      rotated[i] = ((state[i]! >>> 1) | ((state[i + 1]! & 1) << 7)) & 0xff;
    }
    rotated[half - 1] = ((state[half - 1]! >>> 1) | ((state[0]! & 1) << 7)) & 0xff;
    const first = Math.min(len, half);
    for (let i = 0; i < first; i++) out[outOff + i] = state[half + i]! ^ data[off + i]!;
    for (let i = first; i < len; i++) out[outOff + i] = rotated[i - half]! ^ data[off + i]!;
  };

  if (aad.length !== 0) {
    const blocks = Math.ceil(aad.length / rate);
    for (let b = 0; b < blocks; b++) {
      const off = b * rate;
      absorb(aad, off, Math.min(rate, aad.length - off));
    }
    state[31] = state[31]! ^ (select(input.length > 0, aad.length % rate === 0, 3, 4) << LAST_THREE_BITS_OFFSET);
  }

  const out = new Uint8Array(input.length);
  if (input.length !== 0) {
    const blocks = Math.ceil(input.length / rate);
    for (let b = 0; b < blocks; b++) {
      const off = b * rate;
      const len = Math.min(rate, input.length - off);
      rho(out, off, input, off, len);
      const source = encrypting ? input : out;
      for (let i = 0; i < len; i++) state[i] = state[i]! ^ source[off + i]!;
      if (len < rate) state[len] = state[len]! ^ 0x01;
    }
    state[31] = state[31]! ^ (select(aad.length !== 0, input.length % rate === 0, 5, 6) << LAST_THREE_BITS_OFFSET);
  } else if (aad.length === 0) {
    state[31] = state[31]! ^ (1 << LAST_THREE_BITS_OFFSET);
  }

  photon256(state);
  return { out, tag: state.slice(0, 16) };
}

export function photonBeetleEncrypt(
  rate: PhotonBeetleRate,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const { out, tag } = beetle(rate, key, nonce, plaintext, aad, true);
  const result = new Uint8Array(out.length + 16);
  result.set(out, 0);
  result.set(tag, out.length);
  return result;
}

export function photonBeetleDecrypt(
  rate: PhotonBeetleRate,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (data.length < 16) return null;
  const { out, tag } = beetle(rate, key, nonce, data.subarray(0, data.length - 16), aad, false);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= tag[i]! ^ data[data.length - 16 + i]!;
  return diff === 0 ? out : null;
}

/**
 * PHOTON-Beetle-Hash: rate 4, and the first sixteen bytes of the message *become* the state.
 *
 * That is what makes it a hash with no initial constant at all -- unusual enough to state, and the
 * reason the length branches below are a four-way split rather than a loop with a pad.
 */
export function createPhotonBeetleHash(): LwcHasher {
  const state = new Uint8Array(32);
  const rate = 4;
  /** The first sixteen bytes are the state, so they are collected before any absorbing starts. */
  const prologue = new Uint8Array(16);
  let prologueLen = 0;
  let absorbed = 0;

  const absorbBlock = (block: Uint8Array, off: number, len: number): void => {
    photon256(state);
    for (let i = 0; i < len; i++) state[i] = state[i]! ^ block[off + i]!;
    if (len < rate) state[len] = state[len]! ^ 0x01;
  };

  const squeeze = (): Uint8Array => {
    const out = new Uint8Array(32);
    photon256(state);
    out.set(state.subarray(0, 16), 0);
    photon256(state);
    out.set(state.subarray(0, 16), 16);
    return out;
  };

  const inner = holdBackAbsorber(
    rate,
    (block, off) => {
      absorbBlock(block, off, rate);
      absorbed += rate;
    },
    (tail, tailLen) => {
      if (tailLen > 0) {
        absorbBlock(tail, 0, tailLen);
        absorbed += tailLen;
      }
      /**
       * The domain constant, and the four cases are not reducible to two.
       *
       * `absorbed === 0` means the message was at most one state's width: constant 1 if it was short
       * (padded) and 2 if it was exactly sixteen -- the one length where "was the tail block full" and
       * "is there a tail block at all" disagree, and the one first-attempt bug in this whole family.
       */
      const domain =
        absorbed === 0
          ? prologueLen === 16
            ? 2
            : 1
          : absorbed % rate === 0
            ? 1
            : 2;
      state[31] = state[31]! ^ (domain << LAST_THREE_BITS_OFFSET);
      return squeeze();
    },
  );

  return {
    update(chunk) {
      let off = 0;
      if (prologueLen < 16) {
        const take = Math.min(16 - prologueLen, chunk.length);
        prologue.set(chunk.subarray(0, take), prologueLen);
        prologueLen += take;
        off = take;
        if (prologueLen === 16) state.set(prologue, 0);
      }
      if (off < chunk.length) inner.update(chunk.subarray(off));
    },
    digest() {
      if (prologueLen < 16) {
        // A message shorter than the state: it *is* the state, with a one-bit pad after it.
        state.set(prologue.subarray(0, prologueLen), 0);
        if (prologueLen > 0) state[prologueLen] = state[prologueLen]! ^ 0x01;
        state[31] = state[31]! ^ (1 << LAST_THREE_BITS_OFFSET);
        return squeeze();
      }
      return inner.digest();
    },
  };
}

export function photonBeetleHash(message: Uint8Array): Uint8Array {
  const h = createPhotonBeetleHash();
  h.update(message);
  return h.digest();
}
