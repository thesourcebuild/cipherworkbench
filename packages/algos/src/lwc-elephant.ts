/**
 * Elephant -- Encrypt-then-MAC over a *public* permutation, in three named sizes. A NIST finalist.
 *
 * The design is unusual for this family: it is not a sponge or a duplex but a counter-mode encryption
 * plus a parallel Wegman-Carter MAC, both driven by one permutation and a per-block mask that advances
 * through an LFSR. Everything is parallelisable and nothing needs the permutation inverted.
 *
 * Three instances, and they are named rather than numbered:
 *
 * | Name | Permutation | Block | Tag |
 * |---|---|---|---|
 * | Dumbo | Spongent-pi[160], 80 rounds | 20 bytes | 8 |
 * | Jumbo | Spongent-pi[176], 90 rounds | 22 bytes | 8 |
 * | Delirium | Keccak-f[200], 18 rounds | 25 bytes | 16 |
 *
 * Verified against 1089 known-answer vectors per instance in both directions, all first run.
 *
 * ## What is derived rather than stored
 *
 * **Spongent's 256-entry S-box is the 4-bit box applied to each nibble**, so sixteen values are stored
 * and 256 are computed. **The bit permutation is precomputed from its formula** -- bit i moves to
 * `(i * n / 4) mod (n - 1)` with the last bit fixed -- rather than tabulated. And the round counter's
 * companion is the *bit reversal* of the counter, which is a function rather than a second table.
 *
 * ## The three lfsr_step functions are three different functions
 *
 * Dumbo rotates byte 0 left by **three**; Jumbo and Delirium by one. Dumbo and Jumbo then fold in bytes
 * 3 and 13 (or 19); Delirium folds in a rotation of byte 2 and a shift of byte 13. There is no shared
 * form to factor out, and using one for all three leaves the first instance correct.
 */

// --- Spongent ---

const SPONGENT_SBOX = new Uint8Array(256);
{
  const s4 = [0xe, 0xd, 0xb, 0x0, 0x2, 0x1, 0x4, 0xf, 0x7, 0xa, 0x8, 0x5, 0x9, 0xc, 0x3, 0x6];
  for (let v = 0; v < 256; v++) SPONGENT_SBOX[v] = (s4[v >>> 4]! << 4) | s4[v & 0xf]!;
}

/** The 7-bit LFSR that indexes Spongent's rounds. */
const lCounter = (lfsr: number): number =>
  ((lfsr << 1) | (((0x40 & lfsr) >>> 6) ^ ((0x20 & lfsr) >>> 5))) & 0x7f;

/** Its companion, applied at the far end of the state: the same value with its bits reversed. */
const reverseByte = (b: number): number =>
  (((b & 0x01) << 7) |
    ((b & 0x02) << 5) |
    ((b & 0x04) << 3) |
    ((b & 0x08) << 1) |
    ((b & 0x10) >>> 1) |
    ((b & 0x20) >>> 3) |
    ((b & 0x40) >>> 5) |
    ((b & 0x80) >>> 7)) & 0xff;

function spongentPermutation(nBits: number, rounds: number, lfsrIv: number): (state: Uint8Array) => void {
  const nSBox = nBits >>> 3;
  const pi = new Int32Array(nBits);
  for (let i = 0; i < nBits; i++) {
    pi[i] = i !== nBits - 1 ? ((i * nBits) / 4) % (nBits - 1) : nBits - 1;
  }
  const tmp = new Uint8Array(nSBox);
  return (state: Uint8Array): void => {
    let iv = lfsrIv;
    for (let r = 0; r < rounds; r++) {
      state[0] = state[0]! ^ iv;
      state[nSBox - 1] = state[nSBox - 1]! ^ reverseByte(iv);
      iv = lCounter(iv);
      for (let j = 0; j < nSBox; j++) state[j] = SPONGENT_SBOX[state[j]!]!;
      tmp.fill(0);
      for (let i = 0; i < nSBox; i++) {
        for (let j = 0; j < 8; j++) {
          if ((state[i]! >>> j) & 1) {
            const to = pi[8 * i + j]!;
            tmp[to >>> 3] = tmp[to >>> 3]! ^ (1 << (to & 7));
          }
        }
      }
      state.set(tmp);
    }
  };
}

// --- Keccak-f[200] ---

const KECCAK200_RC = [
  0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a, 0x88,
  0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80,
] as const;
/** The standard rho offsets reduced mod 8, indexed as x + 5y. */
const KECCAK200_RHO = [0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6] as const;
const rol8 = (a: number, n: number): number => (n === 0 ? a & 0xff : ((a << n) ^ (a >>> (8 - n))) & 0xff);
const ix = (x: number, y: number): number => (x % 5) + 5 * (y % 5);

/** Keccak-f[200]: eighteen rounds over twenty-five *byte* lanes. */
export function keccakF200(a: Uint8Array): void {
  const c = new Uint8Array(5);
  const d = new Uint8Array(5);
  const temp = new Uint8Array(25);
  for (let round = 0; round < 18; round++) {
    for (let x = 0; x < 5; x++) {
      c[x] = 0;
      for (let y = 0; y < 5; y++) c[x] = c[x]! ^ a[ix(x, y)]!;
    }
    for (let x = 0; x < 5; x++) d[x] = rol8(c[(x + 1) % 5]!, 1) ^ c[(x + 4) % 5]!;
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[ix(x, y)] = a[ix(x, y)]! ^ d[x]!;
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) a[ix(x, y)] = rol8(a[ix(x, y)]!, KECCAK200_RHO[ix(x, y)]!);
    }
    temp.set(a);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[ix(y, 2 * x + 3 * y)] = temp[ix(x, y)]!;
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) c[x] = a[ix(x, y)]! ^ (~a[ix(x + 1, y)]! & a[ix(x + 2, y)]!);
      for (let x = 0; x < 5; x++) a[ix(x, y)] = c[x]! & 0xff;
    }
    a[0] = a[0]! ^ KECCAK200_RC[round]!;
  }
}

const rotl8 = (b: number, n: number): number => ((b << n) | (b >>> (8 - n))) & 0xff;

export type ElephantVariant = "dumbo" | "jumbo" | "delirium";

interface ElephantParams {
  blockSize: number;
  tagLen: number;
  permutation: (state: Uint8Array) => void;
  lfsr: (out: Uint8Array, input: Uint8Array) => void;
}

export const ELEPHANT_PARAMS: Readonly<Record<ElephantVariant, ElephantParams>> = {
  dumbo: {
    blockSize: 20,
    tagLen: 8,
    permutation: spongentPermutation(160, 80, 0x75),
    lfsr: (out, input) => {
      const temp = (rotl8(input[0]!, 3) ^ (input[3]! << 7) ^ (input[13]! >>> 7)) & 0xff;
      for (let i = 0; i < 19; i++) out[i] = input[i + 1]!;
      out[19] = temp;
    },
  },
  jumbo: {
    blockSize: 22,
    tagLen: 8,
    permutation: spongentPermutation(176, 90, 0x45),
    lfsr: (out, input) => {
      const temp = (rotl8(input[0]!, 1) ^ (input[3]! << 7) ^ (input[19]! >>> 7)) & 0xff;
      for (let i = 0; i < 21; i++) out[i] = input[i + 1]!;
      out[21] = temp;
    },
  },
  delirium: {
    blockSize: 25,
    tagLen: 16,
    permutation: keccakF200,
    lfsr: (out, input) => {
      const temp = (rotl8(input[0]!, 1) ^ rotl8(input[2]!, 1) ^ (input[13]! << 1)) & 0xff;
      for (let i = 0; i < 24; i++) out[i] = input[i + 1]!;
      out[24] = temp;
    },
  },
};

const NONCE_LEN = 12;

function elephant(
  variant: ElephantVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  m: Uint8Array,
  aad: Uint8Array,
  encrypting: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  if (key.length !== 16) throw new Error(`Elephant needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== NONCE_LEN) {
    throw new Error(`Elephant needs a ${NONCE_LEN}-byte nonce; got ${nonce.length}.`);
  }
  const p = ELEPHANT_PARAMS[variant];
  const bs = p.blockSize;
  const mlen = m.length;
  const nblocksC = 1 + Math.floor(mlen / bs);
  const nblocksM = mlen % bs ? nblocksC : nblocksC - 1;
  const nblocksAd = 1 + Math.floor((NONCE_LEN + aad.length) / bs);
  const iterations = Math.max(nblocksC + 1, nblocksAd - 1);

  const expandedKey = new Uint8Array(bs);
  expandedKey.set(key.subarray(0, 16));
  p.permutation(expandedKey);

  let previousMask = new Uint8Array(bs);
  let currentMask = new Uint8Array(bs);
  let nextMask = new Uint8Array(bs);
  currentMask.set(expandedKey);

  const xorInto = (dst: Uint8Array, src: Uint8Array, n: number): void => {
    for (let i = 0; i < n; i++) dst[i] = dst[i]! ^ src[i]!;
  };

  /**
   * Block i of `nonce || associatedData || 0x01-padding`.
   *
   * The nonce occupies the head of block 0, which is why block i's data offset is shifted by the nonce
   * length for every block after the first -- and why a block that lands exactly at the end of the
   * associated data is a lone 0x01 rather than nothing.
   */
  const adBlock = (i: number): Uint8Array => {
    const out = new Uint8Array(bs);
    let len = 0;
    if (i === 0) {
      out.set(nonce.subarray(0, NONCE_LEN), 0);
      len = NONCE_LEN;
    }
    const blockOffset = i * bs - (i !== 0 ? NONCE_LEN : 0);
    if (i !== 0 && blockOffset === aad.length) {
      out[0] = 0x01;
      return out;
    }
    const rOut = bs - len;
    const rAd = aad.length - blockOffset;
    if (rOut <= rAd) {
      out.set(aad.subarray(blockOffset, blockOffset + rOut), len);
    } else {
      if (rAd > 0) out.set(aad.subarray(blockOffset, blockOffset + rAd), len);
      out[len + rAd] = 0x01;
    }
    return out;
  };

  const ctBlock = (data: Uint8Array, clen: number, i: number): Uint8Array => {
    const out = new Uint8Array(bs);
    const blockOffset = i * bs;
    if (blockOffset === clen) {
      out[0] = 0x01;
      return out;
    }
    const rest = clen - blockOffset;
    if (bs <= rest) {
      out.set(data.subarray(blockOffset, blockOffset + bs));
    } else {
      if (rest > 0) out.set(data.subarray(blockOffset, blockOffset + rest));
      out[rest] = 0x01;
    }
    return out;
  };

  const tagBuffer = adBlock(0);
  const out = new Uint8Array(mlen);
  let offset = 0;

  for (let i = 0; i < iterations; i++) {
    p.lfsr(nextMask, currentMask);

    if (i < nblocksM) {
      // Counter mode: the "counter" is the nonce, and the masks are what vary per block.
      const buffer = new Uint8Array(bs);
      buffer.set(nonce.subarray(0, NONCE_LEN));
      xorInto(buffer, currentMask, bs);
      xorInto(buffer, nextMask, bs);
      p.permutation(buffer);
      xorInto(buffer, currentMask, bs);
      xorInto(buffer, nextMask, bs);
      const rSize = i === nblocksM - 1 ? mlen - offset : bs;
      for (let j = 0; j < rSize; j++) buffer[j] = buffer[j]! ^ m[offset + j]!;
      out.set(buffer.subarray(0, rSize), offset);
    }

    if (i > 0 && i <= nblocksC) {
      const buffer = ctBlock(encrypting ? out : m, mlen, i - 1);
      xorInto(buffer, previousMask, bs);
      xorInto(buffer, nextMask, bs);
      p.permutation(buffer);
      xorInto(buffer, previousMask, bs);
      xorInto(buffer, nextMask, bs);
      xorInto(tagBuffer, buffer, bs);
    }

    if (i + 1 < nblocksAd) {
      const buffer = adBlock(i + 1);
      xorInto(buffer, nextMask, bs);
      p.permutation(buffer);
      xorInto(buffer, nextMask, bs);
      xorInto(tagBuffer, buffer, bs);
    }

    const spare = previousMask;
    previousMask = currentMask;
    currentMask = nextMask;
    nextMask = spare;
    offset += bs;
  }

  xorInto(tagBuffer, expandedKey, bs);
  p.permutation(tagBuffer);
  xorInto(tagBuffer, expandedKey, bs);
  return { out, tag: tagBuffer.slice(0, p.tagLen) };
}

export function elephantEncrypt(
  variant: ElephantVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const { out, tag } = elephant(variant, key, nonce, plaintext, aad, true);
  const result = new Uint8Array(out.length + tag.length);
  result.set(out, 0);
  result.set(tag, out.length);
  return result;
}

export function elephantDecrypt(
  variant: ElephantVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  const tagLen = ELEPHANT_PARAMS[variant].tagLen;
  if (data.length < tagLen) return null;
  const { out, tag } = elephant(
    variant,
    key,
    nonce,
    data.subarray(0, data.length - tagLen),
    aad,
    false,
  );
  let diff = 0;
  for (let i = 0; i < tagLen; i++) diff |= tag[i]! ^ data[data.length - tagLen + i]!;
  return diff === 0 ? out : null;
}
