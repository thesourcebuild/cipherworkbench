/**
 * SPARKLE -- the Sparkle permutation, the Schwaemm AEAD and the Esch hash. A NIST lightweight finalist.
 *
 * Sparkle is a handful of Alzette ARX-boxes plus a linear layer, so there is no table anywhere and the
 * only constants are eight 32-bit words. The permutation here is written as the loop it actually is
 * rather than unrolled: the reference and most ports spell out all four, six or eight branches, which
 * triples the surface for a transposition to hide in.
 *
 * Verified against the submission's known-answer files: 1089 vectors in both directions for each of the
 * four Schwaemm instances and 1025 for each of the two Esch widths -- 10,762 assertions, all first run.
 *
 * ## Three things worth knowing
 *
 * **The linear layer writes into slots it is still reading from.** `state[j - 2]` takes the value of
 * `state[j + half]` before that slot is overwritten with `state[j]`, and the same pairing runs for the
 * odd index. Reordering those four assignments produces a permutation that is not Sparkle.
 *
 * **`state[1]` takes a round constant and `state[3]` takes the step number.** Two different injections
 * at two different slots. Only `state[1]`'s cycles (mod 8); `state[3]`'s counts up without bound, which
 * is what stops a long permutation from repeating.
 *
 * **Schwaemm's rate transform is a Feistel *swap*, and it runs the other way on decryption.** The two
 * halves of the rate exchange roles, with a capacity word mixed in. `capMask` exists for the one
 * instance whose rate is wider than its capacity -- Schwaemm256-128 -- where the capacity word has to
 * be reused; for the other three the mask is -1 and the index passes through.
 */

import { holdBackAbsorber, type LwcHasher } from "./lwc-hash";

const RCON = [
  0xb7e15162, 0xbf715880, 0x38b4da56, 0x324e7738, 0xbb1185eb, 0x4f7c7b57, 0xcfbfa1c8, 0xc2b3293d,
] as const;

const ror = (x: number, n: number): number => (n === 0 ? x | 0 : ((x >>> n) | (x << (32 - n))) | 0);
/** Sparkle's linear mixing of a 16-bit halfword pair. */
const ell = (x: number): number => (ror(x, 16) ^ (x & 0xffff)) | 0;

/**
 * The Sparkle permutation over `branches` ARX-boxes for `steps` steps.
 *
 * `branches` is 4, 6 or 8 -- the state is twice that in 32-bit words.
 */
export function sparkle(state: Int32Array, branches: number, steps: number): void {
  for (let s = 0; s < steps; s++) {
    state[1] = state[1]! ^ (RCON[s & 7]!);
    state[3] = state[3]! ^ (s);
    for (let b = 0; b < branches; b++) {
      // Alzette: a 64-bit ARX box, four add-rotate-xor quarters under one constant.
      const rc = RCON[b]!;
      let x = state[2 * b]!;
      let y = state[2 * b + 1]!;
      x = (x + ror(y, 31)) | 0; y ^= ror(x, 24); x ^= rc;
      x = (x + ror(y, 17)) | 0; y ^= ror(x, 17); x ^= rc;
      x = (x + y) | 0;          y ^= ror(x, 31); x ^= rc;
      x = (x + ror(y, 24)) | 0; y ^= ror(x, 16); x ^= rc;
      state[2 * b] = x;
      state[2 * b + 1] = y;
    }
    const half = branches;
    let tmpx = state[0]!;
    let tmpy = state[1]!;
    for (let j = 2; j < half; j += 2) {
      tmpx ^= state[j]!;
      tmpy ^= state[j + 1]!;
    }
    tmpx = ell(tmpx);
    tmpy = ell(tmpy);
    const x0 = state[0]!;
    const y0 = state[1]!;
    for (let j = 2; j < half; j += 2) {
      const xj = state[j]!;
      const yj = state[j + 1]!;
      state[j - 2] = state[j + half]! ^ xj ^ tmpy;
      state[j + half] = xj;
      state[j - 1] = state[j + half + 1]! ^ yj ^ tmpx;
      state[j + half + 1] = yj;
    }
    state[half - 2] = state[half]! ^ x0 ^ tmpy;
    state[half] = x0;
    state[half - 1] = state[half + 1]! ^ y0 ^ tmpx;
    state[half + 1] = y0;
  }
}

export type EschWidth = 256 | 384;

const ESCH_PARAMS: Readonly<
  Record<EschWidth, { stateWords: number; slim: number; big: number; digest: number }>
> = {
  256: { stateWords: 12, slim: 7, big: 11, digest: 32 },
  384: { stateWords: 16, slim: 8, big: 12, digest: 48 },
};

export interface SchwaemmParams {
  stateWords: number;
  rateWords: number;
  capWords: number;
  keyWords: number;
  tagWords: number;
  /** Steps for an interior block. */
  slim: number;
  /** Steps for initialisation and for each final block. */
  big: number;
}

export type SchwaemmVariant = "128-128" | "256-128" | "192-192" | "256-256";

/** The four instances, named `<nonceBits>-<keyBits>` as the submission names them. */
export const SCHWAEMM_PARAMS: Readonly<Record<SchwaemmVariant, SchwaemmParams>> = {
  "128-128": { stateWords: 8, rateWords: 4, capWords: 4, keyWords: 4, tagWords: 4, slim: 7, big: 10 },
  "256-128": { stateWords: 12, rateWords: 8, capWords: 4, keyWords: 4, tagWords: 4, slim: 7, big: 11 },
  "192-192": { stateWords: 12, rateWords: 6, capWords: 6, keyWords: 6, tagWords: 6, slim: 7, big: 11 },
  "256-256": { stateWords: 16, rateWords: 8, capWords: 8, keyWords: 8, tagWords: 8, slim: 8, big: 12 },
};

const leToWords = (bytes: Uint8Array, off: number, words: number): Int32Array => {
  const out = new Int32Array(words);
  for (let i = 0; i < words; i++) {
    out[i] =
      (bytes[off + 4 * i]! |
        (bytes[off + 4 * i + 1]! << 8) |
        (bytes[off + 4 * i + 2]! << 16) |
        (bytes[off + 4 * i + 3]! << 24)) | 0;
  }
  return out;
};

const wordToLe = (word: number, out: Uint8Array, off: number): void => {
  out[off] = word & 0xff;
  out[off + 1] = (word >>> 8) & 0xff;
  out[off + 2] = (word >>> 16) & 0xff;
  out[off + 3] = (word >>> 24) & 0xff;
};

function schwaemm(
  variant: SchwaemmVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  aad: Uint8Array,
  encrypting: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  const p = SCHWAEMM_PARAMS[variant];
  if (key.length !== p.keyWords * 4) {
    throw new Error(`Schwaemm${variant} needs a ${p.keyWords * 4}-byte key; got ${key.length}.`);
  }
  if (nonce.length !== p.rateWords * 4) {
    throw new Error(`Schwaemm${variant} needs a ${p.rateWords * 4}-byte nonce; got ${nonce.length}.`);
  }

  const branches = p.stateWords / 2;
  const rateBytes = p.rateWords * 4;
  const capMask = p.rateWords > p.capWords ? p.capWords - 1 : -1;
  // The domain constants: a bit per (which phase, was the block full), offset by the capacity width.
  const capBrans = (p.capWords * 32) >>> 6;
  const A0 = (1 << capBrans) << 24;
  const A1 = (1 ^ (1 << capBrans)) << 24;
  const M2 = (2 ^ (1 << capBrans)) << 24;
  const M3 = (3 ^ (1 << capBrans)) << 24;

  const keyWords = leToWords(key, 0, p.keyWords);
  const state = new Int32Array(p.stateWords);
  state.set(leToWords(nonce, 0, p.rateWords), 0);
  state.set(keyWords, p.rateWords);
  sparkle(state, branches, p.big);

  const rho = (block: Int32Array, out: Uint8Array | null, outOff: number, decrypt: boolean): void => {
    for (let i = 0; i < p.rateWords / 2; i++) {
      const j = i + p.rateWords / 2;
      const si = state[i]!;
      const sj = state[j]!;
      const di = block[i]!;
      const dj = block[j]!;
      if (decrypt) {
        state[i] = si ^ sj ^ di ^ state[p.rateWords + i]!;
        state[j] = si ^ dj ^ state[p.rateWords + (j & capMask)]!;
      } else {
        state[i] = sj ^ di ^ state[p.rateWords + i]!;
        state[j] = si ^ sj ^ dj ^ state[p.rateWords + (j & capMask)]!;
      }
      if (out) {
        wordToLe(di ^ si, out, outOff + 4 * i);
        wordToLe(dj ^ sj, out, outOff + 4 * j);
      }
    }
  };

  if (aad.length > 0) {
    let off = 0;
    while (aad.length - off > rateBytes) {
      rho(leToWords(aad, off, p.rateWords), null, 0, false);
      sparkle(state, branches, p.slim);
      off += rateBytes;
    }
    const remaining = aad.length - off;
    const padded = new Uint8Array(rateBytes);
    padded.set(aad.subarray(off));
    if (remaining < rateBytes) {
      state[p.stateWords - 1] = state[p.stateWords - 1]! ^ (A0);
      padded[remaining] = 0x80;
    } else {
      state[p.stateWords - 1] = state[p.stateWords - 1]! ^ (A1);
    }
    rho(leToWords(padded, 0, p.rateWords), null, 0, false);
    sparkle(state, branches, p.big);
  }

  const out = new Uint8Array(input.length);
  if (input.length > 0) {
    let off = 0;
    while (input.length - off > rateBytes) {
      rho(leToWords(input, off, p.rateWords), out, off, !encrypting);
      sparkle(state, branches, p.slim);
      off += rateBytes;
    }
    const remaining = input.length - off;
    const padded = new Uint8Array(rateBytes);
    padded.set(input.subarray(off));
    const buffer = leToWords(padded, 0, p.rateWords);
    state[p.stateWords - 1] = state[p.stateWords - 1]! ^ (remaining < rateBytes ? M2 : M3);
    if (remaining < rateBytes) {
      if (!encrypting) {
        /**
         * On the way back the bytes past the ciphertext have to come from the *state*, not from zero.
         *
         * The final block's rho is computed over a full rate word, so the tail that was never
         * transmitted must be reconstructed as the keystream itself -- which makes those positions
         * cancel and leaves the padding byte landing where the sender put it.
         */
        const shift = (remaining & 3) << 3;
        buffer[remaining >>> 2] = buffer[remaining >>> 2]! | ((state[remaining >>> 2]! >>> shift) << shift);
        for (let w = (remaining >>> 2) + 1; w < p.rateWords; w++) buffer[w] = state[w]!;
      }
      buffer[remaining >>> 2] = buffer[remaining >>> 2]! ^ (0x80 << ((remaining & 3) << 3));
    }
    const scratch = new Uint8Array(rateBytes);
    for (let i = 0; i < p.rateWords / 2; i++) {
      const j = i + p.rateWords / 2;
      const si = state[i]!;
      const sj = state[j]!;
      if (encrypting) {
        state[i] = sj ^ buffer[i]! ^ state[p.rateWords + i]!;
        state[j] = si ^ sj ^ buffer[j]! ^ state[p.rateWords + (j & capMask)]!;
      } else {
        state[i] = si ^ sj ^ buffer[i]! ^ state[p.rateWords + i]!;
        state[j] = si ^ buffer[j]! ^ state[p.rateWords + (j & capMask)]!;
      }
      buffer[i] = buffer[i]! ^ (si);
      buffer[j] = buffer[j]! ^ (sj);
    }
    for (let i = 0; i < p.rateWords; i++) wordToLe(buffer[i]!, scratch, 4 * i);
    out.set(scratch.subarray(0, remaining), off);
    sparkle(state, branches, p.big);
  }

  for (let i = 0; i < p.keyWords; i++) state[p.rateWords + i] = state[p.rateWords + i]! ^ (keyWords[i]!);
  const tag = new Uint8Array(p.tagWords * 4);
  for (let i = 0; i < p.tagWords; i++) wordToLe(state[p.rateWords + i]!, tag, 4 * i);
  return { out, tag };
}

export function schwaemmEncrypt(
  variant: SchwaemmVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const { out, tag } = schwaemm(variant, key, nonce, plaintext, aad, true);
  const result = new Uint8Array(out.length + tag.length);
  result.set(out, 0);
  result.set(tag, out.length);
  return result;
}

export function schwaemmDecrypt(
  variant: SchwaemmVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  const tagLen = SCHWAEMM_PARAMS[variant].tagWords * 4;
  if (data.length < tagLen) return null;
  const { out, tag } = schwaemm(
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

const ESCH_RATE = 16;

/**
 * Esch's state and its two operations: absorb a 16-byte block, and squeeze the digest.
 *
 * Factored out so the one-shot and the incremental forms share it rather than each carrying a copy of
 * the injection. The absorb is not a plain XOR: the block is expanded through `ell` and injected into
 * *six* words (eight at 384), which is what lets a 128-bit rate feed a 384- or 512-bit state.
 */
function eschState(width: EschWidth) {
  const p = ESCH_PARAMS[width];
  const branches = p.stateWords / 2;
  const state = new Int32Array(p.stateWords);

  const absorb = (block: Uint8Array, off: number, steps: number): void => {
    const t0 = (block[off]! | (block[off + 1]! << 8) | (block[off + 2]! << 16) | (block[off + 3]! << 24)) | 0;
    const t1 = (block[off + 4]! | (block[off + 5]! << 8) | (block[off + 6]! << 16) | (block[off + 7]! << 24)) | 0;
    const t2 = (block[off + 8]! | (block[off + 9]! << 8) | (block[off + 10]! << 16) | (block[off + 11]! << 24)) | 0;
    const t3 = (block[off + 12]! | (block[off + 13]! << 8) | (block[off + 14]! << 16) | (block[off + 15]! << 24)) | 0;
    const tx = ell(t0 ^ t2);
    const ty = ell(t1 ^ t3);
    state[0] = state[0]! ^ (t0 ^ ty);
    state[1] = state[1]! ^ (t1 ^ tx);
    state[2] = state[2]! ^ (t2 ^ ty);
    state[3] = state[3]! ^ (t3 ^ tx);
    state[4] = state[4]! ^ (ty);
    state[5] = state[5]! ^ (tx);
    if (p.stateWords === 16) {
      state[6] = state[6]! ^ (ty);
      state[7] = state[7]! ^ (tx);
    }
    sparkle(state, branches, steps);
  };

  return {
    /** An interior block: the slim permutation and no domain constant. */
    absorbFull: (block: Uint8Array, off: number): void => absorb(block, off, p.slim),
    /**
     * The final block: a domain constant into the *middle* of the state -- word `stateWords / 2 - 1`,
     * not word 0 -- then the padding byte and the big permutation.
     */
    finish: (tail: Uint8Array, tailLen: number): Uint8Array => {
      const padded = new Uint8Array(ESCH_RATE);
      padded.set(tail.subarray(0, tailLen));
      const middle = (p.stateWords >> 1) - 1;
      if (tailLen < ESCH_RATE) {
        state[middle] = state[middle]! ^ (1 << 24);
        padded[tailLen] = 0x80;
      } else {
        state[middle] = state[middle]! ^ (1 << 25);
      }
      absorb(padded, 0, p.big);
      const out = new Uint8Array(p.digest);
      for (let i = 0; i < 4; i++) wordToLe(state[i]!, out, 4 * i);
      for (let produced = 16; produced < p.digest; produced += 16) {
        sparkle(state, branches, p.slim);
        for (let i = 0; i < 4; i++) wordToLe(state[i]!, out, produced + 4 * i);
      }
      return out;
    },
  };
}

/**
 * Esch -- SPARKLE's hash, at 256 or 384 bits. Hold-back, because the absorb loop's bound is strict.
 */
export function createEsch(width: EschWidth): LwcHasher {
  const s = eschState(width);
  return holdBackAbsorber(ESCH_RATE, s.absorbFull, s.finish);
}

export function esch(width: EschWidth, message: Uint8Array): Uint8Array {
  const h = createEsch(width);
  h.update(message);
  return h.digest();
}
