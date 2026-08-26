/**
 * TWINE-80, the generalised Feistel network with a 64-bit block (Suzaki, Minematsu, Morioka and Kobayashi,
 * SAC 2012).
 *
 * `legacy`. No break of the full 36 rounds, but the published cryptanalysis reaches 23 of them with
 * biclique and impossible-differential attacks, and nothing has been built on it since -- so it does not
 * get `modern` on the terms SKINNY does. It is here because it is one of the small set of designs that
 * showed a *type-2 generalised Feistel* with a good nibble permutation can beat a plain SPN on hardware
 * area, which is a real result and the reason it is cited.
 *
 * There is almost nothing to it: sixteen nibbles, one 4-bit S-box, and a permutation of the sixteen
 * positions. No matrix, no field arithmetic, and the entire round is eight independent
 * `nibble ^= S[nibble ^ key]` steps followed by the permutation.
 *
 * Three things to preserve.
 *
 * **The last round has no permutation.** Thirty-six rounds of substitution but only thirty-five
 * permutations -- the usual "no diffusion in the final round", and here it is visible as a loop of 35
 * followed by one bare substitution. Running 36 permutations is right for nothing.
 *
 * **The nibble order within a byte is low first.** Nibble 0 is the *low* half of byte 0, which is the
 * opposite of LED's convention one file over -- and both are what their own published vectors assume.
 *
 * **The key state is twenty nibbles rotated twice per round.** The first four rotate left by one, then
 * all twenty rotate left by four. Doing only the second is right for the first round and wrong for the
 * other thirty-five, which is the kind of thing a single published vector does catch.
 *
 * TWINE-128 exists and is not offered: its key schedule is a different function over 32 nibbles, and no
 * reachable source publishes a vector for it.
 *
 * No oracle -- OpenSSL has never implemented TWINE. What stands behind it is the designers' own vector,
 * as carried by FELICS's benchmarking suite, checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const KEY = 10;
const ROUNDS = 36;

/** The 4-bit S-box, and its inverse derived at load. */
const SBOX = [12, 0, 15, 10, 2, 11, 9, 5, 8, 3, 13, 7, 1, 14, 6, 4] as const;
const SBOX_INVERSE = (() => {
  const out = new Array<number>(16).fill(-1);
  SBOX.forEach((v, i) => (out[v] = i));
  if (out.some((v) => v < 0)) throw new Error("TWINE's S-box is not a permutation.");
  return out;
})();

/** The nibble permutation, as a destination per source position. */
const PERMUTATION = [5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14] as const;

/**
 * The 35 round constants, six bits each.
 *
 * Not the LED and SKINNY LFSR -- TWINE's own sequence, which its specification tabulates. Only the
 * schedule reads them, split into a high triple and a low triple.
 */
const ROUND_CONSTANTS = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28,
  0x13, 0x26, 0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0e, 0x1c, 0x38, 0x33, 0x25,
  0x09, 0x12, 0x24,
] as const;

/** Eight round-key nibbles per round, 36 rounds' worth. */
function schedule(key: Uint8Array): number[][] {
  // Twenty nibbles, read from five little-endian 16-bit words, low nibble of each word first.
  const state: number[] = [];
  for (let i = 0; i < 20; i++) {
    const word = key[2 * (i >> 2)]! | (key[2 * (i >> 2) + 1]! << 8);
    state.push((word >> (4 * (i & 3))) & 0xf);
  }

  const rounds: number[][] = [];
  const emit = (): void => {
    rounds.push([
      state[1]!,
      state[3]!,
      state[4]!,
      state[6]!,
      state[13]!,
      state[14]!,
      state[15]!,
      state[16]!,
    ]);
  };
  for (let r = 0; r < ROUNDS - 1; r++) {
    emit();
    state[1] = state[1]! ^ SBOX[state[0]!]!;
    state[4] = state[4]! ^ SBOX[state[16]!]!;
    state[7] = state[7]! ^ (ROUND_CONSTANTS[r]! >> 3);
    state[19] = state[19]! ^ (ROUND_CONSTANTS[r]! & 0x07);
    // Two rotations: the first four nibbles by one, then all twenty by four.
    const first = state[0]!;
    state[0] = state[1]!;
    state[1] = state[2]!;
    state[2] = state[3]!;
    state[3] = first;
    const head = state.slice(0, 4);
    for (let i = 0; i < 16; i++) state[i] = state[i + 4]!;
    for (let i = 0; i < 4; i++) state[16 + i] = head[i]!;
  }
  emit();
  return rounds;
}

/** TWINE-80 as a `BlockCipher`. */
export function createTwine(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`TWINE-80's key is exactly 10 bytes; this one is ${key.length}.`);
  }
  const rounds = schedule(key);

  const load = (src: Uint8Array): number[] => {
    const out: number[] = [];
    for (let i = 0; i < BLOCK; i++) out.push(src[i]! & 0xf, (src[i]! >> 4) & 0xf);
    return out;
  };
  const store = (nibbles: readonly number[], dst: Uint8Array): void => {
    for (let i = 0; i < BLOCK; i++) {
      dst[i] = (nibbles[2 * i]! & 0xf) | ((nibbles[2 * i + 1]! & 0xf) << 4);
    }
  };
  /** The eight independent Feistel steps of one round. */
  const substitute = (s: number[], keys: readonly number[], box: readonly number[]): void => {
    for (let i = 0; i < 8; i++) s[2 * i + 1] = s[2 * i + 1]! ^ box[s[2 * i]! ^ keys[i]!]!;
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      const s = load(src);
      for (let r = 0; r < ROUNDS - 1; r++) {
        substitute(s, rounds[r]!, SBOX);
        const permuted = new Array<number>(16);
        for (let i = 0; i < 16; i++) permuted[PERMUTATION[i]!] = s[i]!;
        for (let i = 0; i < 16; i++) s[i] = permuted[i]!;
      }
      // The last round substitutes and stops -- no permutation.
      substitute(s, rounds[ROUNDS - 1]!, SBOX);
      store(s, dst);
    },
    decryptBlock: (src, dst) => {
      const s = load(src);
      /**
       * The Feistel step is its own inverse *given the same S-box*, because it XORs into the odd nibble
       * without touching the even one it reads -- so decryption reuses `SBOX`, not `SBOX_INVERSE`. The
       * inverse box exists only for the assertion that the box is a permutation at all, which is what a
       * mistyped entry breaks.
       */
      substitute(s, rounds[ROUNDS - 1]!, SBOX);
      for (let r = ROUNDS - 2; r >= 0; r--) {
        const permuted = new Array<number>(16);
        for (let i = 0; i < 16; i++) permuted[i] = s[PERMUTATION[i]!]!;
        for (let i = 0; i < 16; i++) s[i] = permuted[i]!;
        substitute(s, rounds[r]!, SBOX);
      }
      store(s, dst);
    },
  };
}

/** Exported so a test can require the box to be a permutation without re-deriving it. */
export const TWINE_SBOX_INVERSE: readonly number[] = SBOX_INVERSE;
