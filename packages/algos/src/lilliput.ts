/**
 * Lilliput-80, an extended generalised Feistel network with a bit-permutation layer (Berger, Francq,
 * Minier and Thomas, IEEE Transactions on Computers 2016). 64-bit block, 80-bit key, 30 rounds.
 *
 * `legacy`. Unstandardised and undeployed; here to reproduce values.
 *
 * **There is only one key size.** LILLIPUT is defined at a 64-bit block and an 80-bit key and nothing
 * else -- a note here once claimed a 128-bit variant "with a different schedule", which was wrong. The
 * 128-bit key belongs to **Lilliput-AE**, the authors' later NIST lightweight submission, which is a
 * *tweakable authenticated-encryption* scheme rather than a wider key for this cipher. Lilliput-AE was
 * also withdrawn after an attack recovering its key from a single message, so it is not a candidate for
 * this repo either.
 *
 * What makes it worth having is the *shape* of its Feistel: an EGFN is neither a classical two-branch
 * Feistel nor a Type-2 generalised one. Sixteen nibble branches, and one round updates the whole
 * right half from the whole left half at once -- branch 8 from branch 7, branch 9 from branches 6 and
 * 7, and so on, with branch 15 taking a running XOR of seven of them. That is the "extended" part,
 * and it is what lets a round achieve full diffusion where a Type-2 network needs several.
 *
 * Three things to preserve.
 *
 * **The key schedule is the work, not the round function.** The round function is eight S-box lookups
 * and some XORs; the schedule is two coupled linear feedback state machines over twenty nibbles, run
 * once per round. `MixingLFSM` updates seven specific nibbles from seven others with nibble-width
 * rotations, and `PermutationLFSM` then rotates each of four five-nibble groups by one position. The
 * round key is *extracted before* both, from eight fixed nibble positions, bit-transposed through a
 * multiply-by-four-modulo-31 pattern, passed through the S-box, and finally XORed with the round
 * number split across two nibbles.
 *
 * **The bit transposition is `4i mod 31`, not a nibble permutation.** Thirty-two bits are gathered
 * from eight nibbles least-significant-bit first and scattered to `MUL4MOD31[j]`; index 31 maps to
 * itself, which is why the table is not a rotation. Getting this wrong gives a schedule that is
 * perfectly deterministic and matches nothing.
 *
 * **The permutation layer is absent from the final round.** Twenty-nine rounds of Feistel-then-permute
 * and then one bare Feistel, exactly as with PRINCE's and PRIDE's last rounds -- so decryption is one
 * Feistel, then twenty-nine of inverse-permute-then-Feistel.
 *
 * The state is kept as nibbles throughout rather than packed into bytes, because every operation here
 * is nibble-wide and packing would put a shift and a mask around each one. The tool's bindings convert
 * at the boundary.
 *
 * Verified against the designers' own test vector in both directions.
 */

import type { BlockCipher } from "./blockmodes";

const ROUNDS = 30;
const BLOCK = 8;
const KEY = 10;

/** The 4-bit S-box, used by both the round function and the key schedule. */
const SBOX = [4, 8, 7, 1, 9, 3, 2, 14, 0, 11, 6, 15, 10, 5, 13, 12] as const;

/** The branch permutation: branch j moves to position P[j]. */
const PERMUTATION = [13, 9, 14, 8, 10, 11, 12, 15, 4, 5, 3, 1, 2, 6, 0, 7] as const;

/**
 * `4i mod 31` for i in 0..31, which is where bit i of the gathered round key lands.
 *
 * Derived rather than transcribed -- 31 is prime and 4 generates a subgroup, so the map is a
 * bijection on 0..30 with 31 fixed. The fixed point is the whole reason a rotation is the wrong
 * mental model here.
 */
const MUL4MOD31 = (() => {
  const table = new Uint8Array(32);
  for (let i = 0; i < 32; i++) table[i] = i === 31 ? 31 : (4 * i) % 31;
  const seen = new Set(table);
  if (seen.size !== 32) throw new Error("Lilliput: the bit transposition must be a permutation");
  return table;
})();

/** One round key per round, extracted before each state advance. */
function schedule(keyNibbles: readonly number[]): number[][] {
  const k = Array.from(keyNibbles);
  const out: number[][] = [];

  const extract = (round: number): void => {
    const taps = [k[1]!, k[3]!, k[6]!, k[9]!, k[10]!, k[13]!, k[16]!, k[18]!];
    const rk = new Array<number>(8).fill(0);
    for (let j = 0; j < 32; j++) {
      const to = MUL4MOD31[j]!;
      if (taps[j >> 2]! & 1) rk[to >> 2] = rk[to >> 2]! | (1 << (to & 3));
      taps[j >> 2] = taps[j >> 2]! >> 1;
    }
    for (let i = 0; i < 8; i++) rk[i] = SBOX[rk[i]!]!;
    rk[6] = rk[6]! ^ ((round << 3) & 0x0f);
    rk[7] = rk[7]! ^ ((round >> 1) & 0x0f);
    out.push(rk);
  };

  for (let round = 0; round < ROUNDS - 1; round++) {
    extract(round);

    // MixingLFSM: seven nibbles updated from seven others, with nibble-width rotations.
    k[0] = k[0]! ^ ((k[4]! >> 1) ^ ((k[4]! << 3) & 0x0f));
    k[1] = k[1]! ^ (k[2]! >> 3);
    k[6] = k[6]! ^ ((k[7]! << 3) & 0x0f);
    k[9] = k[9]! ^ (((k[8]! << 1) & 0x0f) ^ (k[8]! >> 3));
    k[11] = k[11]! ^ ((k[12]! >> 1) ^ ((k[12]! << 3) & 0x0f));
    k[13] = k[13]! ^ (k[12]! >> 3);
    k[16] = k[16]! ^ (((k[15]! << 3) & 0x0f) ^ ((k[17]! << 1) & 0x0f) ^ (k[17]! >> 3));
    for (let i = 0; i < 20; i++) k[i] = k[i]! & 0x0f;

    // PermutationLFSM: each group of five nibbles rotates by one.
    for (let group = 0; group < 4; group++) {
      const base = 5 * group;
      const last = k[base + 4]!;
      for (let i = 4; i > 0; i--) k[base + i] = k[base + i - 1]!;
      k[base] = last;
    }
  }
  extract(ROUNDS - 1);
  return out;
}

function crypt(keyNibbles: readonly number[], blockNibbles: readonly number[], decrypt: boolean): number[] {
  const rk = schedule(keyNibbles);
  const x = Array.from(blockNibbles);

  /** One EGFN round: the right eight branches absorb the left eight, plus a running XOR. */
  const feistel = (r: number): void => {
    const key = rk[r]!;
    x[8] = x[8]! ^ SBOX[x[7]! ^ key[0]!]!;
    x[9] = x[9]! ^ SBOX[x[6]! ^ key[1]!]! ^ x[7]!;
    x[10] = x[10]! ^ SBOX[x[5]! ^ key[2]!]! ^ x[7]!;
    x[11] = x[11]! ^ SBOX[x[4]! ^ key[3]!]! ^ x[7]!;
    x[12] = x[12]! ^ SBOX[x[3]! ^ key[4]!]! ^ x[7]!;
    x[13] = x[13]! ^ SBOX[x[2]! ^ key[5]!]! ^ x[7]!;
    x[14] = x[14]! ^ SBOX[x[1]! ^ key[6]!]! ^ x[7]!;
    x[15] =
      x[15]! ^ SBOX[x[0]! ^ key[7]!]! ^ x[7]! ^ x[6]! ^ x[5]! ^ x[4]! ^ x[3]! ^ x[2]! ^ x[1]!;
    for (let i = 0; i < 16; i++) x[i] = x[i]! & 0x0f;
  };

  if (!decrypt) {
    for (let r = 0; r < ROUNDS - 1; r++) {
      feistel(r);
      const t = new Array<number>(16);
      for (let j = 0; j < 16; j++) t[PERMUTATION[j]!] = x[j]!;
      for (let j = 0; j < 16; j++) x[j] = t[j]!;
    }
    feistel(ROUNDS - 1);
  } else {
    feistel(ROUNDS - 1);
    for (let r = ROUNDS - 2; r >= 0; r--) {
      const t = new Array<number>(16);
      for (let j = 0; j < 16; j++) t[j] = x[PERMUTATION[j]!]!;
      for (let j = 0; j < 16; j++) x[j] = t[j]!;
      feistel(r);
    }
  }
  return x;
}

const toNibbles = (bytes: Uint8Array): number[] => {
  const out: number[] = [];
  for (const byte of bytes) {
    out.push((byte >> 4) & 0x0f, byte & 0x0f);
  }
  return out;
};

const fromNibbles = (nibbles: readonly number[]): Uint8Array => {
  const out = new Uint8Array(nibbles.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = (nibbles[2 * i]! << 4) | nibbles[2 * i + 1]!;
  return out;
};

export function createLilliput(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`Lilliput-80 needs a key of exactly ${KEY} bytes; this one is ${key.length}.`);
  }
  const keyNibbles = toNibbles(key);
  return {
    blockSize: BLOCK,
    encryptBlock(src, dst) {
      dst.set(fromNibbles(crypt(keyNibbles, toNibbles(src.subarray(0, BLOCK)), false)));
    },
    decryptBlock(src, dst) {
      dst.set(fromNibbles(crypt(keyNibbles, toNibbles(src.subarray(0, BLOCK)), true)));
    },
  };
}
