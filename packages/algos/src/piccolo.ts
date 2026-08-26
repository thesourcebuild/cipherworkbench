/**
 * Piccolo-80, the generalised Feistel with a byte-permuting round shuffle (Shibutani, Isobe, Hiwatari,
 * Mitsuda, Akishita and Shirai, CHES 2011).
 *
 * `legacy`. No break of the full 25 rounds, but biclique attacks reach all of them at a cost just under
 * exhaustive search -- so it is here to reproduce values.
 *
 * What distinguishes it from TWINE and LBlock, its two closest neighbours here, is the **round
 * permutation**: instead of shuffling nibbles, Piccolo swaps *half-words* between the four 16-bit words
 * of its state, taking the high byte of one and the low byte of another. That is one byte-move per word on
 * an 8-bit machine, which is cheaper than any nibble shuffle, and it is the design's whole trick.
 *
 * Four things to preserve.
 *
 * **The round function has two S-box layers around one matrix.** Substitute four nibbles, multiply by a
 * 4-by-4 matrix over GF(2^4), substitute again. Only one layer is right for nothing, and it is easy to
 * write only one because the matrix step reads as the end of the function.
 *
 * **The whitening keys are byte-interleaved from the master key.** `wk0` takes the high byte of key word 0
 * and the low byte of word 1; `wk1` the reverse. So the whitening is not a slice of the key, and treating
 * it as one gives a cipher whose *middle* is entirely correct.
 *
 * **The key schedule cycles through five cases.** `m` runs 0 to 4 and repeats, and cases 0 and 2 share an
 * expression while 1 and 4 share another -- so the pattern is not "one case per round modulo something
 * small". Getting it wrong gives correct round keys for the first two rounds.
 *
 * **Decryption swaps the round-key pairs on odd rounds.** Reversing the key order alone is not enough: the
 * two keys within each round exchange places on every other round, which is what the reference expresses
 * as a parity test. Without it the cipher inverts against itself and reproduces nothing.
 *
 * Piccolo-128 is not offered: a different schedule over five more constants, and no reachable vector.
 *
 * No oracle -- OpenSSL has never implemented Piccolo. What stands behind it is the designers' own vector,
 * as carried by FELICS's benchmarking suite, checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;
const KEY = 10;
const ROUNDS = 25;

const u16 = (x: number): number => x & 0xffff;

/** The 4-bit S-box, and the two GF(2^4) multiplication tables the matrix needs. */
const SBOX = [0xe, 0x4, 0xb, 0x2, 0x3, 0x8, 0x0, 0x9, 0x1, 0xa, 0x7, 0xf, 0x6, 0xc, 0x5, 0xd] as const;

/**
 * Multiplication by 2 and 3 in GF(2^4) under `x^4 + x + 1`, derived rather than stored.
 *
 * Every reference ships both as sixteen-entry literals. They are one shift-and-reduce and one XOR, so the
 * tests compare these against the reference's tables and a mistyped entry has nowhere to live.
 */
const MUL2 = new Uint8Array(16);
const MUL3 = new Uint8Array(16);
for (let x = 0; x < 16; x++) {
  const doubled = (x & 8) !== 0 ? ((x << 1) ^ 0x3) & 0xf : (x << 1) & 0xf;
  MUL2[x] = doubled;
  MUL3[x] = doubled ^ x;
}

/** Exported so a test can pin the two derivations against the reference's literals. */
export const PICCOLO_MULTIPLY: readonly Readonly<Uint8Array>[] = [MUL2, MUL3];

{
  if (new Set(SBOX).size !== 16) throw new Error("Piccolo's S-box is not a permutation.");
}

/** One row of the matrix: `p0 ^ p1 ^ 2*p2 ^ 3*p3`. */
const row = (p0: number, p1: number, p2: number, p3: number): number =>
  p0 ^ p1 ^ MUL2[p2]! ^ MUL3[p3]!;

/** The round function: substitute, multiply, substitute. */
function f(x: number): number {
  const a = SBOX[(x >> 12) & 0xf]!;
  const b = SBOX[(x >> 8) & 0xf]!;
  const c = SBOX[(x >> 4) & 0xf]!;
  const d = SBOX[x & 0xf]!;
  const y0 = row(c, d, a, b);
  const y1 = row(d, a, b, c);
  const y2 = row(a, b, c, d);
  const y3 = row(b, c, d, a);
  return u16((SBOX[y0]! << 12) | (SBOX[y1]! << 8) | (SBOX[y2]! << 4) | SBOX[y3]!);
}

/** The 25 key-schedule constants, one 32-bit value per round. */
const CONSTANTS = [
  0x293d071c, 0x253e1f1a, 0x213f1718, 0x3d382f16, 0x39392714, 0x353a3f12, 0x313b3710, 0x0d344f0e,
  0x0935470c, 0x05365f0a, 0x01375708, 0x1d306f06, 0x19316704, 0x15327f02, 0x11337700, 0x6d2c8f3e,
  0x692d873c, 0x652e9f3a, 0x612f9738, 0x7d28af36, 0x7929a734, 0x752abf32, 0x712bb730, 0x4d24cf2e,
  0x4925c72c,
] as const;

/** Piccolo-80 as a `BlockCipher`. */
export function createPiccolo(key: Uint8Array): BlockCipher {
  if (key.length !== KEY) {
    throw new Error(`Piccolo-80's key is exactly 10 bytes; this one is ${key.length}.`);
  }
  // Five little-endian 16-bit key words.
  const mk = [0, 1, 2, 3, 4].map((i) => u16(key[2 * i]! | (key[2 * i + 1]! << 8)));

  // The whitening keys, byte-interleaved rather than sliced.
  const wk = [
    u16((mk[0]! & 0xff00) | (mk[1]! & 0x00ff)),
    u16((mk[1]! & 0xff00) | (mk[0]! & 0x00ff)),
    u16((mk[4]! & 0xff00) | (mk[3]! & 0x00ff)),
    u16((mk[3]! & 0xff00) | (mk[4]! & 0x00ff)),
  ];

  const rk: number[] = [];
  let phase = 0;
  for (let round = 0; round < ROUNDS; round++) {
    let value = CONSTANTS[round]! >>> 0;
    if (phase === 0 || phase === 2) value = (value ^ ((mk[2]! | (mk[3]! << 16)) >>> 0)) >>> 0;
    else if (phase === 3) value = (value ^ (((mk[4]! << 16) | mk[4]!) >>> 0)) >>> 0;
    else value = (value ^ ((mk[0]! | (mk[1]! << 16)) >>> 0)) >>> 0;
    rk.push(u16(value & 0xffff), u16(value >>> 16));
    phase = phase === 4 ? 0 : phase + 1;
  }

  /** The round permutation: half-words traded between the four state words. */
  const shuffle = (x: number[]): void => {
    const y0 = u16((x[1]! & 0xff00) | (x[3]! & 0x00ff));
    const y1 = u16((x[2]! & 0xff00) | (x[0]! & 0x00ff));
    const y2 = u16((x[3]! & 0xff00) | (x[1]! & 0x00ff));
    const y3 = u16((x[0]! & 0xff00) | (x[2]! & 0x00ff));
    x[0] = y0;
    x[1] = y1;
    x[2] = y2;
    x[3] = y3;
  };

  /**
   * Both directions, which differ only in which round keys each round takes.
   *
   * `keysFor(round)` returns the pair, and on the way back the pair is swapped on odd rounds -- which is
   * the part that is not simply "the same keys in reverse".
   */
  const run = (
    src: Uint8Array,
    dst: Uint8Array,
    firstWhiten: readonly [number, number],
    lastWhiten: readonly [number, number],
    keysFor: (round: number) => readonly [number, number],
  ): void => {
    // The block is four little-endian words, and the state order is x3, x2, x1, x0.
    const words = [0, 1, 2, 3].map((i) => u16(src[2 * i]! | (src[2 * i + 1]! << 8)));
    const x = [words[3]!, words[2]!, words[1]!, words[0]!];
    x[2] = u16(x[2]! ^ firstWhiten[1]);
    x[0] = u16(x[0]! ^ firstWhiten[0]);
    for (let round = 0; round < ROUNDS - 1; round++) {
      const [a, b] = keysFor(round);
      x[1] = u16(x[1]! ^ f(x[0]!) ^ a);
      x[3] = u16(x[3]! ^ f(x[2]!) ^ b);
      shuffle(x);
    }
    const [a, b] = keysFor(ROUNDS - 1);
    x[1] = u16(x[1]! ^ f(x[0]!) ^ a);
    x[3] = u16(x[3]! ^ f(x[2]!) ^ b);
    x[0] = u16(x[0]! ^ lastWhiten[0]);
    x[2] = u16(x[2]! ^ lastWhiten[1]);
    const out = [x[3]!, x[2]!, x[1]!, x[0]!];
    for (let i = 0; i < 4; i++) {
      dst[2 * i] = out[i]! & 0xff;
      dst[2 * i + 1] = (out[i]! >> 8) & 0xff;
    }
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) =>
      run(src, dst, [wk[0]!, wk[1]!], [wk[2]!, wk[3]!], (round) => [rk[2 * round]!, rk[2 * round + 1]!]),
    decryptBlock: (src, dst) =>
      run(src, dst, [wk[2]!, wk[3]!], [wk[0]!, wk[1]!], (round) => {
        const base = 2 * ROUNDS - 2 * round - 2;
        // The pair swaps on odd rounds, which reversing the order alone does not do.
        return round % 2 === 0 ? [rk[base]!, rk[base + 1]!] : [rk[base + 1]!, rk[base]!];
      }),
  };
}
