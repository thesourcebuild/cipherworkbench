/**
 * CAST-256 (RFC 2612), an AES finalist, and the cheapest cipher in this repo to have added.
 *
 * It reuses CAST5 *entirely*: the same four S-boxes, the same three round functions f1/f2/f3, the same
 * masking-and-rotation subkey pair. What is new is the shape -- 128-bit block instead of 64, four
 * 32-bit registers instead of two, and a generalised Feistel network of 48 rounds arranged as twelve
 * quad-rounds, the first six forward and the last six in reverse.
 *
 * **So this file stores no tables**, and that is the point worth recording rather than a convenience.
 * The 4 KB of S-box constants are already in `cast5.ts`, already parsed out of RFC 2144 by script, and
 * already pinned by CAST5's own published vectors. Reusing them means a CAST-256 vector that fails
 * points at CAST-256's key schedule -- which is the new and intricate part -- rather than at 1024
 * numbers that might have been mistyped. A second copy of those tables would have been a second
 * chance to be wrong about something already verified.
 *
 * Two things about the key schedule, which is where the difficulty is.
 *
 * **The round constants are an arithmetic progression, not a table.** `Cm` starts at 0x5A827999 and
 * advances by 0x6ED9EBA1; `Cr` starts at 19 and advances by 17 mod 32. Both magic numbers are the
 * SHA-1 round constants, which is a nice piece of history and, more usefully, means these are
 * generated rather than transcribed.
 *
 * **The forward octave is applied twice per quad-round, and the subkeys are read off in a scrambled
 * order.** `Kr` comes from kappa words 0, 2, 4, 6 masked to five bits and `Km` from words 7, 5, 3, 1
 * -- descending odd indices against ascending even ones. Getting that order wrong gives a cipher that
 * is a perfectly good 48-round Feistel network and matches nothing, which is this family's recurring
 * failure mode.
 *
 * Decryption is the same twelve quad-rounds with the *index* reversed, `11 - i`, rather than a second
 * schedule. RFC 2612's own presentation does the same.
 *
 * Security: no attack better than exhaustive search on the full cipher. It lost to Rijndael on
 * performance, and it is the only AES finalist whose S-boxes were already in this tree.
 */

import { castRoundFunction } from "./cast5";
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;
/** Twelve quad-rounds: six forward, six reverse. 48 rounds in all. */
const QUADS = 12;

const u32 = (x: number): number => x >>> 0;

const load = (src: Uint8Array, at: number): number =>
  u32((src[at]! << 24) | (src[at + 1]! << 16) | (src[at + 2]! << 8) | src[at + 3]!);

function store(value: number, dst: Uint8Array, at: number): void {
  dst[at] = (value >>> 24) & 0xff;
  dst[at + 1] = (value >>> 16) & 0xff;
  dst[at + 2] = (value >>> 8) & 0xff;
  dst[at + 3] = value & 0xff;
}

/**
 * The 96 (Tm, Tr) pairs, generated once at module load.
 *
 * Two arithmetic progressions, exactly as RFC 2612 section 2.4 defines them. Note that the eight
 * values within each group of eight are consecutive rather than repeated -- the RFC's nested loop over
 * i and j is doing nothing but numbering, and flattening it would be equivalent, so it is written
 * flat with the count stated instead.
 */
const TM = new Array<number>(192);
const TR = new Array<number>(192);
{
  let cm = 0x5a827999;
  let cr = 19;
  for (let i = 0; i < 192; i++) {
    TM[i] = cm;
    TR[i] = cr;
    cm = u32(cm + 0x6ed9eba1);
    cr = (cr + 17) & 31;
  }
}

/** RFC 2612's f1, f2 and f3 -- CAST5's, over CAST5's S-boxes. */
const f1 = (d: number, km: number, kr: number): number => castRoundFunction(1, d, km, kr);
const f2 = (d: number, km: number, kr: number): number => castRoundFunction(2, d, km, kr);
const f3 = (d: number, km: number, kr: number): number => castRoundFunction(3, d, km, kr);

interface Subkeys {
  /** Rotation amounts, four per quad-round, masked to five bits. */
  kr: number[];
  /** Masking words, four per quad-round. */
  km: number[];
}

function schedule(key: Uint8Array): Subkeys {
  // Zero-padded to 256 bits. RFC 2612 allows 128 to 256 in 32-bit steps; shorter keys are the same
  // cipher with a padded kappa, which is what makes 160, 192 and 224 legal rather than special.
  const padded = new Uint8Array(32);
  padded.set(key);
  const kappa = [0, 1, 2, 3, 4, 5, 6, 7].map((i) => load(padded, i * 4));

  const kr: number[] = [];
  const km: number[] = [];

  /** One forward octave, W(kappa): eight steps down the register file and back to the top. */
  const octave = (at: number): void => {
    kappa[6] = u32(kappa[6]! ^ f1(kappa[7]!, TM[at]!, TR[at]!));
    kappa[5] = u32(kappa[5]! ^ f2(kappa[6]!, TM[at + 1]!, TR[at + 1]!));
    kappa[4] = u32(kappa[4]! ^ f3(kappa[5]!, TM[at + 2]!, TR[at + 2]!));
    kappa[3] = u32(kappa[3]! ^ f1(kappa[4]!, TM[at + 3]!, TR[at + 3]!));
    kappa[2] = u32(kappa[2]! ^ f2(kappa[3]!, TM[at + 4]!, TR[at + 4]!));
    kappa[1] = u32(kappa[1]! ^ f3(kappa[2]!, TM[at + 5]!, TR[at + 5]!));
    kappa[0] = u32(kappa[0]! ^ f1(kappa[1]!, TM[at + 6]!, TR[at + 6]!));
    kappa[7] = u32(kappa[7]! ^ f2(kappa[0]!, TM[at + 7]!, TR[at + 7]!));
  };

  for (let i = 0; i < QUADS; i++) {
    octave(i * 16);
    octave(i * 16 + 8);
    // Ascending even words for the rotations, descending odd words for the masks. Not symmetrical,
    // and the asymmetry is the specification's.
    kr.push(kappa[0]! & 31, kappa[2]! & 31, kappa[4]! & 31, kappa[6]! & 31);
    km.push(kappa[7]!, kappa[5]!, kappa[3]!, kappa[1]!);
  }

  return { kr, km };
}

/** CAST-256 as a `BlockCipher`. The key is 16 to 32 bytes, in multiples of four. */
export function createCast6(key: Uint8Array): BlockCipher {
  if (key.length < 16 || key.length > 32 || key.length % 4 !== 0) {
    throw new Error(
      `CAST-256's key is 16, 20, 24, 28 or 32 bytes; this one is ${key.length}.`,
    );
  }
  const { kr, km } = schedule(key);

  /**
   * The network, in both directions, differing only in which quad-round each step reads.
   *
   * Six forward quad-rounds then six reverse ones -- and "reverse" means the four f-applications run
   * bottom to top over the same registers, not that the round is inverted. Decryption walks the
   * quad-round *index* backwards through the same structure, which is why there is one function here
   * and not two.
   */
  const run = (src: Uint8Array, dst: Uint8Array, forward: boolean): void => {
    let a = load(src, 0);
    let b = load(src, 4);
    let c = load(src, 8);
    let d = load(src, 12);

    for (let i = 0; i < QUADS; i++) {
      const x = (forward ? i : QUADS - 1 - i) * 4;
      if (i < 6) {
        c = u32(c ^ f1(d, km[x]!, kr[x]!));
        b = u32(b ^ f2(c, km[x + 1]!, kr[x + 1]!));
        a = u32(a ^ f3(b, km[x + 2]!, kr[x + 2]!));
        d = u32(d ^ f1(a, km[x + 3]!, kr[x + 3]!));
      } else {
        d = u32(d ^ f1(a, km[x + 3]!, kr[x + 3]!));
        a = u32(a ^ f3(b, km[x + 2]!, kr[x + 2]!));
        b = u32(b ^ f2(c, km[x + 1]!, kr[x + 1]!));
        c = u32(c ^ f1(d, km[x]!, kr[x]!));
      }
    }

    store(a, dst, 0);
    store(b, dst, 4);
    store(c, dst, 8);
    store(d, dst, 12);
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => run(src, dst, true),
    decryptBlock: (src, dst) => run(src, dst, false),
  };
}
