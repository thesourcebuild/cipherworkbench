/**
 * GIMLI, a 384-bit permutation and the sponge hash built on it (Bernstein, Kolbl, Lucks, Massolino,
 * Mendel, Nawaz, Schneider, Schwabe, Standaert, Todo and Viguier, CHES 2017). NIST lightweight
 * cryptography round-2 candidate.
 *
 * `modern`. No attack reaches the full 24 rounds.
 *
 * The design goal was *cross-platform* performance rather than a single target: the state is twelve
 * 32-bit words viewed as a 3x4 matrix, the non-linear layer works down each column independently, and
 * the only inter-column movement is a swap of adjacent words in the top row every second round. That
 * shape vectorises on a 128-bit SIMD unit, fits four registers on a 32-bit microcontroller, and
 * bitslices on an 8-bit one -- which is the whole argument for it.
 *
 * **Which GIMLI-Hash this is, and why it matters.** Two conventions are in circulation and they
 * disagree on every input. This implements the one from the GIMLI paper and the NIST lightweight
 * submission: absorb 16-byte blocks, XOR a single `0x01` at the padding position, XOR `0x01` into
 * **byte 47** -- the top of the *capacity*, not the end of the rate -- then squeeze. FELICS's
 * `hash_functions` suite instead writes a SHAKE-style `0x1f` at the padding position and `0x80` at
 * byte 15, which is a different function; its two vectors do not reproduce under the standard rule and
 * the standard vectors do not reproduce under its. The standard one is what is implemented, because it
 * is what the submission specifies and what other implementations agree on -- verified against all
 * 1,024 records of `rweather/lightweight-crypto`'s `GIMLI-24-HASH.txt`, generated from the
 * submission's own reference code. Same judgement as NORX v3.0 and Ascon v1.3 over their alternatives.
 *
 * Three things to preserve.
 *
 * **The round counter counts down and the constant is XORed only every fourth round.** `0x9e377900 |
 * round` goes into word 0 when `round & 3` is 0, which -- because the loop runs 24 down to 1 -- means
 * rounds 24, 20, 16, 12, 8 and 4. Counting up gives a different set of six constants.
 *
 * **The two swaps are on different residues.** The small swap (words 0-1 and 2-3) happens when
 * `round & 3` is 0, alongside the constant; the big swap (words 0-2 and 1-3) when it is 2. Applying
 * both on the same residue, or one on the wrong one, gives a permutation that is perfectly invertible
 * and matches nothing.
 *
 * **The SP-box reads all three words before writing any of them.** `x`, `y` and `z` are captured
 * first; the three assignments then use the captured values, and the column is written back top-to-
 * bottom in the order z, y, x. Writing as you go corrupts the later expressions.
 *
 * The state is bytes on the outside and words on the inside, converted little-endian at each
 * permutation. Keeping the canonical copy as bytes is what makes the sponge's padding and squeeze read
 * as byte operations, which is how the specification states them.
 */

export const GIMLI_STATE_BYTES = 48;
export const GIMLI_RATE = 16;
export const GIMLI_DIGEST = 32;

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number => (n === 0 ? u32(x) : u32((x << n) | (x >>> (32 - n))));

/** The 24-round permutation, in place over twelve 32-bit words. */
export function gimliPermute(s: Uint32Array): void {
  for (let round = 24; round > 0; round--) {
    for (let column = 0; column < 4; column++) {
      const x = rotl(s[column]!, 24);
      const y = rotl(s[4 + column]!, 9);
      const z = u32(s[8 + column]!);
      s[8 + column] = u32(x ^ u32(z << 1) ^ u32((y & z) << 2));
      s[4 + column] = u32(y ^ x ^ u32((x | z) << 1));
      s[column] = u32(z ^ y ^ u32((x & y) << 3));
    }
    if ((round & 3) === 0) {
      let t = s[0]!;
      s[0] = s[1]!;
      s[1] = t;
      t = s[2]!;
      s[2] = s[3]!;
      s[3] = t;
      s[0] = u32(s[0]! ^ u32(0x9e377900 | round));
    } else if ((round & 3) === 2) {
      let t = s[0]!;
      s[0] = s[2]!;
      s[2] = t;
      t = s[1]!;
      s[1] = s[3]!;
      s[3] = t;
    }
  }
}

/**
 * The sponge, incremental.
 *
 * A full block is absorbed and permuted as soon as it arrives -- unlike the NIST lightweight sponges
 * in `lwc-hash.ts`, which must hold a block back. GIMLI-Hash always absorbs a padding block, even when
 * the message length is already a multiple of the rate, so there is no "was this block last" question
 * to defer.
 */
export class GimliHash {
  private readonly bytes = new Uint8Array(GIMLI_STATE_BYTES);
  private readonly words = new Uint32Array(12);
  private filled = 0;
  private done = false;

  constructor(private readonly digestLength: number = GIMLI_DIGEST) {
    if (!Number.isInteger(digestLength) || digestLength < 1) {
      throw new Error(`GIMLI-Hash: the digest length must be a positive integer; got ${digestLength}.`);
    }
  }

  private permute(): void {
    for (let i = 0; i < 12; i++) {
      this.words[i] = u32(
        this.bytes[4 * i]! |
          (this.bytes[4 * i + 1]! << 8) |
          (this.bytes[4 * i + 2]! << 16) |
          (this.bytes[4 * i + 3]! << 24),
      );
    }
    gimliPermute(this.words);
    for (let i = 0; i < 12; i++) {
      const w = this.words[i]!;
      this.bytes[4 * i] = w & 0xff;
      this.bytes[4 * i + 1] = (w >>> 8) & 0xff;
      this.bytes[4 * i + 2] = (w >>> 16) & 0xff;
      this.bytes[4 * i + 3] = (w >>> 24) & 0xff;
    }
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("GIMLI-Hash: update() after digest()");
    for (const byte of chunk) {
      this.bytes[this.filled] = this.bytes[this.filled]! ^ byte;
      this.filled += 1;
      if (this.filled === GIMLI_RATE) {
        this.permute();
        this.filled = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("GIMLI-Hash: digest() called twice");
    this.done = true;
    this.bytes[this.filled] = this.bytes[this.filled]! ^ 0x01;
    // The domain bit goes at the top of the capacity, not at the end of the rate. See the header.
    this.bytes[GIMLI_STATE_BYTES - 1] = this.bytes[GIMLI_STATE_BYTES - 1]! ^ 0x01;
    this.permute();

    const out = new Uint8Array(this.digestLength);
    let written = 0;
    while (written < this.digestLength) {
      const take = Math.min(GIMLI_RATE, this.digestLength - written);
      out.set(this.bytes.subarray(0, take), written);
      written += take;
      if (written < this.digestLength) this.permute();
    }
    return out;
  }
}

export function createGimliHash(digestLength: number = GIMLI_DIGEST): GimliHash {
  return new GimliHash(digestLength);
}

export function gimliHash(message: Uint8Array, digestLength: number = GIMLI_DIGEST): Uint8Array {
  const h = new GimliHash(digestLength);
  h.update(message);
  return h.digest();
}
