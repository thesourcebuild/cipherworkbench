/**
 * PHOTON-128/16/16, the lightweight sponge hash from the PHOTON family (Guo, Peyrin and Poschmann,
 * CRYPTO 2011). 144-bit state as a 6x6 grid of nibbles, 12 rounds, 16-bit rate, 128-bit digest.
 *
 * `legacy`. No attack on the hash, but it is superseded for new work by the NIST lightweight winner
 * and by PHOTON-Beetle, which is the same family's AEAD entry and is already here. Note this is a
 * *different* permutation from PHOTON-Beetle's: that one is PHOTON-256, an 8x8 grid over GF(2^4) with
 * its own serial coefficients. Sharing the name is not sharing the function.
 *
 * **Nothing is stored.** All three of its tables come out of eighteen numbers and a table this repo
 * already has, which is the strongest case of the derive-don't-transcribe rule in the family:
 *
 * - **The S-box is PRESENT's**, imported rather than re-listed. So PRESENT's own published vectors and
 *   LED's already pin it, and a PHOTON failure points at the diffusion rather than at sixteen nibbles.
 * - **The MixColumns matrix is `A^6`** for the serial matrix whose last row is the six coefficients
 *   (1, 2, 8, 5, 8, 2) -- that is what "MixColumnSerial" means, and it is the reason the family is
 *   cheap in hardware. The reference ships the 36 resulting entries; here six produce them.
 * - **The 72 round constants are twelve internal constants XORed with six row constants.** Every
 *   implementation ships the 6x12 grid; it is 18 numbers.
 *
 * Each derivation is checked at load against the reference's own first row, so a wrong coefficient
 * fails immediately rather than producing a hash that is self-consistent and matches nothing.
 *
 * Three things to preserve.
 *
 * **The preset goes in the last row, not the first.** Three bytes -- digest bits, rate bits, rate bits
 * -- as six nibbles at cells 30 to 35. Every other sponge here initialises from a leading IV, and
 * putting these at the front gives a plausible wrong answer for every input.
 *
 * **A padding block is always absorbed.** As with GIMLI, PHOTON pads unconditionally, so a message
 * whose length is already a multiple of the rate gets a whole extra block of `0x80 0x00`. There is no
 * "was this block last" question and therefore no need to hold a block back.
 *
 * **The squeeze reads the first row and permutes between blocks.** Two bytes at a time from cells 0 to
 * 3, so a 16-byte digest is eight squeezes and seven permutations.
 *
 * Verified against FELICS's two vectors, which additionally publish the post-initialisation and
 * post-update states -- so a failure localises to a phase rather than to the whole function.
 */

import { PRESENT_SBOX } from "./present";

const D = 6;
const ROUNDS = 12;
const CELLS = D * D;

export const PHOTON_RATE = 2;
export const PHOTON_DIGEST = 16;

/** GF(2^4) under x^4 + x + 1 -- the reference's `ReductionPoly` of 0x3. */
function fieldMul(a: number, b: number): number {
  let x = a;
  let acc = 0;
  for (let i = 0; i < 4; i++) {
    if ((b >> i) & 1) acc ^= x;
    x = x & 8 ? (x << 1) ^ 0x13 : x << 1;
  }
  return acc & 0xf;
}

/** The serial coefficients: the last row of the matrix whose sixth power is MixColumns. */
const SERIAL = [1, 2, 8, 5, 8, 2] as const;

const MIX = (() => {
  const a: number[][] = [];
  for (let i = 0; i < D; i++) {
    const row: number[] = [];
    for (let j = 0; j < D; j++) row.push(i < D - 1 ? (j === i + 1 ? 1 : 0) : SERIAL[j]!);
    a.push(row);
  }
  let m: number[][] = [];
  for (let i = 0; i < D; i++) {
    const row: number[] = [];
    for (let j = 0; j < D; j++) row.push(i === j ? 1 : 0);
    m.push(row);
  }
  for (let n = 0; n < D; n++) {
    const next: number[][] = [];
    for (let i = 0; i < D; i++) {
      const row: number[] = [];
      for (let j = 0; j < D; j++) {
        let sum = 0;
        for (let k = 0; k < D; k++) sum ^= fieldMul(a[i]![k]!, m[k]![j]!);
        row.push(sum);
      }
      next.push(row);
    }
    m = next;
  }
  // The reference's own first row, which a wrong coefficient or a wrong power fails.
  if (m[0]!.join(",") !== "1,2,8,5,8,2" || m[1]!.join(",") !== "2,5,1,2,6,12") {
    throw new Error("PHOTON: the MixColumns derivation does not reproduce the reference's matrix");
  }
  return m;
})();

/** Twelve internal constants and six row constants; their XOR is the 6x12 grid. */
const INTERNAL_CONSTANTS = [1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10] as const;
const ROW_CONSTANTS = [0, 1, 3, 7, 6, 4] as const;

const RC = (() => {
  const table: number[][] = [];
  for (let i = 0; i < D; i++) table.push(INTERNAL_CONSTANTS.map((c) => c ^ ROW_CONSTANTS[i]!));
  if (table[0]!.join(",") !== "1,3,7,14,13,11,6,12,9,2,5,10" || table[5]!.join(",") !== "5,7,3,10,9,15,2,8,13,6,1,14") {
    throw new Error("PHOTON: the round-constant derivation does not reproduce the reference's grid");
  }
  return table;
})();

/** The 12-round permutation, in place over 36 nibbles held row-major. */
export function photonPermute(s: Uint8Array): void {
  const column = new Uint8Array(D);
  const row = new Uint8Array(D);
  for (let r = 0; r < ROUNDS; r++) {
    for (let i = 0; i < D; i++) s[i * D] = s[i * D]! ^ RC[i]![r]!;
    for (let i = 0; i < CELLS; i++) s[i] = PRESENT_SBOX[s[i]!]!;
    // Row i rotates left by i; row 0 is unmoved, which is why the loop starts at 1.
    for (let i = 1; i < D; i++) {
      for (let j = 0; j < D; j++) row[j] = s[i * D + j]!;
      for (let j = 0; j < D; j++) s[i * D + j] = row[(j + i) % D]!;
    }
    for (let j = 0; j < D; j++) {
      for (let i = 0; i < D; i++) {
        let sum = 0;
        for (let k = 0; k < D; k++) sum ^= fieldMul(MIX[i]![k]!, s[k * D + j]!);
        column[i] = sum;
      }
      for (let i = 0; i < D; i++) s[i * D + j] = column[i]!;
    }
  }
}

/** PHOTON-128/16/16, incremental. */
export class PhotonHash {
  private readonly state = new Uint8Array(CELLS);
  private readonly chunk = new Uint8Array(PHOTON_RATE);
  private filled = 0;
  private done = false;

  constructor() {
    // The preset is three bytes in the *last* row: digest bits, rate bits, rate bits.
    const presets = [PHOTON_DIGEST << 1, 8 * PHOTON_RATE, 8 * PHOTON_RATE];
    for (let n = 0; n < presets.length; n++) {
      this.state[30 + 2 * n] = this.state[30 + 2 * n]! ^ ((presets[n]! >> 4) & 0xf);
      this.state[30 + 2 * n + 1] = this.state[30 + 2 * n + 1]! ^ (presets[n]! & 0xf);
    }
  }

  private absorb(): void {
    for (let n = 0; n < PHOTON_RATE; n++) {
      this.state[2 * n] = this.state[2 * n]! ^ ((this.chunk[n]! >> 4) & 0xf);
      this.state[2 * n + 1] = this.state[2 * n + 1]! ^ (this.chunk[n]! & 0xf);
    }
    photonPermute(this.state);
  }

  update(data: Uint8Array): void {
    if (this.done) throw new Error("PHOTON: update() after digest()");
    for (const byte of data) {
      this.chunk[this.filled] = byte;
      this.filled += 1;
      if (this.filled === PHOTON_RATE) {
        this.absorb();
        this.chunk.fill(0);
        this.filled = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("PHOTON: digest() called twice");
    this.done = true;
    // Always a padding block, even when the length is already a multiple of the rate.
    this.chunk.fill(0, this.filled);
    this.chunk[this.filled] = 0x80;
    this.absorb();

    const out = new Uint8Array(PHOTON_DIGEST);
    let written = 0;
    while (written < PHOTON_DIGEST) {
      for (let n = 0; n < PHOTON_RATE && written < PHOTON_DIGEST; n++, written++) {
        out[written] = (this.state[2 * n]! << 4) | this.state[2 * n + 1]!;
      }
      if (written < PHOTON_DIGEST) photonPermute(this.state);
    }
    return out;
  }
}

export function createPhotonHash(): PhotonHash {
  return new PhotonHash();
}

export function photonHash(message: Uint8Array): Uint8Array {
  const h = new PhotonHash();
  h.update(message);
  return h.digest();
}
