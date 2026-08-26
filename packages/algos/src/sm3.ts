import { MerkleDamgard, rotl32, writeBitLength } from "./md-common";

/**
 * SM3, from GB/T 32905-2016 (originally published by China's OSCCA in 2010).
 *
 * A 256-bit Merkle–Damgård hash, mandatory in Chinese commercial cryptography — it is
 * what SM2 signatures hash with, and what TLS cipher suites in the Chinese national
 * suite use. Structurally similar to SHA-256 in its shape (64 rounds, 512-bit blocks,
 * eight 32-bit state words, big-endian) and entirely different in its round function:
 * the message expansion is nonlinear, and each round updates two state words through
 * separate Boolean functions.
 *
 * No published weakness. It is `modern`, not legacy — the only reason it is uncommon
 * outside China is jurisdiction, not cryptanalysis.
 */

/** GB/T 32905-2016 §4.1. */
const IV = /* @__PURE__ */ Int32Array.from([
  0x7380166f | 0, 0x4914b2b9 | 0, 0x172442d7 | 0, 0xda8a0600 | 0,
  0xa96f30bc | 0, 0x163138aa | 0, 0xe38dee4d | 0, 0xb0fb0e4e | 0,
]);

const T_LOW = 0x79cc4519;
const T_HIGH = 0x7a879d8a;

/** Permutation P0, applied to one of the two round outputs. */
const p0 = (x: number): number => (x ^ rotl32(x, 9) ^ rotl32(x, 17)) >>> 0;
/** Permutation P1, used only in the message expansion. */
const p1 = (x: number): number => (x ^ rotl32(x, 15) ^ rotl32(x, 23)) >>> 0;

/**
 * Rotated round constants, precomputed.
 *
 * `T[j] <<< (j mod 32)` appears in every round. Computing it per round costs two shifts
 * and an or; precomputing sixty-four values costs 256 bytes once. The `j mod 32` is easy
 * to misread as `j` — at j=32 the rotation wraps back to zero, which is exactly the kind
 * of thing that produces a hash that is correct for short inputs and wrong for long ones.
 */
const T_ROTATED = /* @__PURE__ */ (() => {
  const table = new Int32Array(64);
  for (let j = 0; j < 64; j++) {
    table[j] = rotl32(j < 16 ? T_LOW : T_HIGH, j % 32) | 0;
  }
  return table;
})();

class Sm3 extends MerkleDamgard {
  private readonly state = Int32Array.from(IV);
  /** 68 words: the 16 from the block plus 52 expanded. */
  private readonly w = new Int32Array(68);

  constructor() {
    super(64, 32, 8, "SM3");
  }

  protected override compress(block: Uint8Array, offset: number): void {
    const w = this.w;

    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] =
        ((block[j]! << 24) | (block[j + 1]! << 16) | (block[j + 2]! << 8) | block[j + 3]!) | 0;
    }

    // Message expansion. Nonlinear, unlike SHA-256's — P1 is applied to a three-way xor.
    for (let i = 16; i < 68; i++) {
      const x = (w[i - 16]! ^ w[i - 9]! ^ rotl32(w[i - 3]! >>> 0, 15)) >>> 0;
      w[i] = (p1(x) ^ rotl32(w[i - 13]! >>> 0, 7) ^ w[i - 6]!) | 0;
    }

    const s = this.state;
    let a = s[0]! >>> 0;
    let b = s[1]! >>> 0;
    let c = s[2]! >>> 0;
    let d = s[3]! >>> 0;
    let e = s[4]! >>> 0;
    let f = s[5]! >>> 0;
    let g = s[6]! >>> 0;
    let h = s[7]! >>> 0;

    for (let j = 0; j < 64; j++) {
      const a12 = rotl32(a, 12);
      const ss1 = rotl32((((a12 + e) >>> 0) + (T_ROTATED[j]! >>> 0)) >>> 0, 7);
      const ss2 = (ss1 ^ a12) >>> 0;

      // FF and GG switch form at round 16: xor-parity below, and majority /
      // multiplexer above. Two different functions, both changing at the same boundary.
      const ff = j < 16 ? (a ^ b ^ c) >>> 0 : ((a & b) | (a & c) | (b & c)) >>> 0;
      const gg = j < 16 ? (e ^ f ^ g) >>> 0 : ((e & f) | (~e & g)) >>> 0;

      // W'[j] = W[j] xor W[j+4] — which is why 68 words are expanded, not 64.
      const wPrime = (w[j]! ^ w[j + 4]!) >>> 0;

      const tt1 = (((ff + d) >>> 0) + ((ss2 + wPrime) >>> 0)) >>> 0;
      const tt2 = (((gg + h) >>> 0) + ((ss1 + (w[j]! >>> 0)) >>> 0)) >>> 0;

      d = c;
      c = rotl32(b, 9);
      b = a;
      a = tt1;
      h = g;
      g = rotl32(f, 19);
      f = e;
      e = p0(tt2);
    }

    // Davies–Meyer feedforward, as in SHA-2.
    s[0] = (s[0]! ^ a) | 0;
    s[1] = (s[1]! ^ b) | 0;
    s[2] = (s[2]! ^ c) | 0;
    s[3] = (s[3]! ^ d) | 0;
    s[4] = (s[4]! ^ e) | 0;
    s[5] = (s[5]! ^ f) | 0;
    s[6] = (s[6]! ^ g) | 0;
    s[7] = (s[7]! ^ h) | 0;
  }

  protected override writeLength(block: Uint8Array, offset: number, byteLength: number): void {
    writeBitLength(block, offset, byteLength, 8, "be");
  }

  protected override writeDigest(out: Uint8Array): void {
    for (let i = 0; i < 8; i++) {
      const v = this.state[i]! >>> 0;
      out[i * 4] = (v >>> 24) & 0xff;
      out[i * 4 + 1] = (v >>> 16) & 0xff;
      out[i * 4 + 2] = (v >>> 8) & 0xff;
      out[i * 4 + 3] = v & 0xff;
    }
  }
}

export interface Sm3Engine {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

export function createSm3(): Sm3Engine {
  return new Sm3();
}

export function sm3(data: Uint8Array): Uint8Array {
  const engine = new Sm3();
  engine.update(data);
  return engine.digest();
}

export const SM3_OUTPUT_LEN = 32;
export const SM3_BLOCK_LEN = 64;
