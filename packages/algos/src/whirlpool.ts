import { MerkleDamgard, writeBitLength } from "./md-common";

/**
 * Whirlpool, as standardised in ISO/IEC 10118-3:2004 — the third and final revision by
 * Barreto and Rijmen.
 *
 * The one library on npm that offers this (`whirlpool-hash`) implements WHIRLPOOL-0 and
 * WHIRLPOOL-T, the two superseded drafts. They differ from the final function in their
 * S-box and produce entirely different digests, so it is the wrong algorithm rather than
 * an older version of the right one. Hence this.
 *
 * A 512-bit hash built from a 512-bit block cipher (W) in Miyaguchi–Preneel mode: ten
 * rounds over an 8x8 byte state, structurally an AES scaled up, with its own S-box and a
 * circulant MDS matrix. No weakness is known against the final version.
 *
 * Slow, unavoidably. Ten rounds of eight 64-bit table-driven lookups per 64-byte block,
 * with 64-bit arithmetic emulated on 32-bit halves, comes to roughly an order of
 * magnitude more work per byte than SHA-256. That is the design, not a shortcut here.
 */

/**
 * The Whirlpool S-box (ISO/IEC 10118-3, Annex A).
 *
 * Written out rather than generated from the mini-boxes E, E-inverse and R. Generating it
 * is about twenty lines and would be one more thing to get right with no published
 * intermediate value to check against; the S-box itself is tabulated in the standard and
 * the final digests verify it.
 */
const SBOX = /* @__PURE__ */ Uint8Array.from([
  0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
  0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
  0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
  0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
  0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
  0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
  0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
  0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
  0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
  0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
  0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
  0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
  0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
  0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
  0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
  0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
]);

const ROUNDS = 10;

/** Multiply by x in GF(2^8) with Whirlpool's reduction polynomial x^8+x^4+x^3+x^2+1 (0x11d). */
function xtime(v: number): number {
  const shifted = v << 1;
  return (shifted ^ (v & 0x80 ? 0x1d : 0)) & 0xff;
}

/**
 * The eight round tables, as high/low 32-bit halves.
 *
 * `C[t][x]` is the 64-bit row the byte `x` contributes when it sits in column `t`. Each
 * is `C[0][x]` rotated right by `8*t` bits, which is what makes the circulant matrix a
 * set of table lookups instead of a multiply. Storing all eight rotations costs 16 KB and
 * removes a rotate from the innermost loop.
 *
 * The MDS row is the circulant (1, 1, 4, 1, 8, 5, 2, 9) from the standard.
 */
const CHI: Uint32Array[] = [];
const CLO: Uint32Array[] = [];
const RC_HI = new Uint32Array(ROUNDS + 1);
const RC_LO = new Uint32Array(ROUNDS + 1);

(function buildTables(): void {
  for (let t = 0; t < 8; t++) {
    CHI.push(new Uint32Array(256));
    CLO.push(new Uint32Array(256));
  }

  for (let x = 0; x < 256; x++) {
    const v1 = SBOX[x]!;
    const v2 = xtime(v1);
    const v4 = xtime(v2);
    const v5 = v4 ^ v1;
    const v8 = xtime(v4);
    const v9 = v8 ^ v1;

    // C0[x] as eight bytes, most significant first: v1 v1 v4 v1 v8 v5 v2 v9.
    const bytes = [v1, v1, v4, v1, v8, v5, v2, v9];

    for (let t = 0; t < 8; t++) {
      // Rotating right by 8*t bits is a byte rotation of the eight-byte row.
      const rotated = [
        bytes[(0 - t + 8) % 8]!,
        bytes[(1 - t + 8) % 8]!,
        bytes[(2 - t + 8) % 8]!,
        bytes[(3 - t + 8) % 8]!,
        bytes[(4 - t + 8) % 8]!,
        bytes[(5 - t + 8) % 8]!,
        bytes[(6 - t + 8) % 8]!,
        bytes[(7 - t + 8) % 8]!,
      ];
      CHI[t]![x] =
        (((rotated[0]! << 24) | (rotated[1]! << 16) | (rotated[2]! << 8) | rotated[3]!) >>> 0);
      CLO[t]![x] =
        (((rotated[4]! << 24) | (rotated[5]! << 16) | (rotated[6]! << 8) | rotated[7]!) >>> 0);
    }
  }

  /**
   * Round constants. Row r takes its eight bytes from C0..C7 at successive indices, which
   * makes them S-box output rather than arbitrary values.
   */
  RC_HI[0] = 0;
  RC_LO[0] = 0;
  for (let r = 1; r <= ROUNDS; r++) {
    const i = 8 * (r - 1);
    RC_HI[r] =
      (((SBOX[i]! << 24) | (SBOX[i + 1]! << 16) | (SBOX[i + 2]! << 8) | SBOX[i + 3]!) >>> 0);
    RC_LO[r] =
      (((SBOX[i + 4]! << 24) | (SBOX[i + 5]! << 16) | (SBOX[i + 6]! << 8) | SBOX[i + 7]!) >>> 0);
  }
})();

class Whirlpool extends MerkleDamgard {
  // The hash state, and the cipher's key schedule and state, all as hi/lo word pairs.
  private readonly hashHi = new Uint32Array(8);
  private readonly hashLo = new Uint32Array(8);
  private readonly blockHi = new Uint32Array(8);
  private readonly blockLo = new Uint32Array(8);
  private readonly kHi = new Uint32Array(8);
  private readonly kLo = new Uint32Array(8);
  private readonly stateHi = new Uint32Array(8);
  private readonly stateLo = new Uint32Array(8);
  private readonly tmpHi = new Uint32Array(8);
  private readonly tmpLo = new Uint32Array(8);

  constructor() {
    // 32-byte length field: Whirlpool counts message bits in 256 bits of counter.
    super(64, 64, 32, "Whirlpool");
  }

  /**
   * One application of the circulant MDS layer plus S-box, reading from
   * `srcHi`/`srcLo` and writing to `tmpHi`/`tmpLo`.
   *
   * Column `t` of row `i` takes byte `t` of source word `(i - t) mod 8`. That diagonal
   * indexing *is* the ShiftColumns step — there is no separate shift.
   */
  private theta(srcHi: Uint32Array, srcLo: Uint32Array): void {
    for (let i = 0; i < 8; i++) {
      let hi = 0;
      let lo = 0;
      for (let t = 0; t < 8; t++) {
        const j = (i - t) & 7;
        // Bytes 0-3 live in the high word, 4-7 in the low word, most significant first.
        const byte =
          t < 4 ? (srcHi[j]! >>> (24 - t * 8)) & 0xff : (srcLo[j]! >>> (24 - (t - 4) * 8)) & 0xff;
        hi ^= CHI[t]![byte]!;
        lo ^= CLO[t]![byte]!;
      }
      this.tmpHi[i] = hi >>> 0;
      this.tmpLo[i] = lo >>> 0;
    }
  }

  protected override compress(block: Uint8Array, offset: number): void {
    // Load the block as eight big-endian 64-bit words.
    for (let i = 0; i < 8; i++) {
      const j = offset + i * 8;
      this.blockHi[i] =
        (((block[j]! << 24) | (block[j + 1]! << 16) | (block[j + 2]! << 8) | block[j + 3]!) >>> 0);
      this.blockLo[i] =
        (((block[j + 4]! << 24) |
          (block[j + 5]! << 16) |
          (block[j + 6]! << 8) |
          block[j + 7]!) >>>
          0);
    }

    // The hash state is the cipher key; the block is the plaintext.
    for (let i = 0; i < 8; i++) {
      this.kHi[i] = this.hashHi[i]!;
      this.kLo[i] = this.hashLo[i]!;
      this.stateHi[i] = (this.blockHi[i]! ^ this.kHi[i]!) >>> 0;
      this.stateLo[i] = (this.blockLo[i]! ^ this.kLo[i]!) >>> 0;
    }

    for (let r = 1; r <= ROUNDS; r++) {
      // Key schedule: the key is itself run through the round function, with the round
      // constant as its only asymmetry.
      this.theta(this.kHi, this.kLo);
      for (let i = 0; i < 8; i++) {
        this.kHi[i] = this.tmpHi[i]!;
        this.kLo[i] = this.tmpLo[i]!;
      }
      this.kHi[0] = (this.kHi[0]! ^ RC_HI[r]!) >>> 0;
      this.kLo[0] = (this.kLo[0]! ^ RC_LO[r]!) >>> 0;

      // Cipher round, then add the round key.
      this.theta(this.stateHi, this.stateLo);
      for (let i = 0; i < 8; i++) {
        this.stateHi[i] = (this.tmpHi[i]! ^ this.kHi[i]!) >>> 0;
        this.stateLo[i] = (this.tmpLo[i]! ^ this.kLo[i]!) >>> 0;
      }
    }

    // Miyaguchi–Preneel: H = H xor E_H(m) xor m. Xoring in *both* the ciphertext and the
    // plaintext is what distinguishes this from Davies–Meyer.
    for (let i = 0; i < 8; i++) {
      this.hashHi[i] = (this.hashHi[i]! ^ this.stateHi[i]! ^ this.blockHi[i]!) >>> 0;
      this.hashLo[i] = (this.hashLo[i]! ^ this.stateLo[i]! ^ this.blockLo[i]!) >>> 0;
    }
  }

  protected override writeLength(block: Uint8Array, offset: number, byteLength: number): void {
    writeBitLength(block, offset, byteLength, 32, "be");
  }

  protected override writeDigest(out: Uint8Array): void {
    for (let i = 0; i < 8; i++) {
      const hi = this.hashHi[i]!;
      const lo = this.hashLo[i]!;
      out[i * 8] = (hi >>> 24) & 0xff;
      out[i * 8 + 1] = (hi >>> 16) & 0xff;
      out[i * 8 + 2] = (hi >>> 8) & 0xff;
      out[i * 8 + 3] = hi & 0xff;
      out[i * 8 + 4] = (lo >>> 24) & 0xff;
      out[i * 8 + 5] = (lo >>> 16) & 0xff;
      out[i * 8 + 6] = (lo >>> 8) & 0xff;
      out[i * 8 + 7] = lo & 0xff;
    }
  }
}

export interface WhirlpoolEngine {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

export function createWhirlpool(): WhirlpoolEngine {
  return new Whirlpool();
}

export function whirlpool(data: Uint8Array): Uint8Array {
  const engine = new Whirlpool();
  engine.update(data);
  return engine.digest();
}

export const WHIRLPOOL_OUTPUT_LEN = 64;
export const WHIRLPOOL_BLOCK_LEN = 64;
