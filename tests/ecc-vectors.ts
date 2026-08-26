/**
 * Published vectors for the Phase 7 error-correcting codes.
 *
 * | Code | Source |
 * |---|---|
 * | Reed-Solomon | ISO/IEC 18004 Annex I, plus two Data Matrix cases -- transcribed by zxing |
 * | BCH(15,5) | ISO/IEC 18004 Table C.1: all 32 format-information codewords |
 * | BCH(18,6) | ISO/IEC 18004 Table D.1: all 34 version-information codewords, versions 7 to 40 |
 *
 * The two BCH tables are *exhaustive* for their codes rather than a sample: BCH(15,5) has exactly 32
 * codewords, and the standard defines all 34 version words there are. That is unusual here and worth
 * saying, because it means a wrong generator polynomial cannot hide in an untested corner.
 *
 * Hamming(15,11) and (16,11) have no published vector anywhere, and `tests/algos-ecc.test.ts` checks
 * them exhaustively instead -- every codeword, the minimum distance, every single-bit error and every
 * double-bit error. The generalised implementation is separately required to agree with the
 * hand-written (7,4), which *does* have a published value, so that vector transfers across.
 */

export interface RsVector {
  readonly profile: "qr" | "datamatrix";
  readonly note: string;
  readonly data: readonly number[];
  readonly ecc: readonly number[];
}

export const RS_VECTORS: readonly RsVector[] = [
  {
    profile: "qr",
    note: "ISO/IEC 18004 Annex I, the standard's own worked example",
    data: [
      0x10, 0x20, 0x0c, 0x56, 0x61, 0x80, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11,
    ],
    ecc: [
      0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55,
    ],
  },
  {
    profile: "qr",
    note: "a real QR payload, 32 data symbols to 18 ECC",
    data: [
      0x72, 0x67, 0x2f, 0x77, 0x69, 0x6b, 0x69, 0x2f, 0x4d, 0x61, 0x69, 0x6e, 0x5f, 0x50, 0x61, 0x67,
      0x65, 0x3b, 0x3b, 0x00, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11,
    ],
    ecc: [
      0xd8, 0xb8, 0xef, 0x14, 0xec, 0xd0, 0xcc, 0x85, 0x73, 0x40, 0x0b, 0xb5, 0x5a, 0xb8, 0x8b, 0x2e,
      0x08, 0x62,
    ],
  },
  {
    profile: "datamatrix",
    note: "three data symbols, which is the shortest real block either standard uses",
    data: [
      0x8e, 0xa4, 0xba,
    ],
    ecc: [
      0x72, 0x19, 0x05, 0x58, 0x66,
    ],
  },
  {
    profile: "datamatrix",
    note: "a real Data Matrix payload, 36 data symbols to 24 ECC",
    data: [
      0x69, 0x75, 0x75, 0x71, 0x3b, 0x30, 0x30, 0x64, 0x70, 0x65, 0x66, 0x2f, 0x68, 0x70, 0x70, 0x68,
      0x6d, 0x66, 0x2f, 0x64, 0x70, 0x6e, 0x30, 0x71, 0x30, 0x7b, 0x79, 0x6a, 0x6f, 0x68, 0x30, 0x81,
      0xf0, 0x88, 0x1f, 0xb5,
    ],
    ecc: [
      0x1c, 0x64, 0xee, 0xeb, 0xd0, 0x1d, 0x00, 0x03, 0xf0, 0x1c, 0xf1, 0xd0, 0x6d, 0x00, 0x98, 0xda,
      0x80, 0x88, 0xbe, 0xff, 0xb7, 0xfa, 0xa9, 0x95,
    ],
  },
];

export interface BchVector {
  /** The data bits, as an integer. */
  readonly data: number;
  /** The full codeword, masked where the profile has a mask. */
  readonly codeword: number;
}

/** ISO/IEC 18004 Table C.1 -- every BCH(15,5) format-information codeword there is. */
export const BCH_QR_FORMAT: readonly BchVector[] = [
  { data: 0x00, codeword: 0x5412 },
  { data: 0x01, codeword: 0x5125 },
  { data: 0x02, codeword: 0x5e7c },
  { data: 0x03, codeword: 0x5b4b },
  { data: 0x04, codeword: 0x45f9 },
  { data: 0x05, codeword: 0x40ce },
  { data: 0x06, codeword: 0x4f97 },
  { data: 0x07, codeword: 0x4aa0 },
  { data: 0x08, codeword: 0x77c4 },
  { data: 0x09, codeword: 0x72f3 },
  { data: 0x0a, codeword: 0x7daa },
  { data: 0x0b, codeword: 0x789d },
  { data: 0x0c, codeword: 0x662f },
  { data: 0x0d, codeword: 0x6318 },
  { data: 0x0e, codeword: 0x6c41 },
  { data: 0x0f, codeword: 0x6976 },
  { data: 0x10, codeword: 0x1689 },
  { data: 0x11, codeword: 0x13be },
  { data: 0x12, codeword: 0x1ce7 },
  { data: 0x13, codeword: 0x19d0 },
  { data: 0x14, codeword: 0x0762 },
  { data: 0x15, codeword: 0x0255 },
  { data: 0x16, codeword: 0x0d0c },
  { data: 0x17, codeword: 0x083b },
  { data: 0x18, codeword: 0x355f },
  { data: 0x19, codeword: 0x3068 },
  { data: 0x1a, codeword: 0x3f31 },
  { data: 0x1b, codeword: 0x3a06 },
  { data: 0x1c, codeword: 0x24b4 },
  { data: 0x1d, codeword: 0x2183 },
  { data: 0x1e, codeword: 0x2eda },
  { data: 0x1f, codeword: 0x2bed },
];

/** ISO/IEC 18004 Table D.1 -- versions 7 to 40, which are the versions that carry one. */
export const BCH_QR_VERSION: readonly BchVector[] = [
  { data: 7, codeword: 0x07c94 },
  { data: 8, codeword: 0x085bc },
  { data: 9, codeword: 0x09a99 },
  { data: 10, codeword: 0x0a4d3 },
  { data: 11, codeword: 0x0bbf6 },
  { data: 12, codeword: 0x0c762 },
  { data: 13, codeword: 0x0d847 },
  { data: 14, codeword: 0x0e60d },
  { data: 15, codeword: 0x0f928 },
  { data: 16, codeword: 0x10b78 },
  { data: 17, codeword: 0x1145d },
  { data: 18, codeword: 0x12a17 },
  { data: 19, codeword: 0x13532 },
  { data: 20, codeword: 0x149a6 },
  { data: 21, codeword: 0x15683 },
  { data: 22, codeword: 0x168c9 },
  { data: 23, codeword: 0x177ec },
  { data: 24, codeword: 0x18ec4 },
  { data: 25, codeword: 0x191e1 },
  { data: 26, codeword: 0x1afab },
  { data: 27, codeword: 0x1b08e },
  { data: 28, codeword: 0x1cc1a },
  { data: 29, codeword: 0x1d33f },
  { data: 30, codeword: 0x1ed75 },
  { data: 31, codeword: 0x1f250 },
  { data: 32, codeword: 0x209d5 },
  { data: 33, codeword: 0x216f0 },
  { data: 34, codeword: 0x228ba },
  { data: 35, codeword: 0x2379f },
  { data: 36, codeword: 0x24b0b },
  { data: 37, codeword: 0x2542e },
  { data: 38, codeword: 0x26a64 },
  { data: 39, codeword: 0x27541 },
  { data: 40, codeword: 0x28c69 },
];
