/**
 * Twofish, the AES finalist Schneier put forward as Blowfish's successor.
 *
 * A 128-bit block with 128-, 192- or 256-bit keys, and the cipher he has recommended over Blowfish
 * since 1998. Unbroken -- no attack reaches beyond 6 of its 16 rounds -- and widely offered:
 * VeraCrypt, GnuPG, KeePass and several disk-encryption tools list it, usually beside Serpent as the
 * conservative alternative to AES. OpenSSL has never implemented it, so Bouncy Castle's published
 * vectors, one per key size, are the check.
 *
 * Four things to know.
 *
 * **The S-boxes are key-dependent, which is the whole design.** Twofish builds four byte
 * permutations from the key and uses those inside the round function, rather than fixing them like
 * Rijndael. That is why keying costs more than encrypting a block and why the implementation expands
 * the S-boxes once, here, rather than per block.
 *
 * **The two stored permutations are the only constants.** `Q0` and `Q1` are 256 bytes each, parsed
 * from Bouncy Castle's engine; the MDS matrix is *derived* from them at load through the two LFSR
 * steps the specification defines (`0x169` is the field polynomial), and the RS matrix used by the key
 * schedule likewise comes from its own polynomial `0x14d`. So 512 bytes are stored and roughly 4 KB
 * are computed -- the same trade as `seed.ts` and `aria.ts`.
 *
 * **Everything is little-endian.** Words, key material and the block. Big-endian gives a cipher that
 * round-trips and matches nothing.
 *
 * **Two rounds are unrolled per loop iteration, and that is not an optimisation.** The Feistel
 * structure swaps halves each round, so a two-round body lets the four words stay in fixed variables;
 * a one-round body has to rotate them, which is where an implementation quietly drifts. This follows
 * the same shape as the reference.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;
const ROUNDS = 16;

/** The two fixed byte permutations, parsed from the reference implementation. */
const Q0: readonly number[] = [
  0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78,
  0xe4, 0xdd, 0xd1, 0x38, 0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c,
  0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48, 0xf2, 0xd0, 0x8b, 0x30,
  0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
  0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe,
  0x16, 0x0c, 0xe3, 0x61, 0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b,
  0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1, 0xe1, 0xe6, 0xbd, 0x45,
  0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
  0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf,
  0x33, 0xc9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8,
  0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7, 0xa1, 0x1d, 0xaa, 0xed,
  0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
  0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b,
  0x5f, 0x93, 0x0a, 0xef, 0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b,
  0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64, 0x2a, 0xce, 0xcb, 0x2f,
  0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
  0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17,
  0x55, 0x1f, 0x8a, 0x7d, 0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72,
  0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6e, 0x50, 0xde, 0x68,
  0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
  0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42,
  0x4a, 0x5e, 0xc1, 0xe0,
];

const Q1: readonly number[] = [
  0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b,
  0x45, 0x7d, 0xe8, 0x4b, 0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1,
  0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f, 0x5e, 0xba, 0xae, 0x5b,
  0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
  0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54,
  0x92, 0x74, 0x36, 0x51, 0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96,
  0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c, 0x13, 0x95, 0x9c, 0xc7,
  0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
  0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf,
  0x40, 0xe7, 0x2b, 0xe2, 0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9,
  0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17, 0x66, 0x94, 0xa1, 0x1d,
  0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
  0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21,
  0xc4, 0x1a, 0xeb, 0xd9, 0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01,
  0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48, 0x4f, 0xf2, 0x65, 0x8e,
  0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
  0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44,
  0xe0, 0x4d, 0x43, 0x69, 0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e,
  0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc, 0x22, 0xc9, 0xc0, 0x9b,
  0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
  0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56,
  0x55, 0x09, 0xbe, 0x91,
];

const Q = [Q0, Q1] as const;
for (const table of Q) {
  if (new Set(table).size !== 256) throw new Error("A Twofish q permutation is malformed.");
}

/** The field polynomials: 0x169 for the MDS matrix, 0x14d for the RS code the key schedule uses. */
const GF256_FDBK_2 = 0x169 / 2;
const GF256_FDBK_4 = 0x169 / 4;
const RS_GF_FDBK = 0x14d;

/**
 * Which of the two permutations each byte position uses, at each of the four key stages.
 *
 * These index tables are the awkward part of Twofish and they are not derivable -- they are simply
 * how the specification wires `q0` and `q1` into `h`. Named after the reference implementation's own
 * constants so the two can be compared line by line.
 */
const P_00 = 1, P_01 = 0, P_02 = 0, P_03 = P_01 ^ 1, P_04 = 1;
const P_10 = 0, P_11 = 0, P_12 = 1, P_13 = P_11 ^ 1, P_14 = 0;
const P_20 = 1, P_21 = 1, P_22 = 0, P_23 = P_21 ^ 1, P_24 = 0;
const P_30 = 0, P_31 = 1, P_32 = 1, P_33 = P_31 ^ 1, P_34 = 1;

const u32 = (x: number): number => x >>> 0;
const rol = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));
const ror = (x: number, n: number): number => u32((x >>> n) | (x << (32 - n)));

const lfsr1 = (x: number): number => (x >> 1) ^ (x & 1 ? GF256_FDBK_2 : 0);
const lfsr2 = (x: number): number =>
  (x >> 2) ^ (x & 2 ? GF256_FDBK_2 : 0) ^ (x & 1 ? GF256_FDBK_4 : 0);
/** Multiplication by 0x5b and 0xef, the two non-trivial MDS coefficients. */
const mulX = (x: number): number => x ^ lfsr2(x);
const mulY = (x: number): number => x ^ lfsr1(x) ^ lfsr2(x);

/** The MDS matrix, folded into four 256-entry tables and derived from Q at load. */
const MDS: readonly Uint32Array[] = (() => {
  const tables = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
  for (let i = 0; i < 256; i++) {
    const m1 = [Q0[i]!, Q1[i]!];
    const mX = [mulX(m1[0]!) & 0xff, mulX(m1[1]!) & 0xff];
    const mY = [mulY(m1[0]!) & 0xff, mulY(m1[1]!) & 0xff];
    tables[0]![i] = u32(m1[P_00]! | (mX[P_00]! << 8) | (mY[P_00]! << 16) | (mY[P_00]! << 24));
    tables[1]![i] = u32(mY[P_10]! | (mY[P_10]! << 8) | (mX[P_10]! << 16) | (m1[P_10]! << 24));
    tables[2]![i] = u32(mX[P_20]! | (mY[P_20]! << 8) | (m1[P_20]! << 16) | (mY[P_20]! << 24));
    tables[3]![i] = u32(mX[P_30]! | (m1[P_30]! << 8) | (mY[P_30]! << 16) | (mX[P_30]! << 24));
  }
  return tables;
})();

const b0 = (x: number): number => x & 0xff;
const b1 = (x: number): number => (x >>> 8) & 0xff;
const b2 = (x: number): number => (x >>> 16) & 0xff;
const b3 = (x: number): number => (x >>> 24) & 0xff;

const loadLe = (bytes: Uint8Array, at: number): number =>
  u32(bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24));

/** One step of the Reed-Solomon remainder the key schedule uses to build the S-box key. */
function rsRem(x: number): number {
  const b = (x >>> 24) & 0xff;
  const g2 = ((b << 1) ^ (b & 0x80 ? RS_GF_FDBK : 0)) & 0xff;
  const g3 = ((b >>> 1) ^ (b & 0x01 ? RS_GF_FDBK >>> 1 : 0)) ^ g2;
  return u32((x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
}

function rsMdsEncode(k0: number, k1: number): number {
  let r = k1;
  for (let i = 0; i < 4; i++) r = rsRem(r);
  r = u32(r ^ k0);
  for (let i = 0; i < 4; i++) r = rsRem(r);
  return r;
}

interface Expanded {
  subKeys: Int32Array;
  sBox: Int32Array;
}

function expandKey(key: Uint8Array): Expanded {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`Twofish's key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }
  const k64Cnt = key.length / 8;
  const even = [0, 0, 0, 0];
  const odd = [0, 0, 0, 0];
  const sBoxKeys = [0, 0, 0, 0];

  for (let i = 0; i < k64Cnt; i++) {
    even[i] = loadLe(key, i * 8);
    odd[i] = loadLe(key, i * 8 + 4);
    sBoxKeys[k64Cnt - 1 - i] = rsMdsEncode(even[i]!, odd[i]!);
  }

  /** `h`, the function both the subkeys and the S-boxes are built from. */
  const h = (x: number, words: readonly number[]): number => {
    let a = b0(x);
    let b = b1(x);
    let c = b2(x);
    let d = b3(x);
    const [k0, k1, k2, k3] = words as [number, number, number, number];

    if (k64Cnt === 1) {
      return u32(
        MDS[0]![Q[P_01]![a]! ^ b0(k0)]! ^
          MDS[1]![Q[P_11]![b]! ^ b1(k0)]! ^
          MDS[2]![Q[P_21]![c]! ^ b2(k0)]! ^
          MDS[3]![Q[P_31]![d]! ^ b3(k0)]!,
      );
    }
    // 256-bit keys fold in a fourth stage, 192- and 256-bit keys a third; all of them the last two.
    if (k64Cnt === 4) {
      a = Q[P_04]![a]! ^ b0(k3);
      b = Q[P_14]![b]! ^ b1(k3);
      c = Q[P_24]![c]! ^ b2(k3);
      d = Q[P_34]![d]! ^ b3(k3);
    }
    if (k64Cnt >= 3) {
      a = Q[P_03]![a]! ^ b0(k2);
      b = Q[P_13]![b]! ^ b1(k2);
      c = Q[P_23]![c]! ^ b2(k2);
      d = Q[P_33]![d]! ^ b3(k2);
    }
    return u32(
      MDS[0]![Q[P_01]![Q[P_02]![a]! ^ b0(k1)]! ^ b0(k0)]! ^
        MDS[1]![Q[P_11]![Q[P_12]![b]! ^ b1(k1)]! ^ b1(k0)]! ^
        MDS[2]![Q[P_21]![Q[P_22]![c]! ^ b2(k1)]! ^ b2(k0)]! ^
        MDS[3]![Q[P_31]![Q[P_32]![d]! ^ b3(k1)]! ^ b3(k0)]!,
    );
  };

  // 40 subkeys: four of input whitening, four of output whitening, and two per round.
  const subKeys = new Int32Array(8 + 2 * ROUNDS);
  for (let i = 0; i < subKeys.length / 2; i++) {
    const q = u32(i * 0x02020202);
    let a = h(q, even);
    const b = rol(h(u32(q + 0x01010101), odd), 8);
    a = u32(a + b);
    subKeys[i * 2] = a;
    a = u32(a + b);
    subKeys[i * 2 + 1] = rol(a, 9);
  }

  const [k0, k1, k2, k3] = sBoxKeys as [number, number, number, number];
  const sBox = new Int32Array(4 * 256);
  for (let i = 0; i < 256; i++) {
    let a = i;
    let b = i;
    let c = i;
    let d = i;
    if (k64Cnt === 1) {
      sBox[i * 2] = MDS[0]![Q[P_01]![a]! ^ b0(k0)]!;
      sBox[i * 2 + 1] = MDS[1]![Q[P_11]![b]! ^ b1(k0)]!;
      sBox[i * 2 + 0x200] = MDS[2]![Q[P_21]![c]! ^ b2(k0)]!;
      sBox[i * 2 + 0x201] = MDS[3]![Q[P_31]![d]! ^ b3(k0)]!;
      continue;
    }
    if (k64Cnt === 4) {
      a = Q[P_04]![a]! ^ b0(k3);
      b = Q[P_14]![b]! ^ b1(k3);
      c = Q[P_24]![c]! ^ b2(k3);
      d = Q[P_34]![d]! ^ b3(k3);
    }
    if (k64Cnt >= 3) {
      a = Q[P_03]![a]! ^ b0(k2);
      b = Q[P_13]![b]! ^ b1(k2);
      c = Q[P_23]![c]! ^ b2(k2);
      d = Q[P_33]![d]! ^ b3(k2);
    }
    sBox[i * 2] = MDS[0]![Q[P_01]![Q[P_02]![a]! ^ b0(k1)]! ^ b0(k0)]!;
    sBox[i * 2 + 1] = MDS[1]![Q[P_11]![Q[P_12]![b]! ^ b1(k1)]! ^ b1(k0)]!;
    sBox[i * 2 + 0x200] = MDS[2]![Q[P_21]![Q[P_22]![c]! ^ b2(k1)]! ^ b2(k0)]!;
    sBox[i * 2 + 0x201] = MDS[3]![Q[P_31]![Q[P_32]![d]! ^ b3(k1)]! ^ b3(k0)]!;
  }

  return { subKeys, sBox };
}

/** Twofish as a `BlockCipher`. The key-dependent S-boxes are expanded once, here. */
export function createTwofish(key: Uint8Array): BlockCipher {
  const { subKeys, sBox } = expandKey(key);

  const fe32_0 = (x: number): number =>
    u32(
      sBox[0x000 + 2 * (x & 0xff)]! ^
        sBox[0x001 + 2 * ((x >>> 8) & 0xff)]! ^
        sBox[0x200 + 2 * ((x >>> 16) & 0xff)]! ^
        sBox[0x201 + 2 * ((x >>> 24) & 0xff)]!,
    );
  const fe32_3 = (x: number): number =>
    u32(
      sBox[0x000 + 2 * ((x >>> 24) & 0xff)]! ^
        sBox[0x001 + 2 * (x & 0xff)]! ^
        sBox[0x200 + 2 * ((x >>> 8) & 0xff)]! ^
        sBox[0x201 + 2 * ((x >>> 16) & 0xff)]!,
    );

  const store = (words: readonly number[], dst: Uint8Array): void => {
    for (let i = 0; i < 4; i++) {
      dst[4 * i] = words[i]! & 0xff;
      dst[4 * i + 1] = (words[i]! >>> 8) & 0xff;
      dst[4 * i + 2] = (words[i]! >>> 16) & 0xff;
      dst[4 * i + 3] = (words[i]! >>> 24) & 0xff;
    }
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      let x0 = u32(loadLe(src, 0) ^ subKeys[0]!);
      let x1 = u32(loadLe(src, 4) ^ subKeys[1]!);
      let x2 = u32(loadLe(src, 8) ^ subKeys[2]!);
      let x3 = u32(loadLe(src, 12) ^ subKeys[3]!);

      let k = 8;
      for (let round = 0; round < ROUNDS; round += 2) {
        let t0 = fe32_0(x0);
        let t1 = fe32_3(x1);
        x2 = ror(u32(x2 ^ u32(t0 + t1 + subKeys[k++]!)), 1);
        x3 = u32(rol(x3, 1) ^ u32(t0 + 2 * t1 + subKeys[k++]!));

        t0 = fe32_0(x2);
        t1 = fe32_3(x3);
        x0 = ror(u32(x0 ^ u32(t0 + t1 + subKeys[k++]!)), 1);
        x1 = u32(rol(x1, 1) ^ u32(t0 + 2 * t1 + subKeys[k++]!));
      }

      // The halves are exchanged once at the end, which is why the output order is x2, x3, x0, x1.
      store(
        [u32(x2 ^ subKeys[4]!), u32(x3 ^ subKeys[5]!), u32(x0 ^ subKeys[6]!), u32(x1 ^ subKeys[7]!)],
        dst,
      );
    },
    decryptBlock: (src, dst) => {
      let x2 = u32(loadLe(src, 0) ^ subKeys[4]!);
      let x3 = u32(loadLe(src, 4) ^ subKeys[5]!);
      let x0 = u32(loadLe(src, 8) ^ subKeys[6]!);
      let x1 = u32(loadLe(src, 12) ^ subKeys[7]!);

      let k = 8 + 2 * ROUNDS - 1;
      for (let round = 0; round < ROUNDS; round += 2) {
        let t0 = fe32_0(x2);
        let t1 = fe32_3(x3);
        x1 = u32(x1 ^ u32(t0 + 2 * t1 + subKeys[k--]!));
        x0 = u32(rol(x0, 1) ^ u32(t0 + t1 + subKeys[k--]!));
        x1 = ror(x1, 1);

        t0 = fe32_0(x0);
        t1 = fe32_3(x1);
        x3 = u32(x3 ^ u32(t0 + 2 * t1 + subKeys[k--]!));
        x2 = u32(rol(x2, 1) ^ u32(t0 + t1 + subKeys[k--]!));
        x3 = ror(x3, 1);
      }

      store(
        [u32(x0 ^ subKeys[0]!), u32(x1 ^ subKeys[1]!), u32(x2 ^ subKeys[2]!), u32(x3 ^ subKeys[3]!)],
        dst,
      );
    },
  };
}
