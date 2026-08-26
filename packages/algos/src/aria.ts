/**
 * ARIA, RFC 5794. The South Korean national block cipher: 128-bit block, 128/192/256-bit keys.
 *
 * The counterpart to the SM4 in this repo -- a national standard, mandated rather than chosen, and
 * present in OpenSSL (`aria-256-gcm` and friends) and in TLS via RFC 6209. No pure-ESM library offers
 * it, which is why it is here.
 *
 * Structurally it is an involutional SPN rather than a Feistel network, and that single fact explains
 * most of the code. There is no inverse round function: the diffusion layer A is its own inverse, and
 * the substitution layers SL1 and SL2 are each other's, so decryption is the *same* routine driven by
 * a different set of round keys. Which is also the trap -- get the key schedule wrong and encryption
 * and decryption still agree with each other perfectly.
 *
 * Three things to know before touching this.
 *
 * **The tables and the diffusion layer were parsed out of the RFC.** SB1, SB2 and all sixteen
 * equations of A came from RFC 5794's text via a script, for the reason given at the top of
 * `camellia.ts`. Only two of the four S-boxes are stored: the RFC states SB3 and SB4 are the inverses
 * of SB1 and SB2, and `invert` computes them at load, checking the claim as it goes.
 *
 * **SB1 is AES's S-box**, which is why it is imported from `aes-round.ts` rather than stored here --
 * AEGIS needs the same table for its AES round function, and no library this project uses exports one.
 *
 * **The key schedule is checked directly, not only through the ciphertext.** RFC 5794's appendix A.1
 * prints W0..W3 and all thirteen round keys for the 128-bit case, and
 * `tests/algos-camellia-aria.test.ts` asserts those exact values. A rotation constant off by one
 * would otherwise show up only as a wrong ciphertext, with nothing to say which half was at fault.
 */
import { AES_SBOX } from "./aes-round";
import type { BlockCipher } from "./blockmodes";

export const ARIA_BLOCK_SIZE = 16;

/**
 * SB1 is AES's S-box, so it lives in `aes-round.ts` and is imported.
 *
 * RFC 5794 prints it as ARIA's own table; it is byte-for-byte FIPS 197's, which the RFC says outright.
 * One copy rather than two means there is nothing to drift, and it is now checked by two independent
 * published vector sets -- ARIA's three appendix vectors here, and the AESRound vector in the AEGIS
 * draft's appendix A.1.
 */
const SB1 = AES_SBOX;

const SB2 = new Uint8Array([
  0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
  0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
  0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
  0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
  0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
  0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
  0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
  0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
  0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
  0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
  0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
  0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
  0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
  0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
  0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
  0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
]);

/**
 * The inverse of a byte permutation, with the permutation property checked rather than assumed.
 *
 * The RFC says SB3 and SB4 *are* the inverses of SB1 and SB2; this computes them on that basis. If a
 * stored table were ever mistyped into a non-permutation, the check below is what says so, instead of
 * a silently lossy inverse producing a cipher that decrypts to the wrong plaintext.
 */
function invert(table: Uint8Array): Uint8Array {
  const out = new Uint8Array(256);
  for (let x = 0; x < 256; x++) out[table[x]!] = x;
  for (let x = 0; x < 256; x++) {
    if (table[out[x]!] !== x) throw new Error("ARIA S-box table is not a permutation");
  }
  return out;
}

const SB3 = invert(SB1);
const SB4 = invert(SB2);

/** SL1 uses SB1..SB4 in order; SL2 starts two along, which is what makes them inverses. */
const SL1_ORDER: readonly Uint8Array[] = [SB1, SB2, SB3, SB4];
const SL2_ORDER: readonly Uint8Array[] = [SB3, SB4, SB1, SB2];

const A_TERMS: readonly (readonly number[])[] = [
  [3, 4, 6, 8, 9, 13, 14],
  [2, 5, 7, 8, 9, 12, 15],
  [1, 4, 6, 10, 11, 12, 15],
  [0, 5, 7, 10, 11, 13, 14],
  [0, 2, 5, 8, 11, 14, 15],
  [1, 3, 4, 9, 10, 14, 15],
  [0, 2, 7, 9, 10, 12, 13],
  [1, 3, 6, 8, 11, 12, 13],
  [0, 1, 4, 7, 10, 13, 15],
  [0, 1, 5, 6, 11, 12, 14],
  [2, 3, 5, 6, 8, 13, 15],
  [2, 3, 4, 7, 9, 12, 14],
  [1, 2, 6, 7, 9, 11, 12],
  [0, 3, 6, 7, 8, 10, 13],
  [0, 3, 4, 5, 9, 11, 14],
  [1, 2, 4, 5, 8, 10, 15],
];

/** The diffusion layer A. An involution, which is why decryption reuses the encryption routine. */
function diffuse(x: Uint8Array, out: Uint8Array): void {
  for (let i = 0; i < 16; i++) {
    const terms = A_TERMS[i]!;
    let v = 0;
    for (const t of terms) v ^= x[t]!;
    out[i] = v;
  }
}

/**
 * One full round: A(SL(D ^ RK)). FO passes SL1 and FE passes SL2.
 *
 * `out` must not alias `d`: the diffusion layer reads every byte of its input to produce each byte of
 * its output, so writing in place would mix half-updated values.
 */
function feistelRound(
  d: Uint8Array,
  rk: Uint8Array,
  order: readonly Uint8Array[],
  out: Uint8Array,
  scratch: Uint8Array,
): void {
  for (let i = 0; i < 16; i++) scratch[i] = order[i & 3]![d[i]! ^ rk[i]!]!;
  diffuse(scratch, out);
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * C1, C2 and C3, the key-schedule constants. RFC 5794: the first 384 bits of the fractional part of
 * 1/pi, which is a nothing-up-my-sleeve construction and not a value to be clever about.
 */
const CONSTANTS: readonly Uint8Array[] = [
  fromHex("517cc1b727220a94fe13abe8fa9a6ee0"),
  fromHex("6db14acc9e21c820ff28b1d5ef5de2b0"),
  fromHex("db92371d2126e9700324977504e8c90e"),
];

/** Which constant plays CK1, CK2 and CK3 -- the assignment rotates with the key size. */
const CK_ORDER: Record<number, readonly [number, number, number]> = {
  16: [0, 1, 2],
  24: [1, 2, 0],
  32: [2, 0, 1],
};

function xor128(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/** Rotates a 128-bit value right by `n` bits. A negative `n` rotates left. */
function rotr128(x: Uint8Array, n: number): Uint8Array {
  const shift = ((n % 128) + 128) % 128;
  const out = new Uint8Array(16);
  const bytes = shift >>> 3;
  const bits = shift & 7;
  for (let i = 0; i < 16; i++) {
    const hi = x[(i - bytes + 32) & 15]!;
    if (bits === 0) {
      out[i] = hi;
    } else {
      const lo = x[(i - bytes - 1 + 32) & 15]!;
      out[i] = ((lo << (8 - bits)) | (hi >>> bits)) & 0xff;
    }
  }
  return out;
}

/**
 * The 17 encryption round keys, RFC 5794 section 2.2.
 *
 * Written as the pattern the RFC's listing follows rather than as seventeen transcribed lines: four
 * groups of four, each group combining W(j) with a rotation of W(j+1) except the fourth, which
 * rotates W0 and leaves W3 alone -- then a seventeenth key reusing the first rotation. The rotations
 * per group are >>>19, >>>31, <<<61, <<<31. The test pins all thirteen 128-bit keys against the
 * RFC's own printed values, which is what makes deriving them safe.
 */
const GROUP_ROTATIONS: readonly number[] = [19, 31, -61, -31];

function roundKeys(key: Uint8Array): Uint8Array[] {
  const order = CK_ORDER[key.length];
  if (!order) throw new Error(`ARIA takes a 16, 24 or 32-byte key; this one is ${key.length}.`);

  const kl = new Uint8Array(16);
  kl.set(key.subarray(0, 16));
  // KR is the rest of the key, right-padded with zeros -- so all zeros for a 128-bit key.
  const kr = new Uint8Array(16);
  kr.set(key.subarray(16));

  const scratch = new Uint8Array(16);
  const round = (d: Uint8Array, rk: Uint8Array, odd: boolean): Uint8Array => {
    const out = new Uint8Array(16);
    feistelRound(d, rk, odd ? SL1_ORDER : SL2_ORDER, out, scratch);
    return out;
  };

  const w0 = kl;
  const w1 = xor128(round(w0, CONSTANTS[order[0]]!, true), kr);
  const w2 = xor128(round(w1, CONSTANTS[order[1]]!, false), w0);
  const w3 = xor128(round(w2, CONSTANTS[order[2]]!, true), w1);
  const w = [w0, w1, w2, w3];

  const ek: Uint8Array[] = [];
  for (const rot of GROUP_ROTATIONS) {
    for (let j = 0; j < 4; j++) {
      ek.push(
        j < 3
          ? xor128(w[j]!, rotr128(w[j + 1]!, rot))
          : xor128(rotr128(w[0]!, rot), w[3]!),
      );
    }
  }
  ek.push(xor128(w[0]!, rotr128(w[1]!, -19)));
  return ek;
}

/** 12, 14 or 16 rounds, and one more round key than rounds. */
const ROUNDS: Record<number, number> = { 16: 12, 24: 14, 32: 16 };

/**
 * The decryption round keys, section 2.2.
 *
 * dk1 is the last encryption key, dk(n+1) the first, and everything between is the corresponding
 * encryption key run through the diffusion layer. Because A is an involution this is genuinely all
 * that decryption needs -- there is no inverse round function anywhere in this file.
 */
function decryptionKeys(ek: readonly Uint8Array[], rounds: number): Uint8Array[] {
  const dk: Uint8Array[] = [ek[rounds]!];
  for (let i = 2; i <= rounds; i++) {
    const out = new Uint8Array(16);
    diffuse(ek[rounds + 1 - i]!, out);
    dk.push(out);
  }
  dk.push(ek[0]!);
  return dk;
}

function crypt(src: Uint8Array, rk: readonly Uint8Array[], rounds: number, dst: Uint8Array): void {
  let current = new Uint8Array(16);
  let next = new Uint8Array(16);
  const scratch = new Uint8Array(16);
  current.set(src.subarray(0, 16));

  // Rounds 1 to n-1 alternate odd (SL1) and even (SL2).
  for (let r = 1; r <= rounds - 1; r++) {
    feistelRound(current, rk[r - 1]!, r % 2 === 1 ? SL1_ORDER : SL2_ORDER, next, scratch);
    const swap = current;
    current = next;
    next = swap;
  }

  // The last round has no diffusion layer and an extra key addition: SL2(P ^ ek(n)) ^ ek(n+1).
  const last = rk[rounds - 1]!;
  const final = rk[rounds]!;
  for (let i = 0; i < 16; i++) {
    dst[i] = SL2_ORDER[i & 3]![current[i]! ^ last[i]!]! ^ final[i]!;
  }
}

export const ARIA_KEY_SIZES: readonly number[] = [16, 24, 32];

export function createAria(key: Uint8Array): BlockCipher {
  const rounds = ROUNDS[key.length];
  if (rounds === undefined) {
    throw new Error(`ARIA takes a 16, 24 or 32-byte key; this one is ${key.length}.`);
  }
  const ek = roundKeys(key);
  const dk = decryptionKeys(ek, rounds);
  return {
    blockSize: ARIA_BLOCK_SIZE,
    encryptBlock: (src, dst) => crypt(src, ek, rounds, dst),
    decryptBlock: (src, dst) => crypt(src, dk, rounds, dst),
  };
}

/**
 * The key schedule's intermediate values, for the test that pins them against RFC 5794 appendix A.1.
 *
 * Exported deliberately rather than reached into: a wrong rotation constant is invisible in the
 * ciphertext alone -- it says the answer is wrong without saying which half is wrong -- and the RFC
 * prints exactly these numbers.
 */
export function ariaKeySchedule(key: Uint8Array): Uint8Array[] {
  return roundKeys(key);
}
