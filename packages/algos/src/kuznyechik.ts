/**
 * Kuznyechik, the 128-bit half of GOST R 34.12-2015, specified in English by RFC 7801.
 *
 * Russia's AES: mandated for government use, standardised alongside `magma.ts` in the same document,
 * and named after the grasshopper in a Soviet children's song. It replaced GOST 28147-89 because a
 * 64-bit block was no longer defensible, and its structure is an SP-network like Rijndael's rather
 * than the Feistel network Magma kept.
 *
 * Four things to know.
 *
 * **`Pi` is a stored table and its inverse is derived.** The 256-byte substitution was parsed out of
 * RFC 7801's own decimal listing; `Pi^-1` is computed by inversion at load with a permutation check,
 * rather than storing the RFC's second table -- there is nothing to be gained from two chances to
 * mistype the same information. Note the S-box has no published design rationale, which is the
 * standing criticism of the cipher; a decomposition was found in 2016 suggesting it was not random.
 *
 * **The linear layer is 16 applications of a one-byte LFSR step, not a matrix.** `R` computes one
 * byte as a GF(2^8) linear combination of all sixteen, shifts the rest along, and `L` is `R` sixteen
 * times over. The field is GF(2)[x]/(x^8 + x^7 + x^6 + x + 1), which is **not** AES's polynomial --
 * `0xc3`, not `0x1b`.
 *
 * **Byte order runs the other way from the array.** RFC 7801 writes a block as `a_15 || ... || a_0`,
 * so `a_15` is the *first* byte and the coefficient list below reads from the front of the array.
 * Reversing it gives a cipher that inverts perfectly and reproduces nothing.
 *
 * **The key schedule is eight Feistel rounds per subkey pair.** Constants `C_1..C_32` are `L` applied
 * to the numbers 1 to 32, and each group of eight Feistel steps produces the next two round keys.
 *
 * Ten rounds, nine of them `LSX` and the last a bare key XOR. There is no oracle -- OpenSSL's GOST
 * support lives in an engine that is not built here -- so RFC 7801's test vector is the check, and it
 * is a strong one: a wrong table, a wrong polynomial or a reversed byte order all fail it.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;
const KEY_LEN = 32;
/** x^8 + x^7 + x^6 + x + 1, the field GOST R 34.12-2015 uses. Not AES's 0x1b. */
const POLY = 0xc3;

/** RFC 7801's `Pi`, parsed from the RFC's decimal listing. */
const PI: readonly number[] = [
  252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197,
  4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187,
  20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28,
  60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160,
  6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200,
  72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86,
  8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161,
  150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
  50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189,
  13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246,
  124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232,
  40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68,
  26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94,
  85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64,
  134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27,
  131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
  32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229,
  108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,
  57, 75, 99, 182,
];

const PI_INV: readonly number[] = (() => {
  const inverse = new Array<number>(256).fill(-1);
  for (let i = 0; i < 256; i++) inverse[PI[i]!] = i;
  if (inverse.some((v) => v < 0)) throw new Error("Kuznyechik's Pi is not a permutation.");
  return inverse;
})();

/**
 * The coefficients of the linear functional `l`, in array order -- so the first multiplies `a_15`.
 *
 * RFC 7801 has a typo here worth knowing about: it writes `148*delta(a_15) + 32*delta(a_15)`, naming
 * a_15 twice where the second is a_14. The sequence is palindromic apart from its ends, which is what
 * makes the intended reading unambiguous, and the test vector is what confirms it.
 */
const COEFFICIENTS = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1] as const;

/** Multiplication in GF(2^8) under `POLY`. */
function gmul(a: number, b: number): number {
  let left = a;
  let right = b;
  let product = 0;
  for (let i = 0; i < 8; i++) {
    if (right & 1) product ^= left;
    const overflow = left & 0x80;
    left = (left << 1) & 0xff;
    if (overflow) left ^= POLY;
    right >>= 1;
  }
  return product;
}

/**
 * The linear layer, precomputed as sixteen 256-entry tables.
 *
 * `L` is `R` applied sixteen times, and `R` is linear, so `L` is too -- which means it can be
 * expressed as the XOR of one table lookup per input byte. Built at load from `COEFFICIENTS`, which
 * keeps the derivation visible instead of shipping 4 KB of precomputed matrix.
 */
function buildLinearTables(): { forward: Uint8Array[]; inverse: Uint8Array[] } {
  const step = (input: Uint8Array): Uint8Array => {
    let acc = 0;
    for (let i = 0; i < BLOCK; i++) acc ^= gmul(input[i]!, COEFFICIENTS[i]!);
    const next = new Uint8Array(BLOCK);
    next[0] = acc;
    next.set(input.subarray(0, BLOCK - 1), 1);
    return next;
  };
  const stepInverse = (input: Uint8Array): Uint8Array => {
    const shifted = new Uint8Array(BLOCK);
    shifted.set(input.subarray(1), 0);
    let acc = 0;
    for (let i = 0; i < BLOCK - 1; i++) acc ^= gmul(shifted[i]!, COEFFICIENTS[i]!);
    // The byte that was shifted out is recovered from the functional's own output.
    shifted[BLOCK - 1] = gmul(acc ^ input[0]!, 1);
    return shifted;
  };

  const forward: Uint8Array[] = [];
  const inverse: Uint8Array[] = [];
  for (let position = 0; position < BLOCK; position++) {
    const f = new Uint8Array(256 * BLOCK);
    const g = new Uint8Array(256 * BLOCK);
    for (let value = 0; value < 256; value++) {
      const unit = new Uint8Array(BLOCK);
      unit[position] = value;
      let a: Uint8Array = unit;
      const b: Uint8Array = new Uint8Array(BLOCK);
      b.set(unit);
      let inverse = b;
      for (let i = 0; i < BLOCK; i++) {
        a = step(a);
        inverse = stepInverse(inverse);
      }
      f.set(a, value * BLOCK);
      g.set(inverse, value * BLOCK);
    }
    forward.push(f);
    inverse.push(g);
  }
  return { forward, inverse };
}

const { forward: L_TABLES, inverse: L_INV_TABLES } = buildLinearTables();

function applyTables(tables: readonly Uint8Array[], input: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  for (let position = 0; position < BLOCK; position++) {
    const table = tables[position]!;
    const at = input[position]! * BLOCK;
    for (let i = 0; i < BLOCK; i++) out[i] = out[i]! ^ table[at + i]!;
  }
  return out;
}

function substitute(input: Uint8Array, table: readonly number[]): Uint8Array {
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) out[i] = table[input[i]!]!;
  return out;
}

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/** The ten round keys: the master key is the first two, and eight Feistel steps make each next pair. */
function schedule(key: Uint8Array): Uint8Array[] {
  if (key.length !== KEY_LEN) {
    throw new Error(`Kuznyechik's key is 32 bytes; this one is ${key.length}.`);
  }
  let k1: Uint8Array = new Uint8Array(BLOCK);
  let k2: Uint8Array = new Uint8Array(BLOCK);
  k1.set(key.subarray(0, BLOCK));
  k2.set(key.subarray(BLOCK));
  const keys: Uint8Array[] = [k1, k2];

  for (let i = 1; i <= 32; i++) {
    const counter = new Uint8Array(BLOCK);
    // The constants are L applied to the numbers 1..32, written into the *last* byte -- a_0.
    counter[BLOCK - 1] = i;
    const c = applyTables(L_TABLES, counter);
    const next = xorBlocks(applyTables(L_TABLES, substitute(xorBlocks(k1, c), PI)), k2);
    k2 = k1;
    k1 = next;
    if (i % 8 === 0) keys.push(k1, k2);
  }
  return keys;
}

/** Kuznyechik as a `BlockCipher`. */
export function createKuznyechik(key: Uint8Array): BlockCipher {
  const rk = schedule(key);

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      let a: Uint8Array = new Uint8Array(BLOCK);
      a.set(src);
      for (let round = 0; round < 9; round++) {
        a = applyTables(L_TABLES, substitute(xorBlocks(a, rk[round]!), PI));
      }
      dst.set(xorBlocks(a, rk[9]!));
    },
    decryptBlock: (src, dst) => {
      const start = new Uint8Array(BLOCK);
      start.set(src);
      let a: Uint8Array = xorBlocks(start, rk[9]!);
      for (let round = 8; round >= 0; round--) {
        a = xorBlocks(substitute(applyTables(L_INV_TABLES, a), PI_INV), rk[round]!);
      }
      dst.set(a);
    },
  };
}
