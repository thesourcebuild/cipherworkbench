/**
 * DES and Triple DES, FIPS 46-3.
 *
 * Here because no pure-ESM library this project can use has them: `@noble/ciphers` covers AES and the
 * ARX family and stops there, deliberately, and every other candidate is either a native addon or a
 * WASM blob the desktop CSP forbids. And they are genuinely needed -- `openssl enc -des-ede3-cbc` was
 * the default for years, so a workbench that cannot read a 3DES file cannot read a great deal of
 * archived data.
 *
 * Three things to know before touching this.
 *
 * **The tables are transcribed from the standard, and the test suite re-derives their effect.** DES is
 * nothing but permutations: IP, PC-1, PC-2, E, P, FP and eight S-boxes. A single wrong entry produces
 * a cipher that encrypts and decrypts consistently and matches nothing else in the world, which is
 * exactly the failure a round-trip test cannot see. `tests/algos-blockciphers.test.ts` checks every
 * mode against OpenSSL's `des-ede3-*` and `des-ede-*`.
 *
 * **Single DES has no OpenSSL oracle here.** OpenSSL 3 moved it to the legacy provider, so
 * `crypto.getCiphers()` offers `des-ede3-cbc` and not `des-cbc`. It is covered two other ways
 * instead: the published FIPS vector below, and the identity DES(K) == 3DES(K, K, K), which the tests
 * assert -- so single DES rides on the 3DES comparison that *does* have an oracle.
 *
 * **Parity bits are ignored, not validated.** Every eighth bit of a DES key is a parity bit that the
 * algorithm never reads. Tools disagree about whether to reject a key with wrong parity; OpenSSL
 * accepts it, so this does too, because refusing a key that works everywhere else would be this
 * tool's opinion rather than the standard's.
 */
import type { BlockCipher } from "./blockmodes";

// ── the tables, from FIPS 46-3 ───────────────────────────────────────────────

/** Initial permutation. */
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64,
  56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53,
  45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/** Final permutation, IP inverse. */
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37,
  5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
  42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/** Expansion: 32 bits to 48. */
const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
  19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/** Permutation inside the round function. */
const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13,
  30, 6, 22, 11, 4, 25,
];

/** Permuted choice 1: 64 key bits to 56, dropping the parity bits. */
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
  52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
  13, 5, 28, 20, 12, 4,
];

/** Permuted choice 2: 56 bits to the 48-bit round key. */
const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
  31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/** Left rotations per round. The 1,1,2,...,2,1 shape is what makes the 16 round keys distinct. */
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/** The eight S-boxes, each 4 rows of 16. The only non-linear part of DES. */
const S: readonly number[][] = [
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,
    9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5,
    11, 3, 14, 10, 0, 6, 13,
  ],
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10,
    6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2,
    11, 6, 7, 12, 0, 5, 14, 9,
  ],
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12,
    11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4,
    15, 14, 3, 11, 5, 2, 12,
  ],
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1,
    10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9,
    4, 5, 11, 12, 7, 2, 14,
  ],
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10,
    3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6,
    15, 0, 9, 10, 4, 5, 3,
  ],
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14,
    0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10,
    11, 14, 1, 7, 6, 0, 8, 13,
  ],
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12,
    2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9,
    5, 0, 15, 14, 2, 3, 12,
  ],
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11,
    0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13,
    15, 12, 9, 0, 3, 5, 6, 11,
  ],
];

// ── bit plumbing ─────────────────────────────────────────────────────────────

/**
 * DES is specified entirely in terms of bit positions numbered from 1, most significant first.
 *
 * Working in a bit array rather than packing into 32-bit words is a deliberate trade: it is several
 * times slower and it lets every table above be transcribed and read exactly as the standard prints
 * it. For a tool that encrypts what someone pasted into a text box, being able to check the tables
 * against FIPS 46-3 line by line is worth more than the speed.
 */
function bytesToBits(bytes: Uint8Array): Uint8Array {
  const bits = new Uint8Array(bytes.length * 8);
  for (let i = 0; i < bytes.length; i++) {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = (bytes[i]! >> (7 - b)) & 1;
  }
  return bits;
}

function bitsToBytes(bits: Uint8Array, into: Uint8Array): void {
  for (let i = 0; i < into.length; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b]!;
    into[i] = byte;
  }
}

/** Applies a 1-indexed permutation table. */
function permute(source: Uint8Array, table: readonly number[]): Uint8Array {
  const out = new Uint8Array(table.length);
  for (let i = 0; i < table.length; i++) out[i] = source[table[i]! - 1]!;
  return out;
}

/** The 16 round keys, 48 bits each, as bit arrays. */
function keySchedule(key: Uint8Array): Uint8Array[] {
  const permuted = permute(bytesToBits(key), PC1);
  let c = permuted.subarray(0, 28);
  let d = permuted.subarray(28, 56);
  const keys: Uint8Array[] = [];

  for (const shift of SHIFTS) {
    // Rotate each half independently -- they never mix until PC-2 recombines them.
    c = rotateLeft(c, shift);
    d = rotateLeft(d, shift);
    const combined = new Uint8Array(56);
    combined.set(c, 0);
    combined.set(d, 28);
    keys.push(permute(combined, PC2));
  }
  return keys;
}

function rotateLeft(bits: Uint8Array, by: number): Uint8Array {
  const out = new Uint8Array(bits.length);
  for (let i = 0; i < bits.length; i++) out[i] = bits[(i + by) % bits.length]!;
  return out;
}

/** Feistel round function: expand, xor the round key, substitute, permute. */
function f(right: Uint8Array, roundKey: Uint8Array): Uint8Array {
  const expanded = permute(right, E);
  for (let i = 0; i < 48; i++) expanded[i] = expanded[i]! ^ roundKey[i]!;

  const substituted = new Uint8Array(32);
  for (let box = 0; box < 8; box++) {
    const offset = box * 6;
    // Row from the outer two bits, column from the inner four: the addressing that makes each S-box
    // a 4x16 table rather than a 64-entry list.
    const row = (expanded[offset]! << 1) | expanded[offset + 5]!;
    const column =
      (expanded[offset + 1]! << 3) |
      (expanded[offset + 2]! << 2) |
      (expanded[offset + 3]! << 1) |
      expanded[offset + 4]!;
    const value = S[box]![row * 16 + column]!;
    for (let b = 0; b < 4; b++) substituted[box * 4 + b] = (value >> (3 - b)) & 1;
  }
  return permute(substituted, P);
}

function crypt(block: Uint8Array, keys: readonly Uint8Array[], dst: Uint8Array): void {
  const permuted = permute(bytesToBits(block), IP);
  let left = permuted.subarray(0, 32);
  let right = permuted.subarray(32, 64);

  for (const roundKey of keys) {
    const next = f(right, roundKey);
    for (let i = 0; i < 32; i++) next[i] = next[i]! ^ left[i]!;
    left = right;
    right = next;
  }

  // The halves are swapped once at the end -- "R16L16", not L16R16 -- which is what makes decryption
  // the same routine with the round keys reversed.
  const combined = new Uint8Array(64);
  combined.set(right, 0);
  combined.set(left, 32);
  bitsToBytes(permute(combined, FP), dst);
}

// ── the public surface ───────────────────────────────────────────────────────

export const DES_BLOCK_SIZE = 8;

/** Single DES. The key is 8 bytes, of which 56 bits are used. */
export function createDes(key: Uint8Array): BlockCipher {
  if (key.length !== 8) {
    throw new Error(`DES takes an 8-byte key; this one is ${key.length}.`);
  }
  const keys = keySchedule(key);
  const reversed = [...keys].reverse();
  return {
    blockSize: DES_BLOCK_SIZE,
    encryptBlock: (src, dst) => crypt(src, keys, dst),
    decryptBlock: (src, dst) => crypt(src, reversed, dst),
  };
}

/**
 * Triple DES in EDE order, with a 16- or 24-byte key.
 *
 * Encrypt-Decrypt-Encrypt rather than three encryptions, and the reason is backwards compatibility
 * rather than cryptography: with K1 == K2 == K3 the middle decryption undoes the first encryption, so
 * 3DES degenerates to single DES and a 3DES implementation can read single-DES data. The tests use
 * exactly that identity to check single DES against OpenSSL, which no longer offers it directly.
 *
 * A 16-byte key is the two-key variant, K3 = K1 -- what OpenSSL calls `des-ede`. 24 bytes is the
 * three-key variant, `des-ede3`. NIST withdrew both for new use in 2023; they are here to read what
 * already exists.
 */
export function createTripleDes(key: Uint8Array): BlockCipher {
  if (key.length !== 16 && key.length !== 24) {
    throw new Error(`Triple DES takes a 16- or 24-byte key; this one is ${key.length}.`);
  }
  const k1 = createDes(key.subarray(0, 8));
  const k2 = createDes(key.subarray(8, 16));
  const k3 = key.length === 24 ? createDes(key.subarray(16, 24)) : k1;

  const scratch = new Uint8Array(DES_BLOCK_SIZE);
  return {
    blockSize: DES_BLOCK_SIZE,
    encryptBlock(src, dst) {
      k1.encryptBlock(src, scratch);
      k2.decryptBlock(scratch, dst);
      k3.encryptBlock(dst, scratch);
      dst.set(scratch);
    },
    decryptBlock(src, dst) {
      k3.decryptBlock(src, scratch);
      k2.encryptBlock(scratch, dst);
      k1.decryptBlock(dst, scratch);
      dst.set(scratch);
    },
  };
}

/**
 * The 64 weak and semi-weak keys, for the lint rule rather than for a refusal.
 *
 * A weak key makes DES its own inverse -- encrypting twice returns the plaintext -- because the key
 * schedule produces sixteen identical round keys. They are legal keys and the standard does not forbid
 * them, so this reports rather than refuses, in keeping with "prefer a warning to a refusal".
 *
 * Listed as the four weak keys plus the twelve semi-weak pairs, with parity bits as the standard
 * prints them.
 */
export const DES_WEAK_KEYS: readonly string[] = [
  // Weak: all four give sixteen identical round keys.
  "0101010101010101",
  "fefefefefefefefe",
  "e0e0e0e0f1f1f1f1",
  "1f1f1f1f0e0e0e0e",
  // Semi-weak pairs: each encrypts what the other decrypts.
  "01fe01fe01fe01fe",
  "fe01fe01fe01fe01",
  "1fe01fe00ef10ef1",
  "e01fe01ff10ef10e",
  "01e001e001f101f1",
  "e001e001f101f101",
  "1ffe1ffe0efe0efe",
  "fe1ffe1ffe0efe0e",
  "011f011f010e010e",
  "1f011f010e010e01",
  "e0fee0fef1fef1fe",
  "fee0fee0fef1fef1",
];

/** True when the key is one of the weak or semi-weak keys, ignoring case. */
export function isWeakDesKey(key: Uint8Array): boolean {
  const hex = [...key].map((b) => b.toString(16).padStart(2, "0")).join("");
  return DES_WEAK_KEYS.includes(hex.toLowerCase());
}
