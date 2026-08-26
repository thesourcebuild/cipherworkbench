/**
 * Magma: the 64-bit block cipher of GOST R 34.12-2015, specified in English by RFC 8891.
 *
 * The same Feistel network as GOST 28147-89 -- which `gost.ts` already uses inside the GOST R 34.11-94
 * hash -- with one parameter set fixed and the byte order pinned down. That relationship is the reason
 * this is a separate file rather than a mode of `gost.ts`: the hash needs two *interchangeable*
 * parameter sets and a compression function, while the cipher needs exactly one set and a
 * `BlockCipher`. Sharing the Feistel round between them would couple a hash's table catalogue to a
 * cipher's key schedule for the sake of eight lines.
 *
 * Four things to know.
 *
 * **One S-box set, and it is neither of the hash's two.** GOST 28147-89 left the S-boxes to the
 * application, which is why `gost.ts` carries a "test" set and CryptoPro's. GOST R 34.12-2015 closed
 * that hole by fixing `id-tc26-gost-28147-param-Z`, the eight rows below. A cipher with the wrong set
 * is perfectly self-consistent and matches nothing, so the RFC's vector is the only thing that says
 * these rows are right -- and it does, on the first block.
 *
 * **The S-boxes are numbered from the top nibble down.** RFC 8891 writes the substitution as
 * `pi_7 || pi_6 || ... || pi_0` applied to the 32-bit word most significant nibble first. Reading them
 * the other way round gives a cipher that encrypts and decrypts consistently and produces the wrong
 * bytes, which no round-trip test can see.
 *
 * **The key schedule is the simplest part and the easiest to get subtly wrong.** Eight 32-bit subkeys
 * are used in order three times, then in *reverse* order once: rounds 1-24 are `K1..K8` repeated,
 * rounds 25-32 are `K8..K1`. That final reversal is what makes decryption the same network with the
 * schedule inverted.
 *
 * **The last round does not swap.** Thirty-one full Feistel rounds, then a final application of `g`
 * with the halves left in place. Swapping on the last round too is the classic Feistel off-by-one; it
 * yields a permutation that still inverts, so again only a published vector catches it.
 *
 * A 64-bit block means two ciphertext blocks are likely to come out identical after roughly 32 GB
 * under one key -- and under CBC or CFB, a repeat leaks the relationship between the plaintext blocks
 * behind them. That is the practical limit worth knowing rather than any weakness in the cipher, and
 * it is the same problem SWEET32 exploited against 3DES in TLS. `@ocs/cipher`'s `C002` and the tool's
 * own security note carry it.
 */
import type { BlockCipher } from "./blockmodes";

/**
 * `id-tc26-gost-28147-param-Z`, the parameter set GOST R 34.12-2015 fixes, as RFC 8891 tabulates it.
 *
 * Row `i` substitutes nibble `i` counting from the least significant, which is the reverse of the
 * order the RFC prints them in -- the RFC writes the most significant first.
 */
const PI: readonly (readonly number[])[] = [
  [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
  [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
  [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
  [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
  [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
  [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
  [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
  [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

/**
 * The substitution and the 11-bit rotation, precomputed per byte pair.
 *
 * Four 8-bit tables rather than eight 4-bit ones, each already carrying the rotation for its own
 * position -- the same trick `gost.ts` uses, and for the same reason: it turns the round function into
 * four lookups and three ORs. Built once at module load from `PI`, so the tables cannot drift from the
 * published rows.
 */
const TABLES: readonly Uint32Array[] = (() => {
  const out = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
  for (let pair = 0; pair < 4; pair++) {
    const low = PI[pair * 2]!;
    const high = PI[pair * 2 + 1]!;
    for (let byte = 0; byte < 256; byte++) {
      const substituted = (high[(byte >>> 4) & 0xf]! << 4) | low[byte & 0xf]!;
      // Each table's byte sits at bit `pair * 8`; the 11-bit left rotation is folded in here.
      const placed = substituted << (pair * 8);
      out[pair]![byte] = ((placed << 11) | (placed >>> 21)) >>> 0;
    }
  }
  return out;
})();

/** RFC 8891's `g`: add the round key mod 2^32, substitute, rotate left 11. */
function g(a: number, key: number): number {
  const sum = (a + key) >>> 0;
  return (
    (TABLES[0]![sum & 0xff]! |
      TABLES[1]![(sum >>> 8) & 0xff]! |
      TABLES[2]![(sum >>> 16) & 0xff]! |
      TABLES[3]![(sum >>> 24) & 0xff]!) >>>
    0
  );
}

/** Thirty-two round keys from a 256-bit key: `K1..K8` three times, then `K8..K1`. */
function schedule(key: Uint8Array): Uint32Array {
  if (key.length !== 32) {
    throw new Error(`Magma's key is 32 bytes; this one is ${key.length}.`);
  }
  const k = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    k[i] =
      ((key[i * 4]! << 24) | (key[i * 4 + 1]! << 16) | (key[i * 4 + 2]! << 8) | key[i * 4 + 3]!) >>>
      0;
  }

  const rk = new Uint32Array(32);
  for (let i = 0; i < 24; i++) rk[i] = k[i % 8]!;
  for (let i = 0; i < 8; i++) rk[24 + i] = k[7 - i]!;
  return rk;
}

function run(rk: Uint32Array, src: Uint8Array, dst: Uint8Array, forward: boolean): void {
  // Big-endian, most significant half first: RFC 8891's `a_1 || a_0`.
  let high = ((src[0]! << 24) | (src[1]! << 16) | (src[2]! << 8) | src[3]!) >>> 0;
  let low = ((src[4]! << 24) | (src[5]! << 16) | (src[6]! << 8) | src[7]!) >>> 0;

  for (let round = 0; round < 31; round++) {
    const key = rk[forward ? round : 31 - round]!;
    const next = (high ^ g(low, key)) >>> 0;
    high = low;
    low = next;
  }
  // The thirty-second round applies `g` and leaves the halves where they are.
  high = (high ^ g(low, rk[forward ? 31 : 0]!)) >>> 0;

  dst[0] = (high >>> 24) & 0xff;
  dst[1] = (high >>> 16) & 0xff;
  dst[2] = (high >>> 8) & 0xff;
  dst[3] = high & 0xff;
  dst[4] = (low >>> 24) & 0xff;
  dst[5] = (low >>> 16) & 0xff;
  dst[6] = (low >>> 8) & 0xff;
  dst[7] = low & 0xff;
}

/** Magma as a `BlockCipher`, for the shared mode layer. */
export function createMagma(key: Uint8Array): BlockCipher {
  const rk = schedule(key);
  return {
    blockSize: 8,
    encryptBlock: (src, dst) => run(rk, src, dst, true),
    decryptBlock: (src, dst) => run(rk, src, dst, false),
  };
}
