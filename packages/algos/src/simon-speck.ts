/**
 * Simon and Speck, all ten members of each family, from the NSA's 2013 paper.
 *
 * Published together and designed as a pair: Speck is optimised for software and Simon for hardware,
 * and the two are deliberately different constructions rather than variants of one. Both are in
 * ISO/IEC 29167-21 and -22, and Speck shipped in the Linux kernel's `fscrypt` for a while.
 *
 * They are also the only two ciphers in this repo with **no tables at all** -- pure arithmetic, so
 * nothing here could be mistyped. That does not make them safe from error; it moves the risk to word
 * order and to the parameter table, which is what the twenty published vectors pin down.
 *
 * Six things to know.
 *
 * **Speck is ARX: add, rotate, XOR.** One round is `x = ROR(x, alpha) + y XOR k; y = ROL(y, beta) XOR x`.
 * The addition supplies the non-linearity, which is fast in software and awkward in hardware.
 *
 * **Simon is a Feistel network whose round function is bitwise AND.** `f(x) = (ROL(x,1) & ROL(x,8)) ^
 * ROL(x,2)`. No addition anywhere, so no carry chain: the opposite trade.
 *
 * **Every variant is a different function, not a truncation.** The word size sets the block, the key
 * word count sets the key, and both together decide the round count -- and for Simon, which of five
 * constant sequences the key schedule draws on. `SIMON_PARAMS` and `SPECK_ROUNDS` below are the
 * paper's own tables, and a wrong entry gives a cipher that inverts perfectly and matches nothing.
 *
 * **The rotation amounts change for the smallest word size.** Speck32/64 uses `(alpha, beta) = (7, 2)`
 * where every other variant uses `(8, 3)`. One line, easy to miss, and it is the only thing that
 * distinguishes Speck32/64 from a wrong Speck32/64.
 *
 * **24- and 48-bit words are not a mistake.** Simon48 and Speck96 use word sizes that are not powers
 * of two, so rotations are modulo 24 and 48 and every value is masked to that width. `bigint` handles
 * it without special cases, which is most of the reason this file uses `bigint` at all -- the rest is
 * the same argument `xxhash3.ts` makes: these are word-oriented algorithms nobody runs over gigabytes.
 *
 * **The paper and the implementation guide print their vectors in opposite byte orders.** The paper's
 * key and plaintext are big-endian words, most significant first; the guide's `BytesToWords` reads the
 * whole byte string little-endian, so its values are the paper's reversed end to end. Both are in
 * `tests/algos-lightweight.test.ts`, which is what makes the guide's ten a second independent check
 * rather than ten puzzling failures.
 */
import type { BlockCipher } from "./blockmodes";

/** Word sizes the two families define. 24 and 48 are deliberate; see the header. */
export type SimonSpeckWordBits = 16 | 24 | 32 | 48 | 64;

/**
 * The five constant sequences Simon's key schedule draws single bits from.
 *
 * `z1`, `z2` and `z3` were parsed out of the paper's own listing; `z0` and `z4` were written from
 * elsewhere and are confirmed by the vectors -- `z0` by Simon32/64 and Simon48/72, `z4` by
 * Simon128/256, none of which reproduces without the right sequence.
 */
const Z: readonly string[] = [
  "11111010001001010110000111001101111101000100101011000011100110",
  "10001110111110010011000010110101000111011111001001100001011010",
  "10101111011100000011010010011000101000010001111110010110110011",
  "11011011101011000110010111100000010010001010011100110100001111",
  "11010001111001101011011000100000010111000011001010010011101111",
];

/** Rounds and z index per (word size, key words), from the paper's parameter table. */
const SIMON_PARAMS: Record<string, readonly [number, number]> = {
  "16/4": [32, 0],
  "24/3": [36, 0],
  "24/4": [36, 1],
  "32/3": [42, 2],
  "32/4": [44, 3],
  "48/2": [52, 2],
  "48/3": [54, 3],
  "64/2": [68, 2],
  "64/3": [69, 3],
  "64/4": [72, 4],
};

/** Rounds per (word size, key words), from the paper's parameter table. */
const SPECK_ROUNDS: Record<string, number> = {
  "16/4": 22,
  "24/3": 22,
  "24/4": 23,
  "32/3": 26,
  "32/4": 27,
  "48/2": 28,
  "48/3": 29,
  "64/2": 32,
  "64/3": 33,
  "64/4": 34,
};

const maskFor = (bits: number): bigint => (1n << BigInt(bits)) - 1n;

const rotl = (x: bigint, by: number, bits: number): bigint => {
  const shift = BigInt(by % bits);
  return ((x << shift) | (x >> (BigInt(bits) - shift))) & maskFor(bits);
};

const rotr = (x: bigint, by: number, bits: number): bigint => {
  const shift = BigInt(by % bits);
  return ((x >> shift) | (x << (BigInt(bits) - shift))) & maskFor(bits);
};

/** Big-endian words of `bits` bits each, most significant first. */
function readWords(bytes: Uint8Array, bits: number): bigint[] {
  const size = bits / 8;
  const out: bigint[] = [];
  for (let at = 0; at + size <= bytes.length; at += size) {
    let word = 0n;
    for (let i = 0; i < size; i++) word = (word << 8n) | BigInt(bytes[at + i]!);
    out.push(word);
  }
  return out;
}

function writeWords(words: readonly bigint[], bits: number, dst: Uint8Array): void {
  const size = bits / 8;
  words.forEach((word, index) => {
    for (let i = 0; i < size; i++) {
      dst[index * size + i] = Number((word >> BigInt(8 * (size - 1 - i))) & 0xffn);
    }
  });
}

/**
 * The key as `k[0..m-1]`.
 *
 * The paper prints a key as `k[m-1] || ... || k[0]`, most significant word first, so reading it
 * big-endian and reversing gives the schedule's own indexing. Reversing the wrong way is invisible
 * for a one-word key and wrong for every other, which is what the 72-, 96-, 144-, 192- and 256-bit
 * vectors are there to catch.
 */
function keyWords(key: Uint8Array, bits: number, family: string): bigint[] {
  const size = bits / 8;
  if (key.length === 0 || key.length % size !== 0) {
    throw new Error(
      `${family}${bits * 2} takes a key that is a whole number of ${size}-byte words; this one is ${key.length} bytes.`,
    );
  }
  return readWords(key, bits).reverse();
}

function requireParams<T>(table: Record<string, T>, bits: number, words: number, family: string): T {
  const found = table[`${bits}/${words}`];
  if (found === undefined) {
    const offered = Object.keys(table)
      .filter((key) => key.startsWith(`${bits}/`))
      .map((key) => `${bits * 2}/${bits * Number(key.split("/")[1])}`)
      .join(" or ");
    throw new Error(
      `${family}${bits * 2} is not defined with ${words} key words. The variants at this block size are ${offered || "none"}.`,
    );
  }
  return found;
}

// ── Speck ───────────────────────────────────────────────────────────────────

/**
 * Speck at any of its ten sizes. `wordBits` is half the block; the key length decides `m`.
 *
 * Defaults to 64-bit words so `createSpeck(key)` with a 16-byte key is Speck128/128, which is the
 * variant the tool family opened with and the one most implementations mean by "Speck".
 */
export function createSpeck(key: Uint8Array, wordBits: SimonSpeckWordBits = 64): BlockCipher {
  const words = keyWords(key, wordBits, "Speck");
  const rounds = requireParams(SPECK_ROUNDS, wordBits, words.length, "Speck");
  // (7, 2) for the 32-bit block and (8, 3) for every other, which is the whole of the difference.
  const [alpha, beta] = wordBits === 16 ? [7, 2] : [8, 3];
  const mask = maskFor(wordBits);

  const l = words.slice(1);
  let k = words[0]!;
  const rk: bigint[] = [k];
  for (let i = 0; i < rounds - 1; i++) {
    const next = ((((rotr(l[i]!, alpha, wordBits) + k) & mask) ^ BigInt(i)) & mask);
    l.push(next);
    k = rotl(k, beta, wordBits) ^ next;
    rk.push(k & mask);
  }

  const blockSize = (wordBits / 8) * 2;
  return {
    blockSize,
    encryptBlock: (src, dst) => {
      let [x, y] = readWords(src, wordBits) as [bigint, bigint];
      for (const round of rk) {
        x = (((rotr(x, alpha, wordBits) + y) & mask) ^ round) & mask;
        y = rotl(y, beta, wordBits) ^ x;
      }
      writeWords([x, y], wordBits, dst);
    },
    decryptBlock: (src, dst) => {
      let [x, y] = readWords(src, wordBits) as [bigint, bigint];
      // The round inverted: subtract where it added, and unwind the two rotations.
      for (let i = rk.length - 1; i >= 0; i--) {
        y = rotr(y ^ x, beta, wordBits);
        x = rotl(((x ^ rk[i]!) - y) & mask, alpha, wordBits);
      }
      writeWords([x, y], wordBits, dst);
    },
  };
}

// ── Simon ───────────────────────────────────────────────────────────────────

/** Simon at any of its ten sizes. Same convention as `createSpeck`. */
export function createSimon(key: Uint8Array, wordBits: SimonSpeckWordBits = 64): BlockCipher {
  const words = keyWords(key, wordBits, "Simon");
  const [rounds, zIndex] = requireParams(SIMON_PARAMS, wordBits, words.length, "Simon");
  const z = Z[zIndex]!;
  const mask = maskFor(wordBits);
  const m = words.length;

  const rk = [...words];
  for (let i = m; i < rounds; i++) {
    let tmp = rotr(rk[i - 1]!, 3, wordBits);
    // The four-word schedule folds in one more subkey before the second rotation; the others do not.
    if (m === 4) tmp ^= rk[i - 3]!;
    tmp ^= rotr(tmp, 1, wordBits);
    // `3` is `c = 2^n - 4` reduced to the two bits that differ from all-ones, plus the sequence bit.
    rk.push(((~rk[i - m]! & mask) ^ tmp ^ BigInt(z[(i - m) % 62]!) ^ 3n) & mask);
  }

  const f = (x: bigint): bigint =>
    (rotl(x, 1, wordBits) & rotl(x, 8, wordBits)) ^ rotl(x, 2, wordBits);

  const blockSize = (wordBits / 8) * 2;
  return {
    blockSize,
    encryptBlock: (src, dst) => {
      /**
       * `x` is the *upper* word and `y` the lower, which is the half of Simon a round trip cannot
       * check. Swapping them gives a permutation that inverts perfectly and reproduces no published
       * vector -- which is exactly what happened here first, and what the paper's ASCII-looking
       * plaintexts are chosen to make visible.
       */
      let [x, y] = readWords(src, wordBits) as [bigint, bigint];
      for (const round of rk) {
        const previous = x;
        x = (y ^ f(x) ^ round) & mask;
        y = previous;
      }
      writeWords([x, y], wordBits, dst);
    },
    decryptBlock: (src, dst) => {
      let [x, y] = readWords(src, wordBits) as [bigint, bigint];
      for (let i = rk.length - 1; i >= 0; i--) {
        const previous = y;
        y = (x ^ f(y) ^ rk[i]!) & mask;
        x = previous;
      }
      writeWords([x, y], wordBits, dst);
    },
  };
}

/** Every (block bits, key bits) pair the two families define, for the tool catalogue. */
export const SIMON_SPECK_VARIANTS: readonly { blockBits: number; keyBits: number }[] = Object.keys(
  SIMON_PARAMS,
).map((key) => {
  const [bits, words] = key.split("/").map(Number) as [number, number];
  return { blockBits: bits * 2, keyBits: bits * words };
});
