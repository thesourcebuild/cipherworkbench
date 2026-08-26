/**
 * Simeck, the Simon-Speck hybrid (Yang, Zhu, Suder, Aagaard and Gong, CHES 2015).
 *
 * `legacy`. There is no break of the full cipher, but the published cryptanalysis is closer to the full
 * round count than for most of its neighbours here -- differential and linear attacks reach 20 of
 * Simeck32/64's 32 rounds, and there is a related-key impossible-differential result on 22 -- so it does
 * not get `modern` on the same terms Simon and Speck do.
 *
 * The design is one line: **Simon's Feistel with Speck's key schedule shape and a cheaper round
 * function.** Simon's round function is `(x & rotl(x, 8)) ^ rotl(x, 2)`; Simeck's is
 * `(x & rotl(x, 5)) ^ rotl(x, 1)`, which needs one fewer distinct rotation amount and therefore fewer
 * wires. That is the whole contribution, and it is why the cipher is worth having beside Simon rather
 * than instead of it.
 *
 * Three things to preserve.
 *
 * **The key schedule runs the round function on itself.** The state is four words; each round emits the
 * lowest and then advances it by applying the *same* `f` to two of them under a constant. So there is no
 * separate schedule to get wrong -- and no table, because the constant is `2^n - 4` with one bit
 * replaced by the next bit of an LFSR sequence.
 *
 * **The key words load in reverse.** The first word of the key material becomes `t[3]` and the last
 * becomes `t[0]`, which is what the published vectors assume. Loading them forwards gives a cipher that
 * is entirely self-consistent and reproduces nothing.
 *
 * **The sequence is a stored bit string, not an LFSR here.** `0x9A42BB1F` for the 32-bit block and
 * `0x938BCA3083F` for the 64-bit one -- 32 and 44 bits, exactly one per round, consumed lowest bit
 * first. They *are* Simon's LFSR sequences, and a derivation would be possible; two literals of 32 and
 * 44 bits are smaller than the code that would produce them, and the vectors are what checks them.
 *
 * No oracle -- OpenSSL has never implemented Simeck. What stands behind it is twenty vectors from
 * Crypto++'s `TestVectors/simeck.txt`, ten per parameter set, the first of each being the designers'
 * own.
 */
import type { BlockCipher } from "./blockmodes";

export type SimeckVariant = "32-64" | "48-96" | "64-128";

interface SimeckParams {
  /** Word size in bits. The block is two words and the key is four. */
  readonly wordBits: 16 | 24 | 32;
  readonly rounds: number;
  /** `2^n - 4`, with its lowest two bits replaced per round by the sequence below. */
  readonly constant: number;
  /** One bit per round, consumed from the bottom. */
  readonly sequence: bigint;
}

/**
 * All three members, including the 24-bit-word middle one.
 *
 * 48/96 was absent for a while on the grounds that no vector was reachable -- Crypto++'s
 * `TestVectors/simeck.txt` carries 32 and 64 only. That was a failure to look in the obvious place:
 * the designers' paper has a "Test Vectors" section giving all three, and it was fetched and parsed by
 * script rather than transcribed. What makes the extraction trustworthy is that the *same table's*
 * Simeck32/64 row is byte-for-byte Crypto++'s, so one row of the three is independently corroborated.
 *
 * Same lesson as Tiger2's: when a vector seems unreachable, check the primary document before
 * concluding it does not exist.
 */
export const SIMECK_VARIANTS: Readonly<Record<SimeckVariant, SimeckParams>> = {
  "32-64": { wordBits: 16, rounds: 32, constant: 0xfffc, sequence: 0x9a42bb1fn },
  /**
   * 48/96 reuses 32/64's 32-bit sequence over *36* rounds, so its last four round constants shift in
   * zeros. That looks like a truncation bug and is not: it is what the designers' own reference does
   * (`bozhu/Simeck`, by one of the paper's authors), and the paper's published vector only reproduces
   * this way. 64/128 by contrast has a 44-bit sequence for its 44 rounds, an exact fit -- so the three
   * variants are not consistent with each other here, and that is the fact rather than a mistake.
   */
  "48-96": { wordBits: 24, rounds: 36, constant: 0xfffffc, sequence: 0x9a42bb1fn },
  "64-128": { wordBits: 32, rounds: 44, constant: 0xfffffffc, sequence: 0x938bca3083fn },
};

const maskFor = (wordBits: number): number =>
  wordBits === 16 ? 0xffff : wordBits === 24 ? 0xffffff : 0xffffffff;

const rotl = (x: number, n: number, wordBits: number): number =>
  (((x << n) | (x >>> (wordBits - n))) & maskFor(wordBits)) >>> 0;

function readWord(bytes: Uint8Array, index: number, wordBytes: number): number {
  let w = 0;
  for (let b = 0; b < wordBytes; b++) w = ((w << 8) | bytes[index * wordBytes + b]!) >>> 0;
  return w;
}

function writeWord(word: number, out: Uint8Array, index: number, wordBytes: number): void {
  for (let b = 0; b < wordBytes; b++) {
    out[index * wordBytes + b] = (word >>> (8 * (wordBytes - 1 - b))) & 0xff;
  }
}

/** Simeck as a `BlockCipher`. Block is two words, key four. */
export function createSimeck(key: Uint8Array, variant: SimeckVariant = "64-128"): BlockCipher {
  const params = SIMECK_VARIANTS[variant];
  if (params === undefined) throw new Error(`Unknown Simeck variant: ${String(variant)}.`);
  const { wordBits, rounds, constant, sequence } = params;
  const wordBytes = wordBits / 8;
  const keyBytes = 4 * wordBytes;
  if (key.length !== keyBytes) {
    throw new Error(
      `Simeck${variant.replace("-", "/")}'s key is exactly ${keyBytes} bytes; this one is ${key.length}.`,
    );
  }
  const mask = maskFor(wordBits);

  /** One Feistel step, and the same function the key schedule advances itself with. */
  const step = (roundKey: number, left: number, right: number): [number, number] => [
    ((left & rotl(left, 5, wordBits)) ^ rotl(left, 1, wordBits) ^ right ^ roundKey) & mask,
    left,
  ];

  // The key words load in reverse: the first becomes t[3].
  const t = [readWord(key, 3, wordBytes), readWord(key, 2, wordBytes), readWord(key, 1, wordBytes), readWord(key, 0, wordBytes)];
  const rk: number[] = [];
  let c = constant;
  let bits = sequence;
  for (let round = 0; round < rounds; round++) {
    rk.push(t[0]!);
    c = ((c & ~3 & mask) | Number(bits & 1n)) >>> 0;
    bits >>= 1n;
    const [nextLeft, nextRight] = step(c, t[1]!, t[0]!);
    // The four words rotate: what was t[1] becomes t[3].
    t[1] = nextLeft;
    t[0] = nextRight;
    const carried = t[1]!;
    t[1] = t[2]!;
    t[2] = t[3]!;
    t[3] = carried;
  }

  return {
    blockSize: 2 * wordBytes,
    encryptBlock: (src, dst) => {
      let left = readWord(src, 0, wordBytes);
      let right = readWord(src, 1, wordBytes);
      for (let round = 0; round < rounds; round++) [left, right] = step(rk[round]!, left, right);
      writeWord(left, dst, 0, wordBytes);
      writeWord(right, dst, 1, wordBytes);
    },
    decryptBlock: (src, dst) => {
      let left = readWord(src, 0, wordBytes);
      let right = readWord(src, 1, wordBytes);
      for (let round = rounds - 1; round >= 0; round--) {
        // Undo one step: the old left is the current right, and the old right falls out of `f`.
        const oldLeft = right;
        const oldRight =
          (left ^
            (oldLeft & rotl(oldLeft, 5, wordBits)) ^
            rotl(oldLeft, 1, wordBits) ^
            rk[round]!) &
          mask;
        left = oldLeft;
        right = oldRight;
      }
      writeWord(left, dst, 0, wordBytes);
      writeWord(right, dst, 1, wordBytes);
    },
  };
}
