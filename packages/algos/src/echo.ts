/**
 * ECHO, at 224, 256, 384 and 512 bits. Second round of the SHA-3 competition.
 *
 * A wide-pipe Merkle-Damgard hash whose compression function is **AES run over a grid of AES states**.
 * The state is sixteen 128-bit words laid out as a 4x4 grid; a round applies two AES rounds to each
 * word independently, keyed by a 128-bit counter that increments per word, and then treats the grid
 * itself as an AES state -- ShiftRows over the columns of words, MixColumns over the bytes at matching
 * positions. Eight rounds at 224/256 and ten at 384/512, then a feedforward.
 *
 * Nothing here is stored. `aesRound` and `AES_SBOX` come from `aes-round.ts`, so ECHO's substitution
 * and diffusion layer is the table AES's own vectors, ARIA's three appendix vectors and SHAvite-3's
 * KATs already pin. That was worth insisting on: the first version of this derived the S-box itself
 * and got `SBOX[1] = 0x63` because the inverse needs `p[(255 - l[a]) % 255]` rather than
 * `p[255 - l[a]]`, which produced a hash that was perfectly self-consistent and matched nothing.
 *
 * Three things to preserve.
 *
 * **The chaining value is seeded with the digest length, in every word.** All sixteen grid slots start
 * as the digest size in bits as a little-endian 32-bit value with the remaining twelve bytes zero. That
 * is the only thing separating ECHO-224 from a truncated ECHO-256 -- see `truncation: false` on the
 * hash family's metadata.
 *
 * **The two block sizes differ in how much of the grid is chaining value.** 224/256 keep four words of
 * chaining value and take 192 bytes of message; 384/512 keep eight and take 128. So the small variant
 * has the *larger* block, which reads backwards and is what the wide pipe buys.
 *
 * **The final block carries the counter that was current before it.** `savedCounter` is taken after the
 * length is added and before the zeroing that a length-zero final block needs, and it is written at
 * `blockBytes - 16` while the digest size goes at `blockBytes - 18`. An implementation that wrote the
 * *running* counter there is correct for every message that needs a separate length block and wrong for
 * every one that does not.
 *
 * No oracle: OpenSSL never implemented ECHO and nothing in this tree does either. What stands behind it
 * is 72 known-answer vectors from the competition's own KAT files -- four digest sizes at eighteen
 * message lengths -- in `tests/sha3-candidate-kat.ts`.
 */

import { aesRound } from "./aes-round";

/** Multiplication by x in GF(2^8), the same field AES's MixColumns works in. */
const xtime = (a: number): number => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;

const ZERO_KEY = new Uint8Array(16);

export type EchoLength = 28 | 32 | 48 | 64;

/**
 * The grid's ShiftRows, expressed over word indices.
 *
 * Row 1 rotates by one, row 2 by two -- which is a pair of swaps -- and row 3 by three, written as a
 * reverse cycle. The words are columns of the grid, so a row is every fourth index.
 */
function shiftRows(w: Uint8Array[]): void {
  const cycle = (a: number, b: number, c: number, d: number): void => {
    const t = w[a]!;
    w[a] = w[b]!;
    w[b] = w[c]!;
    w[c] = w[d]!;
    w[d] = t;
  };
  cycle(1, 5, 9, 13);
  let t = w[2]!;
  w[2] = w[10]!;
  w[10] = t;
  t = w[6]!;
  w[6] = w[14]!;
  w[14] = t;
  cycle(15, 11, 7, 3);
}

const COLUMNS: readonly (readonly [number, number, number, number])[] = [
  [0, 1, 2, 3],
  [4, 5, 6, 7],
  [8, 9, 10, 11],
  [12, 13, 14, 15],
];

/** An incremental ECHO. */
export function createEcho(outputLen: EchoLength): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
  const small = outputLen <= 32;
  const blockBytes = small ? 192 : 128;
  const cvWords = small ? 4 : 8;
  const rounds = small ? 8 : 10;
  const digestBits = outputLen * 8;

  const cv: Uint8Array[] = [];
  for (let i = 0; i < cvWords; i++) {
    const word = new Uint8Array(16);
    word[0] = digestBits & 0xff;
    word[1] = (digestBits >>> 8) & 0xff;
    cv.push(word);
  }

  // A 128-bit counter of message bits, four little-endian 32-bit limbs.
  const counter = new Uint32Array(4);
  const addBits = (bits: number): void => {
    let carry = BigInt(bits);
    for (let i = 0; i < 4 && carry > 0n; i++) {
      const sum = BigInt(counter[i]! >>> 0) + (carry & 0xffffffffn);
      counter[i] = Number(sum & 0xffffffffn) >>> 0;
      carry = sum >> 32n;
    }
  };

  const scratch = new Uint8Array(16);
  const roundKey = new Uint8Array(16);

  const compress = (block: Uint8Array): void => {
    const w: Uint8Array[] = [];
    for (let i = 0; i < cvWords; i++) w.push(Uint8Array.from(cv[i]!));
    for (let i = 0; i < 16 - cvWords; i++) w.push(block.slice(16 * i, 16 * i + 16));

    const k = Uint32Array.from(counter);
    for (let r = 0; r < rounds; r++) {
      for (let n = 0; n < 16; n++) {
        for (let c = 0; c < 4; c++) {
          roundKey[4 * c] = k[c]! & 0xff;
          roundKey[4 * c + 1] = (k[c]! >>> 8) & 0xff;
          roundKey[4 * c + 2] = (k[c]! >>> 16) & 0xff;
          roundKey[4 * c + 3] = (k[c]! >>> 24) & 0xff;
        }
        aesRound(w[n]!, roundKey, scratch);
        aesRound(scratch, ZERO_KEY, w[n]!);
        // One increment per word, so a round advances the key by sixteen.
        if ((k[0] = (k[0]! + 1) >>> 0) === 0) {
          if ((k[1] = (k[1]! + 1) >>> 0) === 0) {
            if ((k[2] = (k[2]! + 1) >>> 0) === 0) k[3] = (k[3]! + 1) >>> 0;
          }
        }
      }

      shiftRows(w);

      // MixColumns over the grid: byte j of the four words in a column, for every j.
      for (const [ia, ib, ic, id] of COLUMNS) {
        const wa = w[ia]!;
        const wb = w[ib]!;
        const wc = w[ic]!;
        const wd = w[id]!;
        for (let j = 0; j < 16; j++) {
          const a = wa[j]!;
          const b = wb[j]!;
          const c = wc[j]!;
          const d = wd[j]!;
          const ab = a ^ b;
          const bc = b ^ c;
          const cd = c ^ d;
          const abx = xtime(ab);
          const bcx = xtime(bc);
          const cdx = xtime(cd);
          wa[j] = abx ^ bc ^ d;
          wb[j] = bcx ^ a ^ cd;
          wc[j] = cdx ^ ab ^ d;
          wd[j] = abx ^ bcx ^ cdx ^ ab ^ c;
        }
      }
    }

    // The feedforward folds the message and the permuted grid back into the chaining value. The small
    // variant has three message words and four grid words per slot; the big one, one and two.
    for (let i = 0; i < cvWords; i++) {
      const slot = cv[i]!;
      for (let j = 0; j < 16; j++) {
        if (small) {
          slot[j] =
            slot[j]! ^
            block[16 * i + j]! ^
            block[16 * (i + 4) + j]! ^
            block[16 * (i + 8) + j]! ^
            w[i]![j]! ^
            w[i + 4]![j]! ^
            w[i + 8]![j]! ^
            w[i + 12]![j]!;
        } else {
          slot[j] = slot[j]! ^ block[16 * i + j]! ^ w[i]![j]! ^ w[i + 8]![j]!;
        }
      }
    }
  };

  const buf = new Uint8Array(blockBytes);
  let ptr = 0;

  return {
    update: (chunk) => {
      let off = 0;
      while (off < chunk.length) {
        const take = Math.min(blockBytes - ptr, chunk.length - off);
        buf.set(chunk.subarray(off, off + take), ptr);
        off += take;
        ptr += take;
        if (ptr === blockBytes) {
          addBits(blockBytes * 8);
          compress(buf);
          ptr = 0;
        }
      }
    },
    digest: () => {
      const tailBits = ptr * 8;
      addBits(tailBits);
      const savedCounter = Uint32Array.from(counter);
      // An empty final block contributes no bits, so the counter driving its AES keys is zero.
      if (tailBits === 0) counter.fill(0);
      buf[ptr++] = 0x80;
      buf.fill(0, ptr);
      if (ptr > blockBytes - 18) {
        compress(buf);
        counter.fill(0);
        buf.fill(0);
      }
      buf[blockBytes - 18] = digestBits & 0xff;
      buf[blockBytes - 17] = (digestBits >>> 8) & 0xff;
      for (let c = 0; c < 4; c++) {
        for (let b = 0; b < 4; b++) {
          buf[blockBytes - 16 + 4 * c + b] = (savedCounter[c]! >>> (8 * b)) & 0xff;
        }
      }
      compress(buf);

      const out = new Uint8Array(outputLen);
      for (let i = 0; i < outputLen; i++) out[i] = cv[i >> 4]![i & 15]!;
      return out;
    },
  };
}

/** An ECHO digest of any of the four standardised lengths. */
export function echo(outputLen: EchoLength, message: Uint8Array): Uint8Array {
  const h = createEcho(outputLen);
  h.update(message);
  return h.digest();
}