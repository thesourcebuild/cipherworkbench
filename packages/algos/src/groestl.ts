/**
 * Groestl, a SHA-3 finalist, at all four output lengths.
 *
 * One of the five that reached the final round, alongside BLAKE, JH, Keccak and Skein -- all of which
 * this repo already had. It is the one built out of AES: the S-box is Rijndael's, so `aes-round.ts`'s
 * derived table serves it and nothing new is stored. Still used: several cryptocurrencies hash with
 * Groestl, and it is the reference "wide-pipe AES-like" design.
 *
 * Five things to know.
 *
 * **Two permutations per block, not one.** The compression is `f(h, m) = P(h XOR m) XOR Q(m) XOR h`.
 * P and Q are the same construction with different shift amounts and different round constants, which
 * is why they share one function here with a flag rather than being written twice.
 *
 * **The state is a byte matrix in column-major order.** Byte `i` of a block is row `i mod 8`, column
 * `i div 8`. Reading it row-major gives a hash that is self-consistent and matches nothing.
 *
 * **Q's round constant replaces 0xff on the last row; it does not add to it.** Every byte takes 0xff
 * *except* row 7, which takes `(col * 0x10) XOR 0xff XOR round` instead. XORing both -- which is the
 * obvious misreading of "all bytes are 0xff except the last row" -- was the actual first-attempt bug
 * here, and it fails every published vector while leaving the construction perfectly self-consistent.
 *
 * **MixBytes is a circulant matrix over GF(2^8), with AES's polynomial.** `circ(2, 2, 3, 4, 5, 3, 5, 7)`
 * applied to each column. Note it is AES's field (0x11b) but not AES's matrix.
 *
 * **The short and long variants differ in more than output length.** Groestl-224 and -256 use a
 * 512-bit state, 64-byte blocks, 10 rounds and one set of shifts; -384 and -512 use 1024 bits,
 * 128-byte blocks, 14 rounds and another. The row-7 shift is the tell: 7 in the short variant, 11 in
 * the long one.
 *
 * Checked against 72 known-answer vectors -- four output lengths at eighteen message lengths -- taken
 * from sphlib's test data, which carries the NIST SHA-3 competition KATs. See
 * `tests/algos-sha3-candidates.test.ts`.
 */
import { AES_SBOX } from "./aes-round";

/** The circulant row of MixBytes. */
const MIX_ROW = [2, 2, 3, 4, 5, 3, 5, 7] as const;

/** Multiplication in GF(2^8) under AES's polynomial. Only eight small constants ever appear. */
function gmul(a: number, b: number): number {
  let left = a;
  let right = b;
  let product = 0;
  for (let i = 0; i < 8; i++) {
    if (right & 1) product ^= left;
    const overflow = left & 0x80;
    left = (left << 1) & 0xff;
    if (overflow) left ^= 0x1b;
    right >>= 1;
  }
  return product & 0xff;
}

/** Precomputed products, since MixBytes multiplies by the same eight constants for every byte. */
const MUL: readonly Uint8Array[] = MIX_ROW.map((coefficient) => {
  const table = new Uint8Array(256);
  for (let value = 0; value < 256; value++) table[value] = gmul(value, coefficient);
  return table;
});

const SHIFTS = {
  short: { p: [0, 1, 2, 3, 4, 5, 6, 7], q: [1, 3, 5, 7, 0, 2, 4, 6] },
  long: { p: [0, 1, 2, 3, 4, 5, 6, 11], q: [1, 3, 5, 11, 0, 2, 4, 6] },
} as const;

/** P or Q, in place. `cols` is 8 for the short variant and 16 for the long one. */
function permute(state: Uint8Array, cols: 8 | 16, rounds: number, isQ: boolean): void {
  const shifts = cols === 8 ? SHIFTS.short : SHIFTS.long;
  const rows = isQ ? shifts.q : shifts.p;
  const shifted = new Uint8Array(state.length);

  for (let round = 0; round < rounds; round++) {
    // AddRoundConstant.
    if (isQ) {
      for (let col = 0; col < cols; col++) {
        for (let row = 0; row < 7; row++) {
          state[col * 8 + row] = state[col * 8 + row]! ^ 0xff;
        }
        const at = col * 8 + 7;
        state[at] = (state[at]! ^ ((col * 0x10) ^ 0xff ^ round)) & 0xff;
      }
    } else {
      for (let col = 0; col < cols; col++) {
        state[col * 8] = (state[col * 8]! ^ ((col * 0x10) ^ round)) & 0xff;
      }
    }

    // SubBytes and ShiftBytes together: row `r` is read from `shifts[r]` columns along.
    for (let col = 0; col < cols; col++) {
      for (let row = 0; row < 8; row++) {
        shifted[col * 8 + row] = AES_SBOX[state[(((col + rows[row]!) % cols) * 8 + row)]!]!;
      }
    }

    // MixBytes: every column times the circulant matrix.
    for (let col = 0; col < cols; col++) {
      const base = col * 8;
      for (let row = 0; row < 8; row++) {
        let acc = 0;
        for (let k = 0; k < 8; k++) acc ^= MUL[k]![shifted[base + ((row + k) % 8)]!]!;
        state[base + row] = acc;
      }
    }
  }
}

/** A Groestl digest of any of the four standardised lengths. */
export function groestl(outputLen: 28 | 32 | 48 | 64, message: Uint8Array): Uint8Array {
  const short = outputLen <= 32;
  const cols: 8 | 16 = short ? 8 : 16;
  const rounds = short ? 10 : 14;
  const blockLen = cols * 8;

  // The chaining value starts as the output length in bits, big-endian, in the last two bytes.
  const h = new Uint8Array(blockLen);
  const bits = outputLen * 8;
  h[blockLen - 2] = (bits >>> 8) & 0xff;
  h[blockLen - 1] = bits & 0xff;

  const scratchP = new Uint8Array(blockLen);
  const scratchQ = new Uint8Array(blockLen);
  const compress = (block: Uint8Array): void => {
    for (let i = 0; i < blockLen; i++) {
      scratchP[i] = h[i]! ^ block[i]!;
      scratchQ[i] = block[i]!;
    }
    permute(scratchP, cols, rounds, false);
    permute(scratchQ, cols, rounds, true);
    for (let i = 0; i < blockLen; i++) h[i] = h[i]! ^ scratchP[i]! ^ scratchQ[i]!;
  };

  /**
   * Padding: `0x80`, zeros, then the *block count* -- not the message length -- as a 64-bit
   * big-endian value in the last eight bytes, counting the padding block itself.
   */
  const blocks: Uint8Array[] = [];
  let at = 0;
  for (; at + blockLen <= message.length; at += blockLen) {
    blocks.push(message.subarray(at, at + blockLen));
  }
  const rest = message.length - at;
  const tail = new Uint8Array(blockLen);
  tail.set(message.subarray(at));
  tail[rest] = 0x80;
  blocks.push(tail);
  // The count needs eight bytes of room; if the 0x80 left too little, it goes in a further block.
  if (rest + 1 > blockLen - 8) blocks.push(new Uint8Array(blockLen));

  const last = blocks[blocks.length - 1]!;
  const count = BigInt(blocks.length);
  for (let i = 0; i < 8; i++) last[blockLen - 1 - i] = Number((count >> BigInt(8 * i)) & 0xffn);

  for (const block of blocks) compress(block);

  // The output transform, omega: truncate P(h) XOR h to the digest length.
  const finalP = new Uint8Array(blockLen);
  finalP.set(h);
  permute(finalP, cols, rounds, false);
  const out = new Uint8Array(outputLen);
  for (let i = 0; i < outputLen; i++) {
    out[i] = h[blockLen - outputLen + i]! ^ finalP[blockLen - outputLen + i]!;
  }
  return out;
}

/** An incremental Groestl, for the streaming interface the hash family expects. */
export function createGroestl(outputLen: 28 | 32 | 48 | 64): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
  /**
   * Buffered rather than truly incremental, and deliberately.
   *
   * Groestl's padding carries the total block count, so nothing can be finalised before the whole
   * message is seen -- but the compression itself could run per block. Buffering keeps this file
   * short and the arithmetic in one place; the hash family's manifest reports `streaming: false`
   * accordingly rather than claiming a progress bar it cannot honour.
   */
  const chunks: Uint8Array[] = [];
  let length = 0;
  return {
    update: (chunk) => {
      chunks.push(chunk);
      length += chunk.length;
    },
    digest: () => {
      const all = new Uint8Array(length);
      let at = 0;
      for (const chunk of chunks) {
        all.set(chunk, at);
        at += chunk.length;
      }
      return groestl(outputLen, all);
    },
  };
}
