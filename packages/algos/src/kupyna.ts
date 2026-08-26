/**
 * Kupyna -- DSTU 7564:2014, Ukraine's national hash. Built entirely on Kalyna's tables.
 *
 * The two Ukrainian standards were designed together and share their primitives: Kupyna's four S-boxes
 * and its MixColumns are **exactly** DSTU 7624's, which this repo already has for the Kalyna cipher. So
 * nothing is stored here at all -- the eight 256-entry lookup tables are derived at load by pushing each
 * S-box entry through MixColumns at its byte position, and the S-boxes themselves come from `kalyna.ts`,
 * where Kalyna's published vectors already pin them.
 *
 * That is the strongest form of the derive-don't-transcribe rule in this repo: a mistyped Kupyna table
 * would produce a hash that is self-consistent and matches nothing, and here there is no table to
 * mistype. A failure points at the mode.
 *
 * Verified against seventeen vectors from Bouncy Castle's `DSTU7564Test` -- which transcribes the
 * standard's annex -- across all three digest sizes. All passed first run.
 *
 * ## What is not Streebog, despite looking like it
 *
 * The state is columns of 64 bits and the compression is `state ^= P(state ^ m) ^ Q(m)` -- two
 * independent permutations of the same block, which is Groestl's shape rather than Streebog's. Three
 * details to keep:
 *
 * **P adds its round constant by XOR and Q by *addition*.** P's constant is `round + 16*col`; Q's is a
 * 64-bit pattern that *decreases* by `0x1000000000000000` per column. Using XOR for both, or the same
 * constant for both, leaves a hash that compresses fine and matches nothing.
 *
 * **The shift amount for the top byte is 7 columns at 512 bits and 11 at 1024**, where every other byte
 * shifts by its own index. That single asymmetry is the whole difference between the two state sizes
 * beyond the column count and the round count.
 *
 * **The length field is 96 bits little-endian**, written as a 32-bit half and then a 64-bit half, at
 * `blockSize - 12`. Twelve bytes, not eight -- so a message that ends within twelve bytes of the block
 * boundary needs an extra block, and the usual `blockSize - 8` test is wrong here.
 */

import { KALYNA_S_BOXES } from "./kalyna";
import { eagerAbsorber, type LwcHasher } from "./lwc-hash";

const MASK64 = (1n << 64n) - 1n;
const ror = (n: number, x: bigint): bigint =>
  n === 0 ? x : ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;

/** Kalyna's MixColumns, byte-sliced. Kupyna uses it verbatim -- see the header. */
function mixColumn(c: bigint): bigint {
  const x1 =
    ((((c & 0x7f7f7f7f7f7f7f7fn) << 1n) & MASK64) ^ (((c & 0x8080808080808080n) >> 7n) * 0x1dn)) & MASK64;
  let u = ror(8, c) ^ c;
  u ^= ror(16, u);
  u ^= ror(48, c);
  let v = u ^ c ^ x1;
  v =
    ((((v & 0x3f3f3f3f3f3f3f3fn) << 2n) & MASK64) ^
      (((v & 0x8080808080808080n) >> 6n) * 0x1dn) ^
      (((v & 0x4040404040404040n) >> 6n) * 0x1dn)) & MASK64;
  return (u ^ ror(32, v) ^ ror(40, x1) ^ ror(48, x1)) & MASK64;
}

/**
 * Eight tables of 256 columns each, derived at load. Nothing here is transcribed.
 *
 * Table k places S-box `k mod 4`'s output at byte position k and pushes the result through MixColumns,
 * so one XOR per byte replaces a substitute-shift-mix layer.
 */
const T: readonly (readonly bigint[])[] = Array.from({ length: 8 }, (_, k) =>
  Array.from({ length: 256 }, (_, b) => mixColumn(BigInt(KALYNA_S_BOXES[k & 3]![b]!) << BigInt(8 * k))),
);

export type KupynaSize = 256 | 384 | 512;

/** Kupyna at 256, 384 or 512 bits. The 256-bit form has half the state and four fewer rounds. */
export function createKupyna(bits: KupynaSize): LwcHasher {
  const hashSize = bits / 8;
  const columns = bits > 256 ? 16 : 8;
  const rounds = bits > 256 ? 14 : 10;
  const blockSize = columns * 8;
  const mask = columns - 1;
  // The one asymmetry between the two state sizes; see the header.
  const topShift = columns === 8 ? 7 : 11;

  const state = new Array<bigint>(columns).fill(0n);
  state[0] = BigInt(blockSize);
  let inputBlocks = 0n;

  const transform = (s: bigint[]): void => {
    const t = s.slice();
    for (let col = 0; col < columns; col++) {
      let v = T[0]![Number(t[col]! & 0xffn)]!;
      for (let k = 1; k < 7; k++) {
        v ^= T[k]![Number((t[(col - k) & mask]! >> BigInt(8 * k)) & 0xffn)]!;
      }
      v ^= T[7]![Number((t[(col - topShift) & mask]! >> 56n) & 0xffn)]!;
      s[col] = v;
    }
  };

  /** P: the round constant is XORed in, and it advances by 16 per column. */
  const p = (s: bigint[]): void => {
    for (let round = 0; round < rounds; round++) {
      let rc = BigInt(round);
      for (let col = 0; col < columns; col++) {
        s[col] = s[col]! ^ rc;
        rc = (rc + 0x10n) & MASK64;
      }
      transform(s);
    }
  };

  /** Q: the round constant is *added*, and it counts down. Not a variant of P. */
  const q = (s: bigint[]): void => {
    for (let round = 0; round < rounds; round++) {
      let rc = ((BigInt(((columns - 1) << 4) ^ round) << 56n) | 0x00f0f0f0f0f0f0f3n) & MASK64;
      for (let col = 0; col < columns; col++) {
        s[col] = (s[col]! + rc) & MASK64;
        rc = (rc - 0x1000000000000000n) & MASK64;
      }
      transform(s);
    }
  };

  const le64 = (buf: Uint8Array, off: number): bigint => {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i]!);
    return v;
  };

  const processBlock = (buf: Uint8Array, off: number): void => {
    const t1 = new Array<bigint>(columns);
    const t2 = new Array<bigint>(columns);
    for (let col = 0; col < columns; col++) {
      const word = le64(buf, off + 8 * col);
      t1[col] = state[col]! ^ word;
      t2[col] = word;
    }
    p(t1);
    q(t2);
    for (let col = 0; col < columns; col++) state[col] = state[col]! ^ t1[col]! ^ t2[col]!;
  };

  return eagerAbsorber(
    blockSize,
    (block, off) => {
      processBlock(block, off);
      inputBlocks += 1n;
    },
    (tail, tailLen) => {
      const buf = new Uint8Array(blockSize);
      buf.set(tail.subarray(0, tailLen));
      let bufOff = tailLen;
      buf[bufOff++] = 0x80;
      const lenPos = blockSize - 12;
      if (bufOff > lenPos) {
        processBlock(buf, 0);
        buf.fill(0);
        bufOff = 0;
      }
      while (bufOff < lenPos) buf[bufOff++] = 0;
      // 96 bits of length, little-endian, as a 32-bit half then a 64-bit half.
      let c =
        (((inputBlocks & 0xffffffffn) * BigInt(blockSize) + BigInt(tailLen)) << 3n) & ((1n << 96n) - 1n);
      const low = c & 0xffffffffn;
      for (let i = 0; i < 4; i++) buf[bufOff + i] = Number((low >> BigInt(8 * i)) & 0xffn);
      bufOff += 4;
      c >>= 32n;
      c = (c + (((inputBlocks >> 32n) * BigInt(blockSize)) << 3n)) & MASK64;
      for (let i = 0; i < 8; i++) buf[bufOff + i] = Number((c >> BigInt(8 * i)) & 0xffn);
      processBlock(buf, 0);

      // The output transform: one more P over the state, folded back in.
      const t1 = state.slice();
      p(t1);
      for (let col = 0; col < columns; col++) state[col] = state[col]! ^ t1[col]!;

      // The digest is the *tail* of the state, not its head.
      const out = new Uint8Array(hashSize);
      let o = 0;
      for (let col = columns - hashSize / 8; col < columns; col++) {
        for (let i = 0; i < 8; i++) out[o + i] = Number((state[col]! >> BigInt(8 * i)) & 0xffn);
        o += 8;
      }
      return out;
    },
  );
}

export function kupyna(bits: KupynaSize, message: Uint8Array): Uint8Array {
  const h = createKupyna(bits);
  h.update(message);
  return h.digest();
}
