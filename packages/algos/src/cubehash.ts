/**
 * CubeHash, Bernstein's SHA-3 second-round candidate, at four output lengths.
 *
 * Not a finalist, and here because it is the simplest respectable hash function in existence: a
 * 1024-bit state, ten lines of round function, and **no tables and no constants at all** beyond the
 * three numbers that configure it. That makes it the one hash in this repo whose correctness rests on
 * nothing that could be mistyped -- the same property Speck and Simon have among the ciphers.
 *
 * Three things to know.
 *
 * **CubeHash16/32 is what "CubeHash" means.** The parameters are rounds-per-block and bytes-per-block;
 * the SHA-3 submission's final proposal was 16 and 32, and that is what these four tools compute.
 * The round count is a parameter of the implementation rather than a constant so a different
 * `CubeHash r/b` could be added later, but only 16/32 has published vectors here.
 *
 * **The initial state is derived, not stored.** Most implementations ship a 128-byte IV per output
 * length. The specification says to set the first three words to the output length, the block size
 * and the round count, and run ten times the round count -- 160 rounds -- so that is what happens at
 * construction. Four IVs that cannot drift from their parameters, for about a millisecond.
 *
 * **The round is written as the specification's ten indexed steps.** Add, rotate by 7, swap on bit 3,
 * XOR, swap on bit 1, add, rotate by 11, swap on bit 2, XOR, swap on bit 0. Reference
 * implementations unroll this into 32 named variables, which is faster and completely unreadable; the
 * indexed form is checkable line by line against the specification.
 *
 * Checked against 72 known-answer vectors from sphlib's test data, which carries the NIST SHA-3
 * competition KATs.
 */

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));

/** One CubeHash round: the specification's ten steps, in order. */
function round(s: Uint32Array): void {
  // 1. Add the low half into the high half. 2. Rotate the low half left 7.
  for (let i = 0; i < 16; i++) s[i + 16] = u32(s[i + 16]! + s[i]!);
  for (let i = 0; i < 16; i++) s[i] = rotl(s[i]!, 7);
  // 3. Swap the two halves of the low half.
  for (let i = 0; i < 8; i++) {
    const swap = s[i]!;
    s[i] = s[i + 8]!;
    s[i + 8] = swap;
  }
  // 4. XOR the high half into the low half. 5. Swap high-half words differing in bit 1.
  for (let i = 0; i < 16; i++) s[i] = u32(s[i]! ^ s[i + 16]!);
  swapOn(s, 16, 2);
  // 6. Add again. 7. Rotate left 11. 8. Swap low-half words differing in bit 2.
  for (let i = 0; i < 16; i++) s[i + 16] = u32(s[i + 16]! + s[i]!);
  for (let i = 0; i < 16; i++) s[i] = rotl(s[i]!, 11);
  swapOn(s, 0, 4);
  // 9. XOR again. 10. Swap high-half words differing in bit 0.
  for (let i = 0; i < 16; i++) s[i] = u32(s[i]! ^ s[i + 16]!);
  swapOn(s, 16, 1);
}

/** Swaps the sixteen words at `base` in pairs whose indices differ in the given bit. */
function swapOn(s: Uint32Array, base: number, bit: number): void {
  for (let i = 0; i < 16; i++) {
    const j = i ^ bit;
    if (j > i) {
      const swap = s[base + i]!;
      s[base + i] = s[base + j]!;
      s[base + j] = swap;
    }
  }
}

export interface CubehashParams {
  rounds: number;
  blockLen: number;
}

const DEFAULT_PARAMS: CubehashParams = { rounds: 16, blockLen: 32 };

/** A CubeHash16/32 digest of any of the four standardised lengths. */
export function cubehash(
  outputLen: 28 | 32 | 48 | 64,
  message: Uint8Array,
  params: CubehashParams = DEFAULT_PARAMS,
): Uint8Array {
  const { rounds, blockLen } = params;
  const s = new Uint32Array(32);
  // The derived initial state: output length, block length, round count, then 10r rounds.
  s[0] = outputLen;
  s[1] = blockLen;
  s[2] = rounds;
  for (let i = 0; i < 10 * rounds; i++) round(s);

  const absorb = (block: Uint8Array): void => {
    for (let i = 0; i < blockLen / 4; i++) {
      const word =
        block[4 * i]! | (block[4 * i + 1]! << 8) | (block[4 * i + 2]! << 16) | (block[4 * i + 3]! << 24);
      s[i] = u32(s[i]! ^ u32(word));
    }
    for (let i = 0; i < rounds; i++) round(s);
  };

  let at = 0;
  for (; at + blockLen <= message.length; at += blockLen) absorb(message.subarray(at, at + blockLen));
  // Padding is a single 0x80 byte and zeros -- there is no length field anywhere in CubeHash.
  const tail = new Uint8Array(blockLen);
  tail.set(message.subarray(at));
  tail[message.length - at] = 0x80;
  absorb(tail);

  // Finalisation: flip the last bit of the state and run 10r more rounds.
  s[31] = u32(s[31]! ^ 1);
  for (let i = 0; i < 10 * rounds; i++) round(s);

  const out = new Uint8Array(outputLen);
  for (let i = 0; i < outputLen; i++) out[i] = (s[i >> 2]! >>> (8 * (i & 3))) & 0xff;
  return out;
}

/** An incremental CubeHash. Unlike Groestl and JH this one could stream; it buffers for symmetry. */
export function createCubehash(outputLen: 28 | 32 | 48 | 64): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
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
      return cubehash(outputLen, all);
    },
  };
}
