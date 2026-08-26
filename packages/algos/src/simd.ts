/**
 * SIMD, at 224, 256, 384 and 512 bits. Second round of the SHA-3 competition.
 *
 * The only algorithm in this repo whose message expansion is a **number-theoretic transform**. A 64- or
 * 128-byte block is treated as a sequence of bytes in GF(257), run through a radix-2 FFT of length 128
 * or 256, twisted by a per-position constant, reduced back into -128..128, and then read out in pairs to
 * form 32 or 64 message words -- four times as many words as the block has. Those drive four rounds of
 * a Davies-Meyer-style step function over four (or eight) parallel copies of a SHA-like state, and four
 * closing steps feed the old chaining value back in as message words.
 *
 * Ported from the reference's small-footprint path, which is the same computation written as loops
 * rather than as a fully unrolled macro expansion, and is legible. Five things to preserve.
 *
 * **The FFT's twiddle multiply overflows int32 and the reference relies on it.** `n` reaches about
 * 9.4 million and `alpha` reaches 256, so the product exceeds 2^31 and C wraps it; `REDS2` then folds the
 * 32-bit value back down. `Math.imul` is therefore mandatory in `fftLoop` -- plain `*` in JavaScript
 * keeps the extra bits as a double and gives a different, wrong answer.
 *
 * **Index 0 of every butterfly is a special case.** `alpha^0` is 1, but `REDS2(n)` is not `n`, so the
 * reference handles the first element as a plain add/subtract before the twiddled loop. Folding it into
 * the loop is wrong for every block.
 *
 * **There is no padding byte.** A short final block is zero-filled with nothing marking where the
 * message stopped, and the bit count gets a block entirely of its own -- so a message and the same
 * message with a trailing zero differ only through that final block. Snefru, GOST R 34.11-94 and
 * belt-hash do the same thing; SIMD is the only SHA-3 candidate here that does. It follows that a
 * block-aligned message compresses only the length block at the end, and one that is not gets two.
 *
 * **The `last` flag changes the twist, not the rounds.** `YOFF_S_F` replaces `YOFF_S_N` for the final
 * block. That is the whole of SIMD's domain separation, and it is why the length block cannot simply be
 * appended as ordinary data.
 *
 * **The closing steps read the chaining value from before this block.** `step(chaining, ...)` runs after
 * the four rounds have already overwritten `state`, and `chaining` is only updated afterwards. Reading
 * the new value there is self-consistent and matches nothing.
 *
 * No oracle: OpenSSL never implemented SIMD and nothing in this tree does either. What stands behind it
 * is 72 known-answer vectors from the competition's own KAT files. With ECHO and Hamsi alongside it,
 * this repo implements all eleven SHA-3 competition designs it set out to.
 */

/** alpha^i mod 257, for i = 0..255. alpha = 41 is a primitive root. */
const ALPHA_TAB = new Int32Array([
  1, 41, 139, 45, 46, 87, 226, 14, 60, 147, 116, 130, 190, 80, 196, 69,
  2, 82, 21, 90, 92, 174, 195, 28, 120, 37, 232, 3, 123, 160, 135, 138,
  4, 164, 42, 180, 184, 91, 133, 56, 240, 74, 207, 6, 246, 63, 13, 19,
  8, 71, 84, 103, 111, 182, 9, 112, 223, 148, 157, 12, 235, 126, 26, 38,
  16, 142, 168, 206, 222, 107, 18, 224, 189, 39, 57, 24, 213, 252, 52, 76,
  32, 27, 79, 155, 187, 214, 36, 191, 121, 78, 114, 48, 169, 247, 104, 152,
  64, 54, 158, 53, 117, 171, 72, 125, 242, 156, 228, 96, 81, 237, 208, 47,
  128, 108, 59, 106, 234, 85, 144, 250, 227, 55, 199, 192, 162, 217, 159, 94,
  256, 216, 118, 212, 211, 170, 31, 243, 197, 110, 141, 127, 67, 177, 61, 188,
  255, 175, 236, 167, 165, 83, 62, 229, 137, 220, 25, 254, 134, 97, 122, 119,
  253, 93, 215, 77, 73, 166, 124, 201, 17, 183, 50, 251, 11, 194, 244, 238,
  249, 186, 173, 154, 146, 75, 248, 145, 34, 109, 100, 245, 22, 131, 231, 219,
  241, 115, 89, 51, 35, 150, 239, 33, 68, 218, 200, 233, 44, 5, 205, 181,
  225, 230, 178, 102, 70, 43, 221, 66, 136, 179, 143, 209, 88, 10, 153, 105,
  193, 203, 99, 204, 140, 86, 185, 132, 15, 101, 29, 161, 176, 20, 49, 210,
  129, 149, 198, 151, 23, 172, 113, 7, 30, 202, 58, 65, 95, 40, 98, 163,
]);

/** alpha^(127*i) mod 257 -- the twist applied to a non-final 64-byte block. */
const YOFF_S_N = new Int32Array([
  1, 98, 95, 58, 30, 113, 23, 198, 129, 49, 176, 29, 15, 185, 140, 99,
  193, 153, 88, 143, 136, 221, 70, 178, 225, 205, 44, 200, 68, 239, 35, 89,
  241, 231, 22, 100, 34, 248, 146, 173, 249, 244, 11, 50, 17, 124, 73, 215,
  253, 122, 134, 25, 137, 62, 165, 236, 255, 61, 67, 141, 197, 31, 211, 118,
  256, 159, 162, 199, 227, 144, 234, 59, 128, 208, 81, 228, 242, 72, 117, 158,
  64, 104, 169, 114, 121, 36, 187, 79, 32, 52, 213, 57, 189, 18, 222, 168,
  16, 26, 235, 157, 223, 9, 111, 84, 8, 13, 246, 207, 240, 133, 184, 42,
  4, 135, 123, 232, 120, 195, 92, 21, 2, 196, 190, 116, 60, 226, 46, 139,
]);

/** The same for the final block, which is what separates it from every other. */
const YOFF_S_F = new Int32Array([
  2, 156, 118, 107, 45, 212, 111, 162, 97, 249, 211, 3, 49, 101, 151, 223,
  189, 178, 253, 204, 76, 82, 232, 65, 96, 176, 161, 47, 189, 61, 248, 107,
  0, 131, 133, 113, 17, 33, 12, 111, 251, 103, 57, 148, 47, 65, 249, 143,
  189, 8, 204, 230, 205, 151, 187, 227, 247, 111, 140, 6, 77, 10, 21, 149,
  255, 101, 139, 150, 212, 45, 146, 95, 160, 8, 46, 254, 208, 156, 106, 34,
  68, 79, 4, 53, 181, 175, 25, 192, 161, 81, 96, 210, 68, 196, 9, 150,
  0, 126, 124, 144, 240, 224, 245, 146, 6, 154, 200, 109, 210, 192, 8, 114,
  68, 249, 53, 27, 52, 106, 70, 30, 10, 146, 117, 251, 180, 247, 236, 108,
]);

/** alpha^(255*i) mod 257, for the 128-byte block. */
const YOFF_B_N = new Int32Array([
  1, 163, 98, 40, 95, 65, 58, 202, 30, 7, 113, 172, 23, 151, 198, 149,
  129, 210, 49, 20, 176, 161, 29, 101, 15, 132, 185, 86, 140, 204, 99, 203,
  193, 105, 153, 10, 88, 209, 143, 179, 136, 66, 221, 43, 70, 102, 178, 230,
  225, 181, 205, 5, 44, 233, 200, 218, 68, 33, 239, 150, 35, 51, 89, 115,
  241, 219, 231, 131, 22, 245, 100, 109, 34, 145, 248, 75, 146, 154, 173, 186,
  249, 238, 244, 194, 11, 251, 50, 183, 17, 201, 124, 166, 73, 77, 215, 93,
  253, 119, 122, 97, 134, 254, 25, 220, 137, 229, 62, 83, 165, 167, 236, 175,
  255, 188, 61, 177, 67, 127, 141, 110, 197, 243, 31, 170, 211, 212, 118, 216,
  256, 94, 159, 217, 162, 192, 199, 55, 227, 250, 144, 85, 234, 106, 59, 108,
  128, 47, 208, 237, 81, 96, 228, 156, 242, 125, 72, 171, 117, 53, 158, 54,
  64, 152, 104, 247, 169, 48, 114, 78, 121, 191, 36, 214, 187, 155, 79, 27,
  32, 76, 52, 252, 213, 24, 57, 39, 189, 224, 18, 107, 222, 206, 168, 142,
  16, 38, 26, 126, 235, 12, 157, 148, 223, 112, 9, 182, 111, 103, 84, 71,
  8, 19, 13, 63, 246, 6, 207, 74, 240, 56, 133, 91, 184, 180, 42, 164,
  4, 138, 135, 160, 123, 3, 232, 37, 120, 28, 195, 174, 92, 90, 21, 82,
  2, 69, 196, 80, 190, 130, 116, 147, 60, 14, 226, 87, 46, 45, 139, 41,
]);

/** And its final-block counterpart. */
const YOFF_B_F = new Int32Array([
  2, 203, 156, 47, 118, 214, 107, 106, 45, 93, 212, 20, 111, 73, 162, 251,
  97, 215, 249, 53, 211, 19, 3, 89, 49, 207, 101, 67, 151, 130, 223, 23,
  189, 202, 178, 239, 253, 127, 204, 49, 76, 236, 82, 137, 232, 157, 65, 79,
  96, 161, 176, 130, 161, 30, 47, 9, 189, 247, 61, 226, 248, 90, 107, 64,
  0, 88, 131, 243, 133, 59, 113, 115, 17, 236, 33, 213, 12, 191, 111, 19,
  251, 61, 103, 208, 57, 35, 148, 248, 47, 116, 65, 119, 249, 178, 143, 40,
  189, 129, 8, 163, 204, 227, 230, 196, 205, 122, 151, 45, 187, 19, 227, 72,
  247, 125, 111, 121, 140, 220, 6, 107, 77, 69, 10, 101, 21, 65, 149, 171,
  255, 54, 101, 210, 139, 43, 150, 151, 212, 164, 45, 237, 146, 184, 95, 6,
  160, 42, 8, 204, 46, 238, 254, 168, 208, 50, 156, 190, 106, 127, 34, 234,
  68, 55, 79, 18, 4, 130, 53, 208, 181, 21, 175, 120, 25, 100, 192, 178,
  161, 96, 81, 127, 96, 227, 210, 248, 68, 10, 196, 31, 9, 167, 150, 193,
  0, 169, 126, 14, 124, 198, 144, 142, 240, 21, 224, 44, 245, 66, 146, 238,
  6, 196, 154, 49, 200, 222, 109, 9, 210, 141, 192, 138, 8, 79, 114, 217,
  68, 128, 249, 94, 53, 30, 27, 61, 52, 135, 106, 212, 70, 238, 30, 185,
  10, 132, 146, 136, 117, 37, 251, 150, 180, 188, 247, 156, 236, 192, 108, 86,
]);

const IV224 = new Uint32Array([
  0x33586e9f, 0x12fff033, 0xb2d9f64d, 0x6f8fea53,
  0xde943106, 0x2742e439, 0x4fbab5ac, 0x62b9ff96,
  0x22e7b0af, 0xc862b3a8, 0x33e00cdc, 0x236b86a6,
  0xf64ae77c, 0xfa373b76, 0x7dc1ee5b, 0x7fb29ce8,
]);

const IV256 = new Uint32Array([
  0x4d567983, 0x07190ba9, 0x8474577b, 0x39d726e9,
  0xaaf3d925, 0x3ee20b03, 0xafd5e751, 0xc96006d3,
  0xc2c2ba14, 0x49b3bcb4, 0xf67caf46, 0x668626c9,
  0xe2eaa8d2, 0x1ff47833, 0xd0c661a5, 0x55693de1,
]);

const IV384 = new Uint32Array([
  0x8a36eebc, 0x94a3bd90, 0xd1537b83, 0xb25b070b,
  0xf463f1b5, 0xb6f81e20, 0x0055c339, 0xb4d144d1,
  0x7360ca61, 0x18361a03, 0x17dcb4b9, 0x3414c45a,
  0xa699a9d2, 0xe39e9664, 0x468bfe77, 0x51d062f8,
  0xb9e3bfe8, 0x63bece2a, 0x8fe506b9, 0xf8cc4ac2,
  0x7ae11542, 0xb1aadda1, 0x64b06794, 0x28d2f462,
  0xe64071ec, 0x1deb91a8, 0x8ac8db23, 0x3f782ab5,
  0x039b5cb8, 0x71ddd962, 0xfade2cea, 0x1416df71,
]);

const IV512 = new Uint32Array([
  0x0ba16b95, 0x72f999ad, 0x9fecc2ae, 0xba3264fc,
  0x5e894929, 0x8e9f30e5, 0x2f1daa37, 0xf0f2c558,
  0xac506643, 0xa90635a5, 0xe25b878b, 0xaab7878f,
  0x88817f7a, 0x0a02892b, 0x559a7550, 0x598f657e,
  0x7eef60a1, 0x6b70e3e8, 0x9c1714d1, 0xb958e2a8,
  0xab02675e, 0xed1c014f, 0xcd8d65bb, 0xfdb7a257,
  0x09254899, 0xd699c7bc, 0x9019b6dc, 0x2b9022e4,
  0x8fa14956, 0x21bf9bd3, 0xb94d0943, 0x6ffddc22,
]);


const IV: Record<string, Uint32Array> = { "224": IV224, "256": IV256, "384": IV384, "512": IV512 };

/** Fold a 16-bit-wide value back down. Used three times in succession to reach -128..128. */
const reds1 = (x: number): number => (x & 0xff) - (x >> 8);
/** Fold a 32-bit value into -32768..98302. */
const reds2 = (x: number): number => (x & 0xffff) + (x >> 16);

const rotl = (x: number, n: number): number =>
  n === 0 ? x >>> 0 : ((x << n) | (x >>> (32 - n))) >>> 0;

/**
 * One radix-2 butterfly layer over `q[rb .. rb + 2 * hk)`.
 *
 * Element 0 is a plain add/subtract; element u is twiddled by `alpha^(u * as)`. The product needs
 * `Math.imul` -- see the note on int32 overflow in the header.
 */
function fftLoop(q: Int32Array, rb: number, hk: number, as: number): void {
  let m = q[rb]!;
  let n = q[rb + hk]!;
  q[rb] = m + n;
  q[rb + hk] = m - n;
  for (let u = 1; u < hk; u++) {
    m = q[rb + u]!;
    n = q[rb + u + hk]!;
    const t = reds2(Math.imul(n, ALPHA_TAB[u * as]!));
    q[rb + u] = m + t;
    q[rb + u + hk] = m - t;
  }
}

/** At length 8 alpha is 41 and the transform reduces to adds and shifts. */
function fft8(x: Uint8Array, xb: number, xs: number, d: Int32Array): void {
  const x0 = x[xb]!;
  const x1 = x[xb + xs]!;
  const x2 = x[xb + 2 * xs]!;
  const x3 = x[xb + 3 * xs]!;
  const a0 = x0 + x2;
  const a1 = x0 + (x2 << 4);
  const a2 = x0 - x2;
  const a3 = x0 - (x2 << 4);
  const b0 = x1 + x3;
  const b1 = reds1((x1 << 2) + (x3 << 6));
  const b2 = (x1 << 4) - (x3 << 4);
  const b3 = reds1((x1 << 6) + (x3 << 2));
  d[0] = a0 + b0;
  d[1] = a1 + b1;
  d[2] = a2 + b2;
  d[3] = a3 + b3;
  d[4] = a0 - b0;
  d[5] = a1 - b1;
  d[6] = a2 - b2;
  d[7] = a3 - b3;
}

const D1 = new Int32Array(8);
const D2 = new Int32Array(8);

/** At length 16 alpha is 2, so multiplication by alpha^i is a shift by i. */
function fft16(x: Uint8Array, xb: number, xs: number, q: Int32Array, rb: number): void {
  fft8(x, xb, xs << 1, D1);
  fft8(x, xb + xs, xs << 1, D2);
  for (let i = 0; i < 8; i++) {
    const s = D2[i]! << i;
    q[rb + i] = D1[i]! + s;
    q[rb + 8 + i] = D1[i]! - s;
  }
}

function fft32(x: Uint8Array, xb: number, xs: number, q: Int32Array, rb: number): void {
  fft16(x, xb, xs << 1, q, rb);
  fft16(x, xb + xs, xs << 1, q, rb + 16);
  fftLoop(q, rb, 16, 8);
}

function fft64(x: Uint8Array, xb: number, xs: number, q: Int32Array, rb: number): void {
  fft32(x, xb, xs << 1, q, rb);
  fft32(x, xb + xs, xs << 1, q, rb + 32);
  fftLoop(q, rb, 32, 4);
}

/** 64 bytes in, 128 residues out. */
function fft128(x: Uint8Array, q: Int32Array): void {
  fft64(x, 0, 2, q, 0);
  fft64(x, 1, 2, q, 64);
  fftLoop(q, 0, 64, 2);
}

/** 128 bytes in, 256 residues out. */
function fft256(x: Uint8Array, q: Int32Array): void {
  fft64(x, 0, 4, q, 0);
  fft64(x, 2, 4, q, 64);
  fftLoop(q, 0, 64, 2);
  fft64(x, 1, 4, q, 128);
  fft64(x, 3, 4, q, 192);
  fftLoop(q, 128, 64, 2);
  fftLoop(q, 0, 128, 1);
}

/** Which sub-block of `q` each group of message words is read from. */
const WSP = [
  4, 6, 0, 2, 7, 5, 3, 1, 15, 11, 12, 8, 9, 13, 10, 14,
  17, 18, 23, 20, 22, 21, 16, 19, 30, 24, 25, 31, 27, 29, 28, 26,
];

const IF = (x: number, y: number, z: number): number => (((y ^ z) & x) ^ z) >>> 0;
const MAJ = (x: number, y: number, z: number): number => ((x & y) | ((x | y) & z)) >>> 0;

/**
 * The permutation applied to the rotated A words, as an XOR mask.
 *
 * The reference writes these as sixteen `PP4_k_n` / `PP8_k_n` defines; every row turns out to be
 * `n ^ c` for one constant, and these are those constants in the order the round index selects them.
 */
const PP4K = [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2];
const PP8K = [1, 6, 2, 3, 5, 7, 4, 1, 6, 2, 3];

/** Per round: the `WSP` offset, the permutation index, four rotations, and how `q` is read. */
const ROUNDS_SMALL = [
  [0, 0, 3, 23, 17, 27, 0, 1, 185],
  [8, 2, 28, 19, 22, 7, 0, 1, 185],
  [16, 1, 29, 9, 15, 5, -128, -64, 233],
  [24, 0, 4, 13, 10, 25, -191, -127, 233],
] as const;
const ROUNDS_BIG = [
  [0, 0, 3, 23, 17, 27, 0, 1, 185],
  [8, 1, 28, 19, 22, 7, 0, 1, 185],
  [16, 2, 29, 9, 15, 5, -256, -128, 233],
  [24, 3, 4, 13, 10, 25, -383, -255, 233],
] as const;
/** The four closing steps: where in the old chaining value the words come from, then r, s and pp. */
const FINAL_SMALL = [
  [0, 4, 13, 3],
  [4, 13, 10, 1],
  [8, 10, 25, 2],
  [12, 25, 4, 3],
] as const;
const FINAL_BIG = [
  [0, 4, 13, 5],
  [8, 13, 10, 7],
  [16, 10, 25, 4],
  [24, 25, 4, 1],
] as const;

export type SimdLength = 28 | 32 | 48 | 64;

/** An incremental SIMD. */
export function createSimd(outputLen: SimdLength): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
  const digestBits = outputLen * 8;
  const small = digestBits <= 256;
  const lanes = small ? 4 : 8;
  const blockBytes = small ? 64 : 128;
  const qLen = small ? 128 : 256;
  const words = lanes * 4;

  const chaining = Uint32Array.from(IV[String(digestBits)]!);
  const q = new Int32Array(qLen);
  const w = new Uint32Array(lanes * 8);
  const state = new Uint32Array(words);
  const tA = new Uint32Array(lanes);
  const buf = new Uint8Array(blockBytes);
  let ptr = 0;
  let blocks = 0n;

  /** One step across all lanes. `src` is either the message schedule or the old chaining value. */
  const step = (
    src: Uint32Array,
    off: number,
    fun: (x: number, y: number, z: number) => number,
    r: number,
    s: number,
    pp: number,
  ): void => {
    for (let n = 0; n < lanes; n++) tA[n] = rotl(state[n]!, r);
    for (let n = 0; n < lanes; n++) {
      const a = state[n]!;
      const b = state[lanes + n]!;
      const c = state[2 * lanes + n]!;
      const d = state[3 * lanes + n]!;
      const tt = (d + src[off + n]! + fun(a, b, c)) >>> 0;
      state[n] = (rotl(tt, s) + tA[pp ^ n]!) >>> 0;
      state[3 * lanes + n] = c;
      state[2 * lanes + n] = b;
      state[lanes + n] = tA[n]!;
    }
  };

  const compress = (last: boolean): void => {
    if (small) fft128(buf, q);
    else fft256(buf, q);

    const yoff = small ? (last ? YOFF_S_F : YOFF_S_N) : last ? YOFF_B_F : YOFF_B_N;
    for (let i = 0; i < qLen; i++) {
      let tq = q[i]! + yoff[i]!;
      tq = reds2(tq);
      tq = reds1(tq);
      tq = reds1(tq);
      q[i] = tq <= 128 ? tq : tq - 257;
    }

    for (let i = 0; i < words; i++) {
      const v =
        buf[4 * i]! | (buf[4 * i + 1]! << 8) | (buf[4 * i + 2]! << 16) | (buf[4 * i + 3]! << 24);
      state[i] = (chaining[i]! ^ v) >>> 0;
    }

    const ppk = small ? PP4K : PP8K;
    const stride = small ? 8 : 16;
    for (const [sb, isp, p0, p1, p2, p3, o1, o2, mm] of small ? ROUNDS_SMALL : ROUNDS_BIG) {
      for (let u = 0; u < lanes * 8; u += lanes) {
        const v = WSP[u / lanes + sb]! * stride;
        for (let j = 0; j < lanes; j++) {
          // Two residues become one word: the low half from `o1`, the high half from `o2`.
          const lo = q[v + 2 * j + o1]! * mm;
          const hi = q[v + 2 * j + o2]! * mm;
          w[u + j] = ((lo & 0xffff) | (hi << 16)) >>> 0;
        }
      }
      const rots = [p0, p1, p2, p3, p0, p1, p2, p3];
      const next = [p1, p2, p3, p0, p1, p2, p3, p0];
      for (let k = 0; k < 8; k++) {
        step(w, k * lanes, k < 4 ? IF : MAJ, rots[k]!, next[k]!, ppk[isp + k]!);
      }
    }

    for (const [off, r, s, pp] of small ? FINAL_SMALL : FINAL_BIG) step(chaining, off, IF, r, s, pp);
    chaining.set(state);
  };

  return {
    update: (chunk) => {
      let off = 0;
      while (off < chunk.length) {
        const take = Math.min(blockBytes - ptr, chunk.length - off);
        buf.set(chunk.subarray(off, off + take), ptr);
        off += take;
        ptr += take;
        if (ptr === blockBytes) {
          compress(false);
          ptr = 0;
          blocks++;
        }
      }
    },
    digest: () => {
      if (ptr > 0) {
        buf.fill(0, ptr);
        compress(false);
      }
      buf.fill(0);
      const bits = blocks * BigInt(blockBytes * 8) + BigInt(ptr * 8);
      for (let i = 0; i < 8; i++) buf[i] = Number((bits >> BigInt(8 * i)) & 0xffn);
      compress(true);

      const out = new Uint8Array(outputLen);
      for (let i = 0; i < outputLen; i++) out[i] = (chaining[i >> 2]! >>> (8 * (i & 3))) & 0xff;
      return out;
    },
  };
}

/** A SIMD digest of any of the four standardised lengths. */
export function simd(outputLen: SimdLength, message: Uint8Array): Uint8Array {
  const h = createSimd(outputLen);
  h.update(message);
  return h.digest();
}
