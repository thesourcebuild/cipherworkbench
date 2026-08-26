/**
 * JH, a SHA-3 finalist, at all four output lengths.
 *
 * The fourth of the five finalists this repo was missing -- BLAKE, Keccak and Skein were already
 * here, Groestl arrived beside this. Hongjun Wu's design, and the most unusual of the five: a
 * 1024-bit state, a bitsliced 4-bit S-box pair chosen *per bit* by the round constant, and a
 * compression function that XORs the message into both halves of the state around one permutation.
 *
 * Four things to know.
 *
 * **The S-box choice is data in the round constant.** JH has two 4-bit S-boxes, and which one applies
 * to a given nibble is decided by the corresponding bit of the round constant. That is why the S-box
 * appears here as eleven boolean operations rather than a table: it computes both and selects
 * bitwise, which is the only sensible way to express it.
 *
 * **The round constants are 42 x 256 bits and were parsed from the reference implementation.** The
 * specification derives them by running the round function on a fixed seed, which would be the
 * preferred route in this repo -- but the derivation needs the round function to already exist and
 * agree, so a table checked against 72 published vectors is the honest trade. A mistyped word gives a
 * hash that is perfectly self-consistent and reproduces nothing.
 *
 * **The initial value is derived, not stored.** Most implementations ship four 128-byte IVs; the
 * specification says to put the digest length in the first two bytes of an otherwise-zero state and
 * run the compression on a zero block. That is what happens here, so the four IVs cost nothing and
 * cannot drift from the lengths they belong to.
 *
 * **Block-aligned messages get one padding block, everything else gets two.** The padding is `0x80`,
 * zeros, and a 128-bit big-endian bit count. When the message is already a multiple of 64 bytes it
 * all fits in one block; otherwise the count needs a block of its own. Getting that wrong fails
 * *only* the block-aligned lengths, which is exactly how it was caught here.
 *
 * `bigint` throughout, for the reason `xxhash3.ts` gives: this is a 64-bit word algorithm whose
 * operations are all bitwise, and a 32-bit-limb rewrite would double the code for a hash nobody runs
 * over gigabytes.
 */

const MASK = (1n << 64n) - 1n;
const not = (x: bigint): bigint => x ^ MASK;

/**
 * The 42 round constants, four 64-bit words each, parsed from the reference implementation.
 *
 * Ordered as the round function consumes them: even-half high, even-half low, odd-half high, odd-half
 * low, per round.
 */
const CONSTANTS: readonly bigint[] = [
  0x72d5dea2df15f867n, 0x7b84150ab7231557n,
  0x81abd6904d5a87f6n, 0x4e9f4fc5c3d12b40n,
  0xea983ae05c45fa9cn, 0x03c5d29966b2999an,
  0x660296b4f2bb538an, 0xb556141a88dba231n,
  0x03a35a5c9a190edbn, 0x403fb20a87c14410n,
  0x1c051980849e951dn, 0x6f33ebad5ee7cddcn,
  0x10ba139202bf6b41n, 0xdc786515f7bb27d0n,
  0x0a2c813937aa7850n, 0x3f1abfd2410091d3n,
  0x422d5a0df6cc7e90n, 0xdd629f9c92c097cen,
  0x185ca70bc72b44acn, 0xd1df65d663c6fc23n,
  0x976e6c039ee0b81an, 0x2105457e446ceca8n,
  0xeef103bb5d8e61fan, 0xfd9697b294838197n,
  0x4a8e8537db03302fn, 0x2a678d2dfb9f6a95n,
  0x8afe7381f8b8696cn, 0x8ac77246c07f4214n,
  0xc5f4158fbdc75ec4n, 0x75446fa78f11bb80n,
  0x52de75b7aee488bcn, 0x82b8001e98a6a3f4n,
  0x8ef48f33a9a36315n, 0xaa5f5624d5b7f989n,
  0xb6f1ed207c5ae0fdn, 0x36cae95a06422c36n,
  0xce2935434efe983dn, 0x533af974739a4ba7n,
  0xd0f51f596f4e8186n, 0x0e9dad81afd85a9fn,
  0xa7050667ee34626an, 0x8b0b28be6eb91727n,
  0x47740726c680103fn, 0xe0a07e6fc67e487bn,
  0x0d550aa54af8a4c0n, 0x91e3e79f978ef19en,
  0x8676728150608dd4n, 0x7e9e5a41f3e5b062n,
  0xfc9f1fec4054207an, 0xe3e41a00cef4c984n,
  0x4fd794f59dfa95d8n, 0x552e7e1124c354a5n,
  0x5bdf7228bdfe6e28n, 0x78f57fe20fa5c4b2n,
  0x05897cefee49d32en, 0x447e9385eb28597fn,
  0x705f6937b324314an, 0x5e8628f11dd6e465n,
  0xc71b770451b920e7n, 0x74fe43e823d4878an,
  0x7d29e8a3927694f2n, 0xddcb7a099b30d9c1n,
  0x1d1b30fb5bdc1be0n, 0xda24494ff29c82bfn,
  0xa4e7ba31b470bfffn, 0x0d324405def8bc48n,
  0x3baefc3253bbd339n, 0x459fc3c1e0298ba0n,
  0xe5c905fdf7ae090fn, 0x947034124290f134n,
  0xa271b701e344ed95n, 0xe93b8e364f2f984an,
  0x88401d63a06cf615n, 0x47c1444b8752afffn,
  0x7ebb4af1e20ac630n, 0x4670b6c5cc6e8ce6n,
  0xa4d5a456bd4fca00n, 0xda9d844bc83e18aen,
  0x7357ce453064d1adn, 0xe8a6ce68145c2567n,
  0xa3da8cf2cb0ee116n, 0x33e906589a94999an,
  0x1f60b220c26f847bn, 0xd1ceac7fa0d18518n,
  0x32595ba18ddd19d3n, 0x509a1cc0aaa5b446n,
  0x9f3d6367e4046bban, 0xf6ca19ab0b56ee7en,
  0x1fb179eaa9282174n, 0xe9bdf7353b3651een,
  0x1d57ac5a7550d376n, 0x3a46c2fea37d7001n,
  0xf735c1af98a4d842n, 0x78edec209e6b6779n,
  0x41836315ea3adba8n, 0xfac33b4d32832c83n,
  0xa7403b1f1c2747f3n, 0x5940f034b72d769an,
  0xe73e4e6cd2214ffdn, 0xb8fd8d39dc5759efn,
  0x8d9b0c492b49ebdan, 0x5ba2d74968f3700dn,
  0x7d3baed07a8d5584n, 0xf5a5e9f0e4f88e65n,
  0xa0b8a2f436103b53n, 0x0ca8079e753eec5an,
  0x9168949256e8884fn, 0x5bb05c55f8babc4cn,
  0xe3bb3b99f387947bn, 0x75daf4d6726b1c5dn,
  0x64aeac28dc34b36dn, 0x6c34a550b828db71n,
  0xf861e2f2108d512an, 0xe3db643359dd75fcn,
  0x1cacbcf143ce3fa2n, 0x67bbd13c02e843b0n,
  0x330a5bca8829a175n, 0x7f34194db416535cn,
  0x923b94c30e794d1en, 0x797475d7b6eeaf3fn,
  0xeaa8d4f7be1a3921n, 0x5cf47e094c232751n,
  0x26a32453ba323cd2n, 0x44a3174a6da6d5adn,
  0xb51d3ea6aff2c908n, 0x83593d98916b3c56n,
  0x4cf87ca17286604dn, 0x46e23ecc086ec7f6n,
  0x2f9833b3b1bc765en, 0x2bd666a5efc4e62an,
  0x06f4b6e8bec1d436n, 0x74ee8215bcef2163n,
  0xfdc14e0df453c969n, 0xa77d5ac406585826n,
  0x7ec1141606e0fa16n, 0x7e90af3d28639d3fn,
  0xd2c9f2e3009bd20cn, 0x5faace30b7d40c30n,
  0x742a5116f2e03298n, 0x0deb30d8e3cef89an,
  0x4bc59e7bb5f17992n, 0xff51e66e048668d3n,
  0x9b234d57e6966731n, 0xcce6a6f3170a7505n,
  0xb17681d913326ccen, 0x3c175284f805a262n,
  0xf42bcbb378471547n, 0xff46548223936a48n,
  0x38df58074e5e6565n, 0xf2fc7c89fc86508en,
  0x31702e44d00bca86n, 0xf04009a23078474en,
  0x65a0ee39d1f73883n, 0xf75ee937e42c3abdn,
  0x2197b2260113f86fn, 0xa344edd1ef9fdee7n,
  0x8ba0df15762592d9n, 0x3c85f7f612dc42ben,
  0xd8a7ec7cab27b07en, 0x538d7ddaaa3ea8den,
  0xaa25ce93bd0269d8n, 0x5af643fd1a7308f9n,
  0xc05fefda174a19a5n, 0x974d66334cfd216an,
  0x35b49831db411570n, 0xea1e0fbbedcd549bn,
  0x9ad063a151974072n, 0xf6759dbf91476fe2n,
];

if (CONSTANTS.length !== 168) {
  throw new Error(`JH needs 42 rounds of four constants; this table has ${CONSTANTS.length}.`);
}

/**
 * JH's S-box layer, bitsliced across four state words with `c` selecting which box per bit.
 *
 * Eleven operations, from the specification's own boolean expression. `tmp` has to be captured before
 * `x0` changes again, which is the one ordering here that a reader is likely to "simplify" wrongly.
 */
function substitute(s: bigint[], i0: number, i1: number, i2: number, i3: number, c: bigint): void {
  let x0 = s[i0]!;
  let x1 = s[i1]!;
  let x2 = s[i2]!;
  let x3 = not(s[i3]!);

  x0 ^= c & not(x2);
  const tmp = c ^ (x0 & x1);
  x0 ^= x2 & x3;
  x3 ^= not(x1) & x2;
  x1 ^= x0 & x2;
  x2 ^= x0 & not(x3);
  x0 ^= x1 | x3;
  x3 ^= x1 & x2;
  x1 ^= tmp & x0;
  x2 ^= tmp;

  s[i0] = x0 & MASK;
  s[i1] = x1 & MASK;
  s[i2] = x2 & MASK;
  s[i3] = x3 & MASK;
}

/** The linear layer: a (4, 2, 3) MDS code over GF(2^4), expressed on eight words. */
function linear(s: bigint[], indices: readonly number[]): void {
  const [a, b, c, d, e, f, g, h] = indices as [
    number, number, number, number, number, number, number, number,
  ];
  s[e] = s[e]! ^ s[b]!;
  s[f] = s[f]! ^ s[c]!;
  s[g] = s[g]! ^ s[d]! ^ s[a]!;
  s[h] = s[h]! ^ s[a]!;
  s[a] = s[a]! ^ s[f]!;
  s[b] = s[b]! ^ s[g]!;
  s[c] = s[c]! ^ s[h]! ^ s[e]!;
  s[d] = s[d]! ^ s[e]!;
  for (const i of indices) s[i] = s[i]! & MASK;
}

/** The six bit-swap masks of the permutation layer; the seventh round swaps whole words instead. */
const SWAPS: readonly (readonly [bigint, bigint])[] = [
  [0x5555555555555555n, 1n],
  [0x3333333333333333n, 2n],
  [0x0f0f0f0f0f0f0f0fn, 4n],
  [0x00ff00ff00ff00ffn, 8n],
  [0x0000ffff0000ffffn, 16n],
  [0x00000000ffffffffn, 32n],
];

/** The odd words' bit permutation for a round, cycling with period seven. */
function permuteOdd(s: bigint[], group: number): void {
  for (const [hi, lo] of [
    [2, 3],
    [6, 7],
    [10, 11],
    [14, 15],
  ] as const) {
    if (group === 6) {
      const swap = s[hi]!;
      s[hi] = s[lo]!;
      s[lo] = swap;
      continue;
    }
    const [mask, shift] = SWAPS[group]!;
    for (const at of [hi, lo]) {
      const x = s[at]!;
      s[at] = (((x >> shift) & mask) | ((x & mask) << shift)) & MASK;
    }
  }
}

/** E8: 42 rounds over the 1024-bit state. */
function e8(s: bigint[]): void {
  for (let round = 0; round < 42; round++) {
    const base = round << 2;
    substitute(s, 0, 4, 8, 12, CONSTANTS[base]!);
    substitute(s, 1, 5, 9, 13, CONSTANTS[base + 1]!);
    substitute(s, 2, 6, 10, 14, CONSTANTS[base + 2]!);
    substitute(s, 3, 7, 11, 15, CONSTANTS[base + 3]!);
    linear(s, [0, 4, 8, 12, 2, 6, 10, 14]);
    linear(s, [1, 5, 9, 13, 3, 7, 11, 15]);
    permuteOdd(s, round % 7);
  }
}

function readWords(block: Uint8Array): bigint[] {
  const out: bigint[] = [];
  for (let i = 0; i < block.length; i += 8) {
    let word = 0n;
    for (let j = 0; j < 8; j++) word = (word << 8n) | BigInt(block[i + j] ?? 0);
    out.push(word);
  }
  return out;
}

/** F8: the message goes into the first half, E8 runs, then into the second half. */
function compress(s: bigint[], block: Uint8Array): void {
  const m = readWords(block);
  for (let i = 0; i < 8; i++) s[i] = s[i]! ^ m[i]!;
  e8(s);
  for (let i = 0; i < 8; i++) s[8 + i] = s[8 + i]! ^ m[i]!;
}

/** A JH digest of any of the four standardised lengths. */
export function jh(outputLen: 28 | 32 | 48 | 64, message: Uint8Array): Uint8Array {
  const s = new Array<bigint>(16).fill(0n);
  // The IV, derived: the digest size in bits at the top of the first word, then a zero block.
  s[0] = BigInt(outputLen * 8) << 48n;
  compress(s, new Uint8Array(64));

  let at = 0;
  for (; at + 64 <= message.length; at += 64) compress(s, message.subarray(at, at + 64));

  const rest = message.length - at;
  const bitCount = BigInt(message.length) * 8n;
  const writeLength = (block: Uint8Array): void => {
    for (let i = 0; i < 16; i++) block[63 - i] = Number((bitCount >> BigInt(8 * i)) & 0xffn);
  };

  if (rest === 0) {
    // One block: the 0x80 and the length both fit, since 1 + 47 + 16 is exactly 64.
    const only = new Uint8Array(64);
    only[0] = 0x80;
    writeLength(only);
    compress(s, only);
  } else {
    const tail = new Uint8Array(64);
    tail.set(message.subarray(at));
    tail[rest] = 0x80;
    compress(s, tail);
    const lengthBlock = new Uint8Array(64);
    writeLength(lengthBlock);
    compress(s, lengthBlock);
  }

  // The digest is the tail of the second half of the state.
  const out = new Uint8Array(outputLen);
  const full = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    for (let j = 0; j < 8; j++) full[i * 8 + j] = Number((s[8 + i]! >> BigInt(8 * (7 - j))) & 0xffn);
  }
  out.set(full.subarray(64 - outputLen));
  return out;
}

/** An incremental JH, buffered for the same reason as Groestl's. */
export function createJh(outputLen: 28 | 32 | 48 | 64): {
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
      return jh(outputLen, all);
    },
  };
}
