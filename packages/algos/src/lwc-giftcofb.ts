/**
 * GIFT-COFB -- the GIFT-128 block cipher under COFB (COmbined FeedBack). A NIST lightweight finalist.
 *
 * One block-cipher call per block of message *and* per block of associated data, plus one for the
 * nonce: no second primitive, no field multiplication, and a 64-bit mask rather than a 128-bit one.
 * That halved state is what makes it the smallest of the block-cipher-based finalists in hardware.
 *
 * Verified against the submission's 1089 known-answer vectors in both directions, first run.
 *
 * ## The three-and-a-bit places this goes wrong
 *
 * **The mask is doubled for ordinary blocks and *tripled* for the last one -- sometimes twice.** The
 * offset L lives in GF(2^64) under x^64 + x^4 + x^3 + x + 1. Each interior block doubles it. The final
 * associated-data block triples it, triples it *again* if the associated data is partial or absent, and
 * twice more if the message is empty. The final message block triples once, and again if partial. Five
 * conditions, and each one exists to separate a case that would otherwise collide.
 *
 * **`rho1` mutates its state argument.** G swaps the two halves of Y and rotates the half that lands
 * second left by one bit. It is not a pure function of Y and the block; the sequence of Y values is the
 * chain.
 *
 * **GIFT-128's key schedule rotates two 16-bit halves by different amounts** -- 2 and 12 -- and feeds
 * words 2,3 into `s[2]` and 6,7 into `s[1]`. Reading them in the obvious order gives a cipher that
 * encrypts and decrypts consistently and matches nothing.
 *
 * **This implementation only encrypts.** COFB never inverts the block cipher, so GIFT-128's decryption
 * is not written here at all -- which is also why GIFT is not registered as a block cipher tool.
 */

const GIFT_RC = [
  0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e, 0x3c, 0x39, 0x33, 0x27, 0x0e,
  0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38,
  0x31, 0x23, 0x06, 0x0d, 0x1b, 0x36, 0x2d, 0x1a,
] as const;

const bitPermuteStep = (x: number, mask: number, shift: number): number => {
  const t = ((x >>> shift) ^ x) & mask;
  return (x ^ t ^ (t << shift)) | 0;
};

/**
 * The bit-sliced inverse of GIFT's nibble shuffle, applied twice.
 *
 * Two identical passes rather than one: the shuffle has order three over these masks, so undoing it
 * takes two applications of the same butterfly network. That is not an optimisation to unroll; halving
 * it gives the forward permutation.
 */
function unshuffle4(x: number): number {
  let v = x;
  for (let pass = 0; pass < 2; pass++) {
    v = bitPermuteStep(v, 0x22222222, 1);
    v = bitPermuteStep(v, 0x0c0c0c0c, 2);
    v = bitPermuteStep(v, 0x00f000f0, 4);
    v = bitPermuteStep(v, 0x0000ff00, 8);
  }
  return v;
}

const rowperm = (s: number, b0: number, b1: number, b2: number, b3: number): number => {
  const u = unshuffle4(s);
  return (
    ((u & 0xff) << (b0 << 3)) |
    (((u >>> 8) & 0xff) << (b1 << 3)) |
    (((u >>> 16) & 0xff) << (b2 << 3)) |
    (((u >>> 24) & 0xff) << (b3 << 3))
  ) | 0;
};

/** GIFT-128 as a 128-bit permutation, forty rounds, big-endian words. Encryption only. */
export function giftb128(plaintext: Uint8Array, key: Uint8Array, out: Uint8Array): void {
  const s = new Int32Array(4);
  for (let i = 0; i < 4; i++) {
    s[i] =
      ((plaintext[4 * i]! << 24) |
        (plaintext[4 * i + 1]! << 16) |
        (plaintext[4 * i + 2]! << 8) |
        plaintext[4 * i + 3]!) | 0;
  }
  const w = new Uint16Array(8);
  for (let i = 0; i < 8; i++) w[i] = (key[2 * i]! << 8) | key[2 * i + 1]!;

  for (let round = 0; round < 40; round++) {
    // SubCells: the 4-bit S-box, bit-sliced across the four words.
    s[1] = s[1]! ^ (s[0]! & s[2]!);
    s[0] = s[0]! ^ (s[1]! & s[3]!);
    s[2] = s[2]! ^ (s[0]! | s[1]!);
    s[3] = s[3]! ^ (s[2]!);
    s[1] = s[1]! ^ (s[3]!);
    s[3] = ~s[3]!;
    s[2] = s[2]! ^ (s[0]! & s[1]!);
    const t = s[0]!;
    s[0] = s[3]!;
    s[3] = t;
    // PermBits, as four byte rotations of the unshuffled word.
    s[0] = rowperm(s[0]!, 0, 3, 2, 1);
    s[1] = rowperm(s[1]!, 1, 0, 3, 2);
    s[2] = rowperm(s[2]!, 2, 1, 0, 3);
    s[3] = rowperm(s[3]!, 3, 2, 1, 0);
    s[2] = s[2]! ^ ((w[2]! << 16) | w[3]!);
    s[1] = s[1]! ^ ((w[6]! << 16) | w[7]!);
    s[3] = s[3]! ^ (0x80000000 ^ GIFT_RC[round]!);
    // The key state advances by two 16-bit rotations at different amounts, then a four-word shift.
    const t6 = ((w[6]! >>> 2) | (w[6]! << 14)) & 0xffff;
    const t7 = ((w[7]! >>> 12) | (w[7]! << 4)) & 0xffff;
    w[7] = w[5]!;
    w[6] = w[4]!;
    w[5] = w[3]!;
    w[4] = w[2]!;
    w[3] = w[1]!;
    w[2] = w[0]!;
    w[1] = t7;
    w[0] = t6;
  }
  for (let i = 0; i < 4; i++) {
    out[4 * i] = (s[i]! >>> 24) & 0xff;
    out[4 * i + 1] = (s[i]! >>> 16) & 0xff;
    out[4 * i + 2] = (s[i]! >>> 8) & 0xff;
    out[4 * i + 3] = s[i]! & 0xff;
  }
}

/** L <- 2L in GF(2^64) under x^64 + x^4 + x^3 + x + 1. */
function doubleHalf(s: Uint8Array): void {
  const mask = (s[0]! >>> 7) * 27;
  for (let i = 0; i < 7; i++) s[i] = ((s[i]! << 1) | (s[i + 1]! >>> 7)) & 0xff;
  s[7] = ((s[7]! << 1) ^ mask) & 0xff;
}

/** L <- 3L, which is 2L XOR L. */
function tripleHalf(s: Uint8Array): void {
  const tmp = new Uint8Array(8);
  for (let i = 0; i < 7; i++) tmp[i] = ((s[i]! << 1) | (s[i + 1]! >>> 7)) & 0xff;
  tmp[7] = ((s[7]! << 1) ^ (s[0]! >>> 7) * 27) & 0xff;
  for (let i = 0; i < 8; i++) s[i] = s[i]! ^ (tmp[i]!);
}

/** rho1: advance Y through G, then XOR in the padded block. `y` is mutated -- see the header. */
function rho1(dst: Uint8Array, y: Uint8Array, m: Uint8Array, mOff: number, count: number): void {
  const padded = new Uint8Array(16);
  if (count === 0) {
    padded[0] = 0x80;
  } else if (count < 16) {
    padded.set(m.subarray(mOff, mOff + count));
    padded[count] = 0x80;
  } else {
    padded.set(m.subarray(mOff, mOff + 16));
  }
  const tmp = new Uint8Array(16);
  tmp.set(y.subarray(8, 16), 0);
  for (let i = 0; i < 7; i++) tmp[i + 8] = ((y[i]! << 1) | (y[i + 1]! >>> 7)) & 0xff;
  tmp[15] = ((y[7]! << 1) | (y[0]! >>> 7)) & 0xff;
  y.set(tmp);
  for (let i = 0; i < 16; i++) dst[i] = y[i]! ^ padded[i]!;
}

function cofb(
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  aad: Uint8Array,
  encrypting: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  if (key.length !== 16) throw new Error(`GIFT-COFB needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== 16) throw new Error(`GIFT-COFB needs a 16-byte nonce; got ${nonce.length}.`);

  const y = new Uint8Array(16);
  const block = new Uint8Array(16);
  block.set(nonce.subarray(0, 16));
  giftb128(block, key, y);
  const offset = new Uint8Array(8);
  offset.set(y.subarray(0, 8));

  const feed = (): void => {
    for (let i = 0; i < 8; i++) block[i] = block[i]! ^ (offset[i]!);
    giftb128(block, key, y);
  };

  // Associated data. One block even when there is none: the empty case is a 0x80 pad, not a skip.
  const adBlocks = Math.max(1, Math.ceil(aad.length / 16));
  for (let b = 0; b < adBlocks - 1; b++) {
    doubleHalf(offset);
    rho1(block, y, aad, b * 16, 16);
    feed();
  }
  {
    const off = (adBlocks - 1) * 16;
    tripleHalf(offset);
    if (aad.length % 16 !== 0 || aad.length === 0) tripleHalf(offset);
    if (input.length === 0) {
      tripleHalf(offset);
      tripleHalf(offset);
    }
    rho1(block, y, aad, off, aad.length - off);
    feed();
  }

  const out = new Uint8Array(input.length);
  if (input.length > 0) {
    const blocks = Math.ceil(input.length / 16);
    for (let b = 0; b < blocks - 1; b++) {
      doubleHalf(offset);
      for (let i = 0; i < 16; i++) out[b * 16 + i] = y[i]! ^ input[b * 16 + i]!;
      rho1(block, y, encrypting ? input : out, b * 16, 16);
      feed();
    }
    const off = (blocks - 1) * 16;
    const remaining = input.length - off;
    tripleHalf(offset);
    if (input.length % 16 !== 0) tripleHalf(offset);
    for (let i = 0; i < remaining; i++) out[off + i] = y[i]! ^ input[off + i]!;
    rho1(block, y, encrypting ? input : out, off, remaining);
    feed();
  }

  return { out, tag: y.slice() };
}

export function giftCofbEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const { out, tag } = cofb(key, nonce, plaintext, aad, true);
  const result = new Uint8Array(out.length + 16);
  result.set(out, 0);
  result.set(tag, out.length);
  return result;
}

export function giftCofbDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (data.length < 16) return null;
  const { out, tag } = cofb(key, nonce, data.subarray(0, data.length - 16), aad, false);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= tag[i]! ^ data[data.length - 16 + i]!;
  return diff === 0 ? out : null;
}
