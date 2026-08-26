/**
 * OCB3, from RFC 7253, over any 128-bit `BlockCipher`.
 *
 * The fastest AEAD that is not built on AES-NI-specific tricks -- one block-cipher call per block and
 * nothing else, where GCM needs a field multiplication as well -- and free of patents since 2021, which
 * is why it is worth having now and was not before. OpenSSL has it (`aes-*-ocb`) and
 * `@noble/ciphers` does not.
 *
 * Six things to know before touching this, because OCB has more moving parts than any other mode here.
 *
 * **`double` shifts the other way from XTS.** OCB's doubling is big-endian -- shift left, and fold
 * `0x87` into the *last* byte when the top bit falls off -- where XTS's tweak update is little-endian
 * and folds into the first. Two modes, two conventions, and this repo now implements both; keeping them
 * in separate files is deliberate.
 *
 * **The offsets are a Gray-code walk, not a counter.** `Offset_i = Offset_{i-1} XOR L_{ntz(i)}`, where
 * `ntz` counts trailing zeros. That is what makes OCB one cipher call per block: the offset for block i
 * costs a single XOR. An implementation that recomputed offsets from scratch would be correct and slow;
 * one that used `i` instead of `ntz(i)` would be neither.
 *
 * **The nonce becomes a bit-shifted window.** `Stretch` is 24 bytes, and `Offset_0` is the 128 bits
 * starting at bit `bottom + 1` where `bottom` is the low 6 bits of the formatted nonce. So for 63 of 64
 * nonces the offset does not begin on a byte boundary. This is the part that goes wrong silently: a
 * byte-aligned shortcut is right for one nonce in 64 and wrong for the rest, which a single test vector
 * may well not catch. The tests therefore walk many nonces.
 *
 * **The tag length is baked into the nonce.** `num2str(taglen*8 mod 128, 7)` is the first seven bits of
 * the formatted nonce, so a 12-byte tag and a 16-byte tag give different *ciphertext*, not merely a
 * shorter tag. Truncating a 16-byte OCB tag does not produce the 12-byte-tag output.
 *
 * **The checksum pads with 0x80, not with zeros.** A partial final block contributes `P_* || 1 || 0*`
 * to the checksum -- the same one-then-zeros padding the associated-data hash uses for its own short
 * block.
 *
 * **It is one-shot.** The associated-data hash and the message walk are independent, but the tag needs
 * both, so nothing is authenticated until the end -- as with every AEAD here.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;

/** OCB's doubling: shift left one bit, reduce with 0x87 into the last byte. */
function double(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  const carry = src[0]! >>> 7;
  for (let i = 0; i < BLOCK - 1; i++) {
    out[i] = ((src[i]! << 1) | (src[i + 1]! >>> 7)) & 0xff;
  }
  out[BLOCK - 1] = ((src[BLOCK - 1]! << 1) ^ (carry ? 0x87 : 0)) & 0xff;
  return out;
}

const xorInto = (target: Uint8Array, other: Uint8Array, count = BLOCK): void => {
  for (let i = 0; i < count; i++) target[i] = target[i]! ^ other[i]!;
};

/** Trailing zeros of a positive integer -- the index into the L table for block `i`. */
function ntz(value: number): number {
  let count = 0;
  let n = value;
  while ((n & 1) === 0) {
    count += 1;
    n >>>= 1;
  }
  return count;
}

interface OcbKeys {
  lStar: Uint8Array;
  lDollar: Uint8Array;
  l: Uint8Array[];
}

function setup(cipher: BlockCipher, blocks: number): OcbKeys {
  if (cipher.blockSize !== BLOCK) {
    throw new Error(`OCB is defined only for 128-bit blocks; this cipher's is ${cipher.blockSize * 8}.`);
  }
  const lStar = new Uint8Array(BLOCK);
  cipher.encryptBlock(new Uint8Array(BLOCK), lStar);
  const lDollar = double(lStar);

  const l: Uint8Array[] = [double(lDollar)];
  // One entry per doubling actually needed: ntz never exceeds log2 of the block count.
  const depth = Math.max(1, Math.ceil(Math.log2(blocks + 2)) + 1);
  while (l.length < depth) l.push(double(l[l.length - 1]!));

  return { lStar, lDollar, l };
}

/** `Offset_0`, from the formatted nonce and its bit-shifted stretch. */
function initialOffset(cipher: BlockCipher, nonce: Uint8Array, tagLen: number): Uint8Array {
  if (nonce.length === 0 || nonce.length > 15) {
    throw new Error(`OCB's nonce is 1 to 15 bytes; this one is ${nonce.length}.`);
  }

  const formatted = new Uint8Array(BLOCK);
  formatted[0] = ((tagLen * 8) % 128) << 1;
  // A single 1 bit immediately before the nonce, which is what makes nonces of different lengths
  // unambiguous rather than merely zero-padded.
  const markerAt = BLOCK - nonce.length - 1;
  formatted[markerAt] = (formatted[markerAt]! | 1) & 0xff;
  formatted.set(nonce, BLOCK - nonce.length);

  const bottom = formatted[BLOCK - 1]! & 0x3f;
  const top = Uint8Array.from(formatted);
  top[BLOCK - 1] = top[BLOCK - 1]! & 0xc0;

  const ktop = new Uint8Array(BLOCK);
  cipher.encryptBlock(top, ktop);

  const stretch = new Uint8Array(BLOCK + 8);
  stretch.set(ktop, 0);
  for (let i = 0; i < 8; i++) stretch[BLOCK + i] = ktop[i]! ^ ktop[i + 1]!;

  // Offset_0 is the 128-bit window of Stretch beginning at bit `bottom`.
  const offset = new Uint8Array(BLOCK);
  const byteShift = bottom >>> 3;
  const bitShift = bottom & 7;
  for (let i = 0; i < BLOCK; i++) {
    const hi = stretch[byteShift + i]!;
    const lo = stretch[byteShift + i + 1] ?? 0;
    offset[i] = bitShift === 0 ? hi : ((hi << bitShift) | (lo >>> (8 - bitShift))) & 0xff;
  }
  return offset;
}

/** RFC 7253's HASH: the associated data folded into one block. */
function hashAd(cipher: BlockCipher, keys: OcbKeys, ad: Uint8Array): Uint8Array {
  const sum = new Uint8Array(BLOCK);
  const offset = new Uint8Array(BLOCK);
  const scratch = new Uint8Array(BLOCK);
  const encrypted = new Uint8Array(BLOCK);

  const whole = Math.floor(ad.length / BLOCK);
  for (let block = 1; block <= whole; block++) {
    xorInto(offset, keys.l[ntz(block)]!);
    scratch.set(ad.subarray((block - 1) * BLOCK, block * BLOCK));
    xorInto(scratch, offset);
    cipher.encryptBlock(scratch, encrypted);
    xorInto(sum, encrypted);
  }

  const remainder = ad.length % BLOCK;
  if (remainder > 0) {
    xorInto(offset, keys.lStar);
    scratch.fill(0);
    scratch.set(ad.subarray(whole * BLOCK));
    // One-then-zeros padding, the same rule the message checksum uses.
    scratch[remainder] = 0x80;
    xorInto(scratch, offset);
    cipher.encryptBlock(scratch, encrypted);
    xorInto(sum, encrypted);
  }

  return sum;
}

function run(
  cipher: BlockCipher,
  nonce: Uint8Array,
  data: Uint8Array,
  ad: Uint8Array,
  tagLen: number,
  encrypt: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  if (tagLen < 1 || tagLen > BLOCK) {
    throw new Error(`OCB's tag is 1 to 16 bytes; ${tagLen} was requested.`);
  }

  const whole = Math.floor(data.length / BLOCK);
  const remainder = data.length % BLOCK;
  const keys = setup(cipher, whole);
  const offset = initialOffset(cipher, nonce, tagLen);
  const checksum = new Uint8Array(BLOCK);
  const out = new Uint8Array(data.length);
  const scratch = new Uint8Array(BLOCK);
  const result = new Uint8Array(BLOCK);

  for (let block = 1; block <= whole; block++) {
    const at = (block - 1) * BLOCK;
    xorInto(offset, keys.l[ntz(block)]!);

    scratch.set(data.subarray(at, at + BLOCK));
    xorInto(scratch, offset);
    if (encrypt) {
      // The checksum is over the *plaintext* in both directions, which is why decryption adds to it
      // after recovering the block rather than before.
      xorInto(checksum, data.subarray(at, at + BLOCK));
      cipher.encryptBlock(scratch, result);
    } else {
      cipher.decryptBlock(scratch, result);
    }
    xorInto(result, offset);
    out.set(result, at);
    if (!encrypt) xorInto(checksum, result);
  }

  if (remainder > 0) {
    xorInto(offset, keys.lStar);
    const pad = new Uint8Array(BLOCK);
    cipher.encryptBlock(offset, pad);

    const at = whole * BLOCK;
    for (let i = 0; i < remainder; i++) out[at + i] = data[at + i]! ^ pad[i]!;

    // Checksum over the plaintext tail with one-then-zeros padding.
    const tail = new Uint8Array(BLOCK);
    tail.set((encrypt ? data : out).subarray(at, at + remainder));
    tail[remainder] = 0x80;
    xorInto(checksum, tail);
  }

  xorInto(checksum, offset);
  xorInto(checksum, keys.lDollar);
  const tag = new Uint8Array(BLOCK);
  cipher.encryptBlock(checksum, tag);
  xorInto(tag, hashAd(cipher, keys, ad));

  return { out, tag: tag.subarray(0, tagLen) };
}

/** OCB encryption; the tag is appended. */
export function ocbEncrypt(
  cipher: BlockCipher,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array {
  const { out, tag } = run(cipher, nonce, plaintext, ad, tagLen, true);
  const sealed = new Uint8Array(out.length + tag.length);
  sealed.set(out, 0);
  sealed.set(tag, out.length);
  return sealed;
}

/** OCB decryption. Returns `null` when the tag does not verify. */
export function ocbDecrypt(
  cipher: BlockCipher,
  nonce: Uint8Array,
  sealed: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array | null {
  if (sealed.length < tagLen) return null;
  const split = sealed.length - tagLen;
  const { out, tag } = run(cipher, nonce, sealed.subarray(0, split), ad, tagLen, false);

  let diff = 0;
  for (let i = 0; i < tagLen; i++) diff |= tag[i]! ^ sealed[split + i]!;
  if (diff !== 0) {
    out.fill(0);
    return null;
  }
  return out;
}
