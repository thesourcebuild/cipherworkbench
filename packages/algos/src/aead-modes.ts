/**
 * GCM and CCM over any `BlockCipher`, and the reason both are written here rather than imported.
 *
 * `@noble/ciphers` gives AES-GCM and nothing else authenticated over a *different* cipher, so
 * SM4-GCM -- which RFC 8998 specifies for TLS 1.3 alongside SM3 -- and ARIA-GCM/CCM, which OpenSSL
 * has and this app could not previously reproduce, both needed a mode layer of their own. Written
 * once over the `BlockCipher` interface, they apply to all five ciphers `blockmodes.ts` already
 * serves, exactly as ECB and CBC do.
 *
 * Five things to know before touching this.
 *
 * **Both take a 16-byte block and nothing else.** GCM's field arithmetic and CCM's length encoding
 * are both defined only for 128-bit blocks, so DES and 3DES are excluded by the algorithm rather
 * than by choice -- the constructors say so instead of producing something plausible.
 *
 * **GCM's nonce has a fast path and a general one.** A 12-byte nonce becomes `IV || 0x00000001`
 * directly; any other length is hashed through GHASH first. Almost every deployment uses 12 bytes,
 * which means the general path is the one that goes untested unless a test asks for it -- so the
 * tests use both.
 *
 * **CCM's tag length and nonce length trade against each other.** The nonce is `15 - L` bytes where
 * `L` is the number of bytes used to encode the message length, so a 13-byte nonce caps the message
 * at 2^16 bytes and a 7-byte nonce allows 2^64. That is not a quirk to hide: 802.15.4 and WPA2 use
 * 13-byte nonces precisely because their frames are small, and TLS uses 12.
 *
 * **CCM is not online.** The length of the message goes into the first MAC block, so nothing can be
 * authenticated until the total is known. That is a property of the construction -- it is why the
 * cipher family reports `streaming: false` for every AEAD -- and not something an implementation can
 * arrange around.
 *
 * **The oracle is `node:crypto`.** `aes-*-ccm`, `aes-*-gcm`, `aria-*-ccm` and `aria-*-gcm` are all
 * available there, so `tests/algos-aead-modes.test.ts` compares every mode against OpenSSL at a
 * spread of nonce, tag, message and associated-data lengths. SM4-GCM has no OpenSSL name here and is
 * checked against RFC 8998's own vectors instead.
 */
import type { BlockCipher } from "./blockmodes";
import { Ghash } from "./ghash";

const BLOCK = 16;

/** Tag lengths CCM permits: even, 4 to 16 bytes. */
export const CCM_TAG_LENS: readonly number[] = [4, 6, 8, 10, 12, 14, 16];
/** Nonce lengths CCM permits: 7 to 13 bytes. */
export const CCM_NONCE_LENS: readonly number[] = [7, 8, 9, 10, 11, 12, 13];

function require128(cipher: BlockCipher, mode: string): void {
  if (cipher.blockSize !== BLOCK) {
    throw new Error(
      `${mode} is defined only for 128-bit blocks; this cipher's is ${cipher.blockSize * 8}.`,
    );
  }
}

function xorInto(target: Uint8Array, other: Uint8Array, count = other.length): void {
  for (let i = 0; i < count; i++) target[i] = target[i]! ^ other[i]!;
}

/** Constant-time tag comparison. */
function tagsMatch(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// ── GCM ─────────────────────────────────────────────────────────────────────

/** Counter-mode encryption starting from `counter`, which is advanced in place. */
function gctr(cipher: BlockCipher, counter: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  const keystream = new Uint8Array(BLOCK);

  for (let at = 0; at < data.length; at += BLOCK) {
    cipher.encryptBlock(counter, keystream);
    const take = Math.min(BLOCK, data.length - at);
    for (let i = 0; i < take; i++) out[at + i] = data[at + i]! ^ keystream[i]!;
    // The counter is the low 32 bits only, big-endian, wrapping -- not the whole block, which is
    // what plain CTR does. Incrementing the wrong width is invisible until the 2^32nd block.
    for (let i = BLOCK - 1; i >= BLOCK - 4; i--) {
      counter[i] = (counter[i]! + 1) & 0xff;
      if (counter[i] !== 0) break;
    }
  }
  return out;
}

/** A 64-bit big-endian length in bits, for GCM's final length block. */
function lengthBlock(adLen: number, ctLen: number): Uint8Array {
  const out = new Uint8Array(BLOCK);
  const write = (at: number, bytes: number) => {
    let bits = bytes * 8;
    for (let i = 7; i >= 0; i--) {
      out[at + i] = bits % 256;
      bits = Math.floor(bits / 256);
    }
  };
  write(0, adLen);
  write(8, ctLen);
  return out;
}

interface GcmParts {
  hashKey: Uint8Array;
  j0: Uint8Array;
}

function gcmSetup(cipher: BlockCipher, nonce: Uint8Array): GcmParts {
  if (nonce.length === 0) throw new Error("GCM needs a nonce of at least one byte.");

  const hashKey = new Uint8Array(BLOCK);
  cipher.encryptBlock(new Uint8Array(BLOCK), hashKey);

  const j0 = new Uint8Array(BLOCK);
  if (nonce.length === 12) {
    // The fast path every deployment uses: the nonce, then a counter of 1.
    j0.set(nonce);
    j0[15] = 1;
  } else {
    /**
     * The general path: hash the nonce with its own length block.
     *
     * Reachable only for a nonce that is not 12 bytes, which is rare enough that an implementation can
     * get it wrong and pass every test written against a real protocol. GCM's security argument also
     * weakens here -- two different nonces can hash to the same J0 -- which is why 96 bits is the
     * recommended width rather than merely the common one.
     */
    const hash = new Ghash(hashKey);
    hash.update(nonce);
    hash.update(lengthBlock(0, nonce.length));
    j0.set(hash.digest());
  }
  return { hashKey, j0 };
}

function gcmTag(
  cipher: BlockCipher,
  parts: GcmParts,
  ad: Uint8Array,
  ciphertext: Uint8Array,
  tagLen: number,
): Uint8Array {
  const hash = new Ghash(parts.hashKey);
  hash.update(ad);
  hash.update(ciphertext);
  hash.update(lengthBlock(ad.length, ciphertext.length));

  const counter = Uint8Array.from(parts.j0);
  return gctr(cipher, counter, hash.digest()).subarray(0, tagLen);
}

/** GCM encryption; the tag is appended, as every wire format does it. */
export function gcmEncrypt(
  cipher: BlockCipher,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array {
  require128(cipher, "GCM");
  const parts = gcmSetup(cipher, nonce);

  const counter = Uint8Array.from(parts.j0);
  // Encryption starts at J0 + 1; J0 itself is reserved for the tag.
  for (let i = BLOCK - 1; i >= BLOCK - 4; i--) {
    counter[i] = (counter[i]! + 1) & 0xff;
    if (counter[i] !== 0) break;
  }

  const ciphertext = gctr(cipher, counter, plaintext);
  const tag = gcmTag(cipher, parts, ad, ciphertext, tagLen);

  const out = new Uint8Array(ciphertext.length + tag.length);
  out.set(ciphertext, 0);
  out.set(tag, ciphertext.length);
  return out;
}

/** GCM decryption. Returns `null` when the tag does not verify; nothing partial escapes. */
export function gcmDecrypt(
  cipher: BlockCipher,
  nonce: Uint8Array,
  sealed: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array | null {
  require128(cipher, "GCM");
  if (sealed.length < tagLen) return null;

  const split = sealed.length - tagLen;
  const ciphertext = sealed.subarray(0, split);
  const parts = gcmSetup(cipher, nonce);
  const expected = gcmTag(cipher, parts, ad, ciphertext, tagLen);
  if (!tagsMatch(expected, sealed.subarray(split))) return null;

  const counter = Uint8Array.from(parts.j0);
  for (let i = BLOCK - 1; i >= BLOCK - 4; i--) {
    counter[i] = (counter[i]! + 1) & 0xff;
    if (counter[i] !== 0) break;
  }
  return gctr(cipher, counter, ciphertext);
}

// ── CCM ─────────────────────────────────────────────────────────────────────

function ccmCheck(nonce: Uint8Array, tagLen: number, messageLen: number): number {
  if (!CCM_NONCE_LENS.includes(nonce.length)) {
    throw new Error(`CCM's nonce is 7 to 13 bytes; this one is ${nonce.length}.`);
  }
  if (!CCM_TAG_LENS.includes(tagLen)) {
    throw new Error(`CCM's tag is an even 4 to 16 bytes; ${tagLen} was requested.`);
  }

  // L is what is left of the block after the flags and the nonce, and it bounds the message.
  const l = 15 - nonce.length;
  const max = l >= 8 ? Number.MAX_SAFE_INTEGER : 2 ** (8 * l) - 1;
  if (messageLen > max) {
    throw new Error(
      `A ${nonce.length}-byte nonce leaves ${l} bytes for the length, which caps the message at ${max} bytes; this one is ${messageLen}.`,
    );
  }
  return l;
}

/** The formatted first MAC block, SP 800-38C's B0. */
function ccmFirstBlock(
  nonce: Uint8Array,
  tagLen: number,
  messageLen: number,
  hasAd: boolean,
  l: number,
): Uint8Array {
  const b0 = new Uint8Array(BLOCK);
  b0[0] = (hasAd ? 0x40 : 0) | (((tagLen - 2) / 2) << 3) | (l - 1);
  b0.set(nonce, 1);
  let remaining = messageLen;
  for (let i = BLOCK - 1; i >= BLOCK - l; i--) {
    b0[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return b0;
}

/** The associated data's length prefix, whose width depends on how much there is. */
function ccmAdPrefix(length: number): Uint8Array {
  if (length < 0xff00) {
    return Uint8Array.of((length >>> 8) & 0xff, length & 0xff);
  }
  if (length <= 0xffff_ffff) {
    return Uint8Array.of(
      0xff,
      0xfe,
      (length >>> 24) & 0xff,
      (length >>> 16) & 0xff,
      (length >>> 8) & 0xff,
      length & 0xff,
    );
  }
  const out = new Uint8Array(10);
  out[0] = 0xff;
  out[1] = 0xff;
  let remaining = length;
  for (let i = 9; i >= 2; i--) {
    out[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return out;
}

/** The CBC-MAC over the formatted blocks: B0, then the AAD, then the message, each zero-padded. */
function ccmMac(
  cipher: BlockCipher,
  nonce: Uint8Array,
  ad: Uint8Array,
  message: Uint8Array,
  tagLen: number,
  l: number,
): Uint8Array {
  const y = new Uint8Array(BLOCK);
  const scratch = new Uint8Array(BLOCK);

  const absorb = (block: Uint8Array) => {
    xorInto(y, block, BLOCK);
    cipher.encryptBlock(y, scratch);
    y.set(scratch);
  };

  absorb(ccmFirstBlock(nonce, tagLen, message.length, ad.length > 0, l));

  if (ad.length > 0) {
    const prefix = ccmAdPrefix(ad.length);
    const total = prefix.length + ad.length;
    const padded = new Uint8Array(Math.ceil(total / BLOCK) * BLOCK);
    padded.set(prefix, 0);
    padded.set(ad, prefix.length);
    for (let at = 0; at < padded.length; at += BLOCK) absorb(padded.subarray(at, at + BLOCK));
  }

  for (let at = 0; at < message.length; at += BLOCK) {
    const block = new Uint8Array(BLOCK);
    block.set(message.subarray(at, Math.min(at + BLOCK, message.length)));
    absorb(block);
  }

  return y.subarray(0, tagLen);
}

/** Counter block A_i, which shares the nonce with B0 but carries a different flags byte. */
function ccmCounter(nonce: Uint8Array, l: number, index: number): Uint8Array {
  const a = new Uint8Array(BLOCK);
  a[0] = l - 1;
  a.set(nonce, 1);
  let remaining = index;
  for (let i = BLOCK - 1; i >= BLOCK - l; i--) {
    a[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return a;
}

function ccmCrypt(
  cipher: BlockCipher,
  nonce: Uint8Array,
  data: Uint8Array,
  l: number,
): Uint8Array {
  const out = new Uint8Array(data.length);
  const keystream = new Uint8Array(BLOCK);
  for (let at = 0, index = 1; at < data.length; at += BLOCK, index++) {
    cipher.encryptBlock(ccmCounter(nonce, l, index), keystream);
    const take = Math.min(BLOCK, data.length - at);
    for (let i = 0; i < take; i++) out[at + i] = data[at + i]! ^ keystream[i]!;
  }
  return out;
}

/** CCM encryption; the tag is appended. */
export function ccmEncrypt(
  cipher: BlockCipher,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array {
  require128(cipher, "CCM");
  const l = ccmCheck(nonce, tagLen, plaintext.length);

  const mac = ccmMac(cipher, nonce, ad, plaintext, tagLen, l);
  const ciphertext = ccmCrypt(cipher, nonce, plaintext, l);

  // The tag is the MAC encrypted under counter zero, which is the block CTR encryption skips.
  const s0 = new Uint8Array(BLOCK);
  cipher.encryptBlock(ccmCounter(nonce, l, 0), s0);
  const tag = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) tag[i] = mac[i]! ^ s0[i]!;

  const out = new Uint8Array(ciphertext.length + tagLen);
  out.set(ciphertext, 0);
  out.set(tag, ciphertext.length);
  return out;
}

/** CCM decryption. Returns `null` when the tag does not verify. */
export function ccmDecrypt(
  cipher: BlockCipher,
  nonce: Uint8Array,
  sealed: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array | null {
  require128(cipher, "CCM");
  if (sealed.length < tagLen) return null;

  const split = sealed.length - tagLen;
  const l = ccmCheck(nonce, tagLen, split);
  const plaintext = ccmCrypt(cipher, nonce, sealed.subarray(0, split), l);

  const mac = ccmMac(cipher, nonce, ad, plaintext, tagLen, l);
  const s0 = new Uint8Array(BLOCK);
  cipher.encryptBlock(ccmCounter(nonce, l, 0), s0);
  const expected = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) expected[i] = mac[i]! ^ s0[i]!;

  if (!tagsMatch(expected, sealed.subarray(split))) {
    plaintext.fill(0);
    return null;
  }
  return plaintext;
}
