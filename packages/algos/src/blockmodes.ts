/**
 * The five classical modes of operation, over any block cipher.
 *
 * Written once rather than per cipher, and that is the whole reason this file exists: DES, 3DES, SM4,
 * Camellia and ARIA all arrive as a key schedule plus a 64- or 128-bit block permutation, and every
 * one of them then needs ECB, CBC, CFB, OFB and CTR on top. Five ciphers times five modes is
 * twenty-five implementations if the modes live with the cipher, and five plus five if they do not.
 * `@noble/ciphers` makes the same split -- its `ecb`/`cbc`/`ctr` are constructions over AES -- and
 * this is the same idea generalised to a cipher this repo supplies.
 *
 * Three decisions worth keeping.
 *
 * **The modes are checked against OpenSSL, not against themselves.** `tests/algos-blockciphers.test.ts`
 * runs every cipher through every mode against `node:crypto`, which is the only reason to trust a
 * hand-written CBC: a round-trip test passes just as happily when both halves share a mistake.
 *
 * **PKCS#7 unpadding validates.** Returning whatever the last byte claims would turn a wrong key into
 * silent garbage of a plausible length. It throws instead, with a message about the situation rather
 * than about the arithmetic -- the same rule the cipher family applies to noble's `aes: bad decrypt`.
 *
 * **CTR increments the whole block.** Some specifications treat part of the counter block as a fixed
 * nonce; OpenSSL's `-ctr` does not, and neither does this, so the two agree. A tool whose CTR
 * disagreed with `openssl enc` by a carry would be worse than no CTR at all.
 */

/** A block cipher, as a key schedule already applied. Both methods write into `dst`. */
export interface BlockCipher {
  /** 8 for DES and 3DES; 16 for SM4, Camellia, ARIA and AES. */
  readonly blockSize: number;
  encryptBlock(src: Uint8Array, dst: Uint8Array): void;
  decryptBlock(src: Uint8Array, dst: Uint8Array): void;
}

export type BlockMode = "ecb" | "cbc" | "cfb" | "ofb" | "ctr";

/** True for the modes that need whole blocks and therefore padding. */
export const modeNeedsPadding = (mode: BlockMode): boolean => mode === "ecb" || mode === "cbc";

/** True for the modes that take an IV. ECB is the one that does not, which is its whole problem. */
export const modeNeedsIv = (mode: BlockMode): boolean => mode !== "ecb";

function xorInto(dst: Uint8Array, a: Uint8Array, b: Uint8Array, length: number): void {
  for (let i = 0; i < length; i++) dst[i] = a[i]! ^ b[i]!;
}

/**
 * The padding schemes ECB and CBC can use, and nothing else here needs.
 *
 * Only those two modes pad at all. Every other mode over a block cipher either turns it into a
 * keystream -- CTR, OFB, CFB and the AEADs, where the ciphertext is the plaintext's length -- or
 * defines its own handling: XTS steals ciphertext so that a sector encrypts to exactly a sector, and
 * AES-KW/KWP carry RFC 3394/5649's own scheme. So `padding` is read only on the two block-aligned
 * modes and ignored elsewhere, which is a property of the modes rather than a simplification here.
 *
 * Four schemes, and the set is chosen rather than copied from a library:
 *
 * - **`pkcs7`** is the default and what everything interoperates on. RFC 5652 section 6.3.
 * - **`iso7816`** is ISO/IEC 9797-1 padding method 2 -- a single `0x80` then zeros. Real and current:
 *   it is what EMV and most smartcard traffic uses, and ISO 7816-4 is where most people meet it.
 * - **`x923`** is ANSI X9.23 -- zeros then a length byte in the final position.
 * - **`none`** does not pad, and therefore refuses an input that is not already whole blocks. It is
 *   also what reproduces NIST's SP 800-38A ECB and CBC examples, whose plaintexts are block-aligned
 *   and published unpadded.
 *
 * - **`pkcs5`** is the same algorithm as `pkcs7`, and is offered separately rather than hidden behind
 *   it. The first version of this list left it out on the grounds that two choices producing identical
 *   bytes is worse than one -- which is the opposite of what this repo does everywhere else: the
 *   checksum family lists LRC beside the two's-complement checksum, and BCC beside XOR, because the
 *   protocols name them separately, with `sameAs` making the result panel say the coincidence is
 *   expected. Somebody holding a Java `DES/CBC/PKCS5Padding` value wants to pick that name. Note
 *   PKCS#5 (RFC 8018) is formally defined only for an 8-byte block; every library extends it to wider
 *   ones by aliasing PKCS#7, which is what this does.
 * - **`zero`** fills with zero bytes. Padding is unambiguous; *unpadding* is not, because a plaintext
 *   ending in a zero byte cannot be told from a padded one -- so trailing zeros are stripped and `C009`
 *   says what that costs. Offered rather than refused on the family's usual reasoning: refuse only what
 *   an algorithm genuinely cannot do, and diagnose the rest. It is what CryptoJS's `ZeroPadding` does
 *   and what a good deal of embedded protocol traffic uses.
 * - **`iso10126`** writes random bytes and then the count. Withdrawn in 2007, and its filler makes
 *   *encryption* non-deterministic -- two runs over one input differ, which `C010` states. Decryption is
 *   perfectly determined, since the count is the last byte. The random bytes are injected rather than
 *   drawn here: this package has no platform globals and no dependencies, so the caller passes a
 *   generator and `padBlocks` refuses without one instead of falling back to something predictable.
 */
export type PaddingScheme =
  "pkcs7" | "pkcs5" | "iso7816" | "x923" | "iso10126" | "zero" | "none";

/**
 * A padded copy of `data`, or `data` itself under `"none"`.
 *
 * Every scheme here adds a **whole block** when the input is already aligned, for the reason PKCS#7's
 * own note gives: without it there is no way to tell a message that happens to end in a padding-shaped
 * byte from one that was padded. `"none"` is the exception and refuses instead.
 */
export function padBlocks(
  data: Uint8Array,
  blockSize: number,
  scheme: PaddingScheme = "pkcs7",
  /**
   * Random bytes, for ISO 10126 alone. Injected because this package has no platform globals and no
   * dependencies -- the cipher family passes `randomBytes` from `@ocs/engine`, which wraps
   * `crypto.getRandomValues`.
   *
   * Absent under any other scheme, and a throw rather than a zero-fill under ISO 10126: silently
   * padding with predictable bytes would be a different, weaker scheme wearing this one's name.
   */
  random?: (length: number) => Uint8Array,
): Uint8Array {
  if (scheme === "none") {
    if (data.length % blockSize !== 0) {
      throw new Error(
        `With padding set to None, the input has to be a whole number of ${blockSize}-byte blocks; this one is ${data.length} bytes. Choose a padding scheme, or trim the input.`,
      );
    }
    return data;
  }
  // PKCS#5 is this algorithm; see the note on `PaddingScheme`.
  if (scheme === "pkcs7" || scheme === "pkcs5") return padPkcs7(data, blockSize);

  const padding = blockSize - (data.length % blockSize);
  const out = new Uint8Array(data.length + padding);
  out.set(data);
  if (scheme === "iso7816") {
    // 0x80 then zeros. The zeros are already there; only the marker has to be written.
    out[data.length] = 0x80;
  } else if (scheme === "zero") {
    // Nothing to write: the buffer is already zero, which is the whole scheme.
  } else if (scheme === "iso10126") {
    if (!random) {
      throw new Error(
        "ISO 10126 pads with random bytes and no generator was supplied. This is a wiring error rather than something to act on -- padding with zeros instead would be a different scheme.",
      );
    }
    // Random filler, then the count. One draw of `padding - 1`, since the last byte is the count.
    out.set(random(padding - 1), data.length);
    out[out.length - 1] = padding;
  } else {
    // ANSI X9.23: zeros, then the count in the last byte.
    out[out.length - 1] = padding;
  }
  return out;
}

/**
 * The plaintext with its padding removed, validated.
 *
 * Validation is the point rather than a courtesy. Returning whatever the last byte claims would turn a
 * wrong key into a plausible short plaintext instead of an error, and the message here says which of
 * the two it almost always is -- the same reasoning `unpadPkcs7` already carries.
 */
export function unpadBlocks(
  data: Uint8Array,
  blockSize: number,
  scheme: PaddingScheme = "pkcs7",
): Uint8Array {
  if (scheme === "none") return data;
  if (scheme === "pkcs7" || scheme === "pkcs5") return unpadPkcs7(data, blockSize);
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error(
      `A padded ciphertext is a whole number of ${blockSize}-byte blocks; this one is ${data.length} bytes.`,
    );
  }

  const badPadding =
    "The padding is not valid, which almost always means the key or the IV is wrong rather than the data being corrupt.";

  if (scheme === "iso7816") {
    /*
     * Scan back over the zeros to the 0x80. Bounded by one block: the marker is always inside the
     * final block, so a longer run of zeros is corruption rather than padding to be believed.
     */
    let at = data.length - 1;
    const floor = data.length - blockSize;
    while (at >= floor && data[at] === 0x00) at--;
    if (at < floor || data[at] !== 0x80) throw new Error(badPadding);
    return data.slice(0, at);
  }

  if (scheme === "zero") {
    /*
     * Strip trailing zeros, which is what CryptoJS's `ZeroPadding` does and the only thing available.
     *
     * This is the one scheme here that cannot validate, and the one whose *removal* can be wrong: a
     * plaintext genuinely ending in zero bytes loses them, and nothing in the ciphertext says so. It is
     * not an error -- the operation succeeded and the answer may be short -- so there is nothing to
     * throw about, and `C009` is what tells the user before they rely on it. Bounded by one block: only
     * the final block can be padding, so a longer run of zeros is data.
     */
    let end = data.length;
    const floor = data.length - blockSize;
    while (end > floor && data[end - 1] === 0x00) end--;
    return data.slice(0, end);
  }

  // ANSI X9.23 and ISO 10126: the count is the last byte. X9.23 requires the bytes it covers to be
  // zero; ISO 10126's are random by design, so there is nothing there to check.
  const padding = data[data.length - 1]!;
  if (padding === 0 || padding > blockSize) throw new Error(badPadding);
  if (scheme === "x923") {
    for (let i = data.length - padding; i < data.length - 1; i++) {
      if (data[i] !== 0x00) throw new Error(badPadding);
    }
  }
  return data.slice(0, data.length - padding);
}

/**
 * PKCS#7, as RFC 5652 section 6.3 defines it.
 *
 * Note that a message which is already a whole number of blocks gains a *full* block of padding. That
 * is not waste, it is what makes the padding unambiguous: without it, a message ending in 0x01 could
 * not be told from one padded with a single byte.
 */
export function padPkcs7(data: Uint8Array, blockSize: number): Uint8Array {
  const padding = blockSize - (data.length % blockSize);
  const out = new Uint8Array(data.length + padding);
  out.set(data);
  out.fill(padding, data.length);
  return out;
}

export function unpadPkcs7(data: Uint8Array, blockSize: number): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error(
      `A padded ciphertext is a whole number of ${blockSize}-byte blocks; this one is ${data.length} bytes.`,
    );
  }
  const padding = data[data.length - 1]!;
  if (padding === 0 || padding > blockSize) {
    throw new Error(
      "The padding is not valid, which almost always means the key or the IV is wrong rather than the data being corrupt.",
    );
  }
  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) {
      throw new Error(
        "The padding is not valid, which almost always means the key or the IV is wrong rather than the data being corrupt.",
      );
    }
  }
  return data.slice(0, data.length - padding);
}

/** Big-endian increment of the whole counter block, wrapping at the top. */
function incrementCounter(counter: Uint8Array): void {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = (counter[i]! + 1) & 0xff;
    if (counter[i] !== 0) return;
  }
}

function assertIv(mode: BlockMode, iv: Uint8Array | undefined, blockSize: number): Uint8Array {
  if (!modeNeedsIv(mode)) return new Uint8Array(0);
  if (!iv || iv.length !== blockSize) {
    throw new Error(
      `${mode.toUpperCase()} needs an IV of exactly ${blockSize} bytes; this one is ${iv?.length ?? 0}.`,
    );
  }
  return iv;
}

export interface ModeOptions {
  /** Required by every mode but ECB, and exactly one block long. */
  iv?: Uint8Array;
  /**
   * Which padding ECB and CBC use. Defaults to PKCS#7; ignored by every other mode, which never pads.
   *
   * Replaced a `noPadding` boolean. `"none"` is what that meant, and it is still how NIST's SP 800-38A
   * ECB and CBC examples are reproduced -- their plaintexts are block-aligned and published unpadded.
   * A boolean plus a scheme would have been two ways to say the same thing, which is the drift this
   * repo keeps finding in mirrored metadata.
   */
  padding?: PaddingScheme;
  /** Random bytes for ISO 10126's filler; see `padBlocks`. Unused by every other scheme. */
  random?: (length: number) => Uint8Array;
}

export function encryptBlockMode(
  cipher: BlockCipher,
  mode: BlockMode,
  data: Uint8Array,
  options: ModeOptions = {},
): Uint8Array {
  const size = cipher.blockSize;
  const iv = assertIv(mode, options.iv, size);

  if (mode === "ecb" || mode === "cbc") {
    // `padBlocks` refuses an unaligned input under "none" and names the way out, so the length check
    // that used to sit here would now be unreachable.
    const padded = padBlocks(data, size, options.padding, options.random);
    const out = new Uint8Array(padded.length);
    const block = new Uint8Array(size);
    let previous = iv;
    for (let offset = 0; offset < padded.length; offset += size) {
      const chunk = padded.subarray(offset, offset + size);
      if (mode === "cbc") xorInto(block, chunk, previous, size);
      else block.set(chunk);
      const target = out.subarray(offset, offset + size);
      cipher.encryptBlock(block, target);
      if (mode === "cbc") previous = target;
    }
    return out;
  }

  // The three stream modes. All produce output the length of the input, and all differ only in what
  // is fed into the block function next.
  const out = new Uint8Array(data.length);
  const state = Uint8Array.from(iv);
  const keystream = new Uint8Array(size);

  for (let offset = 0; offset < data.length; offset += size) {
    const length = Math.min(size, data.length - offset);
    cipher.encryptBlock(state, keystream);
    for (let i = 0; i < length; i++) out[offset + i] = data[offset + i]! ^ keystream[i]!;

    if (mode === "ofb") state.set(keystream);
    else if (mode === "ctr") incrementCounter(state);
    // CFB feeds the *ciphertext* forward, which is what makes it self-synchronising and what makes a
    // truncated final block still decryptable.
    else state.set(out.subarray(offset, offset + length), 0);
  }
  return out;
}

export function decryptBlockMode(
  cipher: BlockCipher,
  mode: BlockMode,
  data: Uint8Array,
  options: ModeOptions = {},
): Uint8Array {
  const size = cipher.blockSize;
  const iv = assertIv(mode, options.iv, size);

  if (mode === "ecb" || mode === "cbc") {
    if (data.length === 0 || data.length % size !== 0) {
      throw new Error(
        `${mode.toUpperCase()} ciphertext is a whole number of ${size}-byte blocks; this one is ${data.length} bytes.`,
      );
    }
    const out = new Uint8Array(data.length);
    const plain = new Uint8Array(size);
    let previous = iv;
    for (let offset = 0; offset < data.length; offset += size) {
      const chunk = data.subarray(offset, offset + size);
      cipher.decryptBlock(chunk, plain);
      if (mode === "cbc") {
        xorInto(out.subarray(offset, offset + size), plain, previous, size);
        // A copy, not a reference: `chunk` aliases the caller's buffer, which the loop does not own.
        previous = Uint8Array.from(chunk);
      } else out.set(plain, offset);
    }
    return unpadBlocks(out, size, options.padding);
  }

  if (mode === "ofb" || mode === "ctr") {
    // Symmetric: the keystream does not depend on the data, so decryption is encryption.
    return encryptBlockMode(cipher, mode, data, options);
  }

  // CFB decrypt still uses the *forward* block function -- the cipher is only ever used to make
  // keystream -- but feeds the ciphertext forward from the input rather than the output.
  const out = new Uint8Array(data.length);
  const state = Uint8Array.from(iv);
  const keystream = new Uint8Array(size);

  for (let offset = 0; offset < data.length; offset += size) {
    const length = Math.min(size, data.length - offset);
    cipher.encryptBlock(state, keystream);
    for (let i = 0; i < length; i++) out[offset + i] = data[offset + i]! ^ keystream[i]!;
    state.set(data.subarray(offset, offset + length), 0);
  }
  return out;
}
