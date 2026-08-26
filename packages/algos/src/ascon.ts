/**
 * Ascon: the NIST lightweight cryptography standard, SP 800-232 (2025).
 *
 * Three constructions over one 320-bit permutation -- Ascon-Hash256, Ascon-XOF128 and the
 * Ascon-AEAD128 cipher. NIST selected Ascon in 2023 as the lightweight counterpart to AES-GCM and
 * SHA-256, for constrained devices and for anything that wants one primitive to do both jobs. No
 * library in this project's dependency tree implements it.
 *
 * Five things to know before touching this.
 *
 * **The words are little-endian, which is unusual for a sponge.** Byte i of an 8-byte block sits at
 * bit 8i of the 64-bit word, so a partial block occupies the *low* bytes and the padding bit lands at
 * `0x01 << 8n`. Keccak does the same and SHA-2 does the opposite; guessing here produces a hash that
 * is stable, self-consistent and wrong.
 *
 * **The state is ten 32-bit halves, not five bigints.** A sponge with an 8-byte rate runs twelve
 * rounds per eight bytes of message, so this is the hottest code in the repo per byte of input --
 * `bigint` here would cost roughly an order of magnitude and, unlike XXH3, there is no simplicity to
 * buy with it, because every operation is bitwise and splits cleanly across halves.
 *
 * **The initialising values encode the parameters.** SP 800-232 builds each IV from the variant
 * number, the round counts, the output size and the rate rather than picking arbitrary constants --
 * which is why they are written out as that arithmetic below instead of as three magic numbers. It
 * also means Ascon v1.2's IVs, which many older implementations and blog posts carry, are different
 * values: an implementation checked only against a round trip cannot tell.
 *
 * **AEAD128 has a 16-byte rate and the hash an 8-byte one**, so the cipher absorbs into x0 *and* x1
 * while the hash uses x0 alone. Same permutation, different sponges.
 *
 * **The check is the reference KAT, not a hand-picked vector.** `tests/algos-ascon.test.ts` runs a
 * few hundred of the official known-answer values from the Ascon team's `ascon-c` repository, across
 * every message length that crosses a rate boundary. There is no OpenSSL or WASM oracle for Ascon
 * anywhere here, so breadth of published vectors is the substitute -- see the top of `xxhash3.ts` for
 * why that beats four hand-written values.
 */

export const ASCON_HASH_LEN = 32;
export const ASCON_AEAD_KEY_LEN = 16;
export const ASCON_AEAD_NONCE_LEN = 16;
export const ASCON_AEAD_TAG_LEN = 16;

/** The sponge rates, in bytes. */
const HASH_RATE = 8;
const AEAD_RATE = 16;
/** Ascon-PRF absorbs 32 bytes at a time and squeezes 16 -- wider in both directions than the hash. */
const PRF_IN_RATE = 32;
const PRF_OUT_RATE = 16;

/**
 * The round constants of p12, applied to the low byte of x2.
 *
 * p8 is the last eight of these and p6 the last six -- the permutation is the same, started later,
 * which is what makes a shorter permutation safe to reuse.
 */
const ROUND_CONSTANTS = [
  0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
] as const;

/**
 * A 64-bit initialising value as `[hi, lo]`, assembled from SP 800-232's parameter encoding.
 *
 * `variant | rounds_a << 16 | rounds_b << 20 | outputBits << 24 | rate << 40`, where the fields above
 * bit 32 land in the high half.
 */
function iv(
  variant: number,
  roundsA: number,
  roundsB: number,
  outputBits: number,
  rate: number,
  outRate = 0,
) {
  /**
   * `outputBits << 24` is computed in floating point on purpose.
   *
   * The field straddles bit 32: 128 << 24 is 2^31 and lands in the low half, while 256 << 24 is
   * exactly 2^32 and lands in the high half -- and JavaScript's `<<` is a 32-bit operation, so
   * `256 << 24` evaluates to zero. That silently produced a hash IV with the output size missing.
   */
  const output = outputBits * 0x100_0000;
  const lo = (variant | (roundsA << 16) | (roundsB << 20) | (output % 0x1_0000_0000)) >>> 0;
  // `rate << 40` and `outRate << 48` both live entirely in the high half, at bits 8 and 16 of it.
  const hi =
    (Math.floor(output / 0x1_0000_0000) + rate * 0x100 + outRate * 0x1_0000) >>> 0;
  return [hi, lo] as const;
}

// Variant numbers from SP 800-232: 1 is AEAD, 2 is Hash, 3 is XOF. The keyed modes below carry 5, 6
// and 7, from the Ascon v1.3 submission -- see the note above `asconMac`.
const IV_AEAD128 = iv(1, 12, 8, ASCON_AEAD_TAG_LEN * 8, AEAD_RATE);
const IV_HASH256 = iv(2, 12, 12, ASCON_HASH_LEN * 8, HASH_RATE);
const IV_XOF128 = iv(3, 12, 12, 0, HASH_RATE);
const IV_MAC = iv(5, 12, 12, ASCON_AEAD_TAG_LEN * 8, PRF_IN_RATE, PRF_OUT_RATE);
const IV_PRF = iv(6, 12, 12, 0, PRF_IN_RATE, PRF_OUT_RATE);
const IV_PRF_SHORT = iv(7, 12, 0, ASCON_AEAD_TAG_LEN * 8, 0);

/**
 * The 320-bit state: x0..x4, each as a low half at `2i` and a high half at `2i + 1`.
 *
 * Two entries per word rather than two arrays, so one allocation holds the whole state and the
 * permutation touches one object.
 */
type State = Uint32Array;

const rorHi = (hi: number, lo: number, n: number): number =>
  n < 32 ? ((hi >>> n) | (lo << (32 - n))) >>> 0 : ((lo >>> (n - 32)) | (hi << (64 - n))) >>> 0;

const rorLo = (hi: number, lo: number, n: number): number =>
  n < 32 ? ((lo >>> n) | (hi << (32 - n))) >>> 0 : ((hi >>> (n - 32)) | (lo << (64 - n))) >>> 0;

/**
 * The Ascon permutation, `rounds` rounds ending at the last constant.
 *
 * Written out in locals rather than looping over the state array: ten reads and ten writes per round
 * instead of a hundred, and the substitution layer reads every word after every other word has been
 * modified, which is far easier to check against the specification in this form.
 */
function permute(s: State, rounds: number): void {
  let x0l = s[0]!;
  let x0h = s[1]!;
  let x1l = s[2]!;
  let x1h = s[3]!;
  let x2l = s[4]!;
  let x2h = s[5]!;
  let x3l = s[6]!;
  let x3h = s[7]!;
  let x4l = s[8]!;
  let x4h = s[9]!;

  for (let r = ROUND_CONSTANTS.length - rounds; r < ROUND_CONSTANTS.length; r++) {
    // Round constant, into the low byte of x2.
    x2l = (x2l ^ ROUND_CONSTANTS[r]!) >>> 0;

    // Substitution layer: the 5-bit chi S-box, bitsliced across the five words.
    x0l ^= x4l;
    x0h ^= x4h;
    x4l ^= x3l;
    x4h ^= x3h;
    x2l ^= x1l;
    x2h ^= x1h;

    const t0l = x0l ^ (~x1l & x2l);
    const t0h = x0h ^ (~x1h & x2h);
    const t1l = x1l ^ (~x2l & x3l);
    const t1h = x1h ^ (~x2h & x3h);
    const t2l = x2l ^ (~x3l & x4l);
    const t2h = x2h ^ (~x3h & x4h);
    const t3l = x3l ^ (~x4l & x0l);
    const t3h = x3h ^ (~x4h & x0h);
    const t4l = x4l ^ (~x0l & x1l);
    const t4h = x4h ^ (~x0h & x1h);

    const u0l = (t0l ^ t4l) >>> 0;
    const u0h = (t0h ^ t4h) >>> 0;
    const u1l = (t1l ^ t0l) >>> 0;
    const u1h = (t1h ^ t0h) >>> 0;
    const u2l = ~t2l >>> 0;
    const u2h = ~t2h >>> 0;
    const u3l = (t3l ^ t2l) >>> 0;
    const u3h = (t3h ^ t2h) >>> 0;
    const u4l = t4l >>> 0;
    const u4h = t4h >>> 0;

    // Linear diffusion: x_i ^= ror(x_i, a) ^ ror(x_i, b), with a distinct pair per word.
    x0l = (u0l ^ rorLo(u0h, u0l, 19) ^ rorLo(u0h, u0l, 28)) >>> 0;
    x0h = (u0h ^ rorHi(u0h, u0l, 19) ^ rorHi(u0h, u0l, 28)) >>> 0;
    x1l = (u1l ^ rorLo(u1h, u1l, 61) ^ rorLo(u1h, u1l, 39)) >>> 0;
    x1h = (u1h ^ rorHi(u1h, u1l, 61) ^ rorHi(u1h, u1l, 39)) >>> 0;
    x2l = (u2l ^ rorLo(u2h, u2l, 1) ^ rorLo(u2h, u2l, 6)) >>> 0;
    x2h = (u2h ^ rorHi(u2h, u2l, 1) ^ rorHi(u2h, u2l, 6)) >>> 0;
    x3l = (u3l ^ rorLo(u3h, u3l, 10) ^ rorLo(u3h, u3l, 17)) >>> 0;
    x3h = (u3h ^ rorHi(u3h, u3l, 10) ^ rorHi(u3h, u3l, 17)) >>> 0;
    x4l = (u4l ^ rorLo(u4h, u4l, 7) ^ rorLo(u4h, u4l, 41)) >>> 0;
    x4h = (u4h ^ rorHi(u4h, u4l, 7) ^ rorHi(u4h, u4l, 41)) >>> 0;
  }

  s[0] = x0l >>> 0;
  s[1] = x0h >>> 0;
  s[2] = x1l >>> 0;
  s[3] = x1h >>> 0;
  s[4] = x2l >>> 0;
  s[5] = x2h >>> 0;
  s[6] = x3l >>> 0;
  s[7] = x3h >>> 0;
  s[8] = x4l >>> 0;
  s[9] = x4h >>> 0;
}

/** XORs up to eight bytes into word `w`, little-endian: byte i goes to bit 8i. */
function xorBytes(s: State, w: number, bytes: Uint8Array, at: number, count: number): void {
  for (let i = 0; i < count; i++) {
    const b = bytes[at + i]!;
    if (i < 4) s[w * 2] = (s[w * 2]! ^ (b << (8 * i))) >>> 0;
    else s[w * 2 + 1] = (s[w * 2 + 1]! ^ (b << (8 * (i - 4)))) >>> 0;
  }
}

/** Reads `count` bytes out of word `w`, same convention. */
function readBytes(s: State, w: number, out: Uint8Array, at: number, count: number): void {
  for (let i = 0; i < count; i++) {
    out[at + i] =
      i < 4 ? (s[w * 2]! >>> (8 * i)) & 0xff : (s[w * 2 + 1]! >>> (8 * (i - 4))) & 0xff;
  }
}

/** Replaces `count` bytes of word `w` with the given bytes -- decryption's "insert ciphertext". */
function setBytes(s: State, w: number, bytes: Uint8Array, at: number, count: number): void {
  for (let i = 0; i < count; i++) {
    const b = bytes[at + i]!;
    if (i < 4) {
      const shift = 8 * i;
      s[w * 2] = (((s[w * 2]! & ~(0xff << shift)) | (b << shift)) >>> 0) >>> 0;
    } else {
      const shift = 8 * (i - 4);
      s[w * 2 + 1] = (((s[w * 2 + 1]! & ~(0xff << shift)) | (b << shift)) >>> 0) >>> 0;
    }
  }
}

/** The padding bit, `0x01 << 8n` within one word. */
function padBit(s: State, w: number, n: number): void {
  if (n < 4) s[w * 2] = (s[w * 2]! ^ (1 << (8 * n))) >>> 0;
  else s[w * 2 + 1] = (s[w * 2 + 1]! ^ (1 << (8 * (n - 4)))) >>> 0;
}

// ── the hash and the XOF ─────────────────────────────────────────────────────

export interface AsconHasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

/**
 * Ascon-Hash256 and Ascon-XOF128, which differ only in the initialising value and the output length.
 *
 * A 12-round permutation between every 8-byte block in both directions -- Ascon-Hash256 uses the full
 * p12 for absorbing rather than the p8 that the `-a` variants of the earlier proposal used, and
 * getting that wrong is another mistake a round trip cannot see.
 */
class AsconSponge implements AsconHasher {
  private readonly state = new Uint32Array(10);
  private readonly buffer = new Uint8Array(HASH_RATE);
  private buffered = 0;
  private done = false;

  constructor(
    initial: readonly [number, number],
    private readonly outputLen: number,
  ) {
    if (outputLen <= 0) throw new Error("Ascon: output length must be positive");
    this.state[1] = initial[0];
    this.state[0] = initial[1];
    permute(this.state, 12);
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("Ascon: update after digest");
    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(HASH_RATE - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === HASH_RATE) {
        xorBytes(this.state, 0, this.buffer, 0, HASH_RATE);
        permute(this.state, 12);
        this.buffered = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("Ascon: digest called twice");
    this.done = true;

    // Final block: the tail, then the single 1 bit immediately after it.
    xorBytes(this.state, 0, this.buffer, 0, this.buffered);
    padBit(this.state, 0, this.buffered);
    permute(this.state, 12);

    const out = new Uint8Array(this.outputLen);
    let remaining = this.outputLen;
    let at = 0;
    while (remaining > HASH_RATE) {
      readBytes(this.state, 0, out, at, HASH_RATE);
      permute(this.state, 12);
      at += HASH_RATE;
      remaining -= HASH_RATE;
    }
    readBytes(this.state, 0, out, at, remaining);
    return out;
  }
}

export function createAsconHash256(): AsconHasher {
  return new AsconSponge(IV_HASH256, ASCON_HASH_LEN);
}

/** Ascon-XOF128. The output length is the caller's, which is what makes it an XOF. */
export function createAsconXof128(outputLen: number): AsconHasher {
  return new AsconSponge(IV_XOF128, outputLen);
}

export function asconHash256(data: Uint8Array): Uint8Array {
  const h = createAsconHash256();
  h.update(data);
  return h.digest();
}

export function asconXof128(data: Uint8Array, outputLen: number): Uint8Array {
  const h = createAsconXof128(outputLen);
  h.update(data);
  return h.digest();
}

// ── Ascon-AEAD128 ────────────────────────────────────────────────────────────

/**
 * One-shot, and deliberately so.
 *
 * An AEAD cannot emit authenticated output before it has seen every byte, which is the same reason
 * the cipher family reports `streaming: false` for AES-GCM. There is nothing to stream over.
 */
function initAead(key: Uint8Array, nonce: Uint8Array): State {
  if (key.length !== ASCON_AEAD_KEY_LEN) {
    throw new Error(`Ascon-AEAD128 takes a 16-byte key; this one is ${key.length}.`);
  }
  if (nonce.length !== ASCON_AEAD_NONCE_LEN) {
    throw new Error(`Ascon-AEAD128 takes a 16-byte nonce; this one is ${nonce.length}.`);
  }

  const s = new Uint32Array(10);
  s[1] = IV_AEAD128[0];
  s[0] = IV_AEAD128[1];
  xorBytes(s, 1, key, 0, 8);
  xorBytes(s, 2, key, 8, 8);
  xorBytes(s, 3, nonce, 0, 8);
  xorBytes(s, 4, nonce, 8, 8);
  permute(s, 12);
  // Second key XOR, into the top 128 bits.
  xorBytes(s, 3, key, 0, 8);
  xorBytes(s, 4, key, 8, 8);
  return s;
}

/** Absorbs the associated data, then the domain-separation bit that closes that phase. */
function absorbAd(s: State, ad: Uint8Array): void {
  if (ad.length > 0) {
    let at = 0;
    while (ad.length - at >= AEAD_RATE) {
      xorBytes(s, 0, ad, at, 8);
      xorBytes(s, 1, ad, at + 8, 8);
      permute(s, 8);
      at += AEAD_RATE;
    }
    const remaining = ad.length - at;
    if (remaining >= 8) {
      xorBytes(s, 0, ad, at, 8);
      xorBytes(s, 1, ad, at + 8, remaining - 8);
      padBit(s, 1, remaining - 8);
    } else {
      xorBytes(s, 0, ad, at, remaining);
      padBit(s, 0, remaining);
    }
    permute(s, 8);
  }

  // Domain separation: the top bit of x4, whether or not there was any associated data.
  s[9] = (s[9]! ^ 0x8000_0000) >>> 0;
}

function finalize(s: State, key: Uint8Array, out: Uint8Array, at: number): void {
  xorBytes(s, 2, key, 0, 8);
  xorBytes(s, 3, key, 8, 8);
  permute(s, 12);
  xorBytes(s, 3, key, 0, 8);
  xorBytes(s, 4, key, 8, 8);
  readBytes(s, 3, out, at, 8);
  readBytes(s, 4, out, at + 8, 8);
}

/** Encrypts, appending the 16-byte tag -- the layout every AEAD in this repo uses. */
export function asconAead128Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const s = initAead(key, nonce);
  absorbAd(s, ad);

  const out = new Uint8Array(plaintext.length + ASCON_AEAD_TAG_LEN);
  let at = 0;
  while (plaintext.length - at >= AEAD_RATE) {
    xorBytes(s, 0, plaintext, at, 8);
    xorBytes(s, 1, plaintext, at + 8, 8);
    readBytes(s, 0, out, at, 8);
    readBytes(s, 1, out, at + 8, 8);
    permute(s, 8);
    at += AEAD_RATE;
  }

  const remaining = plaintext.length - at;
  if (remaining >= 8) {
    xorBytes(s, 0, plaintext, at, 8);
    xorBytes(s, 1, plaintext, at + 8, remaining - 8);
    readBytes(s, 0, out, at, 8);
    readBytes(s, 1, out, at + 8, remaining - 8);
    padBit(s, 1, remaining - 8);
  } else {
    xorBytes(s, 0, plaintext, at, remaining);
    readBytes(s, 0, out, at, remaining);
    padBit(s, 0, remaining);
  }

  finalize(s, key, out, plaintext.length);
  return out;
}

/**
 * Decrypts and verifies, returning `null` when the tag does not match.
 *
 * `null` rather than a throw because a failed tag is a *result* in this app -- the cipher family
 * renders it as one -- and rather than a boolean out-parameter because there is no plaintext to hand
 * back when verification fails. Nothing partial is returned: releasing unverified plaintext is the
 * mistake AEADs exist to prevent.
 */
export function asconAead128Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array | null {
  if (ciphertext.length < ASCON_AEAD_TAG_LEN) return null;

  const s = initAead(key, nonce);
  absorbAd(s, ad);

  const messageLen = ciphertext.length - ASCON_AEAD_TAG_LEN;
  const out = new Uint8Array(messageLen);
  let at = 0;
  while (messageLen - at >= AEAD_RATE) {
    readBytes(s, 0, out, at, 8);
    readBytes(s, 1, out, at + 8, 8);
    for (let i = 0; i < AEAD_RATE; i++) out[at + i] = out[at + i]! ^ ciphertext[at + i]!;
    setBytes(s, 0, ciphertext, at, 8);
    setBytes(s, 1, ciphertext, at + 8, 8);
    permute(s, 8);
    at += AEAD_RATE;
  }

  const remaining = messageLen - at;
  if (remaining >= 8) {
    readBytes(s, 0, out, at, 8);
    readBytes(s, 1, out, at + 8, remaining - 8);
    for (let i = 0; i < remaining; i++) out[at + i] = out[at + i]! ^ ciphertext[at + i]!;
    setBytes(s, 0, ciphertext, at, 8);
    setBytes(s, 1, ciphertext, at + 8, remaining - 8);
    padBit(s, 1, remaining - 8);
  } else {
    readBytes(s, 0, out, at, remaining);
    for (let i = 0; i < remaining; i++) out[at + i] = out[at + i]! ^ ciphertext[at + i]!;
    setBytes(s, 0, ciphertext, at, remaining);
    padBit(s, 0, remaining);
  }

  const tag = new Uint8Array(ASCON_AEAD_TAG_LEN);
  finalize(s, key, tag, 0);

  // Constant-time comparison: every byte is examined whatever the first one says.
  let diff = 0;
  for (let i = 0; i < ASCON_AEAD_TAG_LEN; i++) diff |= tag[i]! ^ ciphertext[messageLen + i]!;
  return diff === 0 ? out : null;
}


// ── Ascon-MAC, Ascon-PRF and Ascon-PRFShort ─────────────────────────────────

export const ASCON_PRF_KEY_LEN = 16;
export const ASCON_MAC_TAG_LEN = 16;
/** Ascon-PRFShort takes at most 16 bytes in and gives at most 16 out. */
export const ASCON_PRF_SHORT_MAX = 16;

/**
 * Ascon's own keyed modes, from the v1.3 submission rather than SP 800-232.
 *
 * Worth being precise about, because it is the kind of thing that gets flattened: NIST standardised
 * Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 and *not* these. Ascon-MAC, Ascon-PRF
 * and Ascon-PRFShort are the designers' own constructions, published with the submission and shipped
 * with known-answer files in the reference repository -- which is what makes them checkable here. The
 * tool metadata says the same thing rather than implying NIST blessed them.
 *
 * All three key the permutation directly, which is the point: no ipad/opad, no nesting, one pass. The
 * MAC is the PRF with a fixed 16-byte output and a different variant number in the IV; PRFShort is a
 * separate construction for inputs of at most 16 bytes that gets away with a single permutation.
 */
class AsconPrfEngine implements AsconHasher {
  private readonly state = new Uint32Array(10);
  private readonly buffer = new Uint8Array(PRF_IN_RATE);
  private buffered = 0;
  private done = false;

  constructor(
    initial: readonly [number, number],
    key: Uint8Array,
    private readonly outputLen: number,
  ) {
    if (key.length !== ASCON_PRF_KEY_LEN) {
      throw new Error(`Ascon's keyed modes take a 16-byte key; this one is ${key.length}.`);
    }
    if (outputLen <= 0) throw new Error("Ascon: output length must be positive");

    this.state[1] = initial[0];
    this.state[0] = initial[1];
    xorBytes(this.state, 1, key, 0, 8);
    xorBytes(this.state, 2, key, 8, 8);
    permute(this.state, 12);
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("Ascon: update after digest");
    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(PRF_IN_RATE - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === PRF_IN_RATE) {
        for (let word = 0; word < 4; word++) xorBytes(this.state, word, this.buffer, word * 8, 8);
        permute(this.state, 12);
        this.buffered = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("Ascon: digest called twice");
    this.done = true;

    /**
     * The final, short block: whole words first, then the partial one plus its padding bit.
     *
     * Note there is *no* permutation between absorbing this and the domain separation -- the single
     * `p12` after the separation bit covers both. An implementation that permuted here as the full-block
     * path does would be self-consistent and wrong.
     */
    const wholeWords = Math.floor(this.buffered / 8);
    for (let word = 0; word < wholeWords; word++) {
      xorBytes(this.state, word, this.buffer, word * 8, 8);
    }
    const remainder = this.buffered % 8;
    xorBytes(this.state, wholeWords, this.buffer, wholeWords * 8, remainder);
    padBit(this.state, wholeWords, remainder);

    // Domain separation: the top bit of x4, as in the AEAD.
    this.state[9] = (this.state[9]! ^ 0x8000_0000) >>> 0;
    permute(this.state, 12);

    const out = new Uint8Array(this.outputLen);
    let remaining = this.outputLen;
    let at = 0;
    let word = 0;
    while (remaining > 8) {
      readBytes(this.state, word, out, at, 8);
      at += 8;
      remaining -= 8;
      word += 1;
      if (word === 2) {
        // Two words is the output rate; squeezing more needs another permutation.
        word = 0;
        permute(this.state, 12);
      }
    }
    readBytes(this.state, word, out, at, remaining);
    return out;
  }
}

/** Ascon-MAC: a 16-byte tag over any message. */
export function createAsconMac(key: Uint8Array): AsconHasher {
  return new AsconPrfEngine(IV_MAC, key, ASCON_MAC_TAG_LEN);
}

/** Ascon-PRF: the same construction with an arbitrary output length. */
export function createAsconPrf(key: Uint8Array, outputLen: number): AsconHasher {
  return new AsconPrfEngine(IV_PRF, key, outputLen);
}

export function asconMac(key: Uint8Array, message: Uint8Array): Uint8Array {
  const h = createAsconMac(key);
  h.update(message);
  return h.digest();
}

export function asconPrf(
  key: Uint8Array,
  message: Uint8Array,
  outputLen = ASCON_MAC_TAG_LEN,
): Uint8Array {
  const h = createAsconPrf(key, outputLen);
  h.update(message);
  return h.digest();
}

/**
 * Ascon-PRFShort: one permutation, for inputs of at most 16 bytes.
 *
 * Not a sponge at all -- the message goes straight into the two words the key does not occupy, the
 * permutation runs once, and the key is XORed back over the output. That makes it about twice as fast
 * as the full PRF for a short input, which is the case it exists for: authenticating a counter, a
 * nonce or a short command in a constrained protocol.
 *
 * The input *length* is part of the IV, so a 4-byte message and the same 4 bytes zero-padded to 8 give
 * different tags. That is deliberate and it is why this cannot be expressed as the PRF with a shorter
 * message.
 */
export function asconPrfShort(
  key: Uint8Array,
  message: Uint8Array,
  outputLen = ASCON_PRF_SHORT_MAX,
): Uint8Array {
  if (key.length !== ASCON_PRF_KEY_LEN) {
    throw new Error(`Ascon-PRFShort takes a 16-byte key; this one is ${key.length}.`);
  }
  if (message.length > ASCON_PRF_SHORT_MAX) {
    throw new Error(
      `Ascon-PRFShort takes at most 16 bytes of input; this one is ${message.length}. Use Ascon-PRF for anything longer.`,
    );
  }
  if (outputLen <= 0 || outputLen > ASCON_PRF_SHORT_MAX) {
    throw new Error(`Ascon-PRFShort produces 1 to 16 bytes; ${outputLen} was requested.`);
  }

  const s = new Uint32Array(10);
  s[1] = IV_PRF_SHORT[0];
  s[0] = IV_PRF_SHORT[1];
  // The message bit length occupies bits 48 and up, which is the high half's bit 16 and up.
  s[1] = (s[1]! + message.length * 8 * 0x1_0000) >>> 0;
  xorBytes(s, 1, key, 0, 8);
  xorBytes(s, 2, key, 8, 8);
  xorBytes(s, 3, message, 0, Math.min(8, message.length));
  if (message.length > 8) xorBytes(s, 4, message, 8, message.length - 8);

  permute(s, 12);

  // The key comes back over the output words, which is what makes this keyed rather than a hash.
  xorBytes(s, 3, key, 0, 8);
  xorBytes(s, 4, key, 8, 8);

  const out = new Uint8Array(outputLen);
  readBytes(s, 3, out, 0, Math.min(8, outputLen));
  if (outputLen > 8) readBytes(s, 4, out, 8, outputLen - 8);
  return out;
}
