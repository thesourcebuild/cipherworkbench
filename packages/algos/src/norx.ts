/**
 * NORX32-4-1 (NORX v3.0), a CAESAR third-round candidate and the only ARX sponge AEAD here.
 *
 * `modern`: no attack on the full construction. It did not reach CAESAR's final portfolio -- Ascon and
 * ACORN took the lightweight slots and AEGIS and OCB the others -- but it has no break, and it is worth
 * having for the design: a Keccak-style duplex over a **BLAKE2-style ARX permutation** instead of a
 * bit-sliced one, with a non-linear mixing function `H(a, b) = (a ^ b) ^ ((a & b) << 1)` that needs no
 * modular addition. That last detail is the point of NORX: the whole cipher is XOR, AND, shift and
 * rotate, so it is constant-time by construction and cheap to protect against side channels.
 *
 * Five things to preserve.
 *
 * **This is v3.0, and the versions are incompatible.** v1.0, v2.0 and v3.0 differ in the initialisation
 * and the domain constants, so a v2.0 implementation reproduces nothing here. The marker is the
 * initialisation: `S[i] = i` for all sixteen words, then **two bare rounds** of `F` before the key and
 * nonce are loaded at all. Anything else is another version.
 *
 * **The rate is twelve words and the capacity four.** A block is 48 bytes, absorbed into `S[0..11]`,
 * and `S[12..15]` never sees data directly -- the key is XORed into it at the end of initialisation and
 * twice more during finalisation.
 *
 * **The domain constant is XORed into `S[15]` before the permutation, not after.** One value per phase
 * (1 for the header, 2 for the payload, 8 for finalisation), and the permutation runs *between* the
 * constant and the data. Absorbing first and separating afterwards is the plausible wrong order.
 *
 * **An empty header or payload is skipped entirely.** Every other sponge here pads an empty region into
 * one block; NORX does not process it at all, so an empty associated data is not the same as a
 * zero-length padded block. The KAT's entry for length 0 is what pins that.
 *
 * **The padding is two marks, not one.** `0x01` immediately after the data and `0x80` OR-ed into the
 * last byte of the block -- so a block with 47 bytes of data gets both marks in the same byte. Writing
 * only the `0x01` is right for no length at all, and writing only the `0x80` is right for none either.
 *
 * What stands behind it: the designers' own KAT sweep at every length from 0 to 255, plus FELICS's two
 * vectors, which additionally publish the state after each of the four phases. See
 * `tests/algos-norx.test.ts`.
 */

const u32 = (x: number): number => x >>> 0;
const rotr = (x: number, c: number): number => u32((x >>> c) | (x << (32 - c)));

/** The non-linear mixing function, which replaces the modular addition a BLAKE round would use. */
const h = (a: number, b: number): number => u32(u32(a ^ b) ^ u32((a & b) << 1));

const ROUNDS = 4;
const RATE_WORDS = 12;
const RATE = RATE_WORDS * 4;
const KEY_LENGTH = 16;
const NONCE_LENGTH = 16;
const TAG_LENGTH = 16;

/** Domain constants, one per phase. NORX also defines trailer, branch and merge, which this omits. */
const TAG_HEADER = 0x01;
const TAG_PAYLOAD = 0x02;
const TAG_FINAL = 0x08;

/** The quarter-round. The four rotations are 8, 11, 16 and 31, and they are rotations *right*. */
function quarter(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = h(s[a]!, s[b]!);
  s[d] = u32(s[d]! ^ s[a]!);
  s[d] = rotr(s[d]!, 8);
  s[c] = h(s[c]!, s[d]!);
  s[b] = u32(s[b]! ^ s[c]!);
  s[b] = rotr(s[b]!, 11);
  s[a] = h(s[a]!, s[b]!);
  s[d] = u32(s[d]! ^ s[a]!);
  s[d] = rotr(s[d]!, 16);
  s[c] = h(s[c]!, s[d]!);
  s[b] = u32(s[b]! ^ s[c]!);
  s[b] = rotr(s[b]!, 31);
}

/** One round: four columns, then four diagonals. Exactly ChaCha's and BLAKE2's shape. */
function round(s: Uint32Array): void {
  quarter(s, 0, 4, 8, 12);
  quarter(s, 1, 5, 9, 13);
  quarter(s, 2, 6, 10, 14);
  quarter(s, 3, 7, 11, 15);
  quarter(s, 0, 5, 10, 15);
  quarter(s, 1, 6, 11, 12);
  quarter(s, 2, 7, 8, 13);
  quarter(s, 3, 4, 9, 14);
}

const permute = (s: Uint32Array): void => {
  for (let i = 0; i < ROUNDS; i++) round(s);
};

const load = (bytes: Uint8Array, at: number): number =>
  u32(bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24));

function store(word: number, out: Uint8Array, at: number): void {
  out[at] = word & 0xff;
  out[at + 1] = (word >>> 8) & 0xff;
  out[at + 2] = (word >>> 16) & 0xff;
  out[at + 3] = (word >>> 24) & 0xff;
}

/**
 * The initialisation, which is the version marker.
 *
 * Sixteen words set to their own index, two bare rounds, then the nonce over words 0 to 3 and the key
 * over 4 to 7. The four parameter words -- word size, round count, parallelism and tag bits -- are
 * XORed into the capacity, and the key goes in again after the permutation.
 */
function initialise(key: Uint8Array, nonce: Uint8Array): Uint32Array {
  const s = new Uint32Array(16);
  for (let i = 0; i < 16; i++) s[i] = i;
  round(s);
  round(s);
  for (let i = 0; i < 4; i++) s[i] = load(nonce, 4 * i);
  for (let i = 0; i < 4; i++) s[4 + i] = load(key, 4 * i);
  s[12] = u32(s[12]! ^ 32); // the word size in bits
  s[13] = u32(s[13]! ^ ROUNDS);
  s[14] = u32(s[14]! ^ 1); // the parallelism degree
  s[15] = u32(s[15]! ^ (8 * TAG_LENGTH));
  permute(s);
  for (let i = 0; i < 4; i++) s[12 + i] = u32(s[12 + i]! ^ load(key, 4 * i));
  return s;
}

/** `0x01` after the data and `0x80` in the block's last byte -- both, and in the same byte at 47. */
function padInto(block: Uint8Array, data: Uint8Array, at: number, length: number): void {
  block.fill(0);
  block.set(data.subarray(at, at + length));
  block[length] = 0x01;
  block[RATE - 1] = block[RATE - 1]! | 0x80;
}

/** Absorb a region. An empty one is skipped entirely, which is unusual and is the point. */
function absorb(s: Uint32Array, data: Uint8Array, domain: number): void {
  if (data.length === 0) return;
  let at = 0;
  for (; data.length - at >= RATE; at += RATE) {
    s[15] = u32(s[15]! ^ domain);
    permute(s);
    for (let i = 0; i < RATE_WORDS; i++) s[i] = u32(s[i]! ^ load(data, at + 4 * i));
  }
  const block = new Uint8Array(RATE);
  padInto(block, data, at, data.length - at);
  s[15] = u32(s[15]! ^ domain);
  permute(s);
  for (let i = 0; i < RATE_WORDS; i++) s[i] = u32(s[i]! ^ load(block, 4 * i));
}

/**
 * The payload phase, in whichever direction.
 *
 * Encrypting XORs the plaintext into the rate and emits the result; decrypting *replaces* the rate word
 * with the ciphertext and emits the difference, so the state ends up holding the same thing either way.
 * That asymmetry is why this cannot be one XOR loop with a flag on the output.
 */
function payload(s: Uint32Array, data: Uint8Array, decrypt: boolean): Uint8Array {
  const out = new Uint8Array(data.length);
  if (data.length === 0) return out;

  let at = 0;
  for (; data.length - at >= RATE; at += RATE) {
    s[15] = u32(s[15]! ^ TAG_PAYLOAD);
    permute(s);
    for (let i = 0; i < RATE_WORDS; i++) {
      const input = load(data, at + 4 * i);
      if (decrypt) {
        store(u32(s[i]! ^ input), out, at + 4 * i);
        s[i] = input;
      } else {
        s[i] = u32(s[i]! ^ input);
        store(s[i]!, out, at + 4 * i);
      }
    }
  }

  const remaining = data.length - at;
  const block = new Uint8Array(RATE);
  if (decrypt) {
    /**
     * The short final block on the way back needs the *keystream* rather than the state, because the
     * padding marks belong to the plaintext block and are not present in the ciphertext. So the rate is
     * read out, the ciphertext laid over its first `remaining` bytes, the marks re-applied, and only
     * then is the state updated -- which is exactly what the reference does and is the one place in
     * this file where the two directions are not mirror images.
     */
    s[15] = u32(s[15]! ^ TAG_PAYLOAD);
    permute(s);
    const rate = new Uint8Array(RATE);
    for (let i = 0; i < RATE_WORDS; i++) store(s[i]!, rate, 4 * i);
    for (let i = 0; i < remaining; i++) out[at + i] = rate[i]! ^ data[at + i]!;
    block.set(out.subarray(at, at + remaining));
    block[remaining] = 0x01;
    block[RATE - 1] = block[RATE - 1]! | 0x80;
    for (let i = 0; i < RATE_WORDS; i++) s[i] = u32(s[i]! ^ load(block, 4 * i));
  } else {
    padInto(block, data, at, remaining);
    s[15] = u32(s[15]! ^ TAG_PAYLOAD);
    permute(s);
    for (let i = 0; i < RATE_WORDS; i++) {
      s[i] = u32(s[i]! ^ load(block, 4 * i));
      store(s[i]!, block, 4 * i);
    }
    out.set(block.subarray(0, remaining), at);
  }
  return out;
}

/** Two permutations with the key folded into the capacity after each. The tag is the capacity. */
function finalise(s: Uint32Array, key: Uint8Array): Uint8Array {
  s[15] = u32(s[15]! ^ TAG_FINAL);
  permute(s);
  for (let i = 0; i < 4; i++) s[12 + i] = u32(s[12 + i]! ^ load(key, 4 * i));
  permute(s);
  for (let i = 0; i < 4; i++) s[12 + i] = u32(s[12 + i]! ^ load(key, 4 * i));

  const tag = new Uint8Array(TAG_LENGTH);
  for (let i = 0; i < 4; i++) store(s[12 + i]!, tag, 4 * i);
  return tag;
}

function check(key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`NORX32-4-1's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`NORX32-4-1's nonce is exactly 16 bytes; this one is ${nonce.length}.`);
  }
}

/**
 * The state after each of the four phases, exported for the tests.
 *
 * FELICS publishes all four, and having them is what makes a wrong answer diagnosable rather than
 * merely wrong -- the same reasoning as `acornPhaseStates`, and it is worth the export for the same
 * reason: the alternative is bisecting a permutation by hand.
 */
export function norxPhaseStates(
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  message: Uint8Array,
): { afterInit: Uint8Array; afterAd: Uint8Array; afterPayload: Uint8Array; afterFinal: Uint8Array } {
  check(key, nonce);
  const pack = (s: Uint32Array): Uint8Array => {
    const out = new Uint8Array(64);
    for (let i = 0; i < 16; i++) store(s[i]!, out, 4 * i);
    return out;
  };
  const s = initialise(key, nonce);
  const afterInit = pack(s);
  absorb(s, ad, TAG_HEADER);
  const afterAd = pack(s);
  payload(s, message, false);
  const afterPayload = pack(s);
  finalise(s, key);
  return { afterInit, afterAd, afterPayload, afterFinal: pack(s) };
}

/** Encrypt and authenticate. Returns the ciphertext with the 16-byte tag appended. */
export function norxEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  message: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  check(key, nonce);
  const s = initialise(key, nonce);
  absorb(s, ad, TAG_HEADER);
  const ciphertext = payload(s, message, false);
  const tag = finalise(s, key);

  const out = new Uint8Array(message.length + TAG_LENGTH);
  out.set(ciphertext);
  out.set(tag, message.length);
  return out;
}

/** Verify and decrypt. Throws when the tag does not match. */
export function norxDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  check(key, nonce);
  if (sealed.length < TAG_LENGTH) {
    throw new Error(
      `NORX32-4-1's output carries a 16-byte tag, so there are at least 16 bytes; this one is ${sealed.length}.`,
    );
  }
  const s = initialise(key, nonce);
  absorb(s, ad, TAG_HEADER);
  const message = payload(s, sealed.subarray(0, sealed.length - TAG_LENGTH), true);
  const expected = finalise(s, key);

  const offset = sealed.length - TAG_LENGTH;
  let diff = 0;
  for (let i = 0; i < TAG_LENGTH; i++) diff |= expected[i]! ^ sealed[offset + i]!;
  if (diff !== 0) throw new Error("NORX32-4-1: the tag does not match.");
  return message;
}
