/**
 * Deoxys-II-256-128, one of the two winners of the CAESAR competition's defence-in-depth use case.
 *
 * It is the only AEAD in this repo built on a **tweakable** block cipher, and that is the reason to
 * have it: everything else here either keys a permutation (Ascon, Xoodyak, the lightweight finalists)
 * or bolts a MAC onto a counter mode (GCM, CCM, OCB). Deoxys-BC-384 takes a 384-bit tweakey -- 256
 * bits of key and 128 bits of tweak -- through the TWEAKEY framework, and the mode gets its domain
 * separation for free by putting a prefix in the tweak instead of into the message.
 *
 * The consequence worth knowing is that it is **nonce-misuse resistant**: repeating a nonce leaks
 * whether two messages are equal and nothing else, where a repeated nonce under GCM or ChaCha20-
 * Poly1305 hands over the key stream and, with it, the authentication key. That is what "defence in
 * depth" meant in CAESAR's use cases, and it is why this is a reasonable thing to reach for rather
 * than a museum piece. `C003` is deliberately not raised against it -- see the cipher family's notes.
 *
 * Five things to preserve.
 *
 * **Deoxys-BC-384 applies MixColumns in its last round.** AES does not, and every AES-derived cipher
 * here has had to have that stated. Sixteen rounds, all identical, with a subtweakey XORed before the
 * first -- so `aesRound` from `aes-round.ts` is exactly the round this needs, and nothing about AES's
 * S-box or its matrix is re-derived. Four independent vector sets already pin that table.
 *
 * **The two halves of the key go in backwards.** `TK2` is the *second* sixteen bytes and `TK3` is the
 * first. Swapping them gives a cipher that encrypts, decrypts and round-trips perfectly and reproduces
 * nothing -- the usual shape, and the one thing here a reader would get wrong from the paper's
 * notation alone, since the paper indexes tweakey words from 1 and the byte string does not.
 *
 * **Both LFSRs run on every byte independently, and they are not inverses.** `lfsr2` shifts left and
 * feeds bit 7 XOR bit 5 into bit 0; `lfsr3` shifts right and feeds bit 0 XOR bit 6 into bit 7. They
 * apply to TK2 and TK3 respectively, once per round, *before* the byte permutation `h`.
 *
 * **The mode is two-pass and the tag is the tweak.** First pass absorbs the associated data and then
 * the message into an accumulator, each block under a tweak carrying a domain prefix and the block
 * number; the accumulator is then encrypted under a tweak built from the nonce to give the tag. The
 * second pass encrypts, using **the tag** as the tweak with the block number XORed into its last four
 * bytes and the nonce as the *plaintext*. So the keystream depends on the whole message, which is
 * where the misuse resistance comes from -- and it is why this cannot stream: nothing can be emitted
 * until the last byte of input has been seen.
 *
 * **`0x80` marks the end of a partial block, and a full final block gets no padding at all.** A
 * message that is an exact multiple of sixteen bytes runs the block loop and stops; one byte more
 * takes a whole extra block with a different domain prefix. Padding unconditionally is right for
 * fifteen lengths in sixteen.
 *
 * No oracle -- OpenSSL never implemented Deoxys and nothing in this tree has it. What stands behind it
 * is the designers' own eight vectors plus an independent implementation's gapless length sweep; see
 * `tests/algos-deoxys.test.ts`, which says which is which.
 */
import { aesRound } from "./aes-round";

const BLOCK = 16;
const ROUNDS = 16;
const KEY_LENGTH = 32;
const NONCE_LENGTH = 15;
const TAG_LENGTH = 16;

/**
 * The round constants, and the one table here that is stored rather than derived.
 *
 * They are the powers of `x` in GF(2^8) under `x^8 + x^4 + x^3 + x + 1` starting from `0x2f`, which is
 * a derivation -- but seventeen bytes is smaller than the code that would produce them, and the
 * relation is checked in the tests rather than relied on here.
 */
const RCON = new Uint8Array([
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
  0x72,
]);

/** The tweakey byte permutation `h`, as a source index per destination position. */
const H = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8] as const;

function permute(t: Uint8Array): void {
  const copy = Uint8Array.from(t);
  for (let i = 0; i < BLOCK; i++) t[i] = copy[H[i]!]!;
}

/** Shift left, feeding bit 7 XOR bit 5 into bit 0. Applied to TK2. */
function lfsr2(t: Uint8Array): void {
  for (let i = 0; i < BLOCK; i++) {
    const x = t[i]!;
    t[i] = ((x << 1) | ((x >> 7) ^ ((x >> 5) & 1))) & 0xff;
  }
}

/** Shift right, feeding bit 0 XOR bit 6 into bit 7. Applied to TK3. Not `lfsr2`'s inverse. */
function lfsr3(t: Uint8Array): void {
  for (let i = 0; i < BLOCK; i++) {
    const x = t[i]!;
    t[i] = ((x >> 1) | (((x & 1) ^ ((x >> 6) & 1)) << 7)) & 0xff;
  }
}

/** The round constant, which occupies the first two columns only. */
function xorRoundConstant(t: Uint8Array, round: number): void {
  t[0] = t[0]! ^ 1;
  t[1] = t[1]! ^ 2;
  t[2] = t[2]! ^ 4;
  t[3] = t[3]! ^ 8;
  for (let i = 4; i < 8; i++) t[i] = t[i]! ^ RCON[round]!;
}

/**
 * The key-dependent half of the tweakey schedule, computed once per key.
 *
 * Separating this from `subTweakeys` is not a micro-optimisation: Deoxys-II runs the block cipher once
 * per block under a *different tweak each time*, so the key half would otherwise be recomputed for
 * every sixteen bytes of a message, seventeen LFSR-and-permute passes at a time.
 */
export function deoxysDeriveKeys(key: Uint8Array): Uint8Array[] {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`Deoxys-II's key is exactly 32 bytes; this one is ${key.length}.`);
  }
  // TK2 is the second half and TK3 the first, which is the way round the byte string is not.
  const tk2 = key.slice(16, 32);
  const tk3 = key.slice(0, 16);

  const derived: Uint8Array[] = [];
  for (let round = 0; round <= ROUNDS; round++) {
    if (round > 0) {
      lfsr2(tk2);
      permute(tk2);
      lfsr3(tk3);
      permute(tk3);
    }
    const k = new Uint8Array(BLOCK);
    for (let i = 0; i < BLOCK; i++) k[i] = tk2[i]! ^ tk3[i]!;
    xorRoundConstant(k, round);
    derived.push(k);
  }
  return derived;
}

/** The tweak half, which is `h` applied repeatedly and XORed into the derived keys. */
function subTweakeys(derived: readonly Uint8Array[], tweak: Uint8Array): Uint8Array[] {
  const tk1 = Uint8Array.from(tweak);
  const stks: Uint8Array[] = [];
  for (let round = 0; round <= ROUNDS; round++) {
    if (round > 0) permute(tk1);
    const stk = new Uint8Array(BLOCK);
    for (let i = 0; i < BLOCK; i++) stk[i] = derived[round]![i]! ^ tk1[i]!;
    stks.push(stk);
  }
  return stks;
}

/** Deoxys-BC-384 on one block. Exported so a test can reach the primitive on its own. */
export function deoxysBcEncrypt(
  derived: readonly Uint8Array[],
  tweak: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const stks = subTweakeys(derived, tweak);
  let a = new Uint8Array(BLOCK);
  let b = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) a[i] = plaintext[i]! ^ stks[0]![i]!;
  for (let round = 1; round <= ROUNDS; round++) {
    // Note the last round mixes columns too, unlike AES's.
    aesRound(a, stks[round]!, b);
    const swap = a;
    a = b;
    b = swap;
  }
  return a;
}

/** Domain-separation prefixes, which live in the top nibble of the tweak's first byte. */
const PREFIX_AD_BLOCK = 0x02;
const PREFIX_AD_FINAL = 0x06;
const PREFIX_MSG_BLOCK = 0x00;
const PREFIX_MSG_FINAL = 0x04;
const PREFIX_TAG = 0x01;

/** `prefix` in the top nibble of byte 0, and the block number big-endian in the last four bytes. */
function tagTweak(prefix: number, blockNumber: number): Uint8Array {
  const tweak = new Uint8Array(BLOCK);
  tweak[0] = (prefix << 4) & 0xff;
  tweak[12] = (blockNumber >>> 24) & 0xff;
  tweak[13] = (blockNumber >>> 16) & 0xff;
  tweak[14] = (blockNumber >>> 8) & 0xff;
  tweak[15] = blockNumber & 0xff;
  return tweak;
}

/** The tag, with its top bit set and the block number XORed -- not written -- into its tail. */
function encryptionTweak(tag: Uint8Array, blockNumber: number): Uint8Array {
  const tweak = Uint8Array.from(tag);
  tweak[0] = tweak[0]! | 0x80;
  tweak[12] = tweak[12]! ^ ((blockNumber >>> 24) & 0xff);
  tweak[13] = tweak[13]! ^ ((blockNumber >>> 16) & 0xff);
  tweak[14] = tweak[14]! ^ ((blockNumber >>> 8) & 0xff);
  tweak[15] = tweak[15]! ^ (blockNumber & 0xff);
  return tweak;
}

function checkNonce(nonce: Uint8Array): void {
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`Deoxys-II's nonce is exactly 15 bytes; this one is ${nonce.length}.`);
  }
}

/**
 * The first pass: absorb one region into the accumulator, block by block.
 *
 * A partial final block is padded with `0x80` and takes `finalPrefix`; a region whose length is an
 * exact multiple of the block size gets no final block at all.
 */
function absorb(
  accumulator: Uint8Array,
  derived: readonly Uint8Array[],
  data: Uint8Array,
  blockPrefix: number,
  finalPrefix: number,
): void {
  let block = 0;
  for (; (block + 1) * BLOCK <= data.length; block++) {
    const out = deoxysBcEncrypt(
      derived,
      tagTweak(blockPrefix, block),
      data.subarray(block * BLOCK, (block + 1) * BLOCK),
    );
    for (let i = 0; i < BLOCK; i++) accumulator[i] = accumulator[i]! ^ out[i]!;
  }
  const remaining = data.length - block * BLOCK;
  if (remaining > 0) {
    const padded = new Uint8Array(BLOCK);
    padded.set(data.subarray(block * BLOCK));
    padded[remaining] = 0x80;
    const out = deoxysBcEncrypt(derived, tagTweak(finalPrefix, block), padded);
    for (let i = 0; i < BLOCK; i++) accumulator[i] = accumulator[i]! ^ out[i]!;
  }
}

/** The tag over the associated data and the message, which the second pass then uses as a tweak. */
function computeTag(
  derived: readonly Uint8Array[],
  nonce: Uint8Array,
  ad: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  const accumulator = new Uint8Array(BLOCK);
  absorb(accumulator, derived, ad, PREFIX_AD_BLOCK, PREFIX_AD_FINAL);
  absorb(accumulator, derived, message, PREFIX_MSG_BLOCK, PREFIX_MSG_FINAL);

  const tweak = new Uint8Array(BLOCK);
  tweak[0] = (PREFIX_TAG << 4) & 0xff;
  tweak.set(nonce, 1);
  return deoxysBcEncrypt(derived, tweak, accumulator);
}

/**
 * The second pass. The *nonce* is the plaintext and the tag is the tweak, which is the inversion that
 * makes this a one-pass-per-direction stream over a fixed input rather than a counter mode over one.
 */
function applyKeystream(
  derived: readonly Uint8Array[],
  nonce: Uint8Array,
  tag: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const noncePlaintext = new Uint8Array(BLOCK);
  noncePlaintext.set(nonce, 1);
  const out = new Uint8Array(data.length);
  for (let block = 0; block * BLOCK < data.length; block++) {
    const stream = deoxysBcEncrypt(derived, encryptionTweak(tag, block), noncePlaintext);
    const n = Math.min(BLOCK, data.length - block * BLOCK);
    for (let i = 0; i < n; i++) out[block * BLOCK + i] = data[block * BLOCK + i]! ^ stream[i]!;
  }
  return out;
}

/** Encrypt and authenticate. Returns the ciphertext with the 16-byte tag appended. */
export function deoxysIISeal(
  key: Uint8Array,
  nonce: Uint8Array,
  message: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  checkNonce(nonce);
  const derived = deoxysDeriveKeys(key);
  const tag = computeTag(derived, nonce, ad, message);
  const ciphertext = applyKeystream(derived, nonce, tag, message);

  const sealed = new Uint8Array(message.length + TAG_LENGTH);
  sealed.set(ciphertext);
  sealed.set(tag, message.length);
  return sealed;
}

/**
 * Verify and decrypt. Throws when the tag does not match.
 *
 * The recomputation is not optional and not a belt-and-braces check: the ciphertext is decrypted
 * *first*, because the received tag is the keystream's tweak, and only then is the tag recomputed over
 * the recovered plaintext. So a forgery produces plausible bytes on the way through and is caught at
 * the end -- which is exactly why nothing may be returned before the comparison.
 */
export function deoxysIIOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  checkNonce(nonce);
  if (sealed.length < TAG_LENGTH) {
    throw new Error(
      `Deoxys-II's output carries a 16-byte tag, so there are at least 16 bytes; this one is ${sealed.length}.`,
    );
  }
  const derived = deoxysDeriveKeys(key);
  const ciphertext = sealed.subarray(0, sealed.length - TAG_LENGTH);
  const tag = sealed.subarray(sealed.length - TAG_LENGTH);

  const message = applyKeystream(derived, nonce, Uint8Array.from(tag), ciphertext);
  const expected = computeTag(derived, nonce, ad, message);

  let diff = 0;
  for (let i = 0; i < TAG_LENGTH; i++) diff |= expected[i]! ^ tag[i]!;
  if (diff !== 0) throw new Error("Deoxys-II: the tag does not match.");
  return message;
}
