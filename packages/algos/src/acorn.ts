/**
 * ACORN-128 v3, one of the seven ciphers in CAESAR's final portfolio and the smallest AEAD here.
 *
 * 293 bits of state in six concatenated LFSRs, and **no tables, no constants and no key schedule at
 * all** -- its whole definition is thirteen tap positions, a majority function and a choose function.
 * Trivium is the only other thing in this repo that austere, and ACORN does authenticated encryption
 * with it. That is why it was in the portfolio's lightweight-hardware use case.
 *
 * `modern`: no attack on the full construction. There is a real caveat and it is a *usage* one rather
 * than a break -- the designers state that a key must not be used for two messages under the same
 * nonce, and unlike a nonce-misuse-resistant mode such as Deoxys-II the consequence here is total.
 *
 * Five things to preserve.
 *
 * **One step function, three callers, and the message bit is chosen last.** Absorbing associated data
 * feeds the data bit; encrypting feeds the plaintext bit; decrypting feeds `ciphertext ^ keystream`,
 * which is the plaintext bit again. So the state always absorbs *plaintext*, and `stepWith` takes a
 * callback rather than a value because for decryption the bit is not known until the keystream bit for
 * that same step has been produced.
 *
 * **The six feedback lines run in order and later ones read earlier results.** `S[230]` is updated by
 * the second line and then read by the keystream function; `S[107]` is updated by the fifth and read
 * by the feedback. Computing all six from a snapshot of the state gives a cipher that is perfectly
 * self-consistent and reproduces nothing.
 *
 * **Bits go in least significant first.** Byte `b` of a message is eight steps taking bit 0, then bit
 * 1, and so on. Most significant first is the other plausible reading and it is wrong.
 *
 * **The padding between phases is 256 steps, not 384.** Sixteen bytes with `ca = 1` and then sixteen
 * with `ca = 0`, the very first bit being a 1 and the rest zero; `cb` is 1 after the associated data
 * and 0 after the message, which is the only thing distinguishing the two paddings. Getting the count
 * wrong here was this implementation's one first-attempt bug, and FELICS's per-phase intermediate
 * states are what localised it in a single comparison -- initialisation matched exactly, so the fault
 * had to be after it.
 *
 * **The state is a ring, not a shifting array.** A step conceptually shifts all 293 bits down by one;
 * doing that literally costs 293 array writes per *bit* of message. `offset` moves instead, so a step
 * touches about sixteen positions. It is still bit-serial and therefore slow -- a few MB/s, in the
 * same range as XXH3 and Whirlpool here -- which is a property of the design rather than of this port.
 *
 * No oracle: nothing in this tree implements ACORN and OpenSSL never did. What stands behind it is
 * four published vector sets with per-phase intermediate states; see `tests/algos-acorn.test.ts`.
 */

const STATE_BITS = 293;
const KEY_LENGTH = 16;
const NONCE_LENGTH = 16;
const TAG_LENGTH = 16;

const maj = (x: number, y: number, z: number): number => (x & y) ^ (x & z) ^ (y & z);
const ch = (x: number, y: number, z: number): number => (x & y) ^ ((x ^ 1) & z);

/**
 * The state as a ring of 293 bits.
 *
 * `read`/`write` take a *logical* index -- 0 is the oldest bit -- and `advance` is what a step's shift
 * becomes: the window moves and the new bit is written at logical 292.
 */
class AcornState {
  private readonly bits = new Uint8Array(STATE_BITS);
  private offset = 0;

  private index(logical: number): number {
    const i = this.offset + logical;
    return i >= STATE_BITS ? i - STATE_BITS : i;
  }

  read(logical: number): number {
    return this.bits[this.index(logical)]!;
  }

  xorInto(logical: number, value: number): void {
    const at = this.index(logical);
    this.bits[at] = this.bits[at]! ^ value;
  }

  advance(newest: number): void {
    // The oldest slot becomes the newest, which is what makes the shift free.
    this.bits[this.offset] = newest;
    this.offset = this.offset + 1 === STATE_BITS ? 0 : this.offset + 1;
  }

  /** The 293 bits packed least significant bit first, which is how every reference prints them. */
  pack(): Uint8Array {
    const out = new Uint8Array(Math.ceil(STATE_BITS / 8));
    for (let i = 0; i < STATE_BITS; i++) {
      if (this.read(i) !== 0) out[i >> 3] = out[i >> 3]! | (1 << (i & 7));
    }
    return out;
  }
}

/**
 * One step. Returns the keystream bit; `chooseMessage` decides what is absorbed, given that bit.
 *
 * The two control bits are the mode: `ca` and `cb` together say which phase this step belongs to, and
 * they are the only thing separating initialisation from the associated data from the message.
 */
function stepWith(
  s: AcornState,
  ca: number,
  cb: number,
  chooseMessage: (keystream: number) => number,
): number {
  // The six feedback lines, in order -- each reads whatever the ones before it wrote.
  s.xorInto(289, s.read(235) ^ s.read(230));
  s.xorInto(230, s.read(196) ^ s.read(193));
  s.xorInto(193, s.read(160) ^ s.read(154));
  s.xorInto(154, s.read(111) ^ s.read(107));
  s.xorInto(107, s.read(66) ^ s.read(61));
  s.xorInto(61, s.read(23) ^ s.read(0));

  const keystream =
    s.read(12) ^
    s.read(154) ^
    maj(s.read(235), s.read(61), s.read(193)) ^
    ch(s.read(230), s.read(111), s.read(66));

  const feedback =
    s.read(0) ^
    (s.read(107) ^ 1) ^
    maj(s.read(244), s.read(23), s.read(160)) ^
    (ca & s.read(196)) ^
    (cb & keystream);

  s.advance(feedback ^ chooseMessage(keystream));
  return keystream;
}

/** Eight steps over one byte, least significant bit first. Returns the keystream byte. */
function stepByte(s: AcornState, ca: number, cb: number, input: number, decrypt: boolean): number {
  let keystream = 0;
  for (let bit = 0; bit < 8; bit++) {
    const supplied = (input >> bit) & 1;
    const ks = stepWith(s, ca, cb, (k) => (decrypt ? supplied ^ k : supplied));
    keystream |= ks << bit;
  }
  return keystream & 0xff;
}

/** 1,792 steps: the key, the nonce, then the key again with a single 1 bit folded in at step 256. */
function initialise(key: Uint8Array, nonce: Uint8Array): AcornState {
  const s = new AcornState();
  for (let j = 0; j < 224; j++) {
    let m: number;
    if (j < 16) m = key[j]!;
    else if (j < 32) m = nonce[j - 16]!;
    else if (j === 32) m = key[0]! ^ 1;
    else m = key[j & 0xf]!;
    stepByte(s, 1, 1, m, false);
  }
  return s;
}

/**
 * The 256-step separator between phases.
 *
 * Sixteen bytes with `ca = 1` and sixteen with `ca = 0`, a single 1 bit at the very start and zeros
 * after. `cb` is 1 after the associated data and 0 after the message, and that is the whole difference
 * between the two -- which is what makes it a domain separator rather than mere padding.
 */
function separate(s: AcornState, cb: number): void {
  for (let j = 0; j < 16; j++) stepByte(s, 1, cb, j === 0 ? 0x01 : 0x00, false);
  for (let j = 0; j < 16; j++) stepByte(s, 0, cb, 0x00, false);
}

/** 768 steps with nothing absorbed; the last 128 keystream bits are the tag. */
function finalise(s: AcornState): Uint8Array {
  for (let j = 0; j < 80; j++) stepByte(s, 1, 1, 0, false);
  const tag = new Uint8Array(TAG_LENGTH);
  for (let i = 0; i < TAG_LENGTH; i++) tag[i] = stepByte(s, 1, 1, 0, false);
  return tag;
}

function check(key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`ACORN-128's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`ACORN-128's nonce is exactly 16 bytes; this one is ${nonce.length}.`);
  }
}

/**
 * The state after initialisation and after absorbing associated data, exported for the tests.
 *
 * These are what the published fixtures carry alongside the ciphertext, and they are the reason this
 * implementation was right on the second attempt rather than the tenth: a wrong answer with a correct
 * post-initialisation state can only be a fault in a later phase.
 */
export function acornPhaseStates(
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
): { afterInit: Uint8Array; afterAd: Uint8Array } {
  check(key, nonce);
  const s = initialise(key, nonce);
  const afterInit = s.pack();
  for (const byte of ad) stepByte(s, 1, 1, byte, false);
  separate(s, 1);
  return { afterInit, afterAd: s.pack() };
}

/** Encrypt and authenticate. Returns the ciphertext with the 16-byte tag appended. */
export function acornEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  message: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  check(key, nonce);
  const s = initialise(key, nonce);
  for (const byte of ad) stepByte(s, 1, 1, byte, false);
  separate(s, 1);

  const out = new Uint8Array(message.length + TAG_LENGTH);
  for (let i = 0; i < message.length; i++) {
    out[i] = message[i]! ^ stepByte(s, 1, 0, message[i]!, false);
  }
  separate(s, 0);
  out.set(finalise(s), message.length);
  return out;
}

/**
 * Verify and decrypt. Throws when the tag does not match.
 *
 * Note the state absorbs the recovered *plaintext*, not the ciphertext -- which is why `stepByte` has
 * to be told which direction it is running rather than simply being handed bytes.
 */
export function acornDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  check(key, nonce);
  if (sealed.length < TAG_LENGTH) {
    throw new Error(
      `ACORN-128's output carries a 16-byte tag, so there are at least 16 bytes; this one is ${sealed.length}.`,
    );
  }
  const s = initialise(key, nonce);
  for (const byte of ad) stepByte(s, 1, 1, byte, false);
  separate(s, 1);

  const length = sealed.length - TAG_LENGTH;
  const message = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    message[i] = sealed[i]! ^ stepByte(s, 1, 0, sealed[i]!, true);
  }
  separate(s, 0);
  const expected = finalise(s);

  let diff = 0;
  for (let i = 0; i < TAG_LENGTH; i++) diff |= expected[i]! ^ sealed[length + i]!;
  if (diff !== 0) throw new Error("ACORN-128: the tag does not match.");
  return message;
}
