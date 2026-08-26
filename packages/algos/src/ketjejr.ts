/**
 * Ketje Jr -- the smallest member of the Keccak team's Ketje family (CAESAR round 2, 2014).
 *
 * `legacy`. No attack on it, but the CAESAR process chose Ascon and NORX over the Ketje family and
 * nothing has been built on it since; the same team's Xoodyak is the successor to reach for.
 *
 * **A MonkeyDuplex over Keccak-p[200], and that 200 is the point.** Every other Keccak-derived thing
 * here -- SHA-3, SHAKE, TurboSHAKE, Xoodyak, Ascon -- has lanes of 64 or 32 bits. Ketje Jr's lanes are
 * **eight bits**, so its whole state is 25 bytes and its rotations are `rol8`. That makes it the
 * smallest permutation-based AEAD in this repo by a wide margin, and it means the round constants and
 * rho offsets are *not* the ones SHA-3 uses: they are Keccak's reduced to a byte, so `0x8000000000008089`
 * becomes `0x89`.
 *
 * Four things to preserve.
 *
 * **The round count counts from the END of the constant list.** `KeccakP200_Permute_Nrounds(n)` runs
 * rounds `18 - n` through `17`, not `0` through `n - 1`. So the 12-round start uses constants 6..17 and
 * the single-round step uses constant 17 alone. Starting from zero gives a permutation that is
 * perfectly invertible and reproduces nothing -- and it is the natural way to write the loop.
 *
 * **Three different round counts, and they are not interchangeable.** 12 to start, **1** per step, 6
 * for the stride between phases. A single-round step is what makes a MonkeyDuplex cheap and is also why
 * Ketje needs the stride: one round is not enough separation between the data phases.
 *
 * **Every state access goes through the twist.** `KetJr_StateTwistIndexes` is not a table of round
 * constants, it is a *coordinate remapping*: byte `i` of the logical rate lives at physical position
 * `TWIST[i]`. Adding, extracting and overwriting all apply it, and only the block-feeding loops in the
 * data phases index the state directly -- which they do through the same table. Skipping it anywhere
 * gives a cipher that round-trips against itself and matches nothing.
 *
 * **The block is two bytes.** So a 7-byte message is three full blocks and a 1-byte remainder, and the
 * `(len + BLOCK - 1) & ~(BLOCK - 1) - BLOCK` expression that finds the full-block count deliberately
 * leaves a *non-empty* final chunk even when the length is a multiple of two -- the last block always
 * goes through the byte-at-a-time path. That is why 7 and 8 byte messages take different paths and why
 * the fixture uses 7.
 *
 * Verified against FELICS's own vector, which publishes the state after *each phase* as well as the
 * ciphertext and tag -- so a failure localises to initialisation, associated data, the data phase or
 * finalisation rather than to the whole construction.
 */

/** Keccak's rho offsets and round constants, reduced to eight-bit lanes. */
const RHO = [0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6] as const;
const ROUND_CONSTANTS = [
  0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
  0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80,
] as const;

/** Byte `i` of the logical rate lives at physical position `TWIST[i]`. See the header. */
const TWIST = [
  0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21,
] as const;

const MAX_ROUNDS = 18;
const START_ROUNDS = 12;
const STEP_ROUNDS = 1;
const STRIDE_ROUNDS = 6;

export const KETJE_JR_BLOCK = 2;
export const KETJE_JR_KEY_LEN = 16;
export const KETJE_JR_NONCE_MAX = 6;
export const KETJE_JR_TAG_LEN = 16;
const STATE = 25;

const FRAME_0 = 0x02;
const FRAME_00 = 0x04;
const FRAME_10 = 0x05;
const FRAME_01 = 0x06;
const FRAME_11 = 0x07;

const at = (x: number, y: number): number => (x % 5) + 5 * (y % 5);
const rol8 = (a: number, n: number): number => (n === 0 ? a & 0xff : ((a << n) ^ (a >> (8 - n))) & 0xff);

function keccakP200Round(A: Uint8Array, round: number): void {
  // theta
  const C = new Uint8Array(5);
  const D = new Uint8Array(5);
  for (let x = 0; x < 5; x++) {
    let c = 0;
    for (let y = 0; y < 5; y++) c ^= A[at(x, y)]!;
    C[x] = c;
  }
  for (let x = 0; x < 5; x++) D[x] = rol8(C[(x + 1) % 5]!, 1) ^ C[(x + 4) % 5]!;
  for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) A[at(x, y)] = A[at(x, y)]! ^ D[x]!;
  // rho
  for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) A[at(x, y)] = rol8(A[at(x, y)]!, RHO[at(x, y)]!);
  // pi
  const copy = A.slice();
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) A[at(y, 2 * x + 3 * y)] = copy[at(x, y)]!;
  }
  // chi
  for (let y = 0; y < 5; y++) {
    const row = new Uint8Array(5);
    for (let x = 0; x < 5; x++) row[x] = A[at(x, y)]! ^ (~A[at(x + 1, y)]! & A[at(x + 2, y)]!);
    for (let x = 0; x < 5; x++) A[at(x, y)] = row[x]!;
  }
  // iota
  A[0] = A[0]! ^ ROUND_CONSTANTS[round]!;
}

/** `n` rounds, taken from the *end* of the constant list. See the header. */
function permute(A: Uint8Array, rounds: number): void {
  for (let i = MAX_ROUNDS - rounds; i < MAX_ROUNDS; i++) keccakP200Round(A, i);
}

const addByte = (A: Uint8Array, value: number, offset: number): void => {
  if (offset < STATE) A[offset] = A[offset]! ^ value;
};
const twistAdd = (A: Uint8Array, value: number, offset: number): void => addByte(A, value, TWIST[offset]!);
const twistExtract = (A: Uint8Array, offset: number): number => A[TWIST[offset]!]!;

function step(A: Uint8Array, size: number, frame: number): void {
  addByte(A, frame, TWIST[size]!);
  addByte(A, 0x08, TWIST[KETJE_JR_BLOCK]!);
  permute(A, STEP_ROUNDS);
}

function initialize(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const A = new Uint8Array(STATE);
  // The key pack: a length byte, the key, a 0x01 terminator, then the nonce and another 0x01.
  const overwrite = (offset: number, data: ArrayLike<number>): void => {
    for (let i = 0; i < data.length; i++) A[TWIST[offset + i]!] = data[i]!;
  };
  overwrite(0, [KETJE_JR_KEY_LEN + 2]);
  overwrite(1, key);
  overwrite(1 + KETJE_JR_KEY_LEN, [0x01]);
  overwrite(1 + KETJE_JR_KEY_LEN + 1, nonce);
  overwrite(1 + KETJE_JR_KEY_LEN + 1 + nonce.length, [0x01]);
  twistAdd(A, 0x80, STATE - 1);
  permute(A, START_ROUNDS);
  return A;
}

function processAssociatedData(A: Uint8Array, ad: Uint8Array): void {
  let remainder = 0;
  let cursor = 0;
  let length = ad.length;
  if (length > KETJE_JR_BLOCK) {
    const size = ((length + (KETJE_JR_BLOCK - 1)) & ~(KETJE_JR_BLOCK - 1)) - KETJE_JR_BLOCK;
    let blocks = size / KETJE_JR_BLOCK;
    do {
      for (let lane = 0; lane < KETJE_JR_BLOCK; lane++) {
        addByte(A, ad[cursor]!, TWIST[lane]!);
        cursor++;
      }
      step(A, KETJE_JR_BLOCK, FRAME_00);
    } while (--blocks !== 0);
    length -= size;
  }
  while (length-- !== 0) twistAdd(A, ad[cursor++]!, remainder++);
  step(A, remainder, FRAME_01);
}

/**
 * The data phase, both directions.
 *
 * Encrypting adds the plaintext byte and *then* reads the state; decrypting reads the state, XORs to
 * recover the plaintext byte and adds *that*. So the state always absorbs plaintext, which is what
 * makes the two paths inverses -- and it is why the block loop cannot be shared with a flag on the XOR
 * alone.
 */
function processData(A: Uint8Array, input: Uint8Array, decrypt: boolean): Uint8Array {
  const out = new Uint8Array(input.length);
  let remainder = 0;
  let cursor = 0;
  let length = input.length;
  if (length > 0) {
    if (length > KETJE_JR_BLOCK) {
      const size = ((length + (KETJE_JR_BLOCK - 1)) & ~(KETJE_JR_BLOCK - 1)) - KETJE_JR_BLOCK;
      let blocks = size / KETJE_JR_BLOCK;
      while (blocks-- !== 0) {
        for (let lane = 0; lane < KETJE_JR_BLOCK; lane++) {
          const position = TWIST[lane]!;
          if (decrypt) {
            const plain = input[cursor]! ^ A[position]!;
            out[cursor] = plain;
            A[position] = A[position]! ^ plain;
          } else {
            A[position] = A[position]! ^ input[cursor]!;
            out[cursor] = A[position]!;
          }
          cursor++;
        }
        addByte(A, 0x08 | FRAME_11, TWIST[KETJE_JR_BLOCK]!);
        permute(A, STEP_ROUNDS);
      }
      length -= size;
    }
    for (let i = 0; i < length; i++) {
      const value = input[cursor]!;
      const plain = decrypt ? value ^ twistExtract(A, remainder) : value;
      out[cursor] = decrypt ? plain : value ^ twistExtract(A, remainder);
      cursor++;
      twistAdd(A, plain, remainder++);
    }
  }
  twistAdd(A, FRAME_10, remainder);
  twistAdd(A, 0x08, KETJE_JR_BLOCK);
  permute(A, STRIDE_ROUNDS);
  return out;
}

function generateTag(A: Uint8Array): Uint8Array {
  const tag = new Uint8Array(KETJE_JR_TAG_LEN);
  let written = 0;
  let part = Math.min(KETJE_JR_TAG_LEN, KETJE_JR_BLOCK);
  for (let i = 0; i < part; i++) tag[written++] = twistExtract(A, i);
  let remaining = KETJE_JR_TAG_LEN - part;
  while (remaining > 0) {
    step(A, 0, FRAME_0);
    part = Math.min(remaining, KETJE_JR_BLOCK);
    for (let i = 0; i < part; i++) tag[written++] = twistExtract(A, i);
    remaining -= part;
  }
  return tag;
}

function requireInputs(key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== KETJE_JR_KEY_LEN) {
    throw new Error(`Ketje Jr's key is exactly ${KETJE_JR_KEY_LEN} bytes; this one is ${key.length}.`);
  }
  if (nonce.length > KETJE_JR_NONCE_MAX) {
    throw new Error(
      `Ketje Jr's nonce is at most ${KETJE_JR_NONCE_MAX} bytes -- the key pack and the nonce ` +
        `share a 25-byte state; this one is ${nonce.length}.`,
    );
  }
}

export function ketjeJrSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  plaintext: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  requireInputs(key, nonce);
  const A = initialize(key, nonce);
  processAssociatedData(A, associatedData);
  const ciphertext = processData(A, plaintext, false);
  return { ciphertext, tag: generateTag(A) };
}

/** Returns null when the tag does not match. */
export function ketjeJrOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Uint8Array | null {
  requireInputs(key, nonce);
  const A = initialize(key, nonce);
  processAssociatedData(A, associatedData);
  const plaintext = processData(A, ciphertext, true);
  const expected = generateTag(A);
  if (expected.length !== tag.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i]! ^ tag[i]!;
  return diff === 0 ? plaintext : null;
}

/** The state after each phase, for the test that checks FELICS's per-phase values. */
export const __ketjeJrPhases = {
  run(key: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array, plaintext: Uint8Array) {
    requireInputs(key, nonce);
    const A = initialize(key, nonce);
    const afterInit = A.slice();
    processAssociatedData(A, associatedData);
    const afterAd = A.slice();
    const ciphertext = processData(A, plaintext, false);
    const afterData = A.slice();
    const tag = generateTag(A);
    return { afterInit, afterAd, afterData, ciphertext, tag };
  },
};
