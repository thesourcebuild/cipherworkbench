/**
 * SAFER+, Massey, Khachatrian and Kuregian's AES candidate -- and the cipher Bluetooth's legacy pairing
 * runs on.
 *
 * `legacy`. There is no break of the full cipher, but it was not an AES finalist and the reason is
 * relevant: its key schedule was shown to be weak enough that related-key and collision attacks reach
 * reduced-round variants, and nothing has been built on it since. It is here to reproduce values --
 * SAFER+ is the E21/E22/E1 primitive in Bluetooth's pre-4.2 pairing, so a captured link key is a real
 * thing to want to check, and this is the third such "here for the capture" cipher after KASUMI and
 * SNOW 3G.
 *
 * The design is unlike anything else in this repo. There is **no S-box table and no MDS matrix**:
 *
 *  - Substitution is `45^x mod 257` and its inverse, applied to alternating byte positions. That is
 *    *discrete exponentiation as an S-box*, which is why 45 appears everywhere in this file.
 *  - Diffusion is a Pseudo-Hadamard Transform -- `(a, b) -> (2a + b, a + b)` over the integers mod 256,
 *    so addition rather than XOR -- run three times with a fixed byte shuffle between, which Massey
 *    named the "Armenian" shuffle.
 *  - The rounds alternate `XOR then exp then add` with `add then log then XOR` per byte position, so a
 *    round is not one operation applied sixteen times.
 *
 * **Nothing at all is stored.** Four things come out of arithmetic:
 *
 *  - the exponentiation box, `45^i mod 257` with 256 written as 0;
 *  - the logarithm box, its inverse;
 *  - **all 512 bytes of the key-schedule bias**, and this is the one worth reading twice. Rows 0 to 15
 *    are `45^(45^m mod 257) mod 257` and rows 16 to 31 are `45^m mod 257` -- the *same* continuous
 *    index `m = 17r + c + 35`, exponentiated twice for the first half of the schedule and once for the
 *    second. LibTomCrypt ships them as a literal 33-by-16 table; its 33rd row is never indexed and is
 *    therefore dead data, which is why only 512 of its 528 bytes are reproduced here.
 *
 * Two things to preserve.
 *
 * **The boxes swap on the way back.** A position that applies `exp` forwards applies `log` in reverse,
 * because the inverse of "exponentiate then add" is "subtract then take the logarithm". Keeping the
 * same box in both directions gives a cipher whose encryption is perfectly correct and whose decryption
 * is not -- which no round trip can see and which cost this implementation its one first-attempt bug.
 *
 * **The last round key is applied without a substitution**, with XOR on the exp positions and addition
 * on the log ones, mirroring the first half of a round and not a whole one.
 *
 * No oracle: OpenSSL never implemented SAFER+ and nothing in this tree has it. What stands behind it is
 * LibTomCrypt's three self-test vectors, one per key length. See `tests/algos-saferp.test.ts`.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;

/** `45^i mod 257`, with 256 written as 0 -- SAFER+'s substitution, and its inverse. */
const EXP = new Uint8Array(256);
const LOG = new Uint8Array(256);
{
  let v = 1;
  for (let i = 0; i < 256; i++) {
    EXP[i] = v === 256 ? 0 : v;
    v = (v * 45) % 257;
  }
  for (let i = 0; i < 256; i++) LOG[EXP[i]!] = i;
}

/** `45^e mod 257`, in 1..256 -- the un-truncated form the bias derivation needs. */
function power45(e: number): number {
  let r = 1;
  for (let i = 0; i < e; i++) r = (r * 45) % 257;
  return r;
}

/**
 * The 32 key-schedule bias rows, derived.
 *
 * One continuous index; the first sixteen rows exponentiate twice and the last sixteen once. See the
 * header -- this is the part of SAFER+ that every implementation ships as half a kilobyte of literal.
 */
const BIAS: number[][] = [];
for (let row = 0; row < 32; row++) {
  const values: number[] = [];
  for (let col = 0; col < BLOCK; col++) {
    const m = 17 * row + 35 + col;
    values.push((row < 16 ? power45(power45(m)) : power45(m)) % 256);
  }
  BIAS.push(values);
}

/** Exported so a test can pin the derivation against a reference's own first row. */
export const SAFERP_BIAS_FIRST: readonly number[] = BIAS[0]!;

/**
 * Which byte positions take the exponentiation box.
 *
 * `true` at 0, 3, 4, 7, 8, 11, 12, 15 -- so the pattern is exp, log, log, exp repeating, which is what
 * makes a SAFER+ round two interleaved operations rather than one.
 */
const USES_EXP = [
  true, false, false, true, true, false, false, true, true, false, false, true, true, false, false,
  true,
] as const;

/** The Armenian shuffle, as a source index per destination position, and its inverse. */
const SHUFFLE = [8, 11, 12, 15, 2, 1, 6, 5, 10, 9, 14, 13, 0, 7, 4, 3] as const;
const SHUFFLE_INVERSE = [12, 5, 4, 15, 14, 7, 6, 13, 0, 9, 8, 1, 2, 11, 10, 3] as const;

const KEY_ROUNDS: Readonly<Record<number, number>> = { 16: 8, 24: 12, 32: 16 };

/** The round keys: `2 * rounds + 1` of them, sixteen bytes each. */
function schedule(key: Uint8Array): { keys: number[][]; rounds: number } {
  const rounds = KEY_ROUNDS[key.length];
  if (rounds === undefined) {
    throw new Error(`SAFER+'s key is 16, 24 or 32 bytes; this one is ${key.length}.`);
  }

  // The key plus a parity byte, rotated left three bits per round key.
  const material = new Uint8Array(key.length + 1);
  let parity = 0;
  for (let i = 0; i < key.length; i++) {
    material[i] = key[i]!;
    parity ^= key[i]!;
  }
  material[key.length] = parity;

  const keys: number[][] = [Array.from(key.subarray(0, BLOCK))];
  for (let n = 1; n <= key.length; n++) {
    for (let i = 0; i < material.length; i++) {
      material[i] = ((material[i]! << 3) | (material[i]! >> 5)) & 0xff;
    }
    // Sixteen bytes selected from a rotating cursor, each with its bias added.
    const row: number[] = [];
    let at = n;
    for (let col = 0; col < BLOCK; col++) {
      row.push((material[at]! + BIAS[n - 1]![col]!) & 0xff);
      if (++at === material.length) at = 0;
    }
    keys.push(row);
  }
  return { keys, rounds };
}

/** Half a round: key, substitution, key. The `pair` index selects the two round keys it uses. */
function substitutionLayer(b: Uint8Array, keys: readonly number[][], pair: number): void {
  const first = keys[pair]!;
  const second = keys[pair + 1]!;
  for (let i = 0; i < BLOCK; i++) {
    b[i] = USES_EXP[i]
      ? (EXP[(b[i]! ^ first[i]!) & 0xff]! + second[i]!) & 0xff
      : LOG[(b[i]! + first[i]!) & 0xff]! ^ second[i]!;
  }
}

/** The inverse. Note the boxes swap: an exp position inverts through the log box. */
function inverseSubstitutionLayer(b: Uint8Array, keys: readonly number[][], pair: number): void {
  const first = keys[pair]!;
  const second = keys[pair + 1]!;
  for (let i = 0; i < BLOCK; i++) {
    b[i] = USES_EXP[i]
      ? LOG[(b[i]! - second[i]!) & 0xff]! ^ first[i]!
      : (EXP[(b[i]! ^ second[i]!) & 0xff]! - first[i]!) & 0xff;
  }
}

/** The Pseudo-Hadamard Transform on eight adjacent pairs, in place. */
function pht(b: Uint8Array): void {
  for (let i = 0; i < BLOCK; i += 2) {
    b[i + 1] = (b[i + 1]! + b[i]!) & 0xff;
    b[i] = (b[i]! + b[i + 1]!) & 0xff;
  }
}

function inversePht(b: Uint8Array): void {
  for (let i = BLOCK - 2; i >= 0; i -= 2) {
    b[i] = (b[i]! - b[i + 1]!) & 0xff;
    b[i + 1] = (b[i + 1]! - b[i]!) & 0xff;
  }
}

const shuffled = (b: Uint8Array, table: readonly number[]) => Uint8Array.from(table, (from) => b[from]!);

/** Four transforms with three shuffles between them, which is one diffusion layer. */
function linear(b: Uint8Array) {
  let state = b;
  for (let i = 0; i < 3; i++) {
    pht(state);
    state = shuffled(state, SHUFFLE);
  }
  pht(state);
  return state;
}

function inverseLinear(b: Uint8Array) {
  let state = b;
  for (let i = 0; i < 3; i++) {
    inversePht(state);
    state = shuffled(state, SHUFFLE_INVERSE);
  }
  inversePht(state);
  return state;
}

/** The final key application: no substitution, and the two operations swapped per position. */
function applyLastKey(b: Uint8Array, last: readonly number[], forward: boolean) {
  const out = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    if (USES_EXP[i]) out[i] = b[i]! ^ last[i]!;
    else out[i] = (forward ? b[i]! + last[i]! : b[i]! - last[i]!) & 0xff;
  }
  return out;
}

/** SAFER+ as a `BlockCipher`. The key is 16, 24 or 32 bytes and the block is always 16. */
export function createSaferPlus(key: Uint8Array): BlockCipher {
  const { keys, rounds } = schedule(key);
  const last = keys[rounds * 2]!;

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      let state: Uint8Array = Uint8Array.from(src.subarray(0, BLOCK));
      for (let r = 0; r < rounds; r++) {
        substitutionLayer(state, keys, 2 * r);
        state = linear(state);
      }
      dst.set(applyLastKey(state, last, true));
    },
    decryptBlock: (src, dst) => {
      let state: Uint8Array = applyLastKey(Uint8Array.from(src.subarray(0, BLOCK)), last, false);
      for (let r = rounds - 1; r >= 0; r--) {
        state = inverseLinear(state);
        inverseSubstitutionLayer(state, keys, 2 * r);
      }
      dst.set(state);
    },
  };
}
