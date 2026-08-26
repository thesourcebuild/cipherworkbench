/**
 * The LS-designs: Robin, Robin* and Fantomas (Grosso, Leurent, Standaert and Varici, FSE 2014).
 *
 * One family, one implementation, three configurations -- which is the point of the paper rather than a
 * convenience here. An LS-design is *defined* by a pair of tables: an **L**inear box over a 16-bit word
 * and an **S**ubstitution box over the eight bits at the same position across eight such words. Pick a
 * pair, and the cipher follows. The three members differ only in which pair, how many rounds, and how the
 * round constant is generated.
 *
 * | Member | Rounds | S-box | L-box | Inverse |
 * |---|---|---|---|---|
 * | Robin | 16 | involutive | involutive | itself, with the constants reversed |
 * | Robin* | 16 | involutive | involutive | itself, with the counter run backwards |
 * | Fantomas | 12 | not | not | a separate S-box and a separate L-box |
 *
 * That table is the whole design space, and it is why **Robin's decryption is its encryption**: both
 * boxes being involutions means the only thing to undo is the order of the round constants. Fantomas
 * traded that property for a better security bound, which is what its extra tables cost.
 *
 * **Robin\* exists because Robin's L-box has an invariant subspace.** Leander, Minaud and Rønjom found
 * that Robin (and PRINCE) have weak-key classes reachable through it; Robin\* is the authors' response,
 * and it changes *only the round constant* -- an incrementing counter rotated per word instead of a table
 * lookup. So the two share every table, and the difference is four lines. That is worth knowing before
 * anyone treats them as unrelated ciphers, and it is why `security` differs between them here.
 *
 * Five things to preserve.
 *
 * **There is no key schedule.** The 128-bit key is XORed in before the first round and after every round,
 * unchanged -- so this is the fourth cipher here with no schedule at all, after LED, PRIDE and
 * Chaskey-LTS.
 *
 * **The state is eight little-endian 16-bit words**, and the S-box operates *across* them bitwise while
 * the L-box operates *within* each. Getting those two axes the wrong way round gives a cipher that is
 * perfectly self-consistent and reproduces nothing.
 *
 * **The L-box is two 256-entry tables, and its inverse is derived.** `v -> L2[v >> 8] ^ L1[v & 0xff]` is
 * linear over GF(2), so the 16-by-16 matrix comes out of evaluating it on sixteen basis vectors and the
 * inverse out of Gaussian elimination -- which is how Fantomas's `LBoxInv` pair is produced here rather
 * than stored. The tests compare the derivation against the reference's literals.
 *
 * **Fantomas's S-box is a 5-bit box, a 3-bit Keccak box and two cross-XOR layers**, and the *Keccak* part
 * is an involution while the whole is not. Its inverse runs the pieces in reverse with the 5-bit box's own
 * inverse -- and note the two negations move from one side of the Keccak layer to the other.
 *
 * **Robin's round constant is `L1[round + 1]`** -- a lookup into the L-box's own first table, which is an
 * unusual thing to reuse and easy to mistake for a separate constant table. Its decryption counts
 * `L1[rounds - round]`.
 *
 * No oracle -- OpenSSL has never implemented any LS-design. What stands behind them is one published
 * vector each from FELICS's benchmarking suite, checked in both directions.
 */
import type { BlockCipher } from "./blockmodes";
import { LS_FANTOMAS_LBOX, LS_ROBIN_LBOX } from "./ls-tables";

const BLOCK = 16;
const KEY = 16;
const WORDS = 8;

export type LsDesign = "robin" | "robinstar" | "fantomas";

const u16 = (x: number): number => x & 0xffff;

/**
 * Robin's S-box: three applications of one function over the eight bit-planes.
 *
 * An involution, which the tests assert -- it is what makes Robin its own inverse.
 */
function robinSbox(x: number[]): void {
  const apply = (a: number, b: number, c: number, d: number, w: number, y: number, z: number, t: number): void => {
    const A = x[a]!;
    const B = x[b]!;
    const C = x[c]!;
    const D = x[d]!;
    const p = u16(u16(A & B) ^ C);
    const r = u16(u16(B | C) ^ D);
    const s = u16(u16(p & D) ^ A);
    const q = u16(u16(r & A) ^ B);
    x[w] = u16(x[w]! ^ p);
    x[y] = u16(x[y]! ^ q);
    x[z] = u16(x[z]! ^ r);
    x[t] = u16(x[t]! ^ s);
  };
  apply(4, 5, 6, 7, 0, 1, 2, 3);
  apply(0, 1, 2, 3, 4, 5, 6, 7);
  apply(4, 5, 6, 7, 0, 1, 2, 3);
}

/** Fantomas's 5-bit box over planes 0 to 4, and its inverse. */
function fantomasS5(x: number[]): void {
  x[2] = u16(x[2]! ^ (x[0]! & x[1]!));
  x[1] = u16(x[1]! ^ x[2]!);
  x[3] = u16(x[3]! ^ (x[0]! & x[4]!));
  x[2] = u16(x[2]! ^ x[3]!);
  x[0] = u16(x[0]! ^ (x[1]! & x[3]!));
  x[4] = u16(x[4]! ^ x[1]!);
  x[1] = u16(x[1]! ^ (x[2]! & x[4]!));
  x[1] = u16(x[1]! ^ x[0]!);
}

function fantomasS5Inverse(x: number[]): void {
  x[1] = u16(x[1]! ^ x[0]!);
  x[1] = u16(x[1]! ^ (x[2]! & x[4]!));
  x[4] = u16(x[4]! ^ x[1]!);
  x[0] = u16(x[0]! ^ (x[1]! & x[3]!));
  x[2] = u16(x[2]! ^ x[3]!);
  x[3] = u16(x[3]! ^ (x[0]! & x[4]!));
  x[1] = u16(x[1]! ^ x[2]!);
  x[2] = u16(x[2]! ^ (x[0]! & x[1]!));
}

/** The 3-bit Keccak box over planes 5 to 7, which *is* an involution. */
function keccakS3(x: number[]): void {
  const a = x[5]!;
  const b = x[6]!;
  const c = x[7]!;
  x[5] = u16(a ^ (u16(~b) & c));
  x[6] = u16(b ^ (u16(~c) & a));
  x[7] = u16(c ^ (u16(~a) & b));
}

function fantomasSbox(x: number[]): void {
  fantomasS5(x);
  for (let i = 0; i < 3; i++) x[i] = u16(x[i]! ^ x[i + 5]!);
  x[3] = u16(~x[3]!);
  x[4] = u16(~x[4]!);
  keccakS3(x);
  for (let i = 0; i < 3; i++) x[i + 5] = u16(x[i + 5]! ^ x[i]!);
  fantomasS5(x);
}

/** The inverse. Note the negations sit on the *other* side of the Keccak layer. */
function fantomasSboxInverse(x: number[]): void {
  fantomasS5Inverse(x);
  for (let i = 0; i < 3; i++) x[i + 5] = u16(x[i + 5]! ^ x[i]!);
  keccakS3(x);
  x[3] = u16(~x[3]!);
  x[4] = u16(~x[4]!);
  for (let i = 0; i < 3; i++) x[i] = u16(x[i]! ^ x[i + 5]!);
  fantomasS5Inverse(x);
}

/**
 * The inverse of an L-box, derived.
 *
 * `v -> L2[v >> 8] ^ L1[v & 0xff]` is linear over GF(2), so the sixteen images of the basis vectors are
 * the matrix and Gaussian elimination gives its inverse. The two 256-entry inverse tables then fall out of
 * the inverse matrix the same way the forward pair encodes the forward one.
 */
function invertLbox(pair: readonly [readonly number[], readonly number[]]): [number[], number[]] {
  const [low, high] = pair;
  const forward = (v: number): number => u16(high[v >> 8]! ^ low[v & 0xff]!);

  // Rows of the matrix, as the images of the sixteen basis vectors, augmented with the identity.
  const rows = Array.from({ length: 16 }, (_, bit) => [forward(1 << bit), 1 << bit]);
  // Gauss-Jordan over GF(2) on the first column of each pair.
  for (let col = 0; col < 16; col++) {
    let pivot = -1;
    for (let r = col; r < 16; r++) {
      if (((rows[r]![0]! >> col) & 1) === 1) {
        pivot = r;
        break;
      }
    }
    if (pivot < 0) throw new Error("An LS-design L-box is singular.");
    const swap = rows[col]!;
    rows[col] = rows[pivot]!;
    rows[pivot] = swap;
    for (let r = 0; r < 16; r++) {
      if (r === col || ((rows[r]![0]! >> col) & 1) === 0) continue;
      rows[r]![0] = u16(rows[r]![0]! ^ rows[col]![0]!);
      rows[r]![1] = u16(rows[r]![1]! ^ rows[col]![1]!);
    }
  }
  // Row `col` now maps basis vector `col` back; build the two byte-indexed tables from it.
  const inverseLow = new Array<number>(256).fill(0);
  const inverseHigh = new Array<number>(256).fill(0);
  for (let byte = 0; byte < 256; byte++) {
    let lowImage = 0;
    let highImage = 0;
    for (let bit = 0; bit < 8; bit++) {
      if (((byte >> bit) & 1) === 0) continue;
      lowImage = u16(lowImage ^ rows[bit]![1]!);
      highImage = u16(highImage ^ rows[bit + 8]![1]!);
    }
    inverseLow[byte] = lowImage;
    inverseHigh[byte] = highImage;
  }
  return [inverseLow, inverseHigh];
}

interface Design {
  readonly rounds: number;
  readonly lbox: readonly [readonly number[], readonly number[]];
  readonly inverseLbox: readonly [readonly number[], readonly number[]];
  readonly sbox: (x: number[]) => void;
  readonly inverseSbox: (x: number[]) => void;
  /** True when the round constant is the incrementing counter rather than a table lookup. */
  readonly counterConstant: boolean;
}

const ROBIN_INVERSE_LBOX = invertLbox(LS_ROBIN_LBOX);
const FANTOMAS_INVERSE_LBOX = invertLbox(LS_FANTOMAS_LBOX);

/** Exported so a test can compare the derivation against the reference's stored tables. */
export const LS_FANTOMAS_INVERSE_LBOX: readonly (readonly number[])[] = FANTOMAS_INVERSE_LBOX;

const DESIGNS: Readonly<Record<LsDesign, Design>> = {
  robin: {
    rounds: 16,
    lbox: LS_ROBIN_LBOX,
    inverseLbox: ROBIN_INVERSE_LBOX,
    sbox: robinSbox,
    inverseSbox: robinSbox,
    counterConstant: false,
  },
  robinstar: {
    rounds: 16,
    lbox: LS_ROBIN_LBOX,
    inverseLbox: ROBIN_INVERSE_LBOX,
    sbox: robinSbox,
    inverseSbox: robinSbox,
    counterConstant: true,
  },
  fantomas: {
    rounds: 12,
    lbox: LS_FANTOMAS_LBOX,
    inverseLbox: FANTOMAS_INVERSE_LBOX,
    sbox: fantomasSbox,
    inverseSbox: fantomasSboxInverse,
    counterConstant: false,
  },
};

/** Robin\*'s counter step. Forwards it adds; backwards it subtracts, starting from the last value. */
const COUNTER_STEP = 2199;

export function createLsDesign(key: Uint8Array, design: LsDesign): BlockCipher {
  const spec = DESIGNS[design];
  if (spec === undefined) throw new Error(`Unknown LS-design: ${String(design)}.`);
  if (key.length !== KEY) {
    throw new Error(`This LS-design's key is exactly 16 bytes; this one is ${key.length}.`);
  }
  const k = Array.from({ length: WORDS }, (_, i) => u16(key[2 * i]! | (key[2 * i + 1]! << 8)));

  const load = (src: Uint8Array): number[] =>
    Array.from({ length: WORDS }, (_, i) => u16(src[2 * i]! | (src[2 * i + 1]! << 8)));
  const store = (x: readonly number[], dst: Uint8Array): void => {
    for (let i = 0; i < WORDS; i++) {
      dst[2 * i] = x[i]! & 0xff;
      dst[2 * i + 1] = (x[i]! >> 8) & 0xff;
    }
  };
  const addKey = (x: number[]): void => {
    for (let i = 0; i < WORDS; i++) x[i] = u16(x[i]! ^ k[i]!);
  };
  /** The counter constant, rotated left by the word index -- Robin\*'s only departure from Robin. */
  const addCounter = (x: number[], t: number): void => {
    x[0] = u16(x[0]! ^ t);
    for (let i = 1; i < WORDS; i++) x[i] = u16(x[i]! ^ u16((t << i) | (t >>> (16 - i))));
  };
  const applyLbox = (x: number[], pair: readonly [readonly number[], readonly number[]]): void => {
    for (let i = 0; i < WORDS; i++) x[i] = u16(pair[1][x[i]! >> 8]! ^ pair[0][x[i]! & 0xff]!);
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      const x = load(src);
      addKey(x);
      let counter = 0;
      for (let round = 0; round < spec.rounds; round++) {
        if (spec.counterConstant) {
          addCounter(x, counter);
          counter = u16(counter + COUNTER_STEP);
        } else {
          x[0] = u16(x[0]! ^ spec.lbox[0][round + 1]!);
        }
        spec.sbox(x);
        applyLbox(x, spec.lbox);
        addKey(x);
      }
      store(x, dst);
    },
    decryptBlock: (src, dst) => {
      const x = load(src);
      addKey(x);
      // The counter runs backwards from where encryption left it.
      let counter = u16(COUNTER_STEP * (spec.rounds - 1));
      for (let round = 0; round < spec.rounds; round++) {
        applyLbox(x, spec.inverseLbox);
        spec.inverseSbox(x);
        addKey(x);
        if (spec.counterConstant) {
          addCounter(x, counter);
          counter = u16(counter - COUNTER_STEP);
        } else {
          x[0] = u16(x[0]! ^ spec.lbox[0][spec.rounds - round]!);
        }
      }
      store(x, dst);
    },
  };
}
