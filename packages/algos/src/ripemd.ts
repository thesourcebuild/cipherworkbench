import { MerkleDamgard, rotl32, writeBitLength } from "./md-common";

/**
 * RIPEMD-128, RIPEMD-256 and RIPEMD-320.
 *
 * `@noble/hashes` carries RIPEMD-160 and none of its three siblings, and no maintained library
 * on npm carries all four -- so these are here for the same reason MD2 and Whirlpool are.
 * RIPEMD-160 is *not* reimplemented: noble's is used for that, and this file's correctness is
 * anchored to it. `generateSchedule` below produces the message-order and rotation tables the
 * same way noble does, from the Rho permutation, and `tests/algos-ripemd.test.ts` builds a
 * RIPEMD-160 out of this generic core and requires it to equal noble's byte for byte. That single
 * assertion covers the schedule, the shift tables, the round constants, the five round functions
 * and the dual-lane step -- which is nearly all of the surface where a transcription error could
 * hide. The published vectors then cover what remains: each variant's own finalisation.
 *
 * The three variants differ in only four things, which is why one parameterised core serves all
 * of them:
 *
 *  - **Rounds.** 128 and 256 run four; 320 runs five, like 160.
 *  - **Step shape.** Four-word lines have no `e` accumulator and no `rotl(c, 10)`; five-word lines
 *    have both.
 *  - **State.** 128 and 160 keep one line's worth of state and cross-add the two lanes at the end.
 *    256 and 320 keep *both* lanes' state -- twice the output -- and swap one word between the
 *    lanes after each round, which is the only thing stopping the two halves from being
 *    independent hashes of the same message.
 *  - **Finalisation.** The doubled variants simply add each lane into its own half; the narrow
 *    ones cross-add in a specific rotated order.
 *
 * Reference: Dobbertin, Bosselaers and Preneel, "RIPEMD-160: A Strengthened Version of RIPEMD",
 * plus the extended-variant definitions of RIPEMD-128/256/320 from the same authors.
 */

/** The permutation the later message orderings are derived from. */
const RHO = /* @__PURE__ */ Uint8Array.from([
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
]);

/** Per-round base rotation amounts, indexed by *word* rather than by step. */
const SHIFTS = /* @__PURE__ */ [
  [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
  [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
  [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
  [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
  [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
].map((row) => Uint8Array.from(row));

/** Left-lane additive constants. RIPEMD-128 and -256 use the first four. */
const KL = /* @__PURE__ */ Uint32Array.from([
  0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e,
]);

/**
 * Right-lane additive constants, and the one place the narrow variants are not simply a prefix.
 *
 * A five-round line uses all of `[0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0]`. A
 * four-round line drops `0x7a6d76e9` and *keeps* the trailing zero -- so it is the first three
 * followed by 0, not the first four. Taking a prefix here would be wrong in a way no round-trip
 * test could see.
 */
const KR5 = /* @__PURE__ */ Uint32Array.from([
  0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000,
]);
const KR4 = /* @__PURE__ */ Uint32Array.from([0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x00000000]);

/** The five round functions. The right lane uses them in reverse order. */
function f(group: number, x: number, y: number, z: number): number {
  if (group === 0) return x ^ y ^ z;
  if (group === 1) return (x & y) | (~x & z);
  if (group === 2) return (x | ~y) ^ z;
  if (group === 3) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}

interface Schedule {
  /** Message word index per step, per round, for each lane. */
  order: Uint8Array[];
  /** Rotation amount per step, per round, for each lane. */
  shifts: Uint8Array[];
}

/**
 * Derives a lane's message order and rotation tables rather than transcribing them.
 *
 * The left lane starts from the identity permutation and the right from `(9i + 5) mod 16`; each
 * later round applies Rho to the previous round's order. The rotation table is then *indexed by
 * the word*, not by the step -- which is the subtlety that makes these tables so easy to get
 * wrong when copied by hand, and the reason they are computed here instead.
 */
function generateSchedule(rounds: number, right: boolean): Schedule {
  const first = Uint8Array.from({ length: 16 }, (_, i) => (right ? (9 * i + 5) % 16 : i));
  const order: Uint8Array[] = [first];
  for (let round = 1; round < rounds; round++) {
    const previous = order[round - 1]!;
    order.push(Uint8Array.from(previous, (word) => RHO[word]!));
  }
  const shifts = order.map((words, round) =>
    Uint8Array.from(words, (word) => SHIFTS[round]![word]!),
  );
  return { order, shifts };
}

/** How one RIPEMD variant differs from the others. */
interface RipemdShape {
  name: string;
  /** Words per lane: 4 for RIPEMD-128/256, 5 for RIPEMD-160/320. */
  lane: 4 | 5;
  /**
   * True for RIPEMD-256/320: both lanes' state is kept and the output is twice as wide.
   *
   * The doubled variants also swap one word between the lanes after each round. Without that
   * swap the two halves would be independent hashes of the same message, and concatenating those
   * would give 256 bits of output with only 128 bits of collision resistance.
   */
  doubled: boolean;
  init: readonly number[];
}

const SHAPES: Readonly<Record<string, RipemdShape>> = {
  "ripemd-128": {
    name: "RIPEMD-128",
    lane: 4,
    doubled: false,
    init: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
  },
  /** Present so the RIPEMD-160 equality check against `@noble/hashes` has something to run. */
  "ripemd-160": {
    name: "RIPEMD-160",
    lane: 5,
    doubled: false,
    init: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
  },
  "ripemd-256": {
    name: "RIPEMD-256",
    lane: 4,
    doubled: true,
    init: [
      0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0x76543210, 0xfedcba98, 0x89abcdef,
      0x01234567,
    ],
  },
  "ripemd-320": {
    name: "RIPEMD-320",
    lane: 5,
    doubled: true,
    init: [
      0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0x76543210, 0xfedcba98,
      0x89abcdef, 0x01234567, 0x3c2d1e0f,
    ],
  },
};

class Ripemd extends MerkleDamgard {
  private readonly h: Int32Array;
  private readonly rounds: number;
  private readonly left: Schedule;
  private readonly right: Schedule;
  private readonly kr: Uint32Array;
  /** One 16-word block, reused. */
  private readonly words = new Int32Array(16);
  /** The two lanes' working state, reused across blocks. */
  private readonly lhs: Int32Array;
  private readonly rhs: Int32Array;

  constructor(private readonly shape: RipemdShape) {
    super(64, shape.init.length * 4, 8, shape.name);
    this.rounds = shape.lane === 4 ? 4 : 5;
    this.left = generateSchedule(this.rounds, false);
    this.right = generateSchedule(this.rounds, true);
    this.kr = shape.lane === 4 ? KR4 : KR5;
    this.h = Int32Array.from(shape.init.map((word) => word | 0));
    this.lhs = new Int32Array(shape.lane);
    this.rhs = new Int32Array(shape.lane);
  }

  protected override compress(block: Uint8Array, offset: number): void {
    const { words, lhs, rhs, h, shape, rounds } = this;
    for (let i = 0; i < 16; i++) {
      const at = offset + i * 4;
      // Little-endian, like MD4 and MD5 and unlike SHA-2.
      words[i] =
        block[at]! |
        (block[at + 1]! << 8) |
        (block[at + 2]! << 16) |
        (block[at + 3]! << 24) |
        0;
    }

    // A doubled variant seeds each lane from its own half of the state; a narrow one seeds both
    // lanes from the same words and only separates them at the end.
    for (let i = 0; i < shape.lane; i++) {
      lhs[i] = h[i]!;
      rhs[i] = shape.doubled ? h[shape.lane + i]! : h[i]!;
    }

    for (let round = 0; round < rounds; round++) {
      const startSlot = this.startSlotFor(round);
      this.runLane(lhs, round, round, this.left, KL[round]!, startSlot);
      this.runLane(rhs, round, rounds - 1 - round, this.right, this.kr[round]!, startSlot);
      if (shape.doubled) {
        // The lane crossover. One word, at the round's own index.
        const swap = lhs[round]!;
        lhs[round] = rhs[round]!;
        rhs[round] = swap;
      }
    }

    if (shape.doubled) {
      for (let i = 0; i < shape.lane; i++) {
        h[i] = (h[i]! + lhs[i]!) | 0;
        h[shape.lane + i] = (h[shape.lane + i]! + rhs[i]!) | 0;
      }
      return;
    }

    this.combineNarrow(lhs, rhs);
  }

  /**
   * Sixteen steps of one lane, operating on fixed state slots.
   *
   * `group` selects the round's message order and rotations; `fGroup` selects the round function,
   * and the two differ for the right lane -- it walks the functions in reverse while walking the
   * schedules forwards. Conflating them is the classic RIPEMD bug.
   *
   * The register rotation is expressed as slot arithmetic rather than by shuffling locals, and
   * that choice is load-bearing rather than stylistic. Each step consumes one register and writes
   * the result over it, the write slot decreasing by one per step; sixteen steps therefore leave
   * the rotation **1 mod 5** out of phase for a five-word lane and **0 mod 4** in phase for a
   * four-word one. Hence `startSlot`, which the caller derives from the round number.
   *
   * Why it matters: the doubled variants swap one word between the lanes after each round, and the
   * swap addresses a *slot*. A locals-based version is perfectly self-consistent and produced a
   * correct RIPEMD-128, RIPEMD-160 and RIPEMD-256 while producing a wrong RIPEMD-320 -- because
   * only the five-word doubled variant has both a phase shift and a swap. The reference's own
   * tables show the shift plainly: RIPEMD-320's rounds begin `0,1,2,3,4`, `4,0,1,2,3`, `3,4,0,1,2`
   * and so on, where RIPEMD-256's every round begins `0,1,2,3`.
   */
  private runLane(
    state: Int32Array,
    group: number,
    fGroup: number,
    schedule: Schedule,
    k: number,
    startSlot: number,
  ): void {
    const lane = this.shape.lane;
    const order = schedule.order[group]!;
    const shifts = schedule.shifts[group]!;
    const words = this.words;

    for (let step = 0; step < 16; step++) {
      // The slot being written, then the ones read from, cyclically after it.
      const a = (((startSlot - step) % lane) + lane) % lane;
      const b = (a + 1) % lane;
      const c = (a + 2) % lane;
      const d = (a + 3) % lane;

      let value =
        rotl32(
          (state[a]! + f(fGroup, state[b]!, state[c]!, state[d]!) + words[order[step]!]! + k) |
            0,
          shifts[step]!,
        ) | 0;

      if (lane === 5) {
        // The five-word step adds `e` after the rotation and carries `c` forward pre-rotated by
        // ten. Both are absent from the four-word variants; that is the whole structural
        // difference between RIPEMD-128/256 and RIPEMD-160/320.
        value = (value + state[(a + 4) % lane]!) | 0;
        state[c] = rotl32(state[c]!, 10) | 0;
      }
      state[a] = value;
    }
  }

  /** The slot a round's first step writes, given the phase shift described on `runLane`. */
  private startSlotFor(round: number): number {
    const lane = this.shape.lane;
    return ((((-16 * round) % lane) + lane) % lane) | 0;
  }

  /**
   * RIPEMD-128 and RIPEMD-160's finalisation: a rotated cross-add of the two lanes.
   *
   * Each new word combines the *old* state one position along with one word from each lane, and
   * the position offsets differ between the two widths. Written with a snapshot of `h` rather than
   * updating in place, because the reference's sequential assignments happen to read old values
   * that a naive in-place translation would already have overwritten.
   */
  private combineNarrow(lhs: Int32Array, rhs: Int32Array): void {
    const h = this.h;
    if (this.shape.lane === 4) {
      const prev = [h[0]!, h[1]!, h[2]!, h[3]!];
      h[0] = (prev[1]! + lhs[2]! + rhs[3]!) | 0;
      h[1] = (prev[2]! + lhs[3]! + rhs[0]!) | 0;
      h[2] = (prev[3]! + lhs[0]! + rhs[1]!) | 0;
      h[3] = (prev[0]! + lhs[1]! + rhs[2]!) | 0;
      return;
    }
    const prev = [h[0]!, h[1]!, h[2]!, h[3]!, h[4]!];
    h[0] = (prev[1]! + lhs[2]! + rhs[3]!) | 0;
    h[1] = (prev[2]! + lhs[3]! + rhs[4]!) | 0;
    h[2] = (prev[3]! + lhs[4]! + rhs[0]!) | 0;
    h[3] = (prev[4]! + lhs[0]! + rhs[1]!) | 0;
    h[4] = (prev[0]! + lhs[1]! + rhs[2]!) | 0;
  }

  protected override writeLength(block: Uint8Array, offset: number, byteLength: number): void {
    writeBitLength(block, offset, byteLength, 8, "le");
  }

  protected override writeDigest(out: Uint8Array): void {
    for (let i = 0; i < this.h.length; i++) {
      const word = this.h[i]!;
      out[i * 4] = word & 0xff;
      out[i * 4 + 1] = (word >>> 8) & 0xff;
      out[i * 4 + 2] = (word >>> 16) & 0xff;
      out[i * 4 + 3] = (word >>> 24) & 0xff;
    }
  }
}

function create(id: string): Ripemd {
  const shape = SHAPES[id];
  if (!shape) throw new Error(`Unknown RIPEMD variant: ${id}`);
  return new Ripemd(shape);
}

export const createRipemd128 = (): Ripemd => create("ripemd-128");
export const createRipemd256 = (): Ripemd => create("ripemd-256");
export const createRipemd320 = (): Ripemd => create("ripemd-320");

/**
 * RIPEMD-160 built from this same core, exported for one purpose: the test that requires it to
 * equal `@noble/hashes`' independent implementation. The app uses noble's, not this.
 */
export const createRipemd160ForTesting = (): Ripemd => create("ripemd-160");
