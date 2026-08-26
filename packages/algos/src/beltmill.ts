/**
 * RadioGatun[32], RadioGatun[64] and Panama -- Daemen's belt-and-mill constructions.
 *
 * Both are the direct ancestors of Keccak: a large state split into a *mill* that does the nonlinear
 * work and a *belt* that carries information forward through a shift register, with the two feeding each
 * other. Panama came first (1998) and was broken for collisions in 2001; RadioGatun (2006) is the
 * redesign, and the sponge construction that became SHA-3 grew out of analysing it.
 *
 * Verified against sphlib's own test files: 39 vectors per RadioGatun width -- the Keccak team's
 * published set, which runs from the empty string up to a 2000-character message -- and Panama's four,
 * including the million-'a' case. All 82 passed first run.
 *
 * ## Three things that decide correctness
 *
 * **The belt rotates once per round, and the mill reads the stage that is about to leave.** The
 * reference avoids the rotation by walking a moving base index backwards; this rotates the array
 * explicitly, which is the same thing and is what the specification describes. Getting the direction
 * wrong gives a hash that is perfectly self-consistent.
 *
 * **The mill's pi step is a permutation *and* a rotation, and the rotation amount is triangular.** Word
 * i takes word `7i mod 19` rotated right by `i(i+1)/2` -- so the amounts are 0, 1, 3, 6, 10, 15... mod
 * the word size, which differ between the 32- and 64-bit variants. That is the only thing separating the
 * two, and it is why they are one implementation.
 *
 * **The blank-round count depends on how much padding there was.** Eighteen rounds total after the last
 * input block, and the padded block itself contributes thirteen -- so the number left over is a function
 * of where in the block the message ended. A fixed count is right for one length in thirteen.
 *
 * ## Panama's two modes are one step function
 *
 * `push` feeds the message into both the buffer and the state; `pull` feeds the *state* into the buffer
 * and reads the buffer back into the state. Same 17-word gamma-pi-theta-sigma step, two different
 * sources for its two inputs -- which is why `step` takes them as functions rather than branching.
 */

import { eagerAbsorber, type LwcHasher } from "./lwc-hash";

/** pi's source permutation: word i takes word 7i mod 19. */
const T7 = Array.from({ length: 19 }, (_, i) => (7 * i) % 19);
/** pi's rotation amounts: the triangular numbers, reduced by the caller to the word size. */
const TRI = Array.from({ length: 19 }, (_, i) => (i * (i + 1)) / 2);

export type RadioGatunWidth = 32 | 64;

/**
 * One RadioGatun engine. `wide` selects 64-bit words, which changes only the rotation amounts.
 *
 * `bigint` for the 64-bit variant rather than a limb pair: the mill is one OR, one NOT and two XORs per
 * word per round, so there is no arithmetic to lose to `bigint`'s overhead beyond a constant factor, and
 * a 32-bit-limb rewrite would double the surface for a transposition.
 */
function radiogatunEngine(bits: RadioGatunWidth) {
  const wide = bits === 64;
  const mask64 = (1n << 64n) - 1n;
  const wb = bits / 8;
  const blockSize = 13 * 3 * wb;

  // One of the two paths is live per engine; both are written so neither needs a runtime branch inside
  // the mill, which runs nineteen times per step.
  const a32 = new Uint32Array(19);
  const a64 = new Array<bigint>(19).fill(0n);
  const belt32: Uint32Array[] = Array.from({ length: 13 }, () => new Uint32Array(3));
  const belt64: bigint[][] = Array.from({ length: 13 }, () => [0n, 0n, 0n]);

  const millWide = (): void => {
    const t = new Array<bigint>(19);
    for (let i = 0; i < 19; i++) {
      t[i] = a64[i]! ^ (a64[(i + 1) % 19]! | (~a64[(i + 2) % 19]! & mask64));
    }
    for (let i = 0; i < 19; i++) {
      const n = TRI[i]! % 64;
      const v = t[T7[i]!]!;
      a64[i] = n === 0 ? v : ((v >> BigInt(n)) | (v << BigInt(64 - n))) & mask64;
    }
    for (let i = 0; i < 19; i++) t[i] = a64[i]! ^ a64[(i + 1) % 19]! ^ a64[(i + 4) % 19]!;
    for (let i = 0; i < 19; i++) a64[i] = t[i]!;
    a64[0] = a64[0]! ^ 1n;
  };

  const millNarrow = (): void => {
    const t = new Uint32Array(19);
    for (let i = 0; i < 19; i++) t[i] = (a32[i]! ^ (a32[(i + 1) % 19]! | ~a32[(i + 2) % 19]!)) >>> 0;
    for (let i = 0; i < 19; i++) {
      const n = TRI[i]! % 32;
      const v = t[T7[i]!]!;
      a32[i] = n === 0 ? v : ((v >>> n) | (v << (32 - n))) >>> 0;
    }
    for (let i = 0; i < 19; i++) t[i] = (a32[i]! ^ a32[(i + 1) % 19]! ^ a32[(i + 4) % 19]!) >>> 0;
    for (let i = 0; i < 19; i++) a32[i] = t[i]!;
    a32[0] = (a32[0]! ^ 1) >>> 0;
  };

  const round = (): void => {
    if (wide) {
      for (let i = 0; i < 12; i++) belt64[i]![i % 3] = belt64[i]![i % 3]! ^ a64[i + 1]!;
      millWide();
      for (let s = 0; s < 3; s++) a64[13 + s] = a64[13 + s]! ^ belt64[12]![s]!;
      const last = belt64[12]!;
      for (let i = 12; i > 0; i--) belt64[i] = belt64[i - 1]!;
      belt64[0] = last;
    } else {
      for (let i = 0; i < 12; i++) belt32[i]![i % 3] = (belt32[i]![i % 3]! ^ a32[i + 1]!) >>> 0;
      millNarrow();
      for (let s = 0; s < 3; s++) a32[13 + s] = (a32[13 + s]! ^ belt32[12]![s]!) >>> 0;
      const last = belt32[12]!;
      for (let i = 12; i > 0; i--) belt32[i] = belt32[i - 1]!;
      belt32[0] = last;
    }
  };

  const pushBlock = (buf: Uint8Array, base: number): void => {
    for (let k = 0; k < 13; k++) {
      for (let s = 0; s < 3; s++) {
        const off = base + wb * (3 * k + s);
        if (wide) {
          let v = 0n;
          for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i]!);
          belt64[0]![s] = belt64[0]![s]! ^ v;
          a64[16 + s] = a64[16 + s]! ^ v;
        } else {
          const v = (buf[off]! | (buf[off + 1]! << 8) | (buf[off + 2]! << 16) | (buf[off + 3]! << 24)) >>> 0;
          belt32[0]![s] = (belt32[0]![s]! ^ v) >>> 0;
          a32[16 + s] = (a32[16 + s]! ^ v) >>> 0;
        }
      }
      round();
    }
  };

  return { blockSize, wb, wide, a32, a64, round, pushBlock };
}

/** RadioGatun[32] or RadioGatun[64], incremental. 256-bit output at both widths. */
export function createRadioGatun(bits: RadioGatunWidth): LwcHasher {
  const e = radiogatunEngine(bits);
  return eagerAbsorber(
    e.blockSize,
    (block, off) => e.pushBlock(block, off),
    (tail, tailLen) => {
      const padded = new Uint8Array(e.blockSize);
      padded.set(tail.subarray(0, tailLen));
      padded[tailLen] = 0x01;
      e.pushBlock(padded, 0);

      /**
       * Eighteen blank rounds in total, thirteen of which the padded block just ran.
       *
       * The remainder is a function of where the message ended in its block, which is what the division
       * computes -- the reference derives it the same way, from the offset the 0x01 landed at.
       */
      const blanks = 17 - Math.floor((e.blockSize - (tailLen + 1)) / (3 * e.wb));
      for (let i = 0; i < blanks; i++) e.round();

      const out = new Uint8Array(32);
      let produced = 0;
      for (;;) {
        for (const index of [1, 2]) {
          if (e.wide) {
            const v = e.a64[index]!;
            for (let i = 0; i < 8; i++) out[produced + i] = Number((v >> BigInt(8 * i)) & 0xffn);
          } else {
            const v = e.a32[index]!;
            for (let i = 0; i < 4; i++) out[produced + i] = (v >>> (8 * i)) & 0xff;
          }
          produced += e.wb;
        }
        if (produced >= 32) break;
        e.round();
      }
      return out;
    },
  );
}

export function radiogatun(bits: RadioGatunWidth, message: Uint8Array): Uint8Array {
  const h = createRadioGatun(bits);
  h.update(message);
  return h.digest();
}

// ---------------------------------------------------------------- Panama

/** pi's source words and left-rotation amounts, over a 17-word state. */
const PANAMA_PI_SRC = [0, 7, 14, 4, 11, 1, 8, 15, 5, 12, 2, 9, 16, 6, 13, 3, 10] as const;
const PANAMA_PI_ROT = [0, 1, 3, 6, 10, 15, 21, 28, 4, 13, 23, 2, 14, 27, 9, 24, 8] as const;
/** The buffer update's eight (destination, source) slot pairs. */
const BUPDATE = [[0, 2], [1, 3], [2, 4], [3, 5], [4, 6], [5, 7], [6, 0], [7, 1]] as const;

/** Panama: a 17-word mill over a 32-stage, 8-word buffer. 256-bit output, 32-byte rate. */
export function createPanama(): LwcHasher {
  const a = new Uint32Array(17);
  const buffer = Array.from({ length: 32 }, () => new Uint32Array(8));
  let ptr = 0;
  const rotl = (x: number, n: number): number => (n === 0 ? x >>> 0 : ((x << n) | (x >>> (32 - n))) >>> 0);

  /** One step. `feedBuffer` and `feedState` are the only difference between push and pull. */
  const step = (feedBuffer: (i: number) => number, feedState: (i: number) => number): void => {
    const ptr24 = (ptr - 8) & 31;
    const ptr31 = (ptr - 1) & 31;
    for (const [dst, src] of BUPDATE) {
      buffer[ptr24]![dst] = (buffer[ptr24]![dst]! ^ buffer[ptr31]![src]!) >>> 0;
      buffer[ptr31]![src] = (buffer[ptr31]![src]! ^ feedBuffer(src)) >>> 0;
    }
    const g = new Uint32Array(17);
    for (let i = 0; i < 17; i++) g[i] = (a[i]! ^ (a[(i + 1) % 17]! | ~a[(i + 2) % 17]!)) >>> 0;
    const p = new Uint32Array(17);
    for (let i = 0; i < 17; i++) p[i] = rotl(g[PANAMA_PI_SRC[i]!]!, PANAMA_PI_ROT[i]!);
    const t = new Uint32Array(17);
    for (let i = 0; i < 17; i++) t[i] = (p[i]! ^ p[(i + 1) % 17]! ^ p[(i + 4) % 17]!) >>> 0;
    const ptr16 = ptr ^ 16;
    a[0] = (t[0]! ^ 1) >>> 0;
    for (let i = 1; i <= 8; i++) a[i] = (t[i]! ^ feedState(i - 1)) >>> 0;
    for (let i = 9; i <= 16; i++) a[i] = (t[i]! ^ buffer[ptr16]![i - 9]!) >>> 0;
    ptr = ptr31;
  };

  const pushBlock = (buf: Uint8Array, off: number): void => {
    const words = new Uint32Array(8);
    for (let i = 0; i < 8; i++) {
      words[i] =
        (buf[off + 4 * i]! |
          (buf[off + 4 * i + 1]! << 8) |
          (buf[off + 4 * i + 2]! << 16) |
          (buf[off + 4 * i + 3]! << 24)) >>> 0;
    }
    step((i) => words[i]!, (i) => words[i]!);
  };

  return eagerAbsorber(
    32,
    (block, off) => pushBlock(block, off),
    (tail, tailLen) => {
      const padded = new Uint8Array(32);
      padded.set(tail.subarray(0, tailLen));
      padded[tailLen] = 0x01;
      pushBlock(padded, 0);
      // Thirty-two pull steps: the state feeds the buffer and the buffer feeds the state.
      for (let n = 0; n < 32; n++) {
        const ptr4 = (ptr + 4) & 31;
        step((i) => a[i + 1]!, (i) => buffer[ptr4]![i]!);
      }
      const out = new Uint8Array(32);
      for (let i = 0; i < 8; i++) {
        const v = a[i + 9]!;
        out[4 * i] = v & 0xff;
        out[4 * i + 1] = (v >>> 8) & 0xff;
        out[4 * i + 2] = (v >>> 16) & 0xff;
        out[4 * i + 3] = (v >>> 24) & 0xff;
      }
      return out;
    },
  );
}

export function panama(message: Uint8Array): Uint8Array {
  const h = createPanama();
  h.update(message);
  return h.digest();
}
