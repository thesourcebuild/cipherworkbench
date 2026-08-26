/**
 * 64-bit unsigned arithmetic on pairs of 32-bit halves.
 *
 * JavaScript has two ways to do 64-bit maths and both have a real cost. `BigInt` is
 * correct and allocates on every operation, which makes it roughly twenty times slower
 * than 32-bit work in a hot loop. Splitting into high and low halves is fast and easy to
 * get subtly wrong.
 *
 * This module exists so the getting-it-wrong happens once, in one place, with its own
 * tests — rather than inline in Whirlpool's round function and again in XXH64's mixing
 * step. Values are passed as `(hi, lo)` pairs of numbers held in the unsigned 32-bit
 * range, and results are returned through the `out` scratch pair so nothing allocates
 * per operation.
 *
 * Every function here treats its inputs as unsigned. `>>> 0` appears liberally for that
 * reason: JavaScript's bitwise operators produce *signed* 32-bit results, so a value
 * with the top bit set comes back negative and poisons every comparison and array index
 * downstream.
 */

/** A mutable 64-bit value. Reused across calls to keep the hot loops allocation-free. */
export interface U64 {
  hi: number;
  lo: number;
}

export const u64 = (hi = 0, lo = 0): U64 => ({ hi: hi >>> 0, lo: lo >>> 0 });

export function set64(out: U64, hi: number, lo: number): U64 {
  out.hi = hi >>> 0;
  out.lo = lo >>> 0;
  return out;
}

export function copy64(out: U64, a: U64): U64 {
  out.hi = a.hi;
  out.lo = a.lo;
  return out;
}

export function add64(out: U64, a: U64, b: U64): U64 {
  // Add the low halves as unsigned and detect the carry by comparison rather than by
  // inspecting bit 32 — the sum can exceed 2^32 and lose that bit to float rounding
  // only above 2^53, which this cannot reach, so the comparison is exact.
  const lo = (a.lo + b.lo) >>> 0;
  const carry = lo < a.lo ? 1 : 0;
  out.lo = lo;
  out.hi = (a.hi + b.hi + carry) >>> 0;
  return out;
}

/**
 * `out = a - b`, wrapping. The borrow is the only thing to get right.
 *
 * Here for Tiger, whose round function subtracts as readily as it adds -- `a -= T1[...] ^ ...` -- and
 * whose key schedule does it four more times.
 */
export function sub64(out: U64, a: U64, b: U64): U64 {
  const lo = a.lo - b.lo;
  // A negative low half means one borrow from the high half; `>>> 0` puts it back in range.
  out.lo = lo >>> 0;
  out.hi = (a.hi - b.hi - (lo < 0 ? 1 : 0)) >>> 0;
  return out;
}

/** `out = a << bits`, for 0 <= bits < 64. The mirror of `shr64`. */
export function shl64(out: U64, a: U64, bits: number): U64 {
  if (bits === 0) return copy64(out, a);
  if (bits < 32) {
    out.hi = ((a.hi << bits) | (a.lo >>> (32 - bits))) >>> 0;
    out.lo = (a.lo << bits) >>> 0;
  } else {
    out.hi = (a.lo << (bits - 32)) >>> 0;
    out.lo = 0;
  }
  return out;
}

/** `out = ~a`. */
export function not64(out: U64, a: U64): U64 {
  out.hi = ~a.hi >>> 0;
  out.lo = ~a.lo >>> 0;
  return out;
}

export function xor64(out: U64, a: U64, b: U64): U64 {
  out.hi = (a.hi ^ b.hi) >>> 0;
  out.lo = (a.lo ^ b.lo) >>> 0;
  return out;
}

/**
 * 64x64 -> 64 multiply, keeping the low 64 bits.
 *
 * Decomposed into four 16-bit limbs per operand rather than two 32-bit halves. With
 * 32-bit halves the partial products reach 2^64 and lose precision as doubles; 16-bit
 * limbs keep every partial product under 2^32, which a double represents exactly.
 */
export function mul64(out: U64, a: U64, b: U64): U64 {
  const a0 = a.lo & 0xffff;
  const a1 = a.lo >>> 16;
  const a2 = a.hi & 0xffff;
  const a3 = a.hi >>> 16;

  const b0 = b.lo & 0xffff;
  const b1 = b.lo >>> 16;
  const b2 = b.hi & 0xffff;
  const b3 = b.hi >>> 16;

  // Column 0: bits 0-15.
  const c0 = a0 * b0;
  const r0 = c0 & 0xffff;

  // Column 1: bits 16-31, carrying in from column 0.
  let c1 = (c0 >>> 16) + a0 * b1;
  let c2 = c1 >>> 16;
  c1 &= 0xffff;
  c1 += a1 * b0;
  c2 += c1 >>> 16;
  const r1 = c1 & 0xffff;

  // Column 2: bits 32-47.
  let c3 = c2 >>> 16;
  c2 &= 0xffff;
  c2 += a0 * b2;
  c3 += c2 >>> 16;
  c2 &= 0xffff;
  c2 += a1 * b1;
  c3 += c2 >>> 16;
  c2 &= 0xffff;
  c2 += a2 * b0;
  c3 += c2 >>> 16;
  const r2 = c2 & 0xffff;

  // Column 3: bits 48-63. Everything above bit 63 is discarded, so no further carry.
  c3 += a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
  const r3 = c3 & 0xffff;

  out.lo = ((r1 << 16) | r0) >>> 0;
  out.hi = ((r3 << 16) | r2) >>> 0;
  return out;
}

export function rotl64(out: U64, a: U64, bits: number): U64 {
  const n = bits & 63;
  if (n === 0) return copy64(out, a);

  if (n === 32) {
    const hi = a.lo;
    out.lo = a.hi;
    out.hi = hi;
    return out;
  }

  if (n < 32) {
    const hi = ((a.hi << n) | (a.lo >>> (32 - n))) >>> 0;
    const lo = ((a.lo << n) | (a.hi >>> (32 - n))) >>> 0;
    out.hi = hi;
    out.lo = lo;
    return out;
  }

  const m = n - 32;
  const hi = ((a.lo << m) | (a.hi >>> (32 - m))) >>> 0;
  const lo = ((a.hi << m) | (a.lo >>> (32 - m))) >>> 0;
  out.hi = hi;
  out.lo = lo;
  return out;
}

/** Logical right shift. Used by xxHash's avalanche steps. */
export function shr64(out: U64, a: U64, bits: number): U64 {
  const n = bits & 63;
  if (n === 0) return copy64(out, a);

  if (n < 32) {
    const lo = ((a.lo >>> n) | (a.hi << (32 - n))) >>> 0;
    out.lo = lo;
    out.hi = a.hi >>> n;
    return out;
  }

  out.lo = a.hi >>> (n - 32);
  out.hi = 0;
  return out;
}

/** `a ^= a >>> bits` — xxHash's shift-xor, the shape it appears in everywhere. */
export function xorShr64(out: U64, a: U64, bits: number): U64 {
  const scratch = SHIFT_SCRATCH;
  shr64(scratch, a, bits);
  return xor64(out, a, scratch);
}

const SHIFT_SCRATCH: U64 = u64();

// ── conversion ──────────────────────────────────────────────────────────────

export function readU64LE(bytes: Uint8Array, offset: number): U64 {
  return {
    lo:
      ((bytes[offset]! | (bytes[offset + 1]! << 8) | (bytes[offset + 2]! << 16)) |
        (bytes[offset + 3]! << 24)) >>>
      0,
    hi:
      ((bytes[offset + 4]! |
        (bytes[offset + 5]! << 8) |
        (bytes[offset + 6]! << 16)) |
        (bytes[offset + 7]! << 24)) >>>
      0,
  };
}

export function readU64BE(bytes: Uint8Array, offset: number): U64 {
  return {
    hi:
      (((bytes[offset]! << 24) | (bytes[offset + 1]! << 16) | (bytes[offset + 2]! << 8)) |
        bytes[offset + 3]!) >>>
      0,
    lo:
      (((bytes[offset + 4]! << 24) |
        (bytes[offset + 5]! << 16) |
        (bytes[offset + 6]! << 8)) |
        bytes[offset + 7]!) >>>
      0,
  };
}

export function writeU64BE(out: Uint8Array, offset: number, value: U64): void {
  out[offset] = (value.hi >>> 24) & 0xff;
  out[offset + 1] = (value.hi >>> 16) & 0xff;
  out[offset + 2] = (value.hi >>> 8) & 0xff;
  out[offset + 3] = value.hi & 0xff;
  out[offset + 4] = (value.lo >>> 24) & 0xff;
  out[offset + 5] = (value.lo >>> 16) & 0xff;
  out[offset + 6] = (value.lo >>> 8) & 0xff;
  out[offset + 7] = value.lo & 0xff;
}

/** The little-endian counterpart, for Skein -- which is little-endian throughout. */
export function writeU64LE(out: Uint8Array, offset: number, value: U64): void {
  out[offset] = value.lo & 0xff;
  out[offset + 1] = (value.lo >>> 8) & 0xff;
  out[offset + 2] = (value.lo >>> 16) & 0xff;
  out[offset + 3] = (value.lo >>> 24) & 0xff;
  out[offset + 4] = value.hi & 0xff;
  out[offset + 5] = (value.hi >>> 8) & 0xff;
  out[offset + 6] = (value.hi >>> 16) & 0xff;
  out[offset + 7] = (value.hi >>> 24) & 0xff;
}

export function toBigInt(value: U64): bigint {
  return (BigInt(value.hi) << 32n) | BigInt(value.lo);
}

export function fromBigInt(out: U64, value: bigint): U64 {
  out.hi = Number((value >> 32n) & 0xffffffffn) >>> 0;
  out.lo = Number(value & 0xffffffffn) >>> 0;
  return out;
}

export function hex64(value: U64): string {
  return value.hi.toString(16).padStart(8, "0") + value.lo.toString(16).padStart(8, "0");
}
