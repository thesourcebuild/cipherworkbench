/**
 * NIST SP 800-108: Recommendation for Key Derivation Using Pseudorandom Functions.
 *
 * Implements the three official modes of SP 800-108:
 *  - Counter Mode (§5.1)
 *  - Feedback Mode (§5.2)
 *  - Double-Pipeline Iteration Mode (§5.3)
 *
 * Each mode takes an underlying PRF (typically HMAC or CMAC), a key-derivation key (K_IN),
 * an optional Label, an optional Context, and the requested output length in bytes L.
 */

export type Sp800108Mode = "counter" | "feedback" | "double-pipeline";

export interface Sp800108Options {
  mode?: Sp800108Mode;
  label?: Uint8Array;
  context?: Uint8Array;
  iv?: Uint8Array;
  /** Counter length in bits: 8, 16, 24, or 32 (default: 32). */
  counterBits?: 8 | 16 | 24 | 32;
}

function encodeUint(val: number, bits: number): Uint8Array {
  const bytes = bits / 8;
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) {
    out[bytes - 1 - i] = (val >>> (8 * i)) & 0xff;
  }
  return out;
}

function concat(...arrays: (Uint8Array | undefined)[]): Uint8Array {
  let total = 0;
  for (const a of arrays) if (a) total += a.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) {
    if (a) {
      out.set(a, pos);
      pos += a.length;
    }
  }
  return out;
}

const ZERO_BYTE = new Uint8Array([0]);

/**
 * Derives `keyLength` bytes using NIST SP 800-108.
 */
export function kdfSp800108(
  prf: (key: Uint8Array, message: Uint8Array) => Uint8Array,
  keyIn: Uint8Array,
  keyLength: number,
  options: Sp800108Options = {},
): Uint8Array {
  if (keyLength <= 0) throw new Error("Derived key length must be > 0 bytes.");
  const mode = options.mode ?? "counter";
  const label = options.label ?? new Uint8Array(0);
  const context = options.context ?? new Uint8Array(0);
  const counterBits = options.counterBits ?? 32;
  const bitLength = keyLength * 8;
  const lEncoded = encodeUint(bitLength, 32);

  const out = new Uint8Array(keyLength);
  let written = 0;
  let i = 1;

  if (mode === "counter") {
    while (written < keyLength) {
      const iEncoded = encodeUint(i, counterBits);
      const msg = concat(iEncoded, label, ZERO_BYTE, context, lEncoded);
      const block = prf(keyIn, msg);
      const toCopy = Math.min(block.length, keyLength - written);
      out.set(block.subarray(0, toCopy), written);
      written += toCopy;
      i++;
    }
  } else if (mode === "feedback") {
    let kPrev = options.iv ?? new Uint8Array(0);
    while (written < keyLength) {
      const iEncoded = encodeUint(i, counterBits);
      const msg = concat(kPrev, iEncoded, label, ZERO_BYTE, context, lEncoded);
      const block = prf(keyIn, msg);
      kPrev = block;
      const toCopy = Math.min(block.length, keyLength - written);
      out.set(block.subarray(0, toCopy), written);
      written += toCopy;
      i++;
    }
  } else if (mode === "double-pipeline") {
    let aPrev = concat(label, ZERO_BYTE, context, lEncoded);
    while (written < keyLength) {
      const aCurr = prf(keyIn, aPrev);
      aPrev = aCurr;
      const iEncoded = encodeUint(i, counterBits);
      const msg = concat(aCurr, iEncoded, label, ZERO_BYTE, context, lEncoded);
      const block = prf(keyIn, msg);
      const toCopy = Math.min(block.length, keyLength - written);
      out.set(block.subarray(0, toCopy), written);
      written += toCopy;
      i++;
    }
  }

  return out;
}
