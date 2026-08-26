/**
 * GOST R 34.11-94, the hash function Streebog replaced. PHP's `gost` and `gost-crypto`.
 *
 * Two parameter sets, and that is the whole difference between the two names: `gost` uses the test
 * S-boxes published with GOST 28147-89 (RFC 5831), `gost-crypto` the CryptoPro set from RFC 4357 that
 * real Russian deployments used. Same construction, unrelated digests. PHP offers both, which is why
 * both are here -- and note that neither is Streebog, the 2012 replacement, which this repo also
 * implements in `streebog.ts`.
 *
 * Five things to know before touching this.
 *
 * **The S-boxes are derived, not transcribed.** Implementations ship four 256-word lookup tables per
 * parameter set with the 11-bit rotation folded in; what the standards actually publish is eight rows
 * of sixteen nibbles. Those nibbles are below, and the tables are built from them at load. The
 * reconstruction was checked against a reference implementation's precomputed tables entry by entry
 * before the nibbles were written down -- 256 numbers to get right instead of 2048.
 *
 * **The compression function is the GOST block cipher used four times.** Each of the four passes
 * derives a 256-bit key from the chaining value and the message block, encrypts one 64-bit half of the
 * chaining value with it, and mixes the result -- which is why `encryptBlock` below is a full
 * 32-round GOST 28147-89 encryption and why the key schedule (`P`) is a byte transposition rather than
 * anything arithmetic.
 *
 * **There is no padding byte and no length byte in the message.** A short final block is zero-filled,
 * and the 256-bit length and a 256-bit running checksum of every block are folded in by two extra
 * compressions at the end. That means "abc" and "abc\0" differ *only* through the length field, and an
 * implementation that forgot either final compression would still produce stable, plausible output.
 *
 * **Everything is little-endian**, including the digest and the length.
 *
 * **It is superseded and weakened.** Mendel et al. published a 2^105 collision attack and a 2^192
 * preimage attack in 2008 -- neither practical, both below the 2^128 / 2^256 the design claims -- and
 * Russia replaced it with Streebog in 2012. Fine for checking old data, wrong for anything new.
 */

const SBOX_TEST: readonly (readonly number[])[] = [
  [0x4, 0xa, 0x9, 0x2, 0xd, 0x8, 0x0, 0xe, 0x6, 0xb, 0x1, 0xc, 0x7, 0xf, 0x5, 0x3],
  [0xe, 0xb, 0x4, 0xc, 0x6, 0xd, 0xf, 0xa, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9],
  [0x5, 0x8, 0x1, 0xd, 0xa, 0x3, 0x4, 0x2, 0xe, 0xf, 0xc, 0x7, 0x6, 0x0, 0x9, 0xb],
  [0x7, 0xd, 0xa, 0x1, 0x0, 0x8, 0x9, 0xf, 0xe, 0x4, 0x6, 0xc, 0xb, 0x2, 0x5, 0x3],
  [0x6, 0xc, 0x7, 0x1, 0x5, 0xf, 0xd, 0x8, 0x4, 0xa, 0x9, 0xe, 0x0, 0x3, 0xb, 0x2],
  [0x4, 0xb, 0xa, 0x0, 0x7, 0x2, 0x1, 0xd, 0x3, 0x6, 0x8, 0x5, 0x9, 0xc, 0xf, 0xe],
  [0xd, 0xb, 0x4, 0x1, 0x3, 0xf, 0x5, 0x9, 0x0, 0xa, 0xe, 0x7, 0x6, 0x8, 0x2, 0xc],
  [0x1, 0xf, 0xd, 0x0, 0x5, 0x7, 0xa, 0x4, 0x9, 0x2, 0x3, 0xe, 0x6, 0xb, 0x8, 0xc],
];

const SBOX_CRYPTO: readonly (readonly number[])[] = [
  [0xa, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xd, 0xc, 0xe, 0x0, 0x9, 0x2, 0xb, 0xf],
  [0x5, 0xf, 0x4, 0x0, 0x2, 0xd, 0xb, 0x9, 0x1, 0x7, 0x6, 0x3, 0xc, 0xe, 0xa, 0x8],
  [0x7, 0xf, 0xc, 0xe, 0x9, 0x4, 0x1, 0x0, 0x3, 0xb, 0x5, 0x2, 0x6, 0xa, 0x8, 0xd],
  [0x4, 0xa, 0x7, 0xc, 0x0, 0xf, 0x2, 0x8, 0xe, 0x1, 0x6, 0x5, 0xd, 0xb, 0x9, 0x3],
  [0x7, 0x6, 0x4, 0xb, 0x9, 0xc, 0x2, 0xa, 0x1, 0x8, 0x0, 0xe, 0xf, 0xd, 0x3, 0x5],
  [0x7, 0x6, 0x2, 0x4, 0xd, 0x9, 0xf, 0x0, 0xa, 0x1, 0x5, 0xb, 0x8, 0xe, 0xc, 0x3],
  [0xd, 0xe, 0x4, 0x1, 0x7, 0x0, 0x5, 0xa, 0x3, 0xc, 0x8, 0xf, 0x6, 0x2, 0x9, 0xb],
  [0x1, 0x3, 0xa, 0x9, 0x5, 0xb, 0x4, 0xf, 0x8, 0x6, 0x7, 0xe, 0xd, 0x0, 0x2, 0xc],
];

/** Which parameter set: PHP's `gost` and `gost-crypto` respectively. */
export type GostVariant = "test" | "crypto";

/**
 * Builds the four lookup tables for one parameter set.
 *
 * `table[i][b]` is the S-box substitution of byte `b` placed at byte position `i` and rotated left by
 * 11, which is the rotation the round function would otherwise have to do afterwards. Two nibbles of
 * the input are substituted by two different S-box rows, which is why the rows come in pairs.
 */
function buildTables(sboxes: readonly (readonly number[])[]): Uint32Array {
  const tables = new Uint32Array(4 * 256);
  for (let i = 0; i < 4; i++) {
    for (let b = 0; b < 256; b++) {
      const substituted = ((sboxes[2 * i + 1]![b >>> 4]! << 4) | sboxes[2 * i]![b & 15]!) >>> 0;
      const placed = (substituted << (8 * i)) >>> 0;
      tables[i * 256 + b] = ((placed << 11) | (placed >>> 21)) >>> 0;
    }
  }
  return tables;
}

const TABLES: Record<GostVariant, Uint32Array> = {
  test: buildTables(SBOX_TEST),
  crypto: buildTables(SBOX_CRYPTO),
};

export const GOST_OUTPUT_LEN = 32;
export const GOST_BLOCK_LEN = 32;

/** One 64-bit half of the chaining value, encrypted with GOST 28147-89 under the derived key. */
function encryptHalf(
  tables: Uint32Array,
  key: Uint32Array,
  right: number,
  left: number,
): [number, number] {
  let r = right;
  let l = left;

  const round = (k: number, target: "l" | "r"): void => {
    const t = ((k + (target === "l" ? r : l)) >>> 0) >>> 0;
    const mixed =
      (tables[(t & 0xff) >>> 0]! ^
        tables[256 + ((t >>> 8) & 0xff)]! ^
        tables[512 + ((t >>> 16) & 0xff)]! ^
        tables[768 + (t >>> 24)]!) >>>
      0;
    if (target === "l") l = (l ^ mixed) >>> 0;
    else r = (r ^ mixed) >>> 0;
  };

  // Three passes over the eight subkeys in order, then one in reverse: 32 rounds.
  for (let pass = 0; pass < 3; pass++) {
    for (let i = 0; i < 8; i += 2) {
      round(key[i]!, "l");
      round(key[i + 1]!, "r");
    }
  }
  for (let i = 7; i > 0; i -= 2) {
    round(key[i]!, "l");
    round(key[i - 1]!, "r");
  }

  // Returned in the order the caller stores them. GOST's cipher ends by swapping its halves, so the
  // value that came out of the left register is stored first -- an easy half-step to get backwards.
  return [l, r];
}

/** The key schedule: a byte transposition of the mixed chaining value and message block. */
function deriveKey(key: Uint32Array, w: Uint32Array): void {
  for (let group = 0; group < 2; group++) {
    const a = group === 0 ? 0 : 1;
    for (let byte = 0; byte < 4; byte++) {
      const shift = 8 * byte;
      let value = 0;
      for (let word = 0; word < 4; word++) {
        const source = (w[a + word * 2]! >>> shift) & 0xff;
        value |= source << (8 * word);
      }
      key[group * 4 + byte] = value >>> 0;
    }
  }
}

/** Psi-style mixing of the eight-word accumulator, GOST's `A` transform. */
function transformA(x: Uint32Array): void {
  const l = (x[0]! ^ x[2]!) >>> 0;
  const r = (x[1]! ^ x[3]!) >>> 0;
  x[0] = x[2]!;
  x[1] = x[3]!;
  x[2] = x[4]!;
  x[3] = x[5]!;
  x[4] = x[6]!;
  x[5] = x[7]!;
  x[6] = l;
  x[7] = r;
}

/** The `A'` transform applied to the message-derived half. */
function transformAA(x: Uint32Array): void {
  let l = x[0]!;
  let r = x[2]!;
  x[0] = x[4]!;
  x[2] = x[6]!;
  x[4] = (l ^ r) >>> 0;
  // Reads the *new* x[0], which is why this is not a symmetric swap.
  x[6] = (x[0]! ^ r) >>> 0;
  l = x[1]!;
  r = x[3]!;
  x[1] = x[5]!;
  x[3] = x[7]!;
  x[5] = (l ^ r) >>> 0;
  x[7] = (x[1]! ^ r) >>> 0;
}

/** The constant C3, XORed in before the third pass. */
const C3 = [0xff00ff00, 0xff00ff00, 0x00ff00ff, 0x00ff00ff, 0x00ffff00, 0xff0000ff, 0x000000ff, 0xff00ffff];

const lo16 = (x: number): number => x & 0xffff;
const hi16 = (x: number): number => (x & 0xffff0000) >>> 0;
const shl16 = (x: number): number => (x << 16) >>> 0;
const shr16 = (x: number): number => x >>> 16;

/**
 * The three mixing stages that finish a compression: 12, 16 and 61 applications of the shift register.
 *
 * Written out as the reference writes them because there is no shorter honest form -- each output word
 * is a specific XOR of halves of specific input words. This is the part of GOST that no amount of
 * staring makes elegant, and the part where a published digest is the only useful check.
 */
function mix12(u: Uint32Array, m: Uint32Array, s: Uint32Array): void {
  const next = new Uint32Array(8);
  next[0] = (m[0]! ^ s[6]!) >>> 0;
  next[1] = (m[1]! ^ s[7]!) >>> 0;
  next[2] =
    (m[2]! ^
      shl16(s[0]!) ^
      shr16(s[0]!) ^
      lo16(s[0]!) ^
      lo16(s[1]!) ^
      shr16(s[1]!) ^
      shl16(s[2]!) ^
      s[6]! ^
      shl16(s[6]!) ^
      hi16(s[7]!) ^
      shr16(s[7]!)) >>>
    0;
  next[3] =
    (m[3]! ^
      lo16(s[0]!) ^
      shl16(s[0]!) ^
      lo16(s[1]!) ^
      shl16(s[1]!) ^
      shr16(s[1]!) ^
      shl16(s[2]!) ^
      shr16(s[2]!) ^
      shl16(s[3]!) ^
      s[6]! ^
      shl16(s[6]!) ^
      shr16(s[6]!) ^
      lo16(s[7]!) ^
      shl16(s[7]!) ^
      shr16(s[7]!)) >>>
    0;
  next[4] =
    (m[4]! ^
      hi16(s[0]!) ^
      shl16(s[0]!) ^
      shr16(s[0]!) ^
      hi16(s[1]!) ^
      shr16(s[1]!) ^
      shl16(s[2]!) ^
      shr16(s[2]!) ^
      shl16(s[3]!) ^
      shr16(s[3]!) ^
      shl16(s[4]!) ^
      shl16(s[6]!) ^
      shr16(s[6]!) ^
      lo16(s[7]!) ^
      shl16(s[7]!) ^
      shr16(s[7]!)) >>>
    0;
  next[5] =
    (m[5]! ^
      shl16(s[0]!) ^
      shr16(s[0]!) ^
      hi16(s[0]!) ^
      lo16(s[1]!) ^
      s[2]! ^
      shr16(s[2]!) ^
      shl16(s[3]!) ^
      shr16(s[3]!) ^
      shl16(s[4]!) ^
      shr16(s[4]!) ^
      shl16(s[5]!) ^
      shl16(s[6]!) ^
      shr16(s[6]!) ^
      hi16(s[7]!) ^
      shl16(s[7]!) ^
      shr16(s[7]!)) >>>
    0;
  next[6] =
    (m[6]! ^
      s[0]! ^
      shr16(s[1]!) ^
      shl16(s[2]!) ^
      s[3]! ^
      shr16(s[3]!) ^
      shl16(s[4]!) ^
      shr16(s[4]!) ^
      shl16(s[5]!) ^
      shr16(s[5]!) ^
      s[6]! ^
      shl16(s[6]!) ^
      shr16(s[6]!) ^
      shl16(s[7]!)) >>>
    0;
  next[7] =
    (m[7]! ^
      hi16(s[0]!) ^
      shl16(s[0]!) ^
      lo16(s[1]!) ^
      shl16(s[1]!) ^
      shr16(s[2]!) ^
      shl16(s[3]!) ^
      s[4]! ^
      shr16(s[4]!) ^
      shl16(s[5]!) ^
      shr16(s[5]!) ^
      shr16(s[6]!) ^
      lo16(s[7]!) ^
      shl16(s[7]!) ^
      shr16(s[7]!)) >>>
    0;
  u.set(next);
}

function mix16(h: Uint32Array, v: Uint32Array, u: Uint32Array): void {
  const next = new Uint32Array(8);
  for (let i = 0; i < 7; i++) {
    next[i] = (h[i]! ^ shl16(u[i + 1]!) ^ shr16(u[i]!)) >>> 0;
  }
  next[7] =
    (h[7]! ^
      hi16(u[0]!) ^
      shl16(u[0]!) ^
      shr16(u[7]!) ^
      hi16(u[1]!) ^
      shl16(u[1]!) ^
      shl16(u[6]!) ^
      hi16(u[7]!)) >>>
    0;
  v.set(next);
}

function mix61(h: Uint32Array, v: Uint32Array): void {
  const next = new Uint32Array(8);
  next[0] =
    (hi16(v[0]!) ^
      shl16(v[0]!) ^
      shr16(v[0]!) ^
      shr16(v[1]!) ^
      hi16(v[1]!) ^
      shl16(v[2]!) ^
      shr16(v[3]!) ^
      shl16(v[4]!) ^
      shr16(v[5]!) ^
      v[5]! ^
      shr16(v[6]!) ^
      shl16(v[7]!) ^
      shr16(v[7]!) ^
      lo16(v[7]!)) >>>
    0;
  next[1] =
    (shl16(v[0]!) ^
      shr16(v[0]!) ^
      hi16(v[0]!) ^
      lo16(v[1]!) ^
      v[2]! ^
      shr16(v[2]!) ^
      shl16(v[3]!) ^
      shr16(v[4]!) ^
      shl16(v[5]!) ^
      shl16(v[6]!) ^
      v[6]! ^
      hi16(v[7]!) ^
      shr16(v[7]!)) >>>
    0;
  next[2] =
    (lo16(v[0]!) ^
      shl16(v[0]!) ^
      shl16(v[1]!) ^
      shr16(v[1]!) ^
      hi16(v[1]!) ^
      shl16(v[2]!) ^
      shr16(v[3]!) ^
      v[3]! ^
      shl16(v[4]!) ^
      shr16(v[5]!) ^
      v[6]! ^
      shr16(v[6]!) ^
      lo16(v[7]!) ^
      shl16(v[7]!) ^
      shr16(v[7]!)) >>>
    0;
  next[3] =
    (shl16(v[0]!) ^
      shr16(v[0]!) ^
      hi16(v[0]!) ^
      hi16(v[1]!) ^
      shr16(v[1]!) ^
      shl16(v[2]!) ^
      shr16(v[2]!) ^
      v[2]! ^
      shl16(v[3]!) ^
      shr16(v[4]!) ^
      v[4]! ^
      shl16(v[5]!) ^
      shl16(v[6]!) ^
      lo16(v[7]!) ^
      shr16(v[7]!)) >>>
    0;
  next[4] =
    (shr16(v[0]!) ^
      shl16(v[1]!) ^
      v[1]! ^
      shr16(v[2]!) ^
      v[2]! ^
      shl16(v[3]!) ^
      shr16(v[3]!) ^
      v[3]! ^
      shl16(v[4]!) ^
      shr16(v[5]!) ^
      v[5]! ^
      shl16(v[6]!) ^
      shr16(v[6]!) ^
      shl16(v[7]!)) >>>
    0;
  next[5] =
    (shl16(v[0]!) ^
      hi16(v[0]!) ^
      shl16(v[1]!) ^
      shr16(v[1]!) ^
      hi16(v[1]!) ^
      shl16(v[2]!) ^
      v[2]! ^
      shr16(v[3]!) ^
      v[3]! ^
      shl16(v[4]!) ^
      shr16(v[4]!) ^
      v[4]! ^
      shl16(v[5]!) ^
      shl16(v[6]!) ^
      shr16(v[6]!) ^
      v[6]! ^
      shl16(v[7]!) ^
      shr16(v[7]!) ^
      hi16(v[7]!)) >>>
    0;
  next[6] =
    (v[0]! ^
      v[2]! ^
      shr16(v[2]!) ^
      v[3]! ^
      shl16(v[3]!) ^
      v[4]! ^
      shr16(v[4]!) ^
      shl16(v[5]!) ^
      shr16(v[5]!) ^
      v[5]! ^
      shl16(v[6]!) ^
      shr16(v[6]!) ^
      v[6]! ^
      shl16(v[7]!) ^
      v[7]!) >>>
    0;
  next[7] =
    (v[0]! ^
      shr16(v[0]!) ^
      shl16(v[1]!) ^
      shr16(v[1]!) ^
      shl16(v[2]!) ^
      shr16(v[3]!) ^
      v[3]! ^
      shl16(v[4]!) ^
      v[4]! ^
      shr16(v[5]!) ^
      v[5]! ^
      shl16(v[6]!) ^
      shr16(v[6]!) ^
      shl16(v[7]!) ^
      v[7]!) >>>
    0;
  h.set(next);
}

export interface GostEngine {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

class Gost implements GostEngine {
  /** Words 0-7 are the chaining value; 8-15 the running sum of every message block. */
  private readonly state = new Uint32Array(16);
  private readonly buffer = new Uint8Array(GOST_BLOCK_LEN);
  private readonly tables: Uint32Array;
  private buffered = 0;
  private length = 0;
  private done = false;

  constructor(variant: GostVariant) {
    const tables = TABLES[variant];
    if (!tables) throw new Error(`Unknown GOST parameter set: ${String(variant)}`);
    this.tables = tables;
  }

  /** The compression function: four passes, then the three mixing stages. */
  private compress(data: Uint32Array): void {
    const h = this.state.subarray(0, 8);
    const u = Uint32Array.from(h);
    const v = Uint32Array.from(data);
    const w = new Uint32Array(8);
    const key = new Uint32Array(8);
    const s = new Uint32Array(8);

    for (let i = 0; i < 8; i += 2) {
      for (let j = 0; j < 8; j++) w[j] = (u[j]! ^ v[j]!) >>> 0;
      deriveKey(key, w);
      const [left, right] = encryptHalf(this.tables, key, h[i]!, h[i + 1]!);
      s[i] = left;
      s[i + 1] = right;

      if (i !== 6) {
        transformA(u);
        if (i === 2) {
          for (let j = 0; j < 8; j++) u[j] = (u[j]! ^ C3[j]!) >>> 0;
        }
        transformAA(v);
      }
    }

    mix12(u, data, s);
    mix16(h, v, u);
    mix61(h, v);
  }

  /** Absorbs one 32-byte block: adds it into the running sum, then compresses. */
  private processBlock(bytes: Uint8Array, at: number): void {
    const data = new Uint32Array(8);
    let carry = 0;
    for (let i = 0; i < 8; i++) {
      const j = at + i * 4;
      data[i] =
        (bytes[j]! | (bytes[j + 1]! << 8) | (bytes[j + 2]! << 16) | (bytes[j + 3]! << 24)) >>> 0;
      const sum = this.state[8 + i]! + data[i]! + carry;
      this.state[8 + i] = sum >>> 0;
      carry = sum > 0xffff_ffff ? 1 : 0;
    }
    this.compress(data);
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("GOST: update after digest");
    this.length += chunk.length;

    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(GOST_BLOCK_LEN - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === GOST_BLOCK_LEN) {
        this.processBlock(this.buffer, 0);
        this.buffered = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("GOST: digest called twice");
    this.done = true;

    // A partial final block is zero-filled. There is no padding bit.
    if (this.buffered > 0) {
      this.buffer.fill(0, this.buffered);
      this.processBlock(this.buffer, 0);
    }

    /**
     * Two extra compressions close the hash: the bit length, then the running block sum.
     *
     * Neither goes through `processBlock`, because neither is a message block -- adding the length
     * into the checksum would be wrong, and it is the sort of wrong that still produces stable output.
     */
    const bits = this.length * 8;
    const lengthBlock = new Uint32Array(8);
    lengthBlock[0] = bits >>> 0;
    lengthBlock[1] = Math.floor(bits / 0x1_0000_0000) >>> 0;
    this.compress(lengthBlock);
    this.compress(Uint32Array.from(this.state.subarray(8, 16)));

    const out = new Uint8Array(GOST_OUTPUT_LEN);
    for (let i = 0; i < 8; i++) {
      const word = this.state[i]!;
      out[i * 4] = word & 0xff;
      out[i * 4 + 1] = (word >>> 8) & 0xff;
      out[i * 4 + 2] = (word >>> 16) & 0xff;
      out[i * 4 + 3] = (word >>> 24) & 0xff;
    }
    return out;
  }
}

export function createGost(variant: GostVariant = "test"): GostEngine {
  return new Gost(variant);
}

export function gost(data: Uint8Array, variant: GostVariant = "test"): Uint8Array {
  const h = createGost(variant);
  h.update(data);
  return h.digest();
}
