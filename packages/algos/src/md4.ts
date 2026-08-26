import { MerkleDamgard, rotl32, writeBitLength } from "./md-common";

/**
 * MD4, from RFC 1320.
 *
 * Structurally MD5's predecessor — same little-endian word order, same padding, three
 * rounds instead of four and no per-step constant table. `@noble/hashes` carries MD5 but
 * not this.
 *
 * Comprehensively broken: collisions are findable by hand-guided differential analysis in
 * under a second, and there are practical preimage attacks. It is here for two reasons
 * that are both about interoperability rather than security — NTLM password hashes are
 * MD4 of the UTF-16LE password, and rsync's legacy protocol used it for block checksums.
 */

/** RFC 1320 §3.3. */
const A0 = 0x67452301;
const B0 = 0xefcdab89;
const C0 = 0x98badcfe;
const D0 = 0x10325476;

/** Round 2 and 3 add these; round 1 adds nothing. RFC 1320 §3.4. */
const ROUND2_CONST = 0x5a827999;
const ROUND3_CONST = 0x6ed9eba1;

// Word order per round. Round 1 is sequential; rounds 2 and 3 stride the block, which is
// the whole of MD4's diffusion strategy and also why it is weak.
const R2_ORDER = /* @__PURE__ */ Uint8Array.from([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]);
const R3_ORDER = /* @__PURE__ */ Uint8Array.from([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]);

const R1_SHIFTS = /* @__PURE__ */ Uint8Array.from([3, 7, 11, 19]);
const R2_SHIFTS = /* @__PURE__ */ Uint8Array.from([3, 5, 9, 13]);
const R3_SHIFTS = /* @__PURE__ */ Uint8Array.from([3, 9, 11, 15]);

class Md4 extends MerkleDamgard {
  private a = A0;
  private b = B0;
  private c = C0;
  private d = D0;
  private readonly words = new Int32Array(16);

  constructor() {
    // 8-byte little-endian length field, as MD5 uses.
    super(64, 16, 8, "MD4");
  }

  protected override compress(block: Uint8Array, offset: number): void {
    const x = this.words;
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      x[i] =
        (block[j]! | (block[j + 1]! << 8) | (block[j + 2]! << 16) | (block[j + 3]! << 24)) | 0;
    }

    let a = this.a;
    let b = this.b;
    let c = this.c;
    let d = this.d;

    // Round 1: F(x,y,z) = (x AND y) OR (NOT x AND z) — the multiplexer.
    for (let i = 0; i < 16; i++) {
      const f = (b & c) | (~b & d);
      const shift = R1_SHIFTS[i & 3]!;
      const next = rotl32((a + f + (x[i]! >>> 0)) >>> 0, shift);
      a = d;
      d = c;
      c = b;
      b = next;
    }

    // Round 2: G(x,y,z) = majority.
    for (let i = 0; i < 16; i++) {
      const g = (b & c) | (b & d) | (c & d);
      const shift = R2_SHIFTS[i & 3]!;
      const k = R2_ORDER[i]!;
      const next = rotl32((a + g + (x[k]! >>> 0) + ROUND2_CONST) >>> 0, shift);
      a = d;
      d = c;
      c = b;
      b = next;
    }

    // Round 3: H(x,y,z) = parity.
    for (let i = 0; i < 16; i++) {
      const h = b ^ c ^ d;
      const shift = R3_SHIFTS[i & 3]!;
      const k = R3_ORDER[i]!;
      const next = rotl32((a + h + (x[k]! >>> 0) + ROUND3_CONST) >>> 0, shift);
      a = d;
      d = c;
      c = b;
      b = next;
    }

    this.a = (this.a + a) | 0;
    this.b = (this.b + b) | 0;
    this.c = (this.c + c) | 0;
    this.d = (this.d + d) | 0;
  }

  protected override writeLength(block: Uint8Array, offset: number, byteLength: number): void {
    writeBitLength(block, offset, byteLength, 8, "le");
  }

  protected override writeDigest(out: Uint8Array): void {
    const words = [this.a, this.b, this.c, this.d];
    for (let i = 0; i < 4; i++) {
      const v = words[i]! >>> 0;
      out[i * 4] = v & 0xff;
      out[i * 4 + 1] = (v >>> 8) & 0xff;
      out[i * 4 + 2] = (v >>> 16) & 0xff;
      out[i * 4 + 3] = (v >>> 24) & 0xff;
    }
  }
}

export interface Md4Engine {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

export function createMd4(): Md4Engine {
  return new Md4();
}

export function md4(data: Uint8Array): Uint8Array {
  const engine = new Md4();
  engine.update(data);
  return engine.digest();
}

export const MD4_OUTPUT_LEN = 16;
export const MD4_BLOCK_LEN = 64;
