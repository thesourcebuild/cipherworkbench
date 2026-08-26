/**
 * The buffering and padding shared by every Merkle–Damgård hash in this package.
 *
 * MD4, SM3 and Whirlpool differ in their compression function, their word order and the
 * width of their length field — and in nothing else. Writing the "accumulate bytes into
 * blocks, then append 0x80, zeros, and the bit length" dance three times is how one of
 * the three ends up with an off-by-one at a block boundary that only shows for inputs of
 * exactly the wrong length.
 *
 * Subclasses supply `compress` and `writeDigest`; this handles the rest.
 */
export abstract class MerkleDamgard {
  protected readonly buffer: Uint8Array;
  protected buffered = 0;
  /**
   * Message length in bytes, as a JS number.
   *
   * Exact up to 2^53 bytes — eight petabytes — which is not a limit worth engineering
   * around. `BigInt` here would cost an allocation per `update` call for no reachable
   * benefit.
   */
  protected byteLength = 0;
  private finished = false;

  constructor(
    readonly blockLen: number,
    readonly outputLen: number,
    /** Bytes reserved at the end of the final block for the length field. */
    private readonly lengthFieldLen: number,
    private readonly name: string,
  ) {
    this.buffer = new Uint8Array(blockLen);
  }

  /** Absorb one full block, starting at `offset`. */
  protected abstract compress(block: Uint8Array, offset: number): void;

  /** Write the final state out, big- or little-endian as the algorithm requires. */
  protected abstract writeDigest(out: Uint8Array): void;

  /**
   * Write the message bit length into the tail of the final block. Big-endian for SM3
   * and Whirlpool, little-endian for MD4 — hence not shared.
   */
  protected abstract writeLength(block: Uint8Array, offset: number, byteLength: number): void;

  update(chunk: Uint8Array): void {
    if (this.finished) throw new Error(`Cannot update a ${this.name} hash after digest().`);

    this.byteLength += chunk.length;
    let offset = 0;

    if (this.buffered > 0) {
      const take = Math.min(this.blockLen - this.buffered, chunk.length);
      this.buffer.set(chunk.subarray(0, take), this.buffered);
      this.buffered += take;
      offset = take;
      if (this.buffered < this.blockLen) return;
      this.compress(this.buffer, 0);
      this.buffered = 0;
    }

    // Compress directly out of the caller's array while whole blocks remain.
    while (offset + this.blockLen <= chunk.length) {
      this.compress(chunk, offset);
      offset += this.blockLen;
    }

    if (offset < chunk.length) {
      this.buffered = chunk.length - offset;
      this.buffer.set(chunk.subarray(offset), 0);
    }
  }

  digest(): Uint8Array {
    if (this.finished) throw new Error(`digest() called twice on the same ${this.name} hash.`);
    this.finished = true;

    const byteLength = this.byteLength;

    // 0x80 always goes in, so the padding is never empty.
    this.buffer[this.buffered++] = 0x80;

    /**
     * If the length field no longer fits after the 0x80, the block is filled with zeros
     * and flushed, and the length goes in a fresh block. This is the case that breaks
     * when written per-algorithm: it triggers only for messages whose length mod
     * blockLen falls in a narrow window near the end.
     */
    if (this.buffered + this.lengthFieldLen > this.blockLen) {
      this.buffer.fill(0, this.buffered);
      this.compress(this.buffer, 0);
      this.buffered = 0;
    }

    this.buffer.fill(0, this.buffered);
    this.writeLength(this.buffer, this.blockLen - this.lengthFieldLen, byteLength);
    this.compress(this.buffer, 0);

    const out = new Uint8Array(this.outputLen);
    this.writeDigest(out);
    return out;
  }
}

/** Rotate a 32-bit value left. `>>> 0` because `<<` yields a signed result. */
export function rotl32(value: number, bits: number): number {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

/**
 * Writes the message length, in bits, into `fieldLen` bytes.
 *
 * `BigInt` here on purpose. `byteLength * 8` can exceed 2^53 and start losing precision,
 * and the alternatives — tracking a 64-bit counter across every `update`, or splitting
 * the multiply by hand — cost complexity in the hot path to solve a problem that only
 * exists in this one function, which runs exactly once per digest.
 */
export function writeBitLength(
  block: Uint8Array,
  offset: number,
  byteLength: number,
  fieldLen: number,
  endian: "be" | "le",
): void {
  let bits = BigInt(byteLength) * 8n;
  for (let i = 0; i < fieldLen; i++) {
    const index = endian === "be" ? offset + fieldLen - 1 - i : offset + i;
    block[index] = Number(bits & 0xffn);
    bits >>= 8n;
  }
}
