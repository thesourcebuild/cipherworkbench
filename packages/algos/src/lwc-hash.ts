/**
 * The shared machinery the four NIST-lightweight hashes need to stream.
 *
 * All four are sponges whose *final* block is treated differently from an interior one -- a different
 * domain constant, a different permutation length, or a padding byte that lands at the block's own
 * length. So all four have to hold one block back until a further byte proves it is not last. That is
 * the same arrangement `belt-hash`, Snefru and GOST R 34.11-94 use in this repo, and it is why `update`
 * cannot simply absorb everything it is handed.
 *
 * The hashers themselves live beside their algorithms, in `lwc-xoodyak.ts`, `lwc-sparkle.ts`,
 * `lwc-photonbeetle.ts` and `lwc-romulus.ts`, because what each does with a block is the interesting
 * part and none of it is shared. What *is* shared is exactly this: the block boundary.
 */

/** The incremental contract the hash family binds. Same shape as noble's hashers. */
export interface LwcHasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

/**
 * Hold-back absorber: `absorbFull` runs only for a block known not to be last.
 *
 * `finish` receives the tail, which is 0 to `rate` bytes and is `rate` bytes exactly when the total
 * length is a positive multiple of the rate. That distinction is the whole point -- for every one of
 * these designs a full final block is padded or dominated differently from a partial one, and an
 * absorber that flushed eagerly would get every exact-multiple length wrong.
 */
export function holdBackAbsorber(
  rate: number,
  absorbFull: (block: Uint8Array, off: number) => void,
  finish: (tail: Uint8Array, tailLen: number) => Uint8Array,
): LwcHasher {
  const held = new Uint8Array(rate);
  let heldLen = 0;
  return {
    update(chunk) {
      let off = 0;
      if (heldLen > 0) {
        const take = Math.min(rate - heldLen, chunk.length);
        held.set(chunk.subarray(0, take), heldLen);
        heldLen += take;
        off = take;
        // Flush the held block only once a further byte is known to exist.
        if (heldLen < rate || off >= chunk.length) return;
        absorbFull(held, 0);
        heldLen = 0;
      }
      while (chunk.length - off > rate) {
        absorbFull(chunk, off);
        off += rate;
      }
      held.set(chunk.subarray(off), 0);
      heldLen = chunk.length - off;
    },
    digest() {
      return finish(held, heldLen);
    },
  };
}

/**
 * Plain absorber: every full block is absorbed as it arrives, and the tail is 0 to `rate - 1` bytes.
 *
 * The counterpart to `holdBackAbsorber`, for a design whose final compression takes a *short* block --
 * Romulus-H pads a zero-length tail rather than a full one, so holding a block back would produce an
 * extra compression that the reference does not do.
 */
export function eagerAbsorber(
  rate: number,
  absorbFull: (block: Uint8Array, off: number) => void,
  finish: (tail: Uint8Array, tailLen: number) => Uint8Array,
): LwcHasher {
  const held = new Uint8Array(rate);
  let heldLen = 0;
  return {
    update(chunk) {
      let off = 0;
      if (heldLen > 0) {
        const take = Math.min(rate - heldLen, chunk.length);
        held.set(chunk.subarray(0, take), heldLen);
        heldLen += take;
        off = take;
        if (heldLen < rate) return;
        absorbFull(held, 0);
        heldLen = 0;
      }
      while (chunk.length - off >= rate) {
        absorbFull(chunk, off);
        off += rate;
      }
      held.set(chunk.subarray(off), 0);
      heldLen = chunk.length - off;
    },
    digest() {
      return finish(held, heldLen);
    },
  };
}
