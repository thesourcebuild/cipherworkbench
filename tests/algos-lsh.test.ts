import { describe, expect, it } from "vitest";
import { createLsh, LSH_FAMILY, lsh } from "@ocs/algos";
import {
  LSH224_RANDOM,
  LSH224_ZEROS,
  LSH256_RANDOM,
  LSH256_ZEROS,
  LSH384_RANDOM,
  LSH384_ZEROS,
  LSH512_RANDOM,
  LSH512_ZEROS,
  type LshVector,
  type LshZeroVector,
} from "./lsh-vectors";

/**
 * LSH, at all four digest sizes, against KISA's own reference values via Crypto++.
 *
 * No oracle: OpenSSL has never implemented LSH and no dependency here does either. What stands behind it
 * is 588 vectors -- 147 per size -- and the shape of that set is the point rather than its size. Both of
 * this implementation's first-attempt bugs were *length-dependent inside a single block*, so the fixture
 * covers every length from 1 to 128 bytes with no gaps:
 *
 *  - The message expansion applies two different permutations to its two halves. Getting that wrong is
 *    correct for every message of fifteen bytes or fewer and wrong from sixteen on, because the padding
 *    byte lands in the first four words below that and the second half is all zero. Sixteen consecutive
 *    passing vectors reads as a working implementation.
 *  - LSH-512's gamma rotation covers seven words where LSH-256's covers six. Every 384- and 512-bit
 *    vector failed and not one 256-bit vector did, which is what pointed at the width rather than the
 *    mode.
 */

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const unhex = (text: string): Uint8Array =>
  text === "" ? new Uint8Array(0) : Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));

type Bits = 224 | 256 | 384 | 512;

const CASES: readonly [Bits, readonly LshVector[], readonly LshZeroVector[]][] = [
  [224, LSH224_RANDOM, LSH224_ZEROS],
  [256, LSH256_RANDOM, LSH256_ZEROS],
  [384, LSH384_RANDOM, LSH384_ZEROS],
  [512, LSH512_RANDOM, LSH512_ZEROS],
];

describe("LSH", () => {
  it("reproduces every random-message vector at all four sizes", () => {
    for (const [bits, random] of CASES) {
      // Every length from 1 to 128, no gaps -- see the header on why that span is the whole point.
      expect(random.length, `LSH-${bits} random fixture`).toBe(127);
      expect(new Set(random.map((v) => v.inputHex.length / 2)).size).toBe(127);
      for (const v of random) {
        expect(hex(lsh(bits, unhex(v.inputHex))), `LSH-${bits} over ${v.inputHex.length / 2} bytes`).toBe(
          v.digest,
        );
      }
    }
  });

  it("reproduces every all-zero vector, up to 65536 bytes", () => {
    for (const [bits, , zeros] of CASES) {
      expect(zeros.length, `LSH-${bits} zero fixture`).toBe(20);
      for (const v of zeros) {
        expect(hex(lsh(bits, new Uint8Array(v.zeroBytes))), `LSH-${bits} over ${v.zeroBytes} zero bytes`).toBe(
          v.digest,
        );
      }
      // The largest reaches 256 compressions at LSH-512's block size, which is the multi-block coverage.
      expect(Math.max(...zeros.map((v) => v.zeroBytes))).toBe(65536);
    }
  });

  /**
   * The short sizes are not truncations of the long ones, because each has its own initial value.
   *
   * Worth pinning rather than implying: they share every line of the compression, so the only thing that
   * makes LSH-224 a different function from a truncated LSH-256 is the IV -- and the hash family's
   * `truncation` flag has to be right about it.
   */
  it("does not truncate 256 to 224, or 512 to 384", () => {
    const message = new TextEncoder().encode("LSH is not a truncation");
    expect(hex(lsh(256, message)).slice(0, 56)).not.toBe(hex(lsh(224, message)));
    expect(hex(lsh(512, message)).slice(0, 96)).not.toBe(hex(lsh(384, message)));
  });

  it("groups the four sizes into two families", () => {
    expect(LSH_FAMILY).toEqual({ 224: 256, 256: 256, 384: 512, 512: 512 });
  });

  it("streams identically to the one-shot form", () => {
    for (const bits of [224, 256, 384, 512] as const) {
      // The block is 128 bytes at 256 and 256 at 512, so the chunk sizes straddle both.
      for (const len of [0, 1, 63, 64, 127, 128, 129, 255, 256, 257, 383, 384, 512]) {
        const message = new Uint8Array(len);
        for (let i = 0; i < len; i++) message[i] = (i * 13 + 7) & 0xff;
        const want = hex(lsh(bits, message));
        for (const chunk of [1, 5, 64, 127, 128, 200, 256]) {
          const h = createLsh(bits);
          for (let off = 0; off < len; off += chunk) {
            h.update(message.subarray(off, Math.min(off + chunk, len)));
          }
          expect(hex(h.digest()), `LSH-${bits} at ${len} bytes in ${chunk}-byte chunks`).toBe(want);
        }
      }
    }
  });
});
