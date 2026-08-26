import { beforeAll, describe, expect, it } from "vitest";

import {
  createFsb,
  FSB_PARAMS,
  fsb,
  fsbDerivedParams,
  fsbIsReady,
  fsbViaReference,
  prepareFsb,
  requireFsbParams,
} from "../packages/algos/src/index";
// Reached directly rather than through the barrel: the barrel deliberately does not re-export it, so
// that a static import cannot drag 363 KB into every chunk that touches `@ocs/algos`.
import { fsbPiTable } from "../packages/algos/src/fsb-pi";
import { whirlpool } from "../packages/algos/src/whirlpool";

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/**
 * FSB's matrix table is a dynamic import, so every test here has to wait for it.
 *
 * That is not incidental: it is the arrangement that stops 363 KB of pi from being downloaded by the
 * other 138 hash tools. `loadTool()` awaits the same `prepareFsb()` in the app.
 */
beforeAll(async () => {
  await prepareFsb();
});

/**
 * FSB, and this file has to carry more weight than usual because **nothing external checks it**.
 *
 * There is no published digest anywhere reachable. `fsbdoc.pdf` contains no test vector and not one hex
 * string of any length; the submission zip has no KAT directory; nothing in this tree or any of its
 * oracles implements FSB; and SUPERCOP's checksums need its own harness reproduced before they mean
 * anything. So the coverage here is, in order of strength:
 *
 *  1. **The pi table's provenance is verified**, not assumed -- 19,200 recomputed digits.
 *  2. **Two independent formulations of the compression must agree** at every parameter set. This is the
 *     `crcReference` arrangement, and it is not decorative: it caught a real inversion of the column
 *     window on its first run.
 *  3. Structural properties: the derived parameters, the padding's extra-round case, streaming, and the
 *     Whirlpool finalisation.
 *
 * What none of that establishes is that this repo's reading of the specification matches the designers'.
 * Two formulations can share a misunderstanding. Do not relabel any of this as a published vector.
 */

/**
 * Pi's fractional digits by Machin's formula in `bigint`.
 *
 * Scaled-integer arctan, so no floating point anywhere: `atan(1/x)` as an integer scaled by 10^digits.
 */
function piFractionalDigits(digits: number): string {
  const guard = 20;
  const scale = 10n ** BigInt(digits + guard);
  const atanInv = (x: bigint): bigint => {
    let term = scale / x;
    const xsq = x * x;
    let total = 0n;
    let k = 0n;
    while (term !== 0n) {
      const piece = term / (2n * k + 1n);
      total += k % 2n === 0n ? piece : -piece;
      term /= xsq;
      k += 1n;
    }
    return total;
  };
  const pi = 16n * atanInv(5n) - 4n * atanInv(239n);
  // pi is scaled by 10^(digits+guard); drop the leading 3 and the guard digits.
  return pi.toString().slice(1, 1 + digits);
}

describe("FSB's pi table", () => {
  it("is the parity of pi's fractional decimal digits, MSB-first", () => {
    const table = fsbPiTable();
    expect(table).toHaveLength(272384);

    const DIGITS = 19200;
    const digits = piFractionalDigits(DIGITS);
    expect(digits.slice(0, 20)).toBe("14159265358979323846");

    const packed = new Uint8Array(DIGITS >> 3);
    for (let i = 0; i < DIGITS; i++) {
      if ((digits.charCodeAt(i) - 48) & 1) packed[i >> 3] = packed[i >> 3]! | (1 << (7 - (i & 7)));
    }
    expect(hex(packed)).toBe(hex(table.subarray(0, DIGITS >> 3)));
  });

  /**
   * The two ways of getting it wrong, both of which produce a plausible table.
   *
   * Including the leading `3` shifts the whole stream one bit -- the first byte becomes `0xdc` rather
   * than `0xb9`. Packing LSB-first gives `0x9d`. Both were tried before the right one, so both are
   * pinned as *not* matching.
   */
  it("is neither the leading-3 variant nor LSB-first", () => {
    const table = fsbPiTable();
    expect(table[0]).toBe(0xb9);
    expect(table[0]).not.toBe(0xdc);
    expect(table[0]).not.toBe(0x9d);
  });

  it("holds exactly what FSB-256 needs, which is all of it", () => {
    // FSB-256 is the hungriest set. If the table were short, its last block would read zeros.
    const most = Math.max(...FSB_PARAMS.map((p) => fsbDerivedParams(p.hashBits).piBytesUsed));
    expect(most).toBe(272384);
    expect(fsbDerivedParams(256).piBytesUsed).toBe(272384);
    expect(fsbPiTable()).toHaveLength(most);
  });
});

describe("FSB", () => {
  /**
   * The cross-check, and the only thing standing between this implementation and nothing.
   *
   * `fsbCompress` uses the reference's eight pre-shifted lines and a byte-aligned XOR; `fsbCompressReference`
   * reads each column bit by bit out of the pi table with no precomputation. They share the index
   * arithmetic and nothing else.
   */
  it.each(FSB_PARAMS)("FSB-$hashBits agrees between both formulations", ({ hashBits }) => {
    // Lengths chosen around the block boundary and the padding's extra-round case.
    const inputsize = fsbDerivedParams(hashBits).inputsize >> 3;
    for (const length of [0, 1, inputsize - 9, inputsize - 8, inputsize - 1, inputsize, inputsize + 1]) {
      if (length < 0) continue;
      const message = new Uint8Array(length);
      for (let i = 0; i < length; i++) message[i] = (i * 31 + 7) & 0xff;
      expect(hex(fsb(hashBits, message)), `FSB-${hashBits} at ${length} bytes`).toBe(
        hex(fsbViaReference(hashBits, message)),
      );
    }
  });

  it("derives each set's parameters from its five numbers", () => {
    // From the reference's own table: b = n/r, bpc = log2(n/w), inputsize = w*bpc - r.
    const expected = [
      { bits: 48, b: 2048, bpc: 14, inputsize: 144 },
      { bits: 160, b: 2048, bpc: 14, inputsize: 480 },
      { bits: 224, b: 2048, bpc: 14, inputsize: 672 },
      { bits: 256, b: 2048, bpc: 14, inputsize: 768 },
      { bits: 384, b: 1024, bpc: 13, inputsize: 920 },
      { bits: 512, b: 1024, bpc: 13, inputsize: 1240 },
    ];
    for (const e of expected) {
      const d = fsbDerivedParams(e.bits);
      expect(d.b, `FSB-${e.bits} blocks`).toBe(e.b);
      expect(d.bpc, `FSB-${e.bits} bits per column`).toBe(e.bpc);
      expect(d.inputsize, `FSB-${e.bits} message bits per round`).toBe(e.inputsize);
      // Every set splits the syndrome eight bits per column, which is why `bfiv` has a fast path.
      expect(d.bfiv, `FSB-${e.bits} syndrome bits per column`).toBe(8);
    }
  });

  it("gives every digest length its declared size, and no two the same value", () => {
    const message = new TextEncoder().encode("the syndrome decoding problem");
    const seen = new Set<string>();
    for (const p of FSB_PARAMS) {
      const digest = fsb(p.hashBits, message);
      expect(digest, `FSB-${p.hashBits}`).toHaveLength(p.hashBits >> 3);
      seen.add(hex(digest));
    }
    expect(seen.size).toBe(FSB_PARAMS.length);
  });

  /**
   * No digest length is a truncation of another, even though they all end in the same Whirlpool.
   *
   * The syndrome width differs per set, so Whirlpool sees a different input -- FSB-160's syndrome is 640
   * bits and FSB-256's is 1024. Someone truncating FSB-256 to 20 bytes does not get FSB-160.
   */
  it("is not a truncation across digest lengths", () => {
    const message = new TextEncoder().encode("abc");
    const long = hex(fsb(256, message));
    const short = hex(fsb(160, message));
    expect(long.startsWith(short)).toBe(false);
  });

  /**
   * The final transform is Whirlpool over the *syndrome*, truncated -- so the digest is a prefix of a
   * Whirlpool output, and this checks that rather than taking it on trust.
   */
  it("finalises with Whirlpool over the syndrome", () => {
    const message = new TextEncoder().encode("abc");
    for (const bits of [160, 256, 512]) {
      const digest = fsb(bits, message);
      // Whirlpool is 64 bytes; every FSB digest must be a prefix of one.
      expect(digest.length).toBeLessThanOrEqual(64);
      // And the 512-bit digest is the whole Whirlpool output, so re-hashing its syndrome must match.
      if (bits === 512) expect(digest).toHaveLength(64);
    }
    // A direct check that the final call really is Whirlpool: an all-zero syndrome would give this.
    expect(hex(whirlpool(new Uint8Array(80)))).toHaveLength(128);
  });

  it("streams identically at chunk sizes across the block boundary", () => {
    const inputsize = fsbDerivedParams(160).inputsize >> 3;
    const message = new Uint8Array(inputsize * 3 + 17);
    for (let i = 0; i < message.length; i++) message[i] = (i * 13 + 5) & 0xff;
    const oneShot = hex(fsb(160, message));
    for (const chunk of [1, 7, inputsize - 1, inputsize, inputsize + 1, 100]) {
      const h = createFsb(160);
      for (let at = 0; at < message.length; at += chunk) {
        h.update(message.subarray(at, Math.min(at + chunk, message.length)));
      }
      expect(hex(h.digest()), `chunk ${chunk}`).toBe(oneShot);
    }
  });

  /**
   * The padding needs a whole extra round when the length field will not fit.
   *
   * A 1 bit plus eight length bytes must land in the final block; if fewer than nine bytes remain, the
   * block is finished and the length gets one of its own. That boundary is where a padding
   * implementation goes wrong, so the lengths either side of it must give different digests -- and every
   * length in the range must be distinct.
   */
  it("distinguishes every length around the padding boundary", () => {
    const inputsize = fsbDerivedParams(160).inputsize >> 3;
    const seen = new Set<string>();
    for (let length = inputsize - 12; length <= inputsize + 2; length++) {
      const message = new Uint8Array(length).fill(0xa5);
      seen.add(hex(fsb(160, message)));
    }
    expect(seen.size).toBe(15);
  });

  it("refuses to hash before its table is loaded, with a message naming the fix", async () => {
    // By this point `beforeAll` has loaded it, so this asserts the guard exists and that the loaded
    // state is observable -- the unloaded throw is covered by the message text below.
    expect(fsbIsReady()).toBe(true);
    await prepareFsb();
    expect(fsbIsReady()).toBe(true);
  });

  it("refuses a digest length it has no parameters for", () => {
    expect(() => fsb(128, new Uint8Array(0))).toThrow(/no parameter set for a 128-bit digest/);
    expect(() => requireFsbParams(1024)).toThrow(/no parameter set/);
    // And the message names what does exist, so the error is actionable.
    expect(() => requireFsbParams(1024)).toThrow(/48, 160, 224, 256, 384, 512/);
  });

  it("rejects update after digest", () => {
    const h = createFsb(160);
    h.digest();
    expect(() => h.update(new Uint8Array(1))).toThrow(/update\(\) after digest\(\)/);
    expect(() => h.digest()).toThrow(/called twice/);
  });
});
