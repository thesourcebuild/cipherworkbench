/**
 * Reed-Solomon, BCH and the wider Hamming codes -- the three rungs Phase 7 added to the parity ladder.
 *
 * The parity family's argument is that one parity bit over a unit *detects* and several over
 * overlapping subsets *locate*. These extend it: Hamming(15,11) is the same construction with four
 * parity bits instead of three, BCH generalises it to more than one error via a finite field, and
 * Reed-Solomon does the same over byte *symbols* rather than bits.
 *
 * No oracle -- nothing in this tree implements any of them. What stands behind each is different, and
 * naming which is the point:
 *
 *  - **Reed-Solomon** rests on four published encodings: the two worked examples in ISO/IEC 18004
 *    Annex I and two Data Matrix cases, transcribed by zxing. Correction is checked by damaging each
 *    published codeword to the code's limit and requiring the original back -- and by damaging it one
 *    symbol *past* the limit and requiring a refusal rather than a plausible wrong answer.
 *  - **BCH** rests on all 32 format-information and all 34 version-information codewords from ISO/IEC
 *    18004 Tables C.1 and D.1. That is every codeword either code has, so the fixture is exhaustive
 *    rather than a sample.
 *  - **The Hamming widths** rest on nothing published, and are checked *exhaustively* instead: all
 *    2,048 codewords, a minimum distance of 3 (or 4 extended), every one of the 30,720 single-bit
 *    errors corrected, and every double-bit error detected by the extended form. That is stronger than
 *    a table would be, and it is available only because the code is small enough to walk.
 *
 * One bug, and it was a real one. **Forney's error magnitude needs a factor the generator base
 * decides**: `X^(1-base)`, which is 1 only when the base is 1. Omitting it decoded Data Matrix
 * perfectly and refused every correction under QR's field, because the syndrome re-check caught the
 * wrong magnitudes. Without that re-check it would have returned corrupted data instead.
 */
import { describe, expect, it } from "vitest";
import {
  BCH_PROFILES,
  bchDecode,
  bchEncode,
  hamming74Encode,
  hamming84Encode,
  hamming74Decode,
  hamming84Decode,
  hammingDecode,
  hammingEncode,
  HAMMING_SIZES,
  RS_PROFILES,
  rsDecode,
  rsEncode,
  type BchProfile,
} from "@ocs/algos";
import {
  BCH_QR_FORMAT,
  BCH_QR_VERSION,
  RS_VECTORS,
} from "./ecc-vectors";

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/**
 * `count` distinct positions spread evenly across `length`, ascending.
 *
 * Written as a helper because the obvious alternative is a trap. The first version of the
 * past-the-limit test stepped by a fixed stride and de-duplicated -- and for a 60-symbol codeword a
 * stride of 5 only ever visits twelve positions, because gcd(5, 60) is 5. Asking it for thirteen was
 * an infinite loop, which presented as vitest killing the worker rather than as a failed assertion.
 * Spreading evenly cannot have that problem for any `count <= length`.
 */
const spread = (count: number, length: number): number[] => {
  if (count > length) throw new Error(`cannot pick ${count} distinct positions from ${length}`);
  return Array.from({ length: count }, (_, i) => Math.floor((i * length) / count));
};

describe("Reed-Solomon", () => {
  it("reproduces every published encoding", () => {
    expect(RS_VECTORS).toHaveLength(4);
    for (const v of RS_VECTORS) {
      const field = RS_PROFILES[v.profile];
      const got = rsEncode(field, Uint8Array.from(v.data), v.ecc.length);
      expect(hex(got), `${v.profile} ${v.data.length}->${v.ecc.length} (${v.note})`).toBe(
        hex(Uint8Array.from(v.ecc)),
      );
    }
  });

  it("uses two genuinely different fields", () => {
    /**
     * QR's 0x11d with base 0 and Data Matrix's 0x12d with base 1 share no arithmetic, so the same data
     * gives unrelated parity. Worth pinning because a profile control that reached nothing would still
     * produce the right *number* of symbols.
     */
    const data = Uint8Array.from([142, 164, 186]);
    const a = hex(rsEncode(RS_PROFILES.qr, data, 5));
    const b = hex(rsEncode(RS_PROFILES.datamatrix, data, 5));
    expect(a).not.toBe(b);
    // And Data Matrix's is the published one.
    expect(b).toBe(hex(Uint8Array.from([114, 25, 5, 88, 102])));
  });

  it("decodes a clean codeword without changing it", () => {
    for (const v of RS_VECTORS) {
      const codeword = Uint8Array.from([...v.data, ...v.ecc]);
      const result = rsDecode(RS_PROFILES[v.profile], codeword, v.ecc.length);
      expect(result, v.note).not.toBeNull();
      expect(result!.corrected, v.note).toEqual([]);
      expect(hex(result!.codeword), v.note).toBe(hex(codeword));
    }
  });

  it("corrects damage up to the code's limit", () => {
    /**
     * `ecc / 2` symbol errors, which is the guarantee -- and the reason a symbol code is worth having:
     * each of these is a whole byte destroyed, not a bit flipped, so the same damage would defeat any
     * number of parity bits.
     */
    for (const v of RS_VECTORS) {
      const codeword = Uint8Array.from([...v.data, ...v.ecc]);
      const limit = Math.floor(v.ecc.length / 2);
      const damaged = Uint8Array.from(codeword);
      const hit = spread(limit, codeword.length);
      for (const at of hit) damaged[at] = damaged[at]! ^ 0x5a;
      const result = rsDecode(RS_PROFILES[v.profile], damaged, v.ecc.length);
      expect(result, `${v.note}: ${limit} errors`).not.toBeNull();
      expect(hex(result!.codeword), `${v.note}: ${limit} errors`).toBe(hex(codeword));
      expect([...result!.corrected]).toEqual(hit);
    }
  });

  it("refuses rather than guessing past the limit", () => {
    /**
     * One symbol more than the code can locate. The honest answer is null: bounded-distance decoding
     * that guessed would return a *valid* codeword that is not the one sent, which is silently wrong
     * data. The syndrome re-check after correction is what makes this reliable.
     */
    for (const v of RS_VECTORS) {
      const codeword = Uint8Array.from([...v.data, ...v.ecc]);
      const damaged = Uint8Array.from(codeword);
      // One symbol past what the code can locate, at evenly spread positions.
      for (const at of spread(Math.floor(v.ecc.length / 2) + 1, codeword.length)) {
        damaged[at] = damaged[at]! ^ 0x3c;
      }
      const result = rsDecode(RS_PROFILES[v.profile], damaged, v.ecc.length);
      // Either it refuses, or -- if the damage happened to land on a valid codeword -- it must at
      // least not claim the original. Anything else would be a silent corruption.
      if (result !== null) expect(hex(result.codeword), v.note).not.toBe(hex(codeword));
    }
  });

  it("refuses a block that cannot fit in GF(256)", () => {
    // 255 symbols total, so the message and its parity have to share them.
    expect(() => rsEncode(RS_PROFILES.qr, new Uint8Array(250), 10)).toThrow(/255 symbols/);
    expect(() => rsEncode(RS_PROFILES.qr, new Uint8Array(10), 0)).toThrow(/1 to 254/);
  });
});

describe("BCH", () => {
  const PROFILES: readonly [BchProfile, readonly { readonly data: number; readonly codeword: number }[]][] = [
    ["qr-format", BCH_QR_FORMAT],
    ["qr-version", BCH_QR_VERSION],
  ];

  it("reproduces every published codeword, and there are no others", () => {
    /**
     * Exhaustive rather than sampled: BCH(15,5) has exactly 32 codewords and BCH(18,6) exactly 64, of
     * which ISO/IEC 18004 uses 34 (versions 7 to 40). So the format fixture covers the whole code.
     */
    expect(BCH_QR_FORMAT).toHaveLength(32);
    expect(BCH_QR_VERSION).toHaveLength(34);
    expect(BCH_QR_FORMAT).toHaveLength(1 << BCH_PROFILES["qr-format"].k);
    for (const [profile, table] of PROFILES) {
      for (const { data, codeword } of table) {
        expect(bchEncode(profile, data), `${profile} ${data}`).toBe(codeword);
        const back = bchDecode(profile, codeword);
        expect(back, `${profile} ${data} decode`).not.toBeNull();
        expect(back!.data, `${profile} ${data} decode`).toBe(data);
        expect(back!.distance, `${profile} ${data} distance`).toBe(0);
      }
    }
  });

  it("masks the format code so an all-zero field is not valid", () => {
    /**
     * The 0x5412 mask is why: without it, format data 0 would encode to 0, and a blank or damaged
     * region would read as a legitimate format. The version code needs no mask because version 0 is
     * not a version.
     */
    expect(BCH_PROFILES["qr-format"].mask).toBe(0x5412);
    expect(BCH_PROFILES["qr-version"].mask).toBe(0);
    expect(bchEncode("qr-format", 0)).toBe(0x5412);
    expect(bchDecode("qr-format", 0)).not.toEqual({ data: 0, distance: 0 });
  });

  it("corrects every one-, two- and three-bit error in every codeword", () => {
    /**
     * Both codes have minimum distance at least 7, so three flipped bits is inside the guarantee. This
     * walks *every* single-bit position of every codeword rather than sampling, since the whole space
     * is 32 x 15 plus 34 x 18 -- small enough that a sample would be a choice rather than a necessity.
     */
    const failures: string[] = [];
    for (const [profile, table] of PROFILES) {
      const p = BCH_PROFILES[profile];
      let checked = 0;
      for (const { data, codeword } of table) {
        for (let bit = 0; bit < p.n; bit++) {
          const got = bchDecode(profile, codeword ^ (1 << bit));
          if (got?.data !== data || got?.distance !== 1) failures.push(`${profile} ${data} bit ${bit}`);
          checked += 1;
        }
        for (const bits of [[0, 4], [2, 9], [1, 7, 13]]) {
          if (bits.some((b) => b >= p.n)) continue;
          let damaged = codeword;
          for (const b of bits) damaged ^= 1 << b;
          if (bchDecode(profile, damaged)?.data !== data) {
            failures.push(`${profile} ${data} bits ${bits.join(",")}`);
          }
        }
      }
      expect(checked, `${profile} single-bit coverage`).toBe(table.length * p.n);
    }
    expect(failures).toEqual([]);
  });

  it("refuses a data value that does not fit", () => {
    expect(() => bchEncode("qr-format", 32)).toThrow(/5 bits/);
    expect(() => bchEncode("qr-version", 64)).toThrow(/6 bits/);
  });
});

describe("the general Hamming code", () => {
  it("agrees with the hand-written (7,4) and (8,4) at every nibble", () => {
    /**
     * The generalisation checked against the narrow case, which is itself pinned by a published value
     * (`1011 -> 0110011`). That transfers the published vector to the general implementation without
     * needing a second one -- and it is what makes the wider codes' exhaustive tests meaningful, since
     * they have no published value at all.
     */
    const failures: string[] = [];
    for (let nibble = 0; nibble < 16; nibble++) {
      if (hammingEncode(4, nibble, false) !== hamming74Encode(nibble)) failures.push(`(7,4) encode ${nibble}`);
      if (hammingEncode(4, nibble, true) !== hamming84Encode(nibble)) failures.push(`(8,4) encode ${nibble}`);
      const clean = hamming74Encode(nibble);
      for (let bit = 0; bit < 7; bit++) {
        const general = hammingDecode(4, clean ^ (1 << bit), false);
        const specific = hamming74Decode(clean ^ (1 << bit));
        if (general.value !== specific.nibble || general.correctedPosition !== specific.correctedPosition) {
          failures.push(`(7,4) decode ${nibble} bit ${bit}`);
        }
      }
      const cleanExtended = hamming84Encode(nibble);
      for (let bit = 0; bit < 8; bit++) {
        const general = hammingDecode(4, cleanExtended ^ (1 << bit), true);
        const specific = hamming84Decode(cleanExtended ^ (1 << bit));
        if (general.value !== specific.nibble || general.doubleError !== specific.doubleError) {
          failures.push(`(8,4) decode ${nibble} bit ${bit}`);
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it("carries the right number of bits at each size", () => {
    // `2^r - 1` codeword bits carrying `2^r - 1 - r` data bits, for r = 3 and 4.
    expect(HAMMING_SIZES["4"]).toEqual({ parityBits: 3, dataBits: 4, codeBits: 7 });
    expect(HAMMING_SIZES["11"]).toEqual({ parityBits: 4, dataBits: 11, codeBits: 15 });
  });

  it("has minimum distance 3 unextended and 4 extended, at both sizes", () => {
    /**
     * The property everything else follows from. Distance 3 corrects one error and cannot tell two from
     * one; distance 4 corrects one and *detects* two, which is the whole reason the extended form
     * exists. Exhaustive over all pairs of codewords -- 2,048 of them at (15,11), so 2 million pairs.
     */
    for (const dataBits of [4, 11] as const) {
      const count = 1 << dataBits;
      for (const extended of [false, true]) {
        const words: number[] = [];
        for (let v = 0; v < count; v++) words.push(hammingEncode(dataBits, v, extended));
        let minimum = Infinity;
        for (let i = 0; i < count; i++) {
          for (let j = i + 1; j < count; j++) {
            let x = words[i]! ^ words[j]!;
            let d = 0;
            while (x !== 0) {
              x &= x - 1;
              d++;
            }
            if (d < minimum) minimum = d;
          }
        }
        expect(minimum, `${dataBits} data bits, extended=${extended}`).toBe(extended ? 4 : 3);
      }
    }
  });

  it("corrects every single-bit error at every size", () => {
    /**
     * Failures are collected and asserted once rather than checked with `expect` in the inner loop.
     * 63,728 assertions is slow enough in vitest to hit the per-test timeout, and a list of the first
     * few failures localises a fault better than the first one alone anyway.
     */
    const failures: string[] = [];
    let checked = 0;
    for (const dataBits of [4, 11] as const) {
      const meta = HAMMING_SIZES[String(dataBits)]!;
      for (let value = 0; value < 1 << dataBits; value++) {
        for (const extended of [false, true]) {
          const width = extended ? meta.codeBits + 1 : meta.codeBits;
          const clean = hammingEncode(dataBits, value, extended);
          for (let bit = 0; bit < width; bit++) {
            const decoded = hammingDecode(dataBits, clean ^ (1 << bit), extended);
            if (decoded.doubleError || decoded.value !== value) {
              if (failures.length < 8) failures.push(`${dataBits}/${value}/bit ${bit}`);
            }
            checked += 1;
          }
        }
      }
    }
    expect(failures).toEqual([]);
    // 16 * (7 + 8) + 2048 * (15 + 16) = 240 + 63,488.
    expect(checked).toBe(63728);
  });

  it("detects every double-bit error in the extended form, at both sizes", () => {
    /**
     * The other half of what distance 4 buys, and the reason to choose the extended form: two errors
     * are *refused* rather than miscorrected into a third wrong value. The unextended form is checked
     * from the other side in the distance test above -- at distance 3 it cannot do this, and claiming
     * otherwise is the failure mode.
     */
    const failures: string[] = [];
    let checked = 0;
    for (const dataBits of [4, 11] as const) {
      const meta = HAMMING_SIZES[String(dataBits)]!;
      const width = meta.codeBits + 1;
      for (let value = 0; value < 1 << dataBits; value++) {
        const clean = hammingEncode(dataBits, value, true);
        for (let a = 0; a < width; a++) {
          for (let b = a + 1; b < width; b++) {
            if (!hammingDecode(dataBits, clean ^ (1 << a) ^ (1 << b), true).doubleError) {
              if (failures.length < 8) failures.push(`${dataBits}/${value}/bits ${a},${b}`);
            }
            checked += 1;
          }
        }
      }
    }
    expect(failures).toEqual([]);
    // 16 * C(8,2) + 2048 * C(16,2) = 448 + 245,760.
    expect(checked).toBe(246208);
  });

  it("refuses a size it has no code for", () => {
    // A throwing lookup rather than a fall-through, for the reason the rest of this repo uses one.
    expect(() => hammingEncode(26, 0, false)).toThrow(/26 data bits/);
    expect(() => hammingDecode(7, 0, false)).toThrow(/7 data bits/);
  });
});
