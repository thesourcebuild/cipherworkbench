import { describe, expect, it } from "vitest";

import {
  RAPIDHASH_DEFAULT_VERSION,
  RAPIDHASH_VERSIONS,
  rapidhash,
  rapidhashBytes,
  requireRapidhashVersion,
  type RapidhashVersion,
} from "../packages/algos/src/index";
import {
  RAPIDHASH_LONG_REPETITIONS,
  RAPIDHASH_LONG_TEXT,
  RAPIDHASH_VECTORS,
} from "./rapidhash-vectors";

const encoder = new TextEncoder();
const longBytes = encoder.encode(RAPIDHASH_LONG_TEXT.repeat(RAPIDHASH_LONG_REPETITIONS));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/**
 * rapidhash at all four published versions, against vectors generated from the reference C.
 *
 * See `tests/rapidhash-vectors.ts` for the provenance -- each version's fixture records the git
 * revision it was compiled from, so this is a differential check rather than a self-consistency one.
 */
describe("rapidhash", () => {
  for (const set of RAPIDHASH_VECTORS) {
    describe(set.version, () => {
      it(`matches all ${set.short.length} short vectors`, () => {
        for (const v of set.short) {
          const message = encoder.encode(v.message);
          expect(
            rapidhash(message, set.version as RapidhashVersion, v.seed),
            `${set.version} ${message.length} bytes at seed ${v.seed}`,
          ).toBe(v.expected);
        }
      });

      it(`matches all ${set.long.length} long vectors, at every branch boundary`, () => {
        for (const v of set.long) {
          expect(
            rapidhash(longBytes.subarray(0, v.length), set.version as RapidhashVersion, v.seed),
            `${set.version} at ${v.length} bytes`,
          ).toBe(v.expected);
        }
      });
    });
  }

  it("covers every registered version", () => {
    expect(RAPIDHASH_VECTORS.map((v) => v.version).sort()).toEqual(
      RAPIDHASH_VERSIONS.map((v) => v.id).sort(),
    );
    expect(RAPIDHASH_VERSIONS.map((v) => v.id)).toEqual(["v1.0", "v2.0", "v2.2", "v3.0"]);
  });

  /**
   * The long fixture's lengths must straddle every boundary, not merely reach them.
   *
   * Each difference between the four versions is a branch point -- v2.0 leaves its medium path at 56
   * where v2.2 leaves at 64, for instance -- so a length exactly *on* a boundary and one either side
   * are three different code paths. If a future trim kept only the round numbers this would fail.
   */
  it("straddles each branch boundary rather than only landing on it", () => {
    const lengths = new Set(RAPIDHASH_VECTORS[0]!.long.map((v) => v.length));
    for (const boundary of [4, 8, 16, 32, 48, 56, 64, 80, 96, 112, 224, 336]) {
      expect(lengths.has(boundary - 1), `${boundary} - 1`).toBe(true);
      expect(lengths.has(boundary), `${boundary}`).toBe(true);
      expect(lengths.has(boundary + 1), `${boundary} + 1`).toBe(true);
    }
  });

  /**
   * v1.0 and v3.0 differ from everything at every length, so those are easy. The interesting pair is
   * v2.0 against v2.2, whose *entire* difference is three things -- and the lengths where they agree
   * are as much a property worth pinning as the lengths where they do not.
   *
   * Derived from the code rather than observed: their differences are the 1-to-3-byte read, the secret
   * index in the third medium-branch mix (which only runs above 48), and where the medium branch ends
   * (56 at v2.0, 64 at v2.2). So they must differ on 1..3 and on 49..64, and agree everywhere else --
   * including above 64, where both take the identical long path.
   *
   * An implementation that wrote one of them over the other would break this in both directions at
   * once, which "all four differ" would not have caught: at 5 bytes all four *should* not differ.
   */
  it("separates v2.0 from v2.2 at exactly the lengths their three differences bite", () => {
    const differs = (length: number): boolean => {
      const message = longBytes.subarray(0, length);
      return rapidhash(message, "v2.0", 0n) !== rapidhash(message, "v2.2", 0n);
    };
    for (let length = 0; length <= 130; length++) {
      const expected = (length >= 1 && length <= 3) || (length >= 49 && length <= 64);
      expect(differs(length), `at ${length} bytes`).toBe(expected);
    }
  });

  it("makes v1.0 and v3.0 distinct from every other version at every non-empty length", () => {
    for (const length of [1, 3, 5, 13, 20, 40, 57, 60, 65, 120, 250]) {
      const message = longBytes.subarray(0, length);
      const values = RAPIDHASH_VERSIONS.map((v) => rapidhash(message, v.id, 0n).toString(16));
      const [v1, v20, v22, v3] = values as [string, string, string, string];
      expect(v1, `v1.0 at ${length}`).not.toBe(v20);
      expect(v1, `v1.0 at ${length}`).not.toBe(v3);
      expect(v3, `v3.0 at ${length}`).not.toBe(v20);
      expect(v3, `v3.0 at ${length}`).not.toBe(v22);
    }
  });

  /**
   * The empty message is the one input where v2.0, v2.2 and v3.0 all agree, and it is worth pinning
   * because it looks exactly like three versions wired to the same implementation.
   *
   * They coincide by construction. v3.0's structural change is that it does not fold the length into
   * the seed -- a no-op at length zero -- and at zero its epilogue `(lo ^ s7) * (hi ^ s1 ^ 0)` is
   * v2's `(lo ^ s7 ^ 0) * (hi ^ s1)`. Both short paths set `a = b = 0`, so nothing else can separate
   * them. v1.0 still differs, because its secret and its default seed are different.
   */
  it("has v2.0, v2.2 and v3.0 agree on the empty message, by construction", () => {
    const empty = new Uint8Array(0);
    const v20 = rapidhash(empty, "v2.0", 0n);
    expect(rapidhash(empty, "v2.2", 0n)).toBe(v20);
    expect(rapidhash(empty, "v3.0", 0n)).toBe(v20);
    expect(rapidhash(empty, "v1.0", 0n)).not.toBe(v20);
    // One byte is enough to separate all four again -- so this is a property of zero, not a wiring bug.
    const one = longBytes.subarray(0, 1);
    expect(new Set(RAPIDHASH_VERSIONS.map((v) => rapidhash(one, v.id, 0n).toString(16))).size).toBe(4);
  });

  /**
   * v1.0's default seed is not zero, and that has to survive being left unspecified.
   *
   * Reading an empty seed field as zero would make the reference's own no-seed answer unreachable from
   * the form. `compute.ts` leaves `seed64` undefined when the field is empty for exactly this reason.
   */
  it("defaults v1.0's seed to the reference's non-zero value", () => {
    expect(requireRapidhashVersion("v1.0").defaultSeed).toBe(0xbdd89aa982704029n);
    for (const version of RAPIDHASH_VERSIONS) {
      if (version.id === "v1.0") continue;
      expect(version.defaultSeed, version.id).toBe(0n);
    }
    const message = encoder.encode("abc");
    // Omitting the seed must equal passing the version's own default, and differ from passing zero.
    expect(rapidhash(message, "v1.0")).toBe(rapidhash(message, "v1.0", 0xbdd89aa982704029n));
    expect(rapidhash(message, "v1.0")).not.toBe(rapidhash(message, "v1.0", 0n));
    // And for the others, omitting it is the same as zero.
    expect(rapidhash(message, "v3.0")).toBe(rapidhash(message, "v3.0", 0n));
  });

  it("declares three secret words at v1.0 and eight after it", () => {
    expect(requireRapidhashVersion("v1.0").secretWords).toBe(3);
    for (const version of ["v2.0", "v2.2", "v3.0"] as const) {
      expect(requireRapidhashVersion(version).secretWords, version).toBe(8);
    }
  });

  it("defaults to the newest version", () => {
    expect(RAPIDHASH_DEFAULT_VERSION).toBe("v3.0");
  });

  it("returns eight bytes, most significant first", () => {
    const message = encoder.encode("abc");
    for (const version of RAPIDHASH_VERSIONS) {
      const value = rapidhash(message, version.id);
      expect(hex(rapidhashBytes(message, version.id)), version.id).toBe(
        value.toString(16).padStart(16, "0"),
      );
    }
  });

  /**
   * `protected` is implemented and not registered as a tool. It must still be reachable and must
   * differ from `fast`, so that a future decision to offer it is a metadata edit rather than new code.
   */
  it("implements the protected rapid_mum, which differs from fast at every version", () => {
    for (const version of RAPIDHASH_VERSIONS) {
      for (const length of [3, 10, 40, 130]) {
        const message = longBytes.subarray(0, length);
        expect(
          rapidhash(message, version.id, undefined, "protected"),
          `${version.id} at ${length} bytes`,
        ).not.toBe(rapidhash(message, version.id, undefined, "fast"));
      }
    }
  });

  it("refuses an unknown version", () => {
    expect(() => requireRapidhashVersion("v4.0")).toThrow(/unknown version/);
  });

  /**
   * None of the four can stream, and it is worth pinning why rather than only that.
   *
   * Every version's final step reads the last sixteen bytes of the message, so the answer depends on
   * the end of the input. Appending a byte therefore changes the result even when the prefix is
   * block-aligned, which is what makes an incremental API impossible without buffering the whole thing.
   */
  it("depends on the end of the message, which is why it cannot stream", () => {
    for (const version of RAPIDHASH_VERSIONS) {
      for (const length of [16, 32, 48, 56, 64, 112, 224]) {
        const shorter = longBytes.subarray(0, length);
        const longer = longBytes.subarray(0, length + 1);
        expect(
          rapidhash(shorter, version.id),
          `${version.id} at ${length}`,
        ).not.toBe(rapidhash(longer, version.id));
      }
    }
  });
});
