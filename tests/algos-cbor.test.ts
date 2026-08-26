import { describe, expect, it } from "vitest";
import {
  CborError,
  decodeCbor,
  encodeCbor,
  isCborMap,
  isCborTagged,
  type CborValue,
} from "@ocs/algos";

const fromHex = (hex: string) =>
  // `?? []` for the empty string, which is itself one of the malformed inputs below.
  Uint8Array.from((hex.match(/../g) ?? []).map((byte) => parseInt(byte, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const map = (entries: [CborValue, CborValue][]): CborValue => ({ cborMap: entries });
const bytes = (...values: number[]) => new Uint8Array(values);

/**
 * RFC 8949 Appendix A, the table of examples.
 *
 * `roundTrip: false` marks the rows the RFC lists to show what a *decoder* must accept but which a
 * deterministic encoder will never write: a non-shortest argument, an indefinite length, a NaN
 * payload. Every other row must survive encode(decode(bytes)) === bytes, which is the strongest
 * statement available here -- it checks the reader and the writer against each other and against the
 * specification at the same time.
 */
const VECTORS: readonly {
  hex: string;
  value: CborValue;
  roundTrip?: false;
  note?: string;
}[] = [
  // ── unsigned and negative integers, every argument width ──
  { hex: "00", value: 0 },
  { hex: "01", value: 1 },
  { hex: "0a", value: 10 },
  { hex: "17", value: 23 },
  { hex: "1818", value: 24 },
  { hex: "1819", value: 25 },
  { hex: "1864", value: 100 },
  { hex: "1903e8", value: 1000 },
  { hex: "1a000f4240", value: 1000000 },
  { hex: "1b000000e8d4a51000", value: 1000000000000 },
  { hex: "1bffffffffffffffff", value: 18446744073709551615n },
  { hex: "3bffffffffffffffff", value: -18446744073709551616n },
  { hex: "20", value: -1 },
  { hex: "29", value: -10 },
  { hex: "3863", value: -100 },
  { hex: "3903e7", value: -1000 },

  // ── floats: half, single, double, and the specials ──
  {
    hex: "f90000",
    value: 0,
    roundTrip: false,
    note: "0.0 as a half; the encoder writes the integer 0",
  },
  {
    hex: "f93c00",
    value: 1,
    roundTrip: false,
    note: "1.0 as a half; the encoder writes the integer 1",
  },
  { hex: "f93e00", value: 1.5 },
  { hex: "f97bff", value: 65504, roundTrip: false, note: "an integer to this encoder" },
  { hex: "fa47c35000", value: 100000, roundTrip: false, note: "an integer to this encoder" },
  { hex: "fa7f7fffff", value: 3.4028234663852886e38 },
  { hex: "fb7e37e43c8800759c", value: 1e300 },
  { hex: "f90001", value: 5.960464477539063e-8 },
  { hex: "f90400", value: 0.00006103515625 },
  { hex: "f9c400", value: -4, roundTrip: false, note: "an integer to this encoder" },
  { hex: "fbc010666666666666", value: -4.1 },
  { hex: "f97c00", value: Infinity },
  { hex: "f9fc00", value: -Infinity },
  { hex: "fa7f800000", value: Infinity, roundTrip: false, note: "a half suffices" },
  { hex: "fb7ff0000000000000", value: Infinity, roundTrip: false, note: "a half suffices" },

  // ── simple values ──
  { hex: "f4", value: false },
  { hex: "f5", value: true },
  { hex: "f6", value: null },
  { hex: "f7", value: undefined },

  // ── tags ──
  {
    hex: "c074323031332d30332d32315432303a30343a30305a",
    value: { tag: 0, value: "2013-03-21T20:04:00Z" },
  },
  { hex: "c11a514b67b0", value: { tag: 1, value: 1363896240 } },
  { hex: "c1fb41d452d9ec200000", value: { tag: 1, value: 1363896240.5 } },
  { hex: "d74401020304", value: { tag: 23, value: bytes(1, 2, 3, 4) } },
  { hex: "d818456449455446", value: { tag: 24, value: bytes(0x64, 0x49, 0x45, 0x54, 0x46) } },
  {
    hex: "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
    value: { tag: 32, value: "http://www.example.com" },
  },

  // ── byte and text strings ──
  { hex: "40", value: bytes() },
  { hex: "4401020304", value: bytes(1, 2, 3, 4) },
  { hex: "60", value: "" },
  { hex: "6161", value: "a" },
  { hex: "6449455446", value: "IETF" },
  { hex: "62225c", value: '"\\' },
  { hex: "62c3bc", value: "ü" },
  { hex: "63e6b0b4", value: "水" },
  { hex: "64f0908591", value: "𐅑" },

  // ── arrays and maps ──
  { hex: "80", value: [] },
  { hex: "83010203", value: [1, 2, 3] },
  { hex: "8301820203820405", value: [1, [2, 3], [4, 5]] },
  {
    hex: "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
    value: Array.from({ length: 25 }, (_, i) => i + 1),
  },
  { hex: "a0", value: map([]) },
  {
    hex: "a201020304",
    value: map([
      [1, 2],
      [3, 4],
    ]),
  },
  {
    hex: "a26161016162820203",
    value: map([
      ["a", 1],
      ["b", [2, 3]],
    ]),
  },
  { hex: "826161a161626163", value: ["a", map([["b", "c"]])] },
  {
    hex: "a56161614161626142616361436164614461656145",
    value: map([
      ["a", "A"],
      ["b", "B"],
      ["c", "C"],
      ["d", "D"],
      ["e", "E"],
    ]),
  },

  // ── indefinite lengths: decode only ──
  { hex: "5f42010243030405ff", value: bytes(1, 2, 3, 4, 5), roundTrip: false },
  { hex: "7f657374726561646d696e67ff", value: "streaming", roundTrip: false },
  { hex: "9fff", value: [], roundTrip: false },
  { hex: "9f018202039f0405ffff", value: [1, [2, 3], [4, 5]], roundTrip: false },
  { hex: "9f01820203820405ff", value: [1, [2, 3], [4, 5]], roundTrip: false },
  { hex: "83018202039f0405ff", value: [1, [2, 3], [4, 5]], roundTrip: false },
  { hex: "83019f0203ff820405", value: [1, [2, 3], [4, 5]], roundTrip: false },
  {
    hex: "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
    value: Array.from({ length: 25 }, (_, i) => i + 1),
    roundTrip: false,
  },
  {
    hex: "bf61610161629f0203ffff",
    value: map([
      ["a", 1],
      ["b", [2, 3]],
    ]),
    roundTrip: false,
  },
  { hex: "826161bf61626163ff", value: ["a", map([["b", "c"]])], roundTrip: false },
  {
    hex: "bf6346756ef563416d7421ff",
    value: map([
      ["Fun", true],
      ["Amt", -2],
    ]),
    roundTrip: false,
  },
];

describe("RFC 8949 Appendix A", () => {
  for (const vector of VECTORS) {
    it(`decodes ${vector.hex}${vector.note ? ` (${vector.note})` : ""}`, () => {
      const { value, trailing } = decodeCbor(fromHex(vector.hex));
      expect(trailing).toBe(0);
      expect(value).toEqual(vector.value);
    });
  }

  for (const vector of VECTORS.filter((v) => v.roundTrip !== false)) {
    it(`re-encodes ${vector.hex} byte for byte`, () => {
      expect(toHex(encodeCbor(vector.value))).toBe(vector.hex);
    });
  }

  it("covers every major type", () => {
    // A guard on the table rather than on the code: a vector list that lost its maps or its tags
    // would still pass every assertion above.
    const majors = new Set(VECTORS.map((v) => parseInt(v.hex.slice(0, 2), 16) >> 5));
    expect([...majors].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });
});

describe("NaN", () => {
  it("decodes each width and re-encodes as the half the RFC shows", () => {
    // Its own test because NaN !== NaN, so the table above cannot assert it by equality.
    for (const hex of ["f97e00", "fa7fc00000", "fb7ff8000000000000"]) {
      expect(Number.isNaN(decodeCbor(fromHex(hex)).value as number)).toBe(true);
    }
    expect(toHex(encodeCbor(NaN))).toBe("f97e00");
  });
});

describe("deterministic encoding", () => {
  it("uses the shortest argument for every integer boundary", () => {
    // RFC 8949 section 4.2.1. An encoder that always used eight bytes would be valid CBOR that never
    // matches anyone else's output.
    expect(toHex(encodeCbor(23))).toBe("17");
    expect(toHex(encodeCbor(24))).toBe("1818");
    expect(toHex(encodeCbor(255))).toBe("18ff");
    expect(toHex(encodeCbor(256))).toBe("190100");
    expect(toHex(encodeCbor(65535))).toBe("19ffff");
    expect(toHex(encodeCbor(65536))).toBe("1a00010000");
    expect(toHex(encodeCbor(4294967295))).toBe("1affffffff");
    expect(toHex(encodeCbor(4294967296))).toBe("1b0000000100000000");
  });

  it("uses the shortest float that round-trips", () => {
    expect(toHex(encodeCbor(1.5))).toBe("f93e00"); // exact in half
    expect(toHex(encodeCbor(3.4028234663852886e38))).toBe("fa7f7fffff"); // exact in single
    expect(toHex(encodeCbor(1.1))).toBe("fb3ff199999999999a"); // needs double
  });

  it("accepts a non-shortest argument on the way in and normalises it on the way out", () => {
    // Permissive reader, deterministic writer: both halves of the rule in one assertion.
    expect(decodeCbor(fromHex("1b0000000000000000")).value).toBe(0);
    expect(toHex(encodeCbor(decodeCbor(fromHex("1b0000000000000000")).value))).toBe("00");
  });
});

describe("malformed input", () => {
  const bad: readonly [string, RegExp][] = [
    ["", /ended in the middle/i],
    ["18", /ended in the middle/i],
    ["1c", /reserved additional information/i],
    ["1e", /reserved additional information/i],
    ["44010203", /claims 4 bytes and only 3 remain/],
    ["830102", /ended in the middle/i],
    ["a1", /ended in the middle/i],
    ["a301020304", /ended in the middle/i],
    ["bf000000ff", /ended after a key with no value/i],
    ["ff", /begins with a break/i],
    ["5f42010263666666ff", /chunk of another type/],
    ["c1", /ended in the middle/i],
    ["dfff", /tag cannot have an indefinite length/i],
    ["1f", /integer cannot have an indefinite length/i],
    ["f818", /must use the one-byte form/],
  ];

  for (const [hex, expected] of bad) {
    it(`rejects ${hex || "(empty)"}`, () => {
      expect(() => decodeCbor(fromHex(hex || ""))).toThrow(expected);
    });
  }

  it("reports the byte offset it got to", () => {
    // The whole reason CborError carries one: "invalid CBOR" is not a message anyone can act on.
    try {
      decodeCbor(fromHex("8301021c"));
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(CborError);
      expect((error as CborError).message).toMatch(/at byte \d+/);
      expect((error as CborError).offset).toBeGreaterThan(0);
    }
  });

  it("refuses nesting deep enough to exhaust the stack", () => {
    // 200 nested single-element arrays. A decoder without a cap turns this into a crash.
    const deep = fromHex("81".repeat(200) + "00");
    expect(() => decodeCbor(deep)).toThrow(/deeper than/i);
  });
});

describe("trailing bytes", () => {
  it("are reported rather than refused", () => {
    // CBOR sequences (RFC 8742) are a real format, and a paste that picked up an extra byte is a
    // more common cause. Both want the first item shown plus a note, not an error.
    const result = decodeCbor(fromHex("0001"));
    expect(result.value).toBe(0);
    expect(result.trailing).toBe(1);
  });
});

describe("shapes the JSON bridge depends on", () => {
  it("keeps map keys as items, in order", () => {
    // Decoding into a JS object would stringify an integer key and lose the ordering that
    // deterministic encoding depends on. COSE uses integer keys for everything.
    const decoded = decodeCbor(fromHex("a3016161026162036163")).value;
    expect(isCborMap(decoded)).toBe(true);
    if (isCborMap(decoded)) {
      expect(decoded.cborMap).toEqual([
        [1, "a"],
        [2, "b"],
        [3, "c"],
      ]);
    }
  });

  it("copies a byte string rather than aliasing the input", () => {
    const input = fromHex("43010203");
    const decoded = decodeCbor(input).value as Uint8Array;
    input[1] = 0xff;
    expect([...decoded]).toEqual([1, 2, 3]);
  });

  it("marks a tag so the bridge can decide what to do with it", () => {
    const decoded = decodeCbor(fromHex("c249010000000000000000")).value;
    expect(isCborTagged(decoded)).toBe(true);
    if (isCborTagged(decoded)) expect(decoded.tag).toBe(2);
  });
});
