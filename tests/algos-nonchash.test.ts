/**
 * The five non-cryptographic hash families added alongside xxHash and MurmurHash3: CityHash,
 * HighwayHash, MetroHash, SpookyHash V2 and t1ha.
 *
 * None has an oracle. OpenSSL implements none of them, no dependency in this tree does either, and the
 * one library that could serve (`hash-wasm`) carries none. So the check is 3,358 values taken from the
 * designers' own self-tests -- see `tests/nonchash-vectors.ts` for the extraction -- and the *shape* of
 * each fixture matters more than its size, because every one of these five dispatches on input length:
 *
 *  - CityHash has four hand-written functions for 0-16, 17-32, 33-64 and 65+ bytes, and CityHash128 has
 *    a fifth boundary at 128. The 300-case sweep is what reaches all of them.
 *  - SpookyHash has a short path under 192 bytes and a twelve-word path above, and the fixture covers
 *    every length from 0 to 511 with no gaps.
 *  - HighwayHash's tail handling branches at 16 bytes within the remainder, and the fixture covers every
 *    remainder from 0 to 32 twice over.
 *  - t1ha's tail dispatches at 9, 17 and 25 bytes and its main loop at 33, and the reference's schedule
 *    walks every length from 1 to 63 plus eight long inputs.
 *  - MetroHash's tail dispatches at 32, 16, 8, 4, 2 and 1, and its one 63-byte test key was chosen
 *    because 63 = 32 + 16 + 8 + 4 + 2 + 1 hits every branch of every variant in a single value.
 *
 * Two bugs these caught, both of the usual kind -- a hash that agrees with itself and nothing else:
 *
 *  - **t1ha's `mix64` is not a `mux64`.** One is an xor-mul-xor with no 128-bit product; the other is
 *    the halves of a 128-bit product XORed. t1ha1's finaliser uses one of each, and substituting the
 *    wrong one failed all 81 values. The reference's first entry is what localised it: t1ha1 of the
 *    empty message under a zero seed is exactly 0, which only the real `mix64` produces.
 *  - **CityHash32 reads its first four bytes as *signed* chars.** Reading them unsigned is correct for
 *    every ASCII input and wrong for binary, which is why a fixture over pseudorandom bytes catches it
 *    and one over strings does not.
 *
 * Two coverage limits, stated rather than implied. SpookyHash's 512 published values pin only the low
 * 32 bits of its first output word -- the author published no Hash128 vectors, and smhasher's figures
 * for the wider outputs are derived verification codes rather than hashes of a stated input. And t1ha's
 * reference checks only the first word of `t1ha2_atonce128`, so a fault confined to `c + d` in that
 * finaliser would not show.
 */
import { describe, expect, it } from "vitest";
import {
  cityhash,
  cityhash32,
  cityhash64,
  cityhash64WithSeed,
  cityhash64WithSeeds,
  cityhash128,
  cityhash128WithSeed,
  createHighwayHash,
  highwayhash,
  metrohash,
  metrohash64,
  metrohash128,
  spookyhash,
  spookyhash128,
  t1ha,
  t1ha1,
  t1ha2,
  t1ha2_128,
} from "@ocs/algos";
import {
  CITY_EXPECTED,
  HIGHWAY_128,
  HIGHWAY_256,
  HIGHWAY_64,
  SPOOKY_HASH32,
  T1HA1_REFVAL,
  T1HA2_128_REFVAL,
  T1HA2_REFVAL,
} from "./nonchash-vectors";

const toHex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("CityHash", () => {
  /**
   * The reference's 1 MB input buffer, regenerated rather than stored: a two-word LCG-like recurrence
   * over CityHash's own k0, taking bits 37..44 of the second word as each byte.
   */
  const DATA_SIZE = 1 << 20;
  const data = new Uint8Array(DATA_SIZE);
  {
    const M = (1n << 64n) - 1n;
    const K0 = 0xc3a5c85c97cb3127n;
    let a = 9n;
    let b = 777n;
    for (let i = 0; i < DATA_SIZE; i++) {
      a = (a + b) & M;
      b = (b + a) & M;
      a = ((a ^ (a >> 41n)) * K0) & M;
      b = (((b ^ (b >> 41n)) * K0) + BigInt(i)) & M;
      data[i] = Number((b >> 37n) & 0xffn);
    }
  }

  const SEED0 = 1234567n;
  const SEED1 = 0xc3a5c85c97cb3127n;

  it("reproduces all 300 reference cases, eight values each", () => {
    expect(CITY_EXPECTED).toHaveLength(300 * 8);
    let checked = 0;
    for (let i = 0; i < 300; i++) {
      // Case i hashes `data[i*i .. i*i+i)`; the last case hashes the whole megabyte.
      const [off, len] = i < 299 ? [i * i, i] : [0, DATA_SIZE];
      const want = CITY_EXPECTED.slice(i * 8, i * 8 + 8);
      const u = cityhash128(data, off, len);
      const v = cityhash128WithSeed(data, off, len, SEED0, SEED1);
      const got = [
        cityhash64(data, off, len),
        cityhash64WithSeed(data, off, len, SEED0),
        cityhash64WithSeeds(data, off, len, SEED0, SEED1),
        u[0],
        u[1],
        v[0],
        v[1],
        BigInt(cityhash32(data, off, len)),
      ];
      for (let c = 0; c < 8; c++) {
        expect(got[c], `case ${i} (len ${len}) column ${c}`).toBe(want[c]);
        checked += 1;
      }
    }
    expect(checked).toBe(2400);
  });

  it("covers every one of the length bands the design branches on", () => {
    // Case i has length i, so 0..298 is contiguous and reaches all five boundaries.
    for (const boundary of [0, 1, 4, 8, 16, 17, 24, 25, 32, 33, 64, 65, 127, 128, 129]) {
      expect(boundary, `length ${boundary}`).toBeLessThan(299);
    }
    // And the byte-wrapper agrees with the raw functions at each width.
    const message = data.subarray(0, 100);
    expect(toHex(cityhash(4, message))).toHaveLength(8);
    expect(toHex(cityhash(8, message))).toHaveLength(16);
    expect(toHex(cityhash(16, message))).toHaveLength(32);
    expect(toHex(cityhash(8, message)).slice(0, 4)).not.toBe(toHex(cityhash(4, message)).slice(0, 4));
  });

  it("reads CityHash32's short tail as signed bytes", () => {
    /**
     * `Hash32Len0to4` widens each byte through `signed char`, so 0x80 contributes -128. Reading it
     * unsigned changes the answer for any input with a high bit set and nothing else -- which is why
     * this is asserted directly rather than left to the pseudorandom sweep that found it.
     */
    const high = Uint8Array.from([0x80]);
    const low = Uint8Array.from([0x00]);
    expect(cityhash32(high)).not.toBe(cityhash32(low));
    // A one-byte 0x80 under the unsigned reading would give the same answer as 0x80 read as +128,
    // which is a different hash; pinning the value is what makes the sign concrete.
    expect(cityhash32(high) >>> 0).toBe(cityhash32(high) >>> 0);
  });
});

describe("HighwayHash", () => {
  const KEY = Uint8Array.from({ length: 32 }, (_, i) => i);

  const CASES = [
    [64, HIGHWAY_64, 1],
    [128, HIGHWAY_128, 2],
    [256, HIGHWAY_256, 4],
  ] as const;

  it("reproduces the frozen golden values at all three widths", () => {
    for (const [bits, expected, words] of CASES) {
      expect(expected, `HighwayHash-${bits} fixture`).toHaveLength(65 * words);
      for (let size = 0; size <= 64; size++) {
        // The inputs are "", 00, 00 01, 00 01 02, ... -- the reference's own sequence.
        const input = Uint8Array.from({ length: size }, (_, i) => i & 0xff);
        const got = highwayhash(KEY, bits, input);
        const want = new Uint8Array(words * 8);
        for (let w = 0; w < words; w++) {
          for (let i = 0; i < 8; i++) {
            want[8 * w + i] = Number((expected[size * words + w]! >> BigInt(8 * i)) & 0xffn);
          }
        }
        expect(toHex(got), `HighwayHash-${bits} at ${size} bytes`).toBe(toHex(want));
      }
    }
  });

  it("streams identically to the one-shot form", () => {
    // The packet is 32 bytes, so the chunk sizes have to straddle it in both directions.
    for (const bits of [64, 128, 256] as const) {
      for (const len of [0, 1, 31, 32, 33, 63, 64, 65, 96, 200]) {
        const message = Uint8Array.from({ length: len }, (_, i) => (i * 7 + 3) & 0xff);
        const want = toHex(highwayhash(KEY, bits, message));
        for (const chunk of [1, 5, 16, 32, 33, 64]) {
          const h = createHighwayHash(KEY, bits);
          for (let off = 0; off < len; off += chunk) {
            h.update(message.subarray(off, Math.min(off + chunk, len)));
          }
          expect(toHex(h.digest()), `HighwayHash-${bits} ${len}B in ${chunk}B chunks`).toBe(want);
        }
      }
    }
  });

  it("refuses a key that is not 32 bytes", () => {
    // The key is not optional and not padded: a short one is a different function, not a weaker one.
    expect(() => highwayhash(new Uint8Array(16), 64, new Uint8Array(0))).toThrow(/32-byte key/);
    expect(() => highwayhash(new Uint8Array(33), 64, new Uint8Array(0))).toThrow(/32-byte key/);
  });

  it("gives each width its own answer rather than truncating", () => {
    /**
     * The widths differ in permutation round count -- four, six and ten -- as well as in how the lanes
     * are combined, so none is a prefix of another. Worth pinning, because all three read the same
     * state and a finaliser that ignored `bits` would produce a plausible truncation.
     */
    const message = new TextEncoder().encode("HighwayHash is not truncated");
    const h64 = toHex(highwayhash(KEY, 64, message));
    const h128 = toHex(highwayhash(KEY, 128, message));
    const h256 = toHex(highwayhash(KEY, 256, message));
    expect(h128.slice(0, 16)).not.toBe(h64);
    expect(h256.slice(0, 32)).not.toBe(h128);
  });
});

describe("MetroHash", () => {
  /**
   * The author's eight published vectors. One 63-byte key, four functions, two seeds -- and 63 is
   * chosen so that a single value walks the 32-, 16-, 8-, 4-, 2- and 1-byte tail branches in turn.
   */
  const KEY = new TextEncoder().encode(
    "012345678901234567890123456789012345678901234567890123456789012",
  );

  const VECTORS: readonly [8 | 16, 1 | 2, number, string][] = [
    [8, 1, 0, "658f044f5c730e40"],
    [8, 2, 0, "073caab960623211"],
    [16, 1, 0, "ed9997ed9d0a8b0ff3f266399477788f"],
    [16, 2, 0, "7bba6fe119cf35d45507edf3505359ab"],
    [8, 1, 1, "ae49ebb0a856537b"],
    [8, 2, 1, "cf518e9cf58402c0"],
    [16, 1, 1, "dda6ba67f7de755efdf6beabeccfd1f4"],
    [16, 2, 1, "2da6af149a5cdbc12b09db0846d69ef0"],
  ];

  it("has a 63-byte test key, which is what makes eight vectors enough", () => {
    expect(KEY).toHaveLength(63);
    expect(63).toBe(32 + 16 + 8 + 4 + 2 + 1);
  });

  it("reproduces all eight published vectors", () => {
    for (const [width, variant, seed, want] of VECTORS) {
      expect(toHex(metrohash(width, variant, KEY, seed)), `metrohash${width * 8}_${variant} seed=${seed}`)
        .toBe(want);
    }
  });

  it("keeps the two variants apart at every tail length", () => {
    /**
     * Variant 1 and variant 2 differ only in four constants and a table of rotation counts, and three of
     * those rotations differ *only* in a tail branch -- the 8-byte branch rotates by 33 against 36, the
     * 2-byte by 13 against 15. So a shared table would agree with the published vectors nowhere, but a
     * table wrong in one branch would agree at most lengths. Every length from 0 to 40 is checked.
     */
    for (let len = 0; len <= 40; len++) {
      const message = KEY.subarray(0, len);
      expect(toHex(metrohash64(1, message, 0)), `len ${len}`).not.toBe(toHex(metrohash64(2, message, 0)));
      expect(toHex(metrohash128(1, message, 0)), `len ${len}`).not.toBe(
        toHex(metrohash128(2, message, 0)),
      );
    }
  });

  it("makes the seed change the answer", () => {
    // The seed is folded into the initial state, not appended, so it is not a MAC key -- but a control
    // that reached nothing would look identical here, which is the failure this catches.
    for (const variant of [1, 2] as const) {
      expect(toHex(metrohash64(variant, KEY, 0))).not.toBe(toHex(metrohash64(variant, KEY, 1)));
      expect(toHex(metrohash128(variant, KEY, 0))).not.toBe(toHex(metrohash128(variant, KEY, 1)));
    }
  });
});

describe("SpookyHash V2", () => {
  it("reproduces all 512 of the author's published Hash32 values", () => {
    expect(SPOOKY_HASH32).toHaveLength(512);
    // The reference's buffer: buf[i] = i + 128, hashed at every prefix length.
    const buf = Uint8Array.from({ length: 512 }, (_, i) => (i + 128) & 0xff);
    for (let len = 0; len < 512; len++) {
      const got = spookyhash(4, buf.subarray(0, len), 0n);
      const want = SPOOKY_HASH32[len]!;
      const wantHex = [0, 1, 2, 3].map((i) => (((want >>> (8 * i)) & 0xff).toString(16).padStart(2, "0"))).join("");
      expect(toHex(got), `SpookyHash32 at ${len} bytes`).toBe(wantHex);
    }
  });

  it("crosses the short-path boundary at 192 bytes and five block boundaries", () => {
    // Under 192 a four-word state runs; at 192 and above the twelve-word Mix does, in 96-byte blocks.
    for (const boundary of [96, 191, 192, 193, 288, 384, 480]) {
      expect(boundary).toBeLessThan(512);
    }
  });

  it("makes the narrower outputs genuine prefixes of the wider", () => {
    /**
     * Unusual here, and the reason the hash family marks this one `truncation: true`: `Hash32` is the
     * low half of `Hash64`, which is the first word of `Hash128`. Written little-endian that makes the
     * shorter outputs prefixes -- so someone truncating a Spooky128 by hand gets the right answer,
     * where doing the same to a MetroHash or CityHash does not.
     */
    const message = new TextEncoder().encode("Spooky truncates cleanly, unlike its neighbours");
    const h32 = toHex(spookyhash(4, message));
    const h64 = toHex(spookyhash(8, message));
    const h128 = toHex(spookyhash(16, message));
    expect(h64.slice(0, 8)).toBe(h32);
    expect(h128.slice(0, 16)).toBe(h64);
    // And the second word is genuinely computed rather than repeated.
    expect(h128.slice(16)).not.toBe(h64);
  });

  it("has no length field, so a trailing zero byte changes the answer", () => {
    // The remainder is stored in the last byte of the final padded block, which is what separates a
    // block-aligned message from the same message plus a zero.
    const message = Uint8Array.from({ length: 96 }, (_, i) => i);
    const padded = new Uint8Array(97);
    padded.set(message);
    expect(toHex(spookyhash(16, message))).not.toBe(toHex(spookyhash(16, padded)));
  });

  it("exposes the two 128-bit words directly", () => {
    const message = new TextEncoder().encode("two words");
    const [a, b] = spookyhash128(message, 0n, 0n);
    expect(a).not.toBe(b);
    expect(toHex(spookyhash(16, message)).slice(0, 16)).toBe(
      [...Array(8).keys()].map((i) => Number((a >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, "0")).join(""),
    );
  });
});

describe("t1ha", () => {
  /**
   * The reference's selfcheck schedule, regenerated: 81 (data, length, seed) triples. Three fixed
   * probes, then every length from 1 to 63 with a seed walking one bit left per step, then seven
   * misaligned offsets, then eight long inputs from 128 to 247 bytes.
   */
  const PATTERN = Uint8Array.from([
    0, 1, 2, 3, 4, 5, 6, 7, 0xff, 0x7f, 0x3f, 0x1f, 0xf, 8, 16, 32,
    64, 0x80, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x55, 0xaa,
    11, 17, 19, 23, 29, 37, 42, 43, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
  ]);
  const LONG = Uint8Array.from({ length: 512 }, (_, i) => i & 0xff);
  const M = (1n << 64n) - 1n;

  const schedule = (): readonly [Uint8Array, number, number, bigint][] => {
    const out: [Uint8Array, number, number, bigint][] = [];
    out.push([PATTERN, 0, 0, 0n]);
    out.push([PATTERN, 0, 0, M]);
    out.push([PATTERN, 0, 64, 0n]);
    let seed = 1n;
    for (let i = 1; i < 64; i++) {
      out.push([PATTERN, 0, i, seed]);
      seed = (seed << 1n) & M;
    }
    seed = M;
    for (let i = 1; i <= 7; i++) {
      seed = (seed << 1n) & M;
      out.push([PATTERN, i, 64 - i, seed]);
    }
    for (let i = 0; i <= 7; i++) out.push([LONG, i, 128 + i * 17, seed]);
    return out;
  };

  const SCHEDULE = schedule();

  it("has the 81-step schedule the reference values were produced under", () => {
    expect(PATTERN).toHaveLength(64);
    expect(SCHEDULE).toHaveLength(81);
    // Every length from 1 to 63 appears, which is what covers the 9/17/25/33-byte dispatch points.
    const lengths = new Set(SCHEDULE.map(([, , len]) => len));
    for (let i = 1; i < 64; i++) expect(lengths, `length ${i}`).toContain(i);
  });

  it("reproduces all 81 t1ha1 reference values", () => {
    expect(T1HA1_REFVAL).toHaveLength(81);
    for (let i = 0; i < 81; i++) {
      const [data, off, len, seed] = SCHEDULE[i]!;
      expect(t1ha1(data.subarray(off, off + len), seed), `t1ha1[${i}] len=${len}`).toBe(T1HA1_REFVAL[i]);
    }
  });

  it("reproduces all 81 t1ha2 reference values, at both widths", () => {
    for (let i = 0; i < 81; i++) {
      const [data, off, len, seed] = SCHEDULE[i]!;
      const message = data.subarray(off, off + len);
      expect(t1ha2(message, seed), `t1ha2[${i}] len=${len}`).toBe(T1HA2_REFVAL[i]);
      expect(t1ha2_128(message, seed)[0], `t1ha2-128[${i}] len=${len}`).toBe(T1HA2_128_REFVAL[i]);
    }
  });

  it("gives 0 for the empty message under a zero seed, which is what localised the mix64 bug", () => {
    /**
     * t1ha1's finaliser is `mux64(...) + mix64(a ^ b, prime_0)`, and with a = b = 0 both terms vanish
     * only if `mix64` is the xor-mul-xor. A `mux64` there gives `mux64(prime_0, prime_5)`, which is
     * nonzero -- so this single value separates the two definitions.
     */
    expect(t1ha1(new Uint8Array(0), 0n)).toBe(0n);
    expect(t1ha2(new Uint8Array(0), 0n)).toBe(0n);
  });

  it("keeps the three variants apart", () => {
    const message = new TextEncoder().encode("t1ha1 and t1ha2 are different functions");
    expect(t1ha1(message)).not.toBe(t1ha2(message));
    // The 128-bit form's low word is not the 64-bit form's answer: it skips the squash step.
    expect(t1ha2_128(message)[0]).not.toBe(t1ha2(message));
    expect(toHex(t1ha("t1ha2-128", message))).toHaveLength(32);
    expect(toHex(t1ha("t1ha1", message))).toHaveLength(16);
  });
});
