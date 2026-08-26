import { describe, expect, it } from "vitest";
import {
  adler32,
  CHECK_INPUT,
  createAdler32,
  createBcc,
  createFletcher16,
  createFletcher32,
  createLrc,
  createOnesComplementSum,
  createSumCheck,
  createTwosComplementChecksum,
  createXorChecksum,
  type ChecksumEngine,
} from "@ocs/algos";

const ascii = (text: string) => new TextEncoder().encode(text);
const bytes = (...values: number[]) => new Uint8Array(values);

function pseudoRandom(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed >>> 0;
  for (let i = 0; i < length; i++) {
    // xorshift32
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[i] = state & 0xff;
  }
  return out;
}

function oneShot(engine: ChecksumEngine, input: Uint8Array): number {
  engine.update(input);
  return engine.digest();
}

/**
 * The vectors that pin the conventions down.
 *
 * Every algorithm here is three lines long, so a test suite that only checked the arithmetic would
 * be checking nothing. What is actually at risk in this family is the *convention*: whether the
 * words are big- or little-endian, whether the sum is complemented, whether the modulus is 255 or
 * 256, and whether a trailing odd byte is padded. Each entry below is a published number that
 * distinguishes one choice from another.
 */
describe("published vectors", () => {
  it("RFC 1071 section 3 — the one's complement sum of its worked example", () => {
    // The RFC prints the octets and the sum together, which makes this the one vector that pins
    // down the end-around carry: without folding the carry back in, this comes out 0xDDF0.
    const input = bytes(0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7);
    expect(oneShot(createOnesComplementSum(false), input).toString(16)).toBe("ddf2");
    // And the value a header would carry is its complement.
    expect(oneShot(createOnesComplementSum(true), input).toString(16)).toBe("220d");
  });

  it("Fletcher-16 — the published values for three ASCII inputs", () => {
    // Two 8-bit sums modulo 255. Using 256 as the modulus, which some implementations do because
    // it is faster, breaks all three of these.
    expect(oneShot(createFletcher16(), ascii("abcde")).toString(16)).toBe("c8f0");
    expect(oneShot(createFletcher16(), ascii("abcdef")).toString(16)).toBe("2057");
    expect(oneShot(createFletcher16(), ascii("abcdefgh")).toString(16)).toBe("627");
  });

  it("Fletcher-32 — the published values, which are little-endian", () => {
    // These are the vectors that decided the default. Big-endian words give 0x50562A2D for
    // "abcdef" — the same four bytes in a different order, and a plausible-looking wrong answer.
    // "abcde" is five bytes, so it also pins down the zero-padding of the trailing word.
    expect(oneShot(createFletcher32(), ascii("abcde")).toString(16)).toBe("f04fc729");
    expect(oneShot(createFletcher32(), ascii("abcdef")).toString(16)).toBe("56502d2a");
    expect(oneShot(createFletcher32(), ascii("abcdefgh")).toString(16)).toBe("ebe19591");
  });

  it("Fletcher-32 big-endian is the byte-swapped little-endian value", () => {
    // Not a published vector but the relationship that explains why the wrong default looks
    // convincing: each 16-bit half swaps, so nothing about the output shape gives it away.
    expect(oneShot(createFletcher32(true), ascii("abcdef")).toString(16)).toBe("50562a2d");
  });

  it("Adler-32 matches RFC 1950's definition on known inputs", () => {
    // adler32("") is the initial state: a=1, b=0.
    expect(adler32(new Uint8Array(0))).toBe(1);
    // "Wikipedia" is the canonical worked example in every description of it.
    expect(adler32(ascii("Wikipedia")).toString(16)).toBe("11e60398");
    expect(adler32(ascii("a")).toString(16)).toBe("620062");
    expect(adler32(ascii("abc")).toString(16)).toBe("24d0127");
  });

  it("Modbus ASCII LRC — the sum of the frame plus its LRC is zero", () => {
    // The property the protocol actually relies on, checked on the read-holding-registers frame
    // from the Modbus application protocol specification: address 0x11, function 0x03, starting
    // register 0x006B, quantity 0x0003. The LRC covers the decoded bytes, not their ASCII hex.
    const frame = bytes(0x11, 0x03, 0x00, 0x6b, 0x00, 0x03);
    const lrc = oneShot(createLrc(), frame);
    expect(lrc).toBe(0x7e);
    const sum = [...frame, lrc].reduce((a, b) => a + b, 0);
    expect(sum & 0xff).toBe(0);
  });

  it("NMEA 0183 — the XOR of a sentence body is its published checksum", () => {
    // Everything between the '$' and the '*', which is what the two hex digits after the
    // asterisk cover.
    const body = "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,";
    expect(oneShot(createXorChecksum(), ascii(body)).toString(16)).toBe("47");
  });
});

describe("the conventions each option selects", () => {
  it("a byte sum and a word sum are different values", () => {
    const input = bytes(0x01, 0x02);
    expect(oneShot(createSumCheck(16, 8), input)).toBe(3);
    expect(oneShot(createSumCheck(16, 16, true), input)).toBe(0x0102);
    expect(oneShot(createSumCheck(16, 16, false), input)).toBe(0x0201);
  });

  it("truncation is independent of grouping", () => {
    // Summing 16-bit words and reporting one byte is a real configuration, so the width and the
    // word size have to be separate settings rather than one "size".
    const input = bytes(0x01, 0x02, 0x03, 0x04);
    expect(oneShot(createSumCheck(8, 16, true), input)).toBe((0x0102 + 0x0304) & 0xff);
  });

  it("a trailing partial word is zero-padded", () => {
    const odd = bytes(0xaa, 0xbb, 0xcc);
    const padded = bytes(0xaa, 0xbb, 0xcc, 0x00);
    for (const wordSize of [16, 32] as const) {
      expect(oneShot(createSumCheck(32, wordSize, true), odd), `word size ${wordSize}`).toBe(
        oneShot(createSumCheck(32, wordSize, true), padded),
      );
    }
  });

  it("the two's complement of the sum brings the total to zero", () => {
    for (const width of [8, 16, 32] as const) {
      const input = pseudoRandom(37, width);
      const sum = oneShot(createSumCheck(width, 8), input);
      const negated = oneShot(createTwosComplementChecksum(width, 8), input);
      const total = width === 32 ? (sum + negated) >>> 0 : (sum + negated) & ((1 << width) - 1);
      expect(total, `width ${width}`).toBe(0);
    }
  });

  it("LRC is the eight-bit two's complement checksum, and BCC in XOR mode is the XOR", () => {
    // Asserted rather than left implicit, because these are listed as separate tools and the claim
    // that they coincide is one the UI makes to the user.
    const input = pseudoRandom(129, 3);
    expect(oneShot(createLrc(), input)).toBe(
      oneShot(createTwosComplementChecksum(8, 8), input),
    );
    expect(oneShot(createBcc("xor"), input)).toBe(oneShot(createXorChecksum(), input));
    expect(oneShot(createBcc("sum"), input)).toBe(oneShot(createSumCheck(8, 8), input));
  });

  it("the sums are blind to reordering and Fletcher is not", () => {
    // The one property worth asserting about strength, because it is what the S002 diagnostic
    // tells the user and it should not be able to become false quietly.
    const forward = pseudoRandom(64, 11);
    const swapped = new Uint8Array(forward);
    [swapped[0], swapped[63]] = [swapped[63]!, swapped[0]!];
    expect(oneShot(createSumCheck(16, 8), swapped)).toBe(
      oneShot(createSumCheck(16, 8), forward),
    );
    expect(oneShot(createXorChecksum(), swapped)).toBe(oneShot(createXorChecksum(), forward));
    expect(oneShot(createFletcher16(), swapped)).not.toBe(oneShot(createFletcher16(), forward));
    expect(oneShot(createFletcher32(), swapped)).not.toBe(oneShot(createFletcher32(), forward));
    expect(adler32(swapped)).not.toBe(adler32(forward));
  });
});

describe("streaming", () => {
  const ENGINES: readonly { label: string; create: () => ChecksumEngine }[] = [
    { label: "sum 8/8", create: () => createSumCheck(8, 8) },
    { label: "sum 32/16 be", create: () => createSumCheck(32, 16, true) },
    { label: "sum 32/32 le", create: () => createSumCheck(32, 32, false) },
    { label: "twos 16/16 be", create: () => createTwosComplementChecksum(16, 16, true) },
    { label: "ones complement", create: () => createOnesComplementSum() },
    { label: "xor", create: () => createXorChecksum() },
    { label: "lrc", create: () => createLrc() },
    { label: "bcc sum", create: () => createBcc("sum") },
    { label: "fletcher16", create: () => createFletcher16() },
    { label: "fletcher32", create: () => createFletcher32() },
    { label: "adler32", create: () => createAdler32() },
  ];

  for (const { label, create } of ENGINES) {
    it(`${label} streams identically to a single update`, () => {
      // 4001 bytes: a prime length, so every chunk size below straddles at least one word
      // boundary — which is the only thing in these engines that has state to get wrong.
      const input = pseudoRandom(4001, 19);
      const expected = oneShot(create(), input);

      for (const chunkSize of [1, 2, 3, 5, 7, 64, 4000, 4001]) {
        const engine = create();
        for (let offset = 0; offset < input.length; offset += chunkSize) {
          engine.update(input.subarray(offset, offset + chunkSize));
        }
        expect(engine.digest(), `${label} at chunk size ${chunkSize}`).toBe(expected);
      }
    });
  }

  it("digest is idempotent, so the padding word is only added once", () => {
    // `digestBytes` and `digest` both flush the word accumulator. The compute path calls both,
    // so a flush that appended a second zero-padded word would corrupt every odd-length input.
    const engine = createSumCheck(32, 16, true);
    engine.update(bytes(0x01, 0x02, 0x03));
    const first = engine.digest();
    expect(engine.digest()).toBe(first);
    expect(engine.digestBytes()).toEqual(engine.digestBytes());
    expect(first).toBe(0x0102 + 0x0300);
  });

  it("Adler-32 does not overflow past the NMAX reduction window", () => {
    // All-0xff maximises both running sums, which is what would break a naive implementation
    // that reduced too late.
    const worst = new Uint8Array(100_000).fill(0xff);
    const value = adler32(worst);
    expect(value).toBeGreaterThan(0);
    expect(value).toBeLessThanOrEqual(0xffffffff);
    // b is the high half and must stay under the modulus.
    expect(value >>> 16).toBeLessThan(65521);
    expect(value & 0xffff).toBeLessThan(65521);
  });

  it("Adler-32 streams identically across the NMAX boundary", () => {
    const input = pseudoRandom(20_000, 7);
    const expected = adler32(input);
    for (const chunkSize of [1, 13, 5551, 5552, 5553, 19_999]) {
      const engine = createAdler32();
      for (let offset = 0; offset < input.length; offset += chunkSize) {
        engine.update(input.subarray(offset, offset + chunkSize));
      }
      expect(engine.digest(), `chunk size ${chunkSize}`).toBe(expected);
    }
  });
});

describe("output bytes", () => {
  it("are big-endian and as wide as the configured width", () => {
    const engine = createSumCheck(32, 8);
    engine.update(bytes(0xff, 0xff));
    expect(Array.from(engine.digestBytes())).toEqual([0x00, 0x00, 0x01, 0xfe]);
  });

  it("Adler-32 emits four big-endian bytes", () => {
    const engine = createAdler32();
    engine.update(ascii("abc"));
    expect(Array.from(engine.digestBytes())).toEqual([0x02, 0x4d, 0x01, 0x27]);
  });

  it("the check input agrees with what the tool catalogue publishes", () => {
    // The other half of this is in `checksum-tool.test.ts`, which asserts the same numbers
    // through the tool layer. Here they are pinned to the algorithms directly, so a wrong
    // default in the family cannot make both halves agree on a wrong value.
    expect(oneShot(createSumCheck(8, 8), CHECK_INPUT)).toBe(0xdd);
    expect(oneShot(createOnesComplementSum(true), CHECK_INPUT)).toBe(0xf62a);
    expect(oneShot(createTwosComplementChecksum(8, 8), CHECK_INPUT)).toBe(0x23);
    expect(oneShot(createXorChecksum(), CHECK_INPUT)).toBe(0x31);
    expect(oneShot(createFletcher16(), CHECK_INPUT)).toBe(0x1ede);
    expect(oneShot(createFletcher32(), CHECK_INPUT)).toBe(0xdf09d509);
    expect(adler32(CHECK_INPUT)).toBe(0x091e01de);
  });
});
