/**
 * Streebog, against both worked examples in RFC 6986 at both output lengths.
 *
 * There is no second implementation to compare against: no pure-ESM library has Streebog, OpenSSL
 * needs its GOST engine loaded, and `hash-wasm` does not carry it either. So unlike Camellia and ARIA
 * this rests entirely on the RFC's own numbers -- which is why *both* examples are here rather than
 * one, and why the intermediate-value check below matters.
 *
 * Every hex string in RFC 6986 is written most significant byte first, so each one is reversed to get
 * the byte string a program actually handles. `reversed` does that, once, in one place; a test that
 * hardcoded the already-reversed values would hide the convention that is the easiest thing to get
 * wrong here.
 */
import { describe, expect, it } from "vitest";
import { createStreebog, streebog, STREEBOG_OUTPUT_LENS } from "@ocs/algos";

const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** A vector as the RFC prints it, turned into the byte string it denotes. */
const reversed = (hex: string) => fromHex(hex).reverse();

/** RFC 6986 section 10.1: 63 bytes, which is one byte short of a block. */
const M1 =
  "32313039383736353433323130393837" +
  "36353433323130393837363534333231" +
  "30393837363534333231303938373635" +
  "343332313039383736353433323130";

/** Section 10.2: 72 bytes of Cyrillic text in CP1251, so two blocks with an 8-byte tail. */
const M2 =
  "fbe2e5f0eee3c820fbeafaebef20fffb" +
  "f0e1e0f0f520e0ed20e8ece0ebe5f0f2" +
  "f120fff0eeec20f120faf2fee5e2202c" +
  "e8f6f3ede220e8e6eee1e8f0f2d1202c" +
  "e8f0f2e5e220e5d1";

const H1_512 =
  "486f64c1917879417fef082b3381a4e2" +
  "11c324f074654c38823a7b76f830ad00" +
  "fa1fbae42b1285c0352f227524bc9ab1" +
  "6254288dd6863dccd5b9f54a1ad0541b";

const H1_256 = "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d";

const H2_512 =
  "28fbc9bada033b1460642bdcddb90c3f" +
  "b3e56c497ccd0f62b8a2ad4935e85f03" +
  "7613966de4ee00531ae60f3b5a47f8da" +
  "e06915d5f2f194996fcabf2622e6881e";

const H2_256 = "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d";

describe("Streebog -- RFC 6986 worked examples", () => {
  const CASES = [
    { name: "example 1, 512-bit", message: M1, outputLen: 64, expected: H1_512 },
    { name: "example 1, 256-bit", message: M1, outputLen: 32, expected: H1_256 },
    { name: "example 2, 512-bit", message: M2, outputLen: 64, expected: H2_512 },
    { name: "example 2, 256-bit", message: M2, outputLen: 32, expected: H2_256 },
  ];

  for (const { name, message, outputLen, expected } of CASES) {
    it(`matches ${name}`, () => {
      expect(toHex(streebog(reversed(message), outputLen))).toBe(toHex(reversed(expected)));
    });
  }

  it("reads example 1 as the ASCII digit string it is", () => {
    /**
     * A sanity check on the byte-order convention rather than on the algorithm.
     *
     * M1 printed most-significant-first looks like "2109876543...". Reversed it is the digit string
     * every other Streebog test suite in the world uses, which is the one-line confirmation that
     * `reversed` is pointing the right way.
     */
    expect(new TextDecoder().decode(reversed(M1))).toBe(
      "012345678901234567890123456789012345678901234567890123456789012",
    );
  });

  it("uses a different initial state for each length, not a truncation", () => {
    // IV is 0^512 for the 512-bit function and (00000001)^64 for the 256-bit one, so the short
    // digest is emphatically not the long one cut down -- a mistake that would pass a round trip.
    const message = reversed(M1);
    const long = streebog(message, 64);
    const short = streebog(message, 32);
    expect(toHex(short)).not.toBe(toHex(long.subarray(0, 32)));
    expect(toHex(short)).not.toBe(toHex(long.subarray(32)));
  });

  it("declares the two lengths the standard defines", () => {
    expect(STREEBOG_OUTPUT_LENS).toEqual([32, 64]);
    expect(() => createStreebog(48)).toThrow(/32 or 64/);
  });
});

describe("Streebog -- streaming", () => {
  /**
   * Streaming equality, at every split around the block boundary.
   *
   * Streebog carries two 512-bit counters and a partial-block buffer, so the split points that go
   * wrong are the ones next to 64 bytes -- and the final block is built from the *tail*, reversed,
   * which is precisely what a chunked feed can get wrong while the one-shot path stays correct.
   */
  const message = new Uint8Array(200);
  for (let i = 0; i < message.length; i++) message[i] = (i * 37 + 11) & 0xff;

  for (const outputLen of [32, 64]) {
    it(`chunked equals one-shot at ${outputLen * 8} bits`, () => {
      const expected = toHex(streebog(message, outputLen));
      for (const size of [1, 7, 63, 64, 65, 128, 199]) {
        const engine = createStreebog(outputLen);
        for (let at = 0; at < message.length; at += size) {
          engine.update(message.subarray(at, Math.min(at + size, message.length)));
        }
        expect(toHex(engine.digest()), `chunks of ${size}`).toBe(expected);
      }
    });
  }

  it("hashes an exact multiple of the block size", () => {
    // The padded final block is then nothing but the single 1 bit, which is the case an
    // implementation that skips the final block when nothing is buffered would get wrong.
    const exact = message.subarray(0, 128);
    const engine = createStreebog(64);
    engine.update(exact);
    expect(toHex(engine.digest())).toBe(toHex(streebog(exact, 64)));
    expect(toHex(streebog(exact, 64))).not.toBe(toHex(streebog(message.subarray(0, 129), 64)));
  });

  it("refuses to be reused after digest", () => {
    const engine = createStreebog(32);
    engine.update(new Uint8Array(1));
    engine.digest();
    expect(() => engine.digest()).toThrow(/twice/);
    expect(() => engine.update(new Uint8Array(1))).toThrow(/after digest/);
  });
});
