/**
 * SOSEMANUK -- eSTREAM's fourth software-profile winner, and the last of the four this repo lacked.
 *
 * No oracle, and only two published vectors reachable: Crypto++'s `TestVectors/sosemanuk.txt`, which
 * carries one from the designers' reference implementation and one from eSTREAM's own submission
 * files. That is thin by count and unusually strong by coverage, which is the reason it is enough:
 *
 *  - The first uses a **5-byte key**, so it exercises Serpent's padding bit -- the `1` written
 *    immediately after a short key, which is what makes a 40-bit key different from the same bytes
 *    zero-extended. And it publishes 160 bytes, which is ten full four-step groups.
 *  - The second uses a **256-bit key** and folds **131,072 bytes** into a 64-byte XOR digest, driving
 *    the LFSR through 32,768 steps. A fault that only shows once the ten-stage register has cycled
 *    thousands of times has nowhere to hide in that.
 *
 * Between them both ends of the key range are covered and the long run is covered. What is *not*
 * covered is a 24-byte key, which nothing publishes -- so it is offered on the specification's word,
 * and this comment is where that is recorded rather than left implied.
 *
 * Two properties are asserted rather than transcribed, because both are what the implementation rests
 * on: the 512 words of multiplication table are derived from the field polynomial and four exponents,
 * and the whole thing reuses Serpent's own S-boxes -- already pinned by Bouncy Castle's Serpent
 * vectors, so a failure here points at SOSEMANUK rather than at a table.
 */
import { describe, expect, it } from "vitest";
import { createSerpent, createSosemanuk, SOSEMANUK_TABLE_FIRST, sosemanukCrypt } from "@ocs/algos";

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.replace(/\s/g, "").match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** Crypto++ `TestVectors/sosemanuk.txt`, "Sosemanuk reference implementation". */
const REFERENCE = {
  key: "a7c083feb7",
  iv: "00112233445566778899aabbccddeeff",
  keystream:
    "fe81d2162c9a100d04895c454a77515bbe6a431a935cb90e2221ebb7ef502328" +
    "943539492eff6310c871054c2889cc728f82e86b1afff4334b6127a13a155c75" +
    "151630bd482eb673ff5db477fa6c53ebe1a4ec38c23c5400c315455d93a2aced" +
    "9598604727fa340d5f2a8bd757b77833f74bd2bc049313c80616b4a06268ae35" +
    "0db92eec4fa56c171374a67a80c006d0ead048ce7b640f17d3d5a62d1f251c21",
} as const;

/** The same file, quoting eSTREAM's submission: set 6, vector #3. */
const LONG_RUN = {
  key: "0f62b5085bae0154a7fa4da0f34699ec3f92e5388bde3184d72a7dd02376c91c",
  iv: "288ff65dc42b92f960c72e95fc63ca31",
  bytes: 131072,
  xorDigest:
    "cc09fb7405dd54bbf09407b1d2033fbbac53f388dd387a46f2b8fcff692a7838" +
    "353523a621a55d08da0ca5348ae96d8b0d6a028f309982ef6628054d01b9a368",
} as const;

describe("SOSEMANUK", () => {
  it("reproduces the reference implementation's 160-byte keystream under a 5-byte key", () => {
    const gen = createSosemanuk(unhex(REFERENCE.key), unhex(REFERENCE.iv));
    expect(hex(gen.keystream(160))).toBe(REFERENCE.keystream);
  });

  it("reproduces eSTREAM's XOR digest over 131,072 bytes", () => {
    /**
     * 32,768 LFSR steps. This is the assertion that makes the fixture's size defensible: it walks the
     * ten-stage register round more than three thousand times, so a feedback tap that happened to
     * agree for the first group could not survive it.
     */
    const ks = createSosemanuk(unhex(LONG_RUN.key), unhex(LONG_RUN.iv)).keystream(LONG_RUN.bytes);
    const digest = new Uint8Array(64);
    for (let i = 0; i < LONG_RUN.bytes; i++) digest[i % 64] = digest[i % 64]! ^ ks[i]!;
    expect(hex(digest)).toBe(LONG_RUN.xorDigest);
  });

  it("derives its two multiplication tables rather than storing 512 words", () => {
    /**
     * The reference's `s_sosemanukMulTables[1]` and `[257]`. Pinned so a change to the field
     * polynomial or to any of the four exponents fails here rather than only in the vectors -- and
     * these two entries are `beta^23 beta^245 beta^48 beta^239` and its counterpart divided through
     * by the constant coefficient, so getting either right by accident is not available.
     */
    expect(SOSEMANUK_TABLE_FIRST.map((v) => v.toString(16))).toEqual(["e19fcf13", "180f40cd"]);
  });

  it("chunks the keystream without losing or repeating a byte", () => {
    const key = unhex(REFERENCE.key);
    const iv = unhex(REFERENCE.iv);
    const whole = hex(createSosemanuk(key, iv).keystream(100));
    const gen = createSosemanuk(key, iv);
    let piecewise = "";
    // Sizes that straddle the sixteen-byte group, since that is where a held buffer goes wrong.
    for (const n of [1, 15, 16, 17, 33, 18]) piecewise += hex(gen.keystream(n));
    expect(piecewise).toBe(whole);
  });

  it("is its own inverse", () => {
    const key = unhex(REFERENCE.key);
    const iv = unhex(REFERENCE.iv);
    const data = Uint8Array.from({ length: 200 }, (_, i) => (i * 7 + 3) & 0xff);
    expect(hex(sosemanukCrypt(key, iv, sosemanukCrypt(key, iv, data)))).toBe(hex(data));
  });

  it("distinguishes a short key from the same bytes zero-extended", () => {
    /**
     * Serpent's padding bit, reached through SOSEMANUK. The reference vector's key is five bytes, so
     * this is the property that vector depends on -- and it is the one thing a zero-padding
     * implementation would get wrong while still passing a round trip.
     */
    const iv = unhex(REFERENCE.iv);
    const short = createSosemanuk(unhex("a7c083feb7"), iv).keystream(16);
    const padded = createSosemanuk(unhex("a7c083feb700000000000000000000000000000000000000"), iv).keystream(
      16,
    );
    expect(hex(short)).not.toBe(hex(padded));
  });

  it("still leaves Serpent itself alone", () => {
    /**
     * `serpentSubkeys` grew a round-count parameter and the S-box table became exported so this
     * cipher could reuse them. Bouncy Castle's 128-bit-key vector, re-asserted here, is what says the
     * refactor did not disturb the cipher those tables were verified through.
     */
    const cipher = createSerpent(unhex("d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9"));
    const out = new Uint8Array(16);
    cipher.encryptBlock(unhex("d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9"), out);
    expect(hex(out)).toBe("20ea07f19c8e93fda30f6b822ad5d486");
  });

  it("refuses a key or IV of the wrong length", () => {
    expect(() => createSosemanuk(new Uint8Array(33), new Uint8Array(16))).toThrow(/1 to 32 bytes/);
    expect(() => createSosemanuk(new Uint8Array(16), new Uint8Array(12))).toThrow(/exactly 16/);
  });
});
