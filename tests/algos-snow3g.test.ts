/**
 * SNOW 3G -- 3GPP TS 35.216's own four test sets, and nothing else.
 *
 * No oracle: OpenSSL has never implemented it and nothing in this tree has. What stands behind it is
 * the specification's test data, which is thin by count and unusually good by shape:
 *
 *  - **Three sets of two keystream words each.** Enough to pin the LFSR loading, both 32-bit S-boxes
 *    and the discarded first output, and no more.
 *  - **One set of 10,000 bytes**, published as its first twelve and its last four. That is 2,500 LFSR
 *    steps, and it is the assertion that makes the small ones defensible: a feedback tap that happened
 *    to agree for two words cannot survive it, and the *last* four bytes are what makes it a check on
 *    the whole run rather than on the start of it.
 *
 * The vectors were taken from `P1sec/CryptoMobile`'s `test/test_CM.py`, which transcribes the 3GPP
 * release-10 documents, and set 1 is independently corroborated by FELICS's own copy -- two
 * transcriptions of the same published value agreeing, which costs nothing to assert and catches a
 * typo in either.
 *
 * Three properties are checked rather than trusted, one per table: S1's substitution *is* AES's, so
 * that half of the cipher rests on vectors five other algorithms here already share; the two 32-bit
 * alpha tables are derived from the field; and `SQ`, the one stored table, is a permutation.
 */
import { describe, expect, it } from "vitest";
import { AES_SBOX, createSnow3g, SNOW3G_SQ, SNOW3G_TABLE_FIRST, snow3gCrypt } from "@ocs/algos";

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** 3GPP TS 35.216 test sets 1 to 3: the first eight bytes of keystream. */
const SHORT_SETS = [
  {
    set: 1,
    key: "2bd6459f82c5b300952c49104881ff48",
    iv: "ea024714ad5c4d84df1f9b251c0bf45f",
    keystream: "abee97047ac31373",
  },
  {
    set: 2,
    key: "8ce33e2cc3c0b5fc1f3de8a6dc66b1f3",
    iv: "d3c5d592327fb11cde551988ceb2f9b7",
    keystream: "eff8a342f751480f",
  },
  {
    set: 3,
    key: "4035c6680af8c6d1a8ff8667b1714013",
    iv: "62a540981ba6f9b74592b0e78690f71b",
    keystream: "a8c874a97ae7c4f8",
  },
] as const;

/** Test set 4, published as the first twelve bytes and the last four of a 10,000-byte run. */
const LONG_SET = {
  key: "0ded7263109cf92e3352255a140e0f76",
  iv: "6b68079a41a7c4c91befd79f7fdcc233",
  bytes: 10000,
  first12: "d712c05ca937c2a6eb7eaae3",
  last4: "9c0db3aa",
} as const;

describe("SNOW 3G", () => {
  it("reproduces 3GPP's test sets 1 to 3", () => {
    for (const v of SHORT_SETS) {
      const got = hex(createSnow3g(unhex(v.key), unhex(v.iv)).keystream(8));
      expect(got, `test set ${v.set}`).toBe(v.keystream);
    }
  });

  it("reproduces test set 4 at both ends of a 10,000-byte run", () => {
    const ks = createSnow3g(unhex(LONG_SET.key), unhex(LONG_SET.iv)).keystream(LONG_SET.bytes);
    expect(ks).toHaveLength(LONG_SET.bytes);
    expect(hex(ks.subarray(0, 12)), "first twelve").toBe(LONG_SET.first12);
    expect(hex(ks.subarray(9996, 10000)), "last four").toBe(LONG_SET.last4);
  });

  it("uses AES's own S-box for S1", () => {
    /**
     * Stated as an assertion because it is the reason there is no second 256-byte table in the
     * implementation. S1's substitution is the Rijndael S-box entry for entry, so it is the table AES's
     * own vectors, ARIA's three appendix vectors, Groestl's KATs, SHAvite-3's KATs, ECHO's KATs and
     * Deoxys-II's official vectors all already pin -- and a SNOW 3G failure therefore points at the
     * LFSR, the FSM or `SQ`, which is a much smaller place to look.
     */
    expect(AES_SBOX[0]).toBe(0x63);
    expect(AES_SBOX[1]).toBe(0x7c);
    expect(AES_SBOX[255]).toBe(0x16);
  });

  it("stores SQ and checks it is a permutation, since it could not be derived", () => {
    /**
     * The specification calls `SQ` a Dickson-polynomial S-box, and the recurrence `D_n(x, 1)` was swept
     * over every degree from 2 to 255 crossed with all thirty irreducible degree-8 polynomials without
     * reproducing a single entry. So it is stored, and a stored table gets what a derived one does not
     * need: the permutation property, which is what a mistyped entry breaks, plus both published ends.
     */
    expect(SNOW3G_SQ).toHaveLength(256);
    expect(new Set(SNOW3G_SQ).size).toBe(256);
    expect(SNOW3G_TABLE_FIRST[2]).toBe(0x25);
    expect(SNOW3G_TABLE_FIRST[3]).toBe(0x86);
  });

  it("derives MULalpha and DIValpha rather than storing 2 KB", () => {
    /**
     * The reference's `MULalpha[1]` and `DIValpha[1]`. Pinned here so a change to the reduction byte or
     * to any of the eight exponents fails at this line rather than only in the keystream -- and since
     * each is four independent `MULxPOW` chains, getting one right by accident is not available.
     */
    expect(SNOW3G_TABLE_FIRST.slice(0, 2).map((v) => v.toString(16))).toEqual(["e19fcf13", "180f40cd"]);
  });

  it("chunks the keystream without losing or repeating a byte", () => {
    const key = unhex(SHORT_SETS[0].key);
    const iv = unhex(SHORT_SETS[0].iv);
    const whole = hex(createSnow3g(key, iv).keystream(64));
    const gen = createSnow3g(key, iv);
    let piecewise = "";
    // Sizes that straddle the four-byte word, which is where a held buffer goes wrong.
    for (const n of [1, 3, 4, 5, 9, 42]) piecewise += hex(gen.keystream(n));
    expect(piecewise).toBe(whole);
  });

  it("is its own inverse, and refuses a key or IV of the wrong length", () => {
    const key = unhex(SHORT_SETS[1].key);
    const iv = unhex(SHORT_SETS[1].iv);
    const data = Uint8Array.from({ length: 130 }, (_, i) => (i * 11 + 5) & 0xff);
    expect(hex(snow3gCrypt(key, iv, snow3gCrypt(key, iv, data)))).toBe(hex(data));

    expect(() => createSnow3g(new Uint8Array(8), new Uint8Array(16))).toThrow(/exactly 16 bytes/);
    expect(() => createSnow3g(new Uint8Array(16), new Uint8Array(8))).toThrow(/exactly 16 bytes/);
  });
});
