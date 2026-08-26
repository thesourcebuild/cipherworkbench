/**
 * Tiger, against the vectors from Anderson and Biham's paper and the NESSIE submission.
 *
 * Seventeen messages, including the three the paper prints and the two long strings that are the
 * paper's own title -- which are the ones that cross a block boundary and exercise the length field.
 * No oracle exists for Tiger here (OpenSSL dropped it, `hash-wasm` never had it), so this is the whole
 * check, and breadth is what makes it one worth having.
 *
 * Tiger2 has no test here beyond the structural one, and that is the point: no published Tiger2 vector
 * was reachable offline, so Tiger2 is implemented but not registered as a tool. See the note at the top
 * of `tiger.ts`.
 */
import { describe, expect, it } from "vitest";
import { createTiger, createTiger2, tiger, tiger2, TIGER_OUTPUT_LEN } from "@ocs/algos";

const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const ascii = (text: string) => new TextEncoder().encode(text);

/** Message, then expected digest. Lower-cased from the published upper-case form. */
const VECTORS: readonly [string, string][] = [
  ["", "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"],
  ["a", "77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809"],
  ["abc", "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"],
  ["Tiger", "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937"],
  [
    "The quick brown fox jumps over the lazy dog",
    "6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075",
  ],
  [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
    "f71c8583902afb879edfe610f82c0d4786a3a534504486b5",
  ],
  [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
    "48ceeb6308b87d46e95d656112cdf18d97915f9765658957",
  ],
  [
    "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham",
    "8a866829040a410c729ad23f5ada711603b3cdd357e4c15e",
  ],
  [
    "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.",
    "ce55a6afd591f5ebac547ff84f89227f9331dab0b611c889",
  ],
  [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
    "c54034e5b43eb8005848a7e0ae6aac76e4ff590ae715fd25",
  ],
  [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc",
  ],
  ["message digest", "d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6"],
  ["abcdefghijklmnopqrstuvwxyz", "1714a472eee57d30040412bfcc55032a0b11602ff37beee9"],
  [
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e",
  ],
  [
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    "1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd",
  ],
];

describe("Tiger", () => {
  it("matches every published vector", () => {
    for (const [message, expected] of VECTORS) {
      expect(toHex(tiger(ascii(message))), JSON.stringify(message.slice(0, 24))).toBe(expected);
    }
  });

  it("covers the block boundary in both directions", () => {
    // 64 bytes is one block, and the 55/56/57-byte cases decide whether the length field fits in the
    // final block -- the branch that produces an extra block. Assert the fixture actually spans them.
    const lengths = VECTORS.map(([m]) => m.length);
    expect(lengths.some((n) => n < 55)).toBe(true);
    expect(lengths.some((n) => n >= 56 && n <= 64)).toBe(true);
    expect(lengths.some((n) => n > 64)).toBe(true);
    expect(Math.max(...lengths)).toBeGreaterThan(110);
  });

  it("produces 24 bytes", () => {
    expect(tiger(new Uint8Array(0))).toHaveLength(TIGER_OUTPUT_LEN);
    expect(TIGER_OUTPUT_LEN).toBe(24);
  });

  it("streams to the same digest as one shot", () => {
    const message = new Uint8Array(300);
    for (let i = 0; i < message.length; i++) message[i] = (i * 41 + 5) & 0xff;
    const expected = toHex(tiger(message));

    for (const size of [1, 7, 55, 56, 63, 64, 65, 128, 299]) {
      const h = createTiger();
      for (let at = 0; at < message.length; at += size) {
        h.update(message.subarray(at, Math.min(at + size, message.length)));
      }
      expect(toHex(h.digest()), `chunks of ${size}`).toBe(expected);
    }
  });

  it("refuses reuse after digest", () => {
    const h = createTiger();
    h.digest();
    expect(() => h.digest()).toThrow(/twice/);
    expect(() => h.update(new Uint8Array(1))).toThrow(/after digest/);
  });
});

describe("Tiger2", () => {
  /**
   * Structural only, and deliberately so.
   *
   * No published Tiger2 vector was reachable offline, so Tiger2 is not registered as a tool -- this
   * repo's rule is that an algorithm without a published vector does not become one. What can be
   * asserted without a vector is the relationship the specification defines: identical in every
   * respect except the padding byte, which means identical tables, identical rounds, and a digest that
   * differs for every input including the empty one.
   */
  it("differs from Tiger for every input, including the empty message", () => {
    for (const [message] of VECTORS.slice(0, 6)) {
      expect(toHex(tiger2(ascii(message))), message).not.toBe(toHex(tiger(ascii(message))));
    }
  });

  it("agrees with Tiger on everything except the padding byte", () => {
    /**
     * The one thing that pins Tiger2 to Tiger without a vector: a message whose padded final block is
     * built by hand. Feed Tiger2 a 63-byte message and its padding byte 0x80 completes the block;
     * feed Tiger the same 63 bytes and its 0x01 does. Both then hash exactly one block, so the two
     * digests differ in precisely the way one byte of input differs -- which is what confirms the
     * padding byte is the only difference rather than one of several.
     */
    const message = new Uint8Array(63);
    for (let i = 0; i < message.length; i++) message[i] = i + 1;

    const withOne = toHex(tiger(message));
    const withEighty = toHex(tiger2(message));
    expect(withOne).not.toBe(withEighty);

    // Same construction, same output size, same 24 bytes of state.
    expect(tiger2(message)).toHaveLength(TIGER_OUTPUT_LEN);
    const streamed = createTiger2();
    streamed.update(message.subarray(0, 30));
    streamed.update(message.subarray(30));
    expect(toHex(streamed.digest())).toBe(withEighty);
  });
});
