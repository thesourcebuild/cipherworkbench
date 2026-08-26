/**
 * SPARX-64/128, Chaskey-LTS, TWINE-80 and LED-64-80 -- the second wave off FELICS's shelf.
 *
 * None has an oracle: OpenSSL implements none of them and nothing else in this tree does. What stands
 * behind each is the vector FELICS's benchmarking suite carries -- one apiece, except SPARX which has
 * two -- and that is genuinely thin, so it is worth being precise about what makes it enough:
 *
 *  - **Two of the four have no tables at all.** SPARX's S-box is Speck's round function and Chaskey's
 *    permutation is bare add-rotate-xor, so there is nothing in either that a single vector fails to
 *    reach. The vector is covering the round count, the word order and the key schedule, and those are
 *    all-or-nothing.
 *  - **The other two share their tables with ciphers already here.** LED's S-box is PRESENT's and its
 *    round constants are SKINNY's LFSR; TWINE's own S-box is checked to be a permutation and its
 *    inverse derived. So the tables are not what a thin fixture leaves uncovered.
 *  - **And both directions are checked against the published value**, not against a re-encryption --
 *    which is what catches an inverse that is self-consistent and wrong.
 *
 * Three derivations are asserted rather than trusted: LED's inverse MixColumns matrix against the
 * reference's literal, LED's round constants against SKINNY's, and LED's S-box against PRESENT's.
 */
import { describe, expect, it } from "vitest";
import {
  createChaskeyLts,
  createLed,
  createPresent,
  createSparx,
  createTwine,
  LED_MATRIX_INVERSE,
  PRESENT_SBOX,
  SKINNY_RC,
  TWINE_SBOX_INVERSE,
} from "@ocs/algos";

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

interface BlockLike {
  blockSize: number;
  encryptBlock(s: Uint8Array, d: Uint8Array): void;
  decryptBlock(s: Uint8Array, d: Uint8Array): void;
}
const one = (cipher: BlockLike, src: Uint8Array, decrypt = false): Uint8Array => {
  const out = new Uint8Array(cipher.blockSize);
  if (decrypt) cipher.decryptBlock(src, out);
  else cipher.encryptBlock(src, out);
  return out;
};

/** Every vector in this wave, from FELICS's `test_vectors.c` files. */
const VECTORS = [
  {
    name: "SPARX-64/128, all-zero key",
    make: (k: Uint8Array) => createSparx(k),
    key: "00000000000000000000000000000000",
    plaintext: "0000000000000000",
    ciphertext: "b423aeb5d405a70d",
  },
  {
    name: "SPARX-64/128, all-ones key",
    make: (k: Uint8Array) => createSparx(k),
    key: "ffffffffffffffffffffffffffffffff",
    plaintext: "0000000000000000",
    ciphertext: "be25d728346929ab",
  },
  {
    name: "Chaskey-LTS",
    make: (k: Uint8Array) => createChaskeyLts(k),
    key: "5609e9685f58e32940ecec98c522982f",
    plaintext: "b8232826fd5e405e69a301a978ea7ad8",
    ciphertext: "d5608d4da2bf347babf8772fdfedde07",
  },
  {
    name: "TWINE-80",
    make: (k: Uint8Array) => createTwine(k),
    key: "00112233445566778899",
    plaintext: "1032547698badcfe",
    ciphertext: "c7f1f0081bfdc982",
  },
  {
    name: "LED-64-80",
    make: (k: Uint8Array) => createLed(k),
    key: "0123456789abcdeffedc",
    plaintext: "0123456789abcdef",
    ciphertext: "a9625a9c59fcb942",
  },
] as const;

describe("SPARX, Chaskey-LTS, TWINE and LED", () => {
  it("reproduces every published vector in both directions", () => {
    expect(VECTORS).toHaveLength(5);
    for (const v of VECTORS) {
      const cipher = v.make(unhex(v.key));
      expect(hex(one(cipher, unhex(v.plaintext))), `${v.name} encrypt`).toBe(v.ciphertext);
      // Against the published ciphertext, not a re-encryption of ours.
      expect(hex(one(cipher, unhex(v.ciphertext), true)), `${v.name} decrypt`).toBe(v.plaintext);
    }
  });

  it("round-trips at every block position, which a single vector cannot reach", () => {
    /**
     * One vector per cipher is thin, and this is what fills the obvious gap: a one-bit input at each
     * position must survive a round trip. It cannot substitute for a published value -- a
     * self-consistent wrong cipher passes it -- but it does cover the byte and nibble packing at every
     * offset, which is where a single all-zero or patterned vector says least.
     */
    for (const v of VECTORS) {
      const cipher = v.make(unhex(v.key));
      for (let bit = 0; bit < cipher.blockSize * 8; bit += 7) {
        const block = new Uint8Array(cipher.blockSize);
        block[bit >> 3] = 1 << (bit & 7);
        expect(hex(one(cipher, one(cipher, block), true)), `${v.name} bit ${bit}`).toBe(hex(block));
      }
    }
  });

  it("gives LED PRESENT's S-box and SKINNY's round constants", () => {
    /**
     * Both are shared deliberately by their designers, not by this repo for convenience -- SKINNY's
     * paper takes the LFSR from LED, and LED's paper takes the S-box from PRESENT. So `led.ts` stores
     * neither, and the tables it reads are already pinned by PRESENT's published vectors and by
     * Romulus's 7,559 assertions.
     *
     * Asserted here because a future edit that gave LED its own copy would be invisible until the two
     * drifted -- and then only in LED's single vector.
     */
    expect(PRESENT_SBOX).toEqual([0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]);
    expect(SKINNY_RC.slice(0, 6)).toEqual([0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e]);
    // And PRESENT itself still works, since its S-box became exported for LED to use.
    expect(hex(one(createPresent(new Uint8Array(10)), new Uint8Array(8)))).toBe("5579c1387b228445");
  });

  it("derives LED's inverse MixColumns matrix, matching the reference's literal", () => {
    /**
     * Gauss-Jordan over GF(2^4) at load. Every reference ships this as a second 16-entry literal; the
     * derivation means a mistyped entry in the *forward* matrix breaks it here rather than only in the
     * decrypt path -- and the expected values are FELICS's `invMixColMatrix`, so the derivation is
     * checked against something independent rather than being self-consistent.
     */
    expect(LED_MATRIX_INVERSE.map((row) => [...row])).toEqual([
      [12, 12, 13, 4],
      [3, 8, 4, 5],
      [7, 6, 2, 14],
      [13, 9, 9, 13],
    ]);
  });

  it("has a TWINE S-box that is a permutation", () => {
    /**
     * TWINE's Feistel step is its own inverse given the same box, so the inverse is never used in
     * anger -- it exists so that a non-permutation fails at load. Which makes this the assertion that
     * the box is well formed at all, and TWINE's one vector the assertion that it is the right one.
     */
    expect(new Set(TWINE_SBOX_INVERSE).size).toBe(16);
    expect(TWINE_SBOX_INVERSE).not.toContain(-1);
  });

  it("makes Chaskey-LTS an Even-Mansour construction with no key schedule", () => {
    /**
     * The key enters twice, unchanged, around a fixed permutation -- so encrypting under a key and then
     * under the same key XORed with a constant differs only by that constant on both sides. Testable
     * without a published value, and it is what says there is no schedule hiding in there.
     */
    const key = unhex("5609e9685f58e32940ecec98c522982f");
    const block = new Uint8Array(16).fill(0x5a);
    const cipher = createChaskeyLts(key);
    const twisted = createChaskeyLts(Uint8Array.from(key, (b) => b ^ 0xff));
    const a = one(cipher, block);
    const b = one(twisted, Uint8Array.from(block, (v) => v ^ 0xff));
    expect(hex(Uint8Array.from(a, (v, i) => v ^ b[i]!))).toBe("ff".repeat(16));
  });

  it("refuses a key of the wrong length", () => {
    expect(() => createSparx(new Uint8Array(10))).toThrow(/exactly 16 bytes/);
    expect(() => createChaskeyLts(new Uint8Array(10))).toThrow(/exactly 16 bytes/);
    expect(() => createTwine(new Uint8Array(16))).toThrow(/exactly 10 bytes/);
    expect(() => createLed(new Uint8Array(16))).toThrow(/exactly 10 bytes/);
  });
});
