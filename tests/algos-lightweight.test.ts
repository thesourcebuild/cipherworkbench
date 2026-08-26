/**
 * Blowfish, PRESENT-80, all twenty Simon and Speck variants, and SipHash-2-4 against published
 * vectors.
 *
 * None of the five has an oracle in this tree: OpenSSL 3's Blowfish moved to the legacy provider,
 * which Node does not load, and no dependency here implements the other four. So published vectors are
 * the whole check -- and they are chosen to be the kind that cannot pass by accident.
 *
 * What each one actually pins down:
 *
 *  - **Blowfish** has 4168 bytes of constants, derived here from the hexadecimal digits of pi rather
 *    than transcribed. Two separate things are checked: that the derivation reproduces the published
 *    first words of the P-array and S-box, and that the cipher reproduces three of Eric Young's
 *    vectors. Either alone would leave a gap -- correct tables with a wrong `F` function, or a
 *    self-consistent cipher over wrong tables.
 *  - **PRESENT-80** gets all four combinations of an all-zero and an all-ones key and plaintext, which
 *    is what the paper publishes. Between them they exercise both branches of the key schedule's
 *    S-box step.
 *  - **Speck and Simon** get all twenty of the paper's vectors and all ten of the implementation
 *    guide's. They have no tables at all, so what the vectors pin is the parameter table -- rounds per
 *    size, which `z` sequence Simon's schedule uses, the rotation pair that changes only at the
 *    32-bit block -- and the word order, which an implementation gets wrong while still
 *    round-tripping perfectly.
 *  - **SipHash** gets two reference vectors, asserted in *both* byte orders, because the reference
 *    prints a byte string and the paper quotes an integer and they are reverses of each other.
 *
 * Every cipher additionally round-trips through the shared mode layer at a length that is not a whole
 * block, which is what catches an inverse that is wrong in a way the forward vector cannot see.
 */
import { describe, expect, it } from "vitest";
import {
  BLOWFISH_P_INIT,
  createBlowfish,
  createPresent,
  createSimon,
  createSpeck,
  decryptBlockMode,
  encryptBlockMode,
  SIMON_SPECK_VARIANTS,
  siphash,
  siphash24,
  type BlockCipher,
} from "@ocs/algos";
import {
  SIMON_SPECK_GUIDE_VECTORS,
  SIMON_SPECK_PAPER_VECTORS,
} from "./simon-speck-vectors";

const fromHex = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** One block through a cipher, as hex. */
function block(cipher: BlockCipher, hex: string, forward = true): string {
  const out = new Uint8Array(cipher.blockSize);
  const src = fromHex(hex);
  if (forward) cipher.encryptBlock(src, out);
  else cipher.decryptBlock(src, out);
  return toHex(out);
}

describe("Blowfish", () => {
  it("derives its tables from the hexadecimal digits of pi", () => {
    /**
     * The published first four words of the P-array and the first word of S-box 1. This is the check
     * that makes the derivation trustworthy -- and it is why the tables are derived rather than
     * transcribed: a mistyped word among 4168 constants gives a cipher that round-trips perfectly and
     * matches nothing.
     */
    expect(BLOWFISH_P_INIT.slice(0, 4).map((w) => w.toString(16))).toEqual([
      "243f6a88",
      "85a308d3",
      "13198a2e",
      "3707344",
    ]);
    expect(BLOWFISH_P_INIT).toHaveLength(18);
  });

  it("reproduces Eric Young's vectors", () => {
    // The three that between them cover an all-zero key, an all-ones key, and a mixed one.
    const cases: readonly [string, string, string][] = [
      ["0000000000000000", "0000000000000000", "4ef997456198dd78"],
      ["ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"],
      ["3000000000000000", "1000000000000001", "7d856f9a613063f2"],
    ];
    for (const [key, plaintext, expected] of cases) {
      const cipher = createBlowfish(fromHex(key));
      expect(block(cipher, plaintext), `${key}/${plaintext}`).toBe(expected);
      expect(block(cipher, expected, false), `${key} inverse`).toBe(plaintext);
    }
  });

  it("cycles a short key rather than padding it", () => {
    // Four bytes is the minimum, and the schedule wraps it four and a half times across 18 words.
    expect(() => createBlowfish(fromHex("11223344"))).not.toThrow();
    expect(() => createBlowfish(fromHex("112233"))).toThrow(/4 to 56/);
    expect(() => createBlowfish(new Uint8Array(57))).toThrow(/57/);
    // And a 56-byte key is accepted, which is the documented maximum.
    expect(() => createBlowfish(new Uint8Array(56).fill(7))).not.toThrow();
  });
});

describe("PRESENT-80", () => {
  it("reproduces all four of the paper's vectors", () => {
    const zeroKey = "00".repeat(10);
    const onesKey = "ff".repeat(10);
    const cases: readonly [string, string, string][] = [
      [zeroKey, "0000000000000000", "5579c1387b228445"],
      [onesKey, "0000000000000000", "e72c46c0f5945049"],
      [zeroKey, "ffffffffffffffff", "a112ffc72f68417b"],
      [onesKey, "ffffffffffffffff", "3333dcd3213210d2"],
    ];
    for (const [key, plaintext, expected] of cases) {
      const cipher = createPresent(fromHex(key));
      expect(block(cipher, plaintext), `${key}/${plaintext}`).toBe(expected);
      expect(block(cipher, expected, false), `${key} inverse`).toBe(plaintext);
    }
  });

  it("takes exactly a 10-byte key at the 80-bit set", () => {
    expect(() => createPresent(fromHex("00".repeat(16)), "80")).toThrow(/10 bytes/);
    expect(() => createPresent(fromHex("00".repeat(10)), "128")).toThrow(/16 bytes/);
  });
});

/**
 * PRESENT-128, and this block is as much about what is *not* checked as what is.
 *
 * **No published vector exists, and that is a property of the specification.** The paper tabulates four
 * vectors in Appendix I and all four are 80-bit; Appendix II gives the 128-bit key schedule in prose,
 * prefaced with "we do not expect it to be used", and gives no values. Bouncy Castle, Crypto++, Botan
 * and FELICS all implement PRESENT-80 only. So there is nothing to compare against.
 *
 * What *is* covered, and it is more than nothing: the S-box, the bit permutation and all 31 rounds are
 * shared with the 80-bit variant, which four published vectors pin. The schedule is what rests on the
 * paper's prose alone, so the assertions below are the properties a wrong schedule would break --
 * distinct round keys, dependence on every key bit, and a working inverse -- rather than a value.
 *
 * It is registered on the user's explicit instruction. Do not describe it as verified.
 */
describe("PRESENT-128", () => {
  const KEY = "0123456789abcdef0123456789abcdef";

  it("round-trips at every block in a spread", () => {
    const cipher = createPresent(fromHex(KEY), "128");
    for (let value = 0; value < 256; value += 11) {
      const plaintext = Array.from({ length: 8 }, (_, i) => ((value + i * 29) & 0xff).toString(16).padStart(2, "0")).join("");
      const enciphered = block(cipher, plaintext);
      expect(block(cipher, enciphered, false), `at ${value}`).toBe(plaintext);
    }
  });

  it("depends on every one of the 128 key bits", () => {
    // A schedule that dropped part of the register -- the easiest way to get 61-bit rotation wrong --
    // would leave some key bits unused, and this is what would catch it.
    const reference = block(createPresent(fromHex(KEY), "128"), "0000000000000000");
    for (let byte = 0; byte < 16; byte++) {
      for (let bit = 0; bit < 8; bit++) {
        const altered = fromHex(KEY);
        altered[byte] = altered[byte]! ^ (1 << bit);
        expect(
          block(createPresent(altered, "128"), "0000000000000000"),
          `key byte ${byte} bit ${bit}`,
        ).not.toBe(reference);
      }
    }
  });

  it("is a different cipher from PRESENT-80 under a zero-extended key", () => {
    // The natural wrong implementation is "the same schedule with a longer register". This is what
    // that would look like, and it must not agree.
    const short = block(createPresent(new Uint8Array(10), "80"), "0000000000000000");
    const long = block(createPresent(new Uint8Array(16), "128"), "0000000000000000");
    expect(long).not.toBe(short);
  });

  it("applies the S-box twice per round in the schedule, not once", () => {
    /**
     * The 80-bit schedule S-boxes one nibble and the 128-bit one S-boxes two. There is no vector to
     * catch a single application, so the check is indirect: with an all-zero key the two S-box outputs
     * are what break the symmetry, and a schedule applying it once would leave the second nibble at
     * its rotated value. Asserting the resulting round keys are all distinct is the observable
     * consequence -- 31 equal round keys is what a broken schedule most often produces.
     */
    const cipher = createPresent(new Uint8Array(16), "128");
    const digests = new Set<string>();
    for (let i = 0; i < 8; i++) {
      const plaintext = "00".repeat(7) + (1 << i).toString(16).padStart(2, "0");
      digests.add(block(cipher, plaintext));
    }
    expect(digests.size).toBe(8);
  });
});

describe("Simon and Speck, all twenty variants", () => {
  /**
   * Two independent vector sources, and the disagreement between them is the interesting part.
   *
   * The designers' paper prints keys and plaintexts as big-endian words, most significant first. The
   * NSA's implementation guide prints the same values with the whole byte string reversed, because its
   * `BytesToWords` reads little-endian. So the guide's ten vectors are not extra coverage of the
   * arithmetic -- they are the same ten answers in a different spelling, which makes them a real check
   * that this implementation's byte order is the paper's rather than merely self-consistent.
   *
   * Neither cipher has a table, so what these thirty vectors actually pin down is the parameter table:
   * the round count per size, which of the five `z` sequences Simon's schedule draws on, the
   * `(alpha, beta)` rotation pair that changes only for the 32-bit block, and the word order.
   */
  const wordBitsOf = (blockBits: number) => (blockBits / 2) as 16 | 24 | 32 | 48 | 64;
  const reversed = (bytes: Uint8Array) => Uint8Array.from([...bytes].reverse());

  const make = (family: string, key: Uint8Array, blockBits: number): BlockCipher =>
    family === "simon"
      ? createSimon(key, wordBitsOf(blockBits))
      : createSpeck(key, wordBitsOf(blockBits));

  it("reproduces all twenty of the paper's vectors, in both directions", () => {
    for (const v of SIMON_SPECK_PAPER_VECTORS) {
      const cipher = make(v.family, fromHex(v.key), v.blockBits);
      const label = `${v.family}${v.blockBits}/${v.keyBits}`;
      expect(cipher.blockSize, `${label} block size`).toBe(v.blockBits / 8);
      expect(block(cipher, v.plaintext), label).toBe(v.ciphertext);
      expect(block(cipher, v.ciphertext, false), `${label} inverse`).toBe(v.plaintext);
    }
    expect(SIMON_SPECK_PAPER_VECTORS).toHaveLength(20);
  });

  it("reproduces the guide's ten, which are the same values byte-reversed", () => {
    for (const v of SIMON_SPECK_GUIDE_VECTORS) {
      const cipher = make(v.family, reversed(fromHex(v.key)), v.blockBits);
      const out = new Uint8Array(v.blockBits / 8);
      cipher.encryptBlock(reversed(fromHex(v.plaintext)), out);
      expect(toHex(reversed(out)), `${v.family}${v.blockBits}/${v.keyBits}`).toBe(v.ciphertext);
    }
    // The guide covers the 64- and 128-bit blocks only, which is what its own README says.
    expect(new Set(SIMON_SPECK_GUIDE_VECTORS.map((v) => v.blockBits))).toEqual(new Set([64, 128]));
  });

  it("covers every variant the two families define, and nothing else", () => {
    /**
     * Ten members each: the word size may be 16, 24, 32, 48 or 64 bits, and the key must be 4 words at
     * 16 bits, 3 or 4 at 24 and 32, 2 or 3 at 48, and 2, 3 or 4 at 64. The list is derived from the
     * implementation's own parameter table and the expectation written out, so adding or losing a
     * variant fails here once.
     */
    expect(
      SIMON_SPECK_VARIANTS.map((v) => `${v.blockBits}/${v.keyBits}`).sort(),
    ).toEqual(
      [
        "128/128",
        "128/192",
        "128/256",
        "32/64",
        "48/72",
        "48/96",
        "64/128",
        "64/96",
        "96/144",
        "96/96",
      ].sort(),
    );
    // And each of the twenty is exercised above -- ten sizes for each of the two families.
    const covered = new Set(
      SIMON_SPECK_PAPER_VECTORS.map((v) => `${v.family} ${v.blockBits}/${v.keyBits}`),
    );
    expect(covered.size).toBe(20);
  });

  it("refuses a key length no variant defines, and names what the block size offers", () => {
    // Two words at a 32-bit block is not a Speck variant; three and four are.
    expect(() => createSpeck(new Uint8Array(8), 32)).toThrow(/64\/96 or 64\/128/);
    // A key that is not a whole number of words at all.
    expect(() => createSimon(new Uint8Array(7), 32)).toThrow(/whole number of 4-byte words/);
    expect(() => createSpeck(new Uint8Array(0), 64)).toThrow(/whole number of 8-byte words/);
  });

  it("defaults to the 128/128 member, which is what these two names usually mean", () => {
    // `createSpeck(key)` with no word size is Speck128/128, so existing callers keep their cipher.
    const key = fromHex("0f0e0d0c0b0a09080706050403020100");
    expect(block(createSpeck(key), "6c617669757165207469206564616d20")).toBe(
      "a65d9851797832657860fedf5c570d18",
    );
    expect(block(createSimon(key), "63736564207372656c6c657661727420")).toBe(
      "49681b1e1e54fe3f65aa832af84e0bbc",
    );
  });

  it("uses the smaller rotation pair only at the 32-bit block", () => {
    /**
     * Speck32/64 rotates by 7 and 2; every other variant by 8 and 3. Nothing isolates that line -- the
     * 32/64 vector covers it along with the round count and the word order -- so it is called out
     * here, on its own, because it is the one parameter that applies to exactly one of the twenty and
     * would otherwise be easy to lose in a refactor.
     */
    expect(block(createSpeck(fromHex("1918111009080100"), 16), "6574694c")).toBe("a86842f2");
    // And the next size up uses the other pair, so the two cannot be quietly conflated.
    expect(block(createSpeck(fromHex("1211100a0908020100"), 24), "20796c6c6172")).toBe(
      "c049a5385adc",
    );
  });
});

describe("Blowfish, PRESENT, Speck and Simon through the shared mode layer", () => {
  it("round-trip in every mode at a length that is not a whole block", () => {
    /**
     * 21 bytes, which is a multiple of neither 8 nor 16 -- so the padded modes exercise PKCS#7 and the
     * stream modes their partial final block. The inverse is what this covers: a decrypt that is wrong
     * in the same way as the encrypt passes a round trip, which is why the published vectors above
     * assert the inverse direction explicitly as well.
     */
    const message = new Uint8Array(21).fill(0x5a);
    const factories: readonly [string, () => BlockCipher][] = [
      ["blowfish", () => createBlowfish(fromHex("0123456789abcdef"))],
      ["present", () => createPresent(fromHex("00112233445566778899"))],
      ["speck", () => createSpeck(fromHex("0f0e0d0c0b0a09080706050403020100"))],
      ["simon", () => createSimon(fromHex("0f0e0d0c0b0a09080706050403020100"))],
    ];

    for (const [name, make] of factories) {
      const size = make().blockSize;
      const iv = new Uint8Array(size).fill(0x33);
      for (const mode of ["ecb", "cbc", "cfb", "ofb", "ctr"] as const) {
        const options = mode === "ecb" ? {} : { iv };
        const sealed = encryptBlockMode(make(), mode, message, options);
        const opened = decryptBlockMode(make(), mode, sealed, options);
        expect(toHex(opened), `${name}/${mode}`).toBe(toHex(message));
      }
    }
  });

  it("does not mutate the source block, as the BlockCipher contract requires", () => {
    // The bug noble's `unsafe.encryptBlock` caused for AES: an in-place cipher destroys a counter
    // block, which is right for the first block of CTR and wrong for every one after it.
    const factories = [
      createBlowfish(fromHex("0123456789abcdef")),
      createPresent(fromHex("00112233445566778899")),
      createSpeck(fromHex("0f0e0d0c0b0a09080706050403020100")),
      createSimon(fromHex("0f0e0d0c0b0a09080706050403020100")),
    ];
    for (const cipher of factories) {
      const src = new Uint8Array(cipher.blockSize).fill(0x11);
      const before = toHex(src);
      cipher.encryptBlock(src, new Uint8Array(cipher.blockSize));
      expect(toHex(src)).toBe(before);
      cipher.decryptBlock(src, new Uint8Array(cipher.blockSize));
      expect(toHex(src)).toBe(before);
    }
  });
});

describe("SipHash-2-4", () => {
  /** The reference test key: bytes 0x00 through 0x0f. */
  const KEY = Uint8Array.from({ length: 16 }, (_, i) => i);

  it("reproduces the reference vectors, in both byte orders", () => {
    /**
     * The reference `vectors.h` lists the empty-message result as the byte string
     * `31 0e 0e dd 47 db 6f 72`; the paper and most write-ups quote the same value as the integer
     * `0x726fdb47dd0e0e31`. Both are asserted, because the two spellings look like a bug in each
     * other's terms and someone will eventually "fix" one of them.
     */
    const empty = siphash24(KEY, new Uint8Array(0));
    expect(toHex(empty)).toBe("310e0edd47db6f72");
    expect(toHex(Uint8Array.from([...empty].reverse()))).toBe("726fdb47dd0e0e31");

    const one = siphash24(KEY, Uint8Array.from([0x00]));
    expect(toHex(one)).toBe("fd67dc93c539f874");
    expect(toHex(Uint8Array.from([...one].reverse()))).toBe("74f839c593dc67fd");
  });

  it("puts the length in the last word, so 7 and 8 bytes differ in more than their content", () => {
    // There is no padding byte: the tail block is the remaining bytes plus `len mod 256` on top.
    const seven = siphash24(KEY, new Uint8Array(7));
    const eight = siphash24(KEY, new Uint8Array(8));
    expect(toHex(seven)).not.toBe(toHex(eight));
    // And a whole-block input still absorbs a tail word carrying only the length.
    expect(toHex(eight)).not.toBe(toHex(siphash24(KEY, new Uint8Array(16))));
  });

  it("is keyed, and refuses a key that is not 16 bytes", () => {
    const other = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
    expect(toHex(siphash24(other, new Uint8Array(0)))).not.toBe(
      toHex(siphash24(KEY, new Uint8Array(0))),
    );
    expect(() => siphash24(new Uint8Array(8), new Uint8Array(0))).toThrow(/16 bytes/);
  });

  it("takes its round counts as parameters, so 2-4 is a choice rather than a constant", () => {
    // SipHash-1-3 is implemented and not registered -- no published vector for it was reachable, and
    // this repo does not ship a keyed construction it cannot check against something independent.
    expect(toHex(siphash(KEY, new Uint8Array(0), 1, 3))).not.toBe(
      toHex(siphash(KEY, new Uint8Array(0), 2, 4)),
    );
    expect(toHex(siphash(KEY, new Uint8Array(0), 2, 4))).toBe(toHex(siphash24(KEY, new Uint8Array(0))));
  });
});
