/**
 * MISTY1 and HIGHT, the first two Phase 6 block ciphers.
 *
 * Neither has an oracle: OpenSSL implemented neither and no dependency in this tree has either. What
 * stands behind them is published vectors, and both sources carry *mode* cases as well as raw block
 * ones -- which is unusually useful here, because those check this repo's own `blockmodes.ts` against
 * a published value rather than against itself. MISTY1's CBC example and HIGHT's eight CBC and 52 CTR
 * vectors are the first published mode vectors in the repo for a cipher added at the same time as
 * them.
 *
 * Both are checked in **both directions against the published plaintext**, never through a round
 * trip. That distinction has earned itself repeatedly here: a wrong inverse is self-consistent, so
 * encrypt-then-decrypt passes while the decrypt path matches nothing. MISTY1 is the case where it
 * matters most -- `FL` and `FLINV` are the same two statements in opposite order, and swapping them
 * leaves encryption entirely correct.
 *
 * One bug, and it was HIGHT's: the eight lanes rotate one slot per round, and generalising the
 * reference's 32 longhand argument lists into `first = (9 - round) mod 8` got the starting lane wrong
 * on the first attempt. The cipher inverted perfectly and reproduced nothing, which is this repo's
 * most-repeated signature.
 */
import { describe, expect, it } from "vitest";
import {
  createHight,
  createMisty1,
  decryptBlockMode,
  encryptBlockMode,
  HIGHT_TABLES,
  MISTY1_S7_FIRST,
  MISTY1_S9_FIRST,
} from "@ocs/algos";
import {
  HIGHT_CBC,
  HIGHT_CTR,
  HIGHT_ECB,
  HIGHT_REF_DELTA,
  HIGHT_REF_F0,
  HIGHT_REF_F1,
} from "./phase6-vectors";

/**
 * The published vectors are block-aligned and their references appended no PKCS#7, so every ECB and
 * CBC call here passes `padding: "none"` -- the same reason NIST's SP 800-38A examples need it.
 */
const NO_PAD = { padding: "none" } as const;

const unhex = (text: string): Uint8Array =>
  text === "" ? new Uint8Array(0) : Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** One raw block through the cipher, without any mode. */
const block = (cipher: { blockSize: number; encryptBlock(s: Uint8Array, d: Uint8Array): void }, src: Uint8Array) => {
  const out = new Uint8Array(cipher.blockSize);
  cipher.encryptBlock(src, out);
  return out;
};
const unblock = (cipher: { blockSize: number; decryptBlock(s: Uint8Array, d: Uint8Array): void }, src: Uint8Array) => {
  const out = new Uint8Array(cipher.blockSize);
  cipher.decryptBlock(src, out);
  return out;
};

describe("MISTY1", () => {
  /**
   * RFC 2994 Appendix A. The plaintext is 128 bits, so the ECB example is two blocks -- which is why
   * the RFC says "MISTY1 is used two times to each 64-bit, namely ECB mode" rather than giving one.
   */
  const KEY = unhex("00112233445566778899aabbccddeeff");
  const PLAINTEXT = unhex("0123456789abcdeffedcba9876543210");
  const ECB_CIPHERTEXT = "8b1da5f56ab3d07c04b68240b13be95d";
  const CBC_IV = unhex("0102030405060708");
  const CBC_CIPHERTEXT = "461c1e879c18c27fb9adf2d80c89031f";

  it("transcribes RFC 2994's S-boxes, and both are permutations", () => {
    // The tables were parsed out of the RFC by script; these are its own first entries, and the
    // permutation property is checked at module load in `phase6-ciphers.ts`.
    expect(MISTY1_S7_FIRST).toBe(0x1b);
    expect(MISTY1_S9_FIRST).toBe(0x1c3);
  });

  it("reproduces the RFC's ECB example, in both directions", () => {
    const cipher = createMisty1(KEY);
    const got = hex(block(cipher, PLAINTEXT.subarray(0, 8))) + hex(block(cipher, PLAINTEXT.subarray(8)));
    expect(got).toBe(ECB_CIPHERTEXT);

    // Decrypting the *published* ciphertext, not re-encrypting our own -- `FL` and `FLINV` are the
    // same statements in opposite order and a round trip cannot tell them apart.
    const want = unhex(ECB_CIPHERTEXT);
    const back = hex(unblock(cipher, want.subarray(0, 8))) + hex(unblock(cipher, want.subarray(8)));
    expect(back).toBe(hex(PLAINTEXT));
  });

  it("reproduces the RFC's CBC example through the shared mode layer", () => {
    /**
     * Worth more than it looks: this is a *published* CBC value, so it checks `blockmodes.ts`'s
     * chaining and this cipher's block function together. Everything else in that layer is checked
     * against `node:crypto`, which has neither of these ciphers.
     */
    const cipher = createMisty1(KEY);
    expect(hex(encryptBlockMode(cipher, "cbc", PLAINTEXT, { iv: CBC_IV, ...NO_PAD }))).toBe(
      CBC_CIPHERTEXT,
    );
    expect(
      hex(decryptBlockMode(cipher, "cbc", unhex(CBC_CIPHERTEXT), { iv: CBC_IV, ...NO_PAD })),
    ).toBe(hex(PLAINTEXT));
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => createMisty1(new Uint8Array(8))).toThrow(/exactly 16 bytes/);
    expect(() => createMisty1(new Uint8Array(24))).toThrow(/exactly 16 bytes/);
  });
});

describe("HIGHT", () => {
  it("derives F0, F1 and DELTA rather than storing them", () => {
    /**
     * The three derivations, checked entry by entry against the reference's literal tables.
     *
     * `F0` and `F1` are three rotations each and `DELTA` comes from a 7-bit LFSR, so 384 bytes of
     * constants become six lines of code. That is only safe because this test exists -- and the
     * DELTA loop in particular has an off-by-one available at the wrap, which would leave two
     * entries equal.
     */
    expect(HIGHT_REF_F0).toHaveLength(256);
    expect(HIGHT_REF_F1).toHaveLength(256);
    expect(HIGHT_REF_DELTA).toHaveLength(128);
    for (let i = 0; i < 256; i++) {
      expect(HIGHT_TABLES.f0[i], `F0[${i}]`).toBe(HIGHT_REF_F0[i]);
      expect(HIGHT_TABLES.f1[i], `F1[${i}]`).toBe(HIGHT_REF_F1[i]);
    }
    for (let i = 0; i < 128; i++) {
      expect(HIGHT_TABLES.delta[i], `DELTA[${i}]`).toBe(HIGHT_REF_DELTA[i]);
    }
    // DELTA's first and last values, as the standard prints them.
    expect(HIGHT_TABLES.delta[0]).toBe(0x5a);
    expect(HIGHT_TABLES.delta[127]).toBe(0x5a);
  });

  it("reproduces all nine ECB vectors, in both directions", () => {
    expect(HIGHT_ECB).toHaveLength(9);
    for (const v of HIGHT_ECB) {
      const cipher = createHight(unhex(v.key));
      expect(hex(block(cipher, unhex(v.plaintext))), `encrypt ${v.key}`).toBe(v.ciphertext);
      expect(hex(unblock(cipher, unhex(v.ciphertext))), `decrypt ${v.key}`).toBe(v.plaintext);
    }
  });

  it("reproduces the published CBC and CTR vectors through the shared mode layer", () => {
    /**
     * 60 published mode vectors, which is the strongest check `blockmodes.ts` has ever had against
     * something other than `node:crypto` -- and `node:crypto` has no HIGHT. The CTR set is the larger
     * one and the more informative: it needs no padding, so a length that is not a multiple of eight
     * exercises the partial final block.
     */
    expect(HIGHT_CBC.length).toBeGreaterThan(0);
    expect(HIGHT_CTR.length).toBeGreaterThan(0);
    for (const v of HIGHT_CBC) {
      const cipher = createHight(unhex(v.key));
      const iv = unhex(v.iv!);
      expect(
        hex(encryptBlockMode(cipher, "cbc", unhex(v.plaintext), { iv, ...NO_PAD })),
        `CBC ${v.key}`,
      ).toBe(v.ciphertext);
      expect(
        hex(decryptBlockMode(cipher, "cbc", unhex(v.ciphertext), { iv, ...NO_PAD })),
        `CBC back ${v.key}`,
      ).toBe(v.plaintext);
    }
    for (const v of HIGHT_CTR) {
      const cipher = createHight(unhex(v.key));
      const iv = unhex(v.iv!);
      expect(
        hex(encryptBlockMode(cipher, "ctr", unhex(v.plaintext), { iv })),
        `CTR ${v.key}`,
      ).toBe(v.ciphertext);
      // CTR is its own inverse, so this checks the keystream is regenerated identically.
      expect(
        hex(encryptBlockMode(cipher, "ctr", unhex(v.ciphertext), { iv })),
        `CTR back ${v.key}`,
      ).toBe(v.plaintext);
    }
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => createHight(new Uint8Array(8))).toThrow(/exactly 16 bytes/);
  });

  it("is not MISTY1, despite sharing a block size and a key size", () => {
    // Both are 64-bit blocks under 128-bit keys, so a factory wired to the wrong one would look
    // entirely plausible. The cipher family's construction-label test covers the same ground for the
    // registered tools; this covers the implementations.
    const key = unhex("00112233445566778899aabbccddeeff");
    const pt = unhex("0123456789abcdef");
    expect(hex(block(createHight(key), pt))).not.toBe(hex(block(createMisty1(key), pt)));
  });

  it("agrees with ECB over two blocks", () => {
    // The mode layer's ECB against the raw block function, which is what makes the ECB fixture above
    // meaningful for the registered tool rather than only for the primitive.
    const cipher = createHight(unhex(HIGHT_ECB[0]!.key));
    const two = unhex(HIGHT_ECB[0]!.plaintext + HIGHT_ECB[1]!.plaintext);
    const viaMode = encryptBlockMode(cipher, "ecb", two, NO_PAD);
    const viaBlocks =
      hex(block(cipher, two.subarray(0, 8))) + hex(block(cipher, two.subarray(8)));
    expect(hex(viaMode)).toBe(viaBlocks);
    expect(hex(decryptBlockMode(cipher, "ecb", viaMode, NO_PAD))).toBe(hex(two));
  });
});
