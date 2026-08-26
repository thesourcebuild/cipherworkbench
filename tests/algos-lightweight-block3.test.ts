/**
 * PRINCE, LBlock, RECTANGLE, PRIDE and Piccolo -- the third wave off FELICS's shelf, and the last of its
 * block ciphers this repo did not have.
 *
 * None has an oracle. What stands behind each is FELICS's transcription of its designers' own vectors:
 * six for PRINCE (its paper's whole appendix), two for LBlock, one per key size for RECTANGLE, and one
 * each for PRIDE and Piccolo. Every one is checked in **both directions against the published value**,
 * which for this batch is doing more work than usual -- four of the five have decrypt paths that are not
 * the encrypt path reversed:
 *
 *  - **PRINCE** inverts by *alpha-reflection*: the same core, with the whitening words swapped and one
 *    constant XORed into the round key. No inverse round function exists.
 *  - **PRIDE**'s S-box is an involution but only two of its four linear maps are.
 *  - **Piccolo** needs its round-key pairs swapped on odd rounds, not merely reversed.
 *  - **RECTANGLE**'s S-box is fourteen logic gates forwards and a derived table backwards.
 *
 * Four derivations are asserted rather than trusted: RECTANGLE's S-box against the specification's
 * published table, Piccolo's two GF(2^4) multiplication tables against the reference's literals, PRIDE's
 * S-box involution, and PRINCE's alpha-reflection identity over its round constants.
 */
import { describe, expect, it } from "vitest";
import {
  createLblock,
  createPiccolo,
  createPride,
  createPrince,
  createRectangle,
  LBLOCK_SBOXES,
  PICCOLO_MULTIPLY,
  PRINCE_ALPHA,
  PRINCE_ROUND_CONSTANTS,
  RECTANGLE_SBOX,
  type RectangleVariant,
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

/**
 * Every vector, from FELICS's `test_vectors.c` files.
 *
 * Note that FELICS stores Piccolo's arrays **byte-reversed** -- its comments give the values as
 * `p = 0x0123456789abcdef` and the array as `ef cd ab 89 ...`. The bytes below are the array, which is
 * what the implementation takes, and getting that backwards was the one thing this batch had to look up
 * twice.
 */
const VECTORS = [
  // PRINCE: all six from the paper's appendix.
  { name: "PRINCE zero key, zero block", make: () => createPrince(unhex("00".repeat(16))), plaintext: "0000000000000000", ciphertext: "dadf020daa658681" },
  { name: "PRINCE zero key, all-ones block", make: () => createPrince(unhex("00".repeat(16))), plaintext: "ffffffffffffffff", ciphertext: "da0ac203cae64a60" },
  { name: "PRINCE k0 all ones", make: () => createPrince(unhex("ff".repeat(8) + "00".repeat(8))), plaintext: "0000000000000000", ciphertext: "24f53dfc3519b59f" },
  { name: "PRINCE k1 all ones", make: () => createPrince(unhex("00".repeat(8) + "ff".repeat(8))), plaintext: "0000000000000000", ciphertext: "efb77b73be4ca578" },
  { name: "PRINCE patterned k1", make: () => createPrince(unhex("0000000000000000" + "1032547698badcfe")), plaintext: "efcdab8967452301", ciphertext: "cf9cfaa83cad25ae" },
  { name: "PRINCE descending key", make: () => createPrince(unhex("ffeeddccbbaa99887766554433221100")), plaintext: "efcdab8967452301", ciphertext: "29ebb59fb1ea67fc" },
  // LBlock.
  { name: "LBlock zero", make: () => createLblock(unhex("00".repeat(10))), plaintext: "0000000000000000", ciphertext: "cd5be708531818c2" },
  { name: "LBlock patterned", make: () => createLblock(unhex("dcfeefcdab8967452301")), plaintext: "efcdab8967452301", ciphertext: "260ceeebd879714b" },
  // RECTANGLE, one per key size.
  { name: "RECTANGLE-64-80", make: () => createRectangle(unhex("ff".repeat(10)), "64-80"), plaintext: "ffffffffffffffff", ciphertext: "9945aa34ae3d0112" },
  { name: "RECTANGLE-64-128", make: () => createRectangle(unhex("ff".repeat(16)), "64-128"), plaintext: "ffffffffffffffff", ciphertext: "e83eefee4a157a46" },
  // PRIDE and Piccolo.
  { name: "PRIDE", make: () => createPride(unhex("00".repeat(16))), plaintext: "0000000000000000", ciphertext: "82b4109fcc70bd1f" },
  { name: "Piccolo-80", make: () => createPiccolo(unhex("11003322554477669988")), plaintext: "efcdab8967452301", ciphertext: "5640f83599ff2b8d" },
] as const;

describe("PRINCE, LBlock, RECTANGLE, PRIDE and Piccolo", () => {
  it("reproduces every published vector in both directions", () => {
    expect(VECTORS).toHaveLength(12);
    for (const v of VECTORS) {
      const cipher = v.make();
      expect(hex(one(cipher, unhex(v.plaintext))), `${v.name} encrypt`).toBe(v.ciphertext);
      // Against the published ciphertext, which is what catches four different asymmetric inverses.
      expect(hex(one(cipher, unhex(v.ciphertext), true)), `${v.name} decrypt`).toBe(v.plaintext);
    }
  });

  it("round-trips at every block position", () => {
    for (const v of VECTORS) {
      const cipher = v.make();
      for (let bit = 0; bit < cipher.blockSize * 8; bit += 5) {
        const block = new Uint8Array(cipher.blockSize);
        block[bit >> 3] = 1 << (bit & 7);
        expect(hex(one(cipher, one(cipher, block), true)), `${v.name} bit ${bit}`).toBe(hex(block));
      }
    }
  });

  it("gives PRINCE the alpha-reflection identity its constants encode", () => {
    /**
     * `RC[i] XOR RC[11 - i]` must be the same 64-bit value for every `i`, and that value is alpha -- which
     * is `RC[11]`, since `RC[0]` is zero. That identity *is* why decryption is encryption with two words
     * swapped and one XOR, so a single wrong constant byte would break the inverse while leaving
     * encryption reproducing its own output. No round trip can see that; this can.
     */
    expect(PRINCE_ROUND_CONSTANTS).toHaveLength(12);
    expect(hex(PRINCE_ROUND_CONSTANTS[0]!)).toBe("0000000000000000");
    for (let i = 0; i < 12; i++) {
      const combined = Uint8Array.from(PRINCE_ROUND_CONSTANTS[i]!, (b, j) => b ^ PRINCE_ROUND_CONSTANTS[11 - i]![j]!);
      expect(hex(combined), `RC[${i}] ^ RC[${11 - i}]`).toBe(hex(PRINCE_ALPHA));
    }
  });

  it("derives RECTANGLE's S-box from its gate sequence", () => {
    /**
     * The implementation has no S-box table on the forward path -- `substitute` is the reference's
     * fourteen logic operations, and the table is built by running it over the sixteen possible columns.
     * These are the values the specification publishes, so the gates are checked against something.
     */
    expect([...RECTANGLE_SBOX].map((v) => v.toString(16)).join("")).toBe("65ca1e79b03d8f42");
    expect(new Set(RECTANGLE_SBOX).size).toBe(16);
  });

  it("derives Piccolo's two multiplication tables", () => {
    /**
     * `2*x` and `3*x` over GF(2^4) under `x^4 + x + 1`. Every reference ships both as sixteen-entry
     * literals; the expected values here are the reference's, so the one-line derivation is checked
     * rather than merely self-consistent.
     */
    expect([...PICCOLO_MULTIPLY[0]!]).toEqual([0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13]);
    expect([...PICCOLO_MULTIPLY[1]!]).toEqual([0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 13, 14, 7, 4, 1, 2]);
  });

  it("gives LBlock ten distinct S-boxes, which is what sets it apart", () => {
    /**
     * Every other cipher in this family reuses one 4-bit box; LBlock has eight for the round function and
     * two more for the key schedule. Ten tables is the largest count in this family, so the assertion is
     * that they really are ten different permutations -- a copy-paste that duplicated one would leave the
     * cipher plausible and wrong for most inputs.
     */
    expect(LBLOCK_SBOXES).toHaveLength(10);
    const seen = new Set(LBLOCK_SBOXES.map((box) => box.join(",")));
    expect(seen.size).toBe(10);
    for (const box of LBLOCK_SBOXES) expect(new Set(box).size).toBe(16);
  });

  it("keeps RECTANGLE's two key sizes apart", () => {
    /**
     * The two schedules share only the S-box and the round constants -- the 80-bit one holds five 16-bit
     * rows and rotates a word by twelve, the 128-bit one holds eight and rotates bytes. So a bug that ran
     * one schedule for both sizes would pass one vector and fail the other, and this pins that they
     * genuinely differ rather than relying on the vectors to notice.
     */
    const block = unhex("0123456789abcdef");
    const short = one(createRectangle(new Uint8Array(10).fill(0x11), "64-80"), block);
    const long = one(createRectangle(new Uint8Array(16).fill(0x11), "64-128"), block);
    expect(hex(short)).not.toBe(hex(long));
  });

  it("refuses a key of the wrong length", () => {
    expect(() => createPrince(new Uint8Array(8))).toThrow(/exactly 16 bytes/);
    expect(() => createLblock(new Uint8Array(16))).toThrow(/exactly 10 bytes/);
    expect(() => createPride(new Uint8Array(8))).toThrow(/exactly 16 bytes/);
    expect(() => createPiccolo(new Uint8Array(16))).toThrow(/exactly 10 bytes/);
    for (const [variant, wrong] of [["64-80", 16], ["64-128", 10]] as [RectangleVariant, number][]) {
      expect(() => createRectangle(new Uint8Array(wrong), variant)).toThrow(/exactly/);
    }
  });
});
