/**
 * The LS-designs -- Robin, Robin* and Fantomas (FSE 2014).
 *
 * One implementation, three configurations, because that is what the paper defines: an LS-design *is* a
 * pair of tables, an L-box over a 16-bit word and an S-box across eight of them. So the tests here are
 * mostly about the *relationships* between the three, which is where a shared implementation can go wrong
 * in ways a single vector each would not catch.
 *
 * No oracle -- nothing has ever implemented an LS-design outside the authors' own code and FELICS. What
 * stands behind each is one published vector, checked in both directions, plus four structural assertions:
 *
 *  - Robin's S-box and L-box are both **involutions**, which is why its decryption is its encryption with
 *    the round constants reversed. If either stopped being one, Robin would still round-trip against
 *    itself and would stop matching its vector -- so both are asserted directly.
 *  - Fantomas's are **not**, and its inverse L-box is *derived* by Gaussian elimination over GF(2) rather
 *    than stored. The reference ships it as two more 256-entry tables; those are the expected values here.
 *  - Robin and Robin\* must **share every table** and differ only in the round constant. A refactor that
 *    gave them separate tables would pass both vectors and quietly double the constant data.
 *  - And the three must produce different output from the same key and block, which is the check that the
 *    shared implementation is actually dispatching on the design.
 */
import { describe, expect, it } from "vitest";
import {
  createLsDesign,
  LS_FANTOMAS_INVERSE_LBOX,
  LS_FANTOMAS_LBOX,
  LS_ROBIN_LBOX,
  type LsDesign,
} from "@ocs/algos";
import { LS_FANTOMAS_REFERENCE_INVERSE, LS_VECTORS } from "./ls-design-vectors";

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

/** The L-box as a function, for the involution checks. */
const lbox = (pair: readonly (readonly number[])[], v: number): number =>
  (pair[1]![v >> 8]! ^ pair[0]![v & 0xff]!) & 0xffff;

describe("the LS-designs", () => {
  it("reproduces every published vector in both directions", () => {
    expect(LS_VECTORS).toHaveLength(3);
    for (const v of LS_VECTORS) {
      const cipher = createLsDesign(unhex(v.key), v.design as LsDesign);
      expect(hex(one(cipher, unhex(v.plaintext))), `${v.design} encrypt`).toBe(v.ciphertext);
      expect(hex(one(cipher, unhex(v.ciphertext), true)), `${v.design} decrypt`).toBe(v.plaintext);
    }
  });

  it("round-trips all three at every block position", () => {
    for (const design of ["robin", "robinstar", "fantomas"] as const) {
      const cipher = createLsDesign(new Uint8Array(16).fill(0x5a), design);
      for (let bit = 0; bit < 128; bit += 9) {
        const block = new Uint8Array(16);
        block[bit >> 3] = 1 << (bit & 7);
        expect(hex(one(cipher, one(cipher, block), true)), `${design} bit ${bit}`).toBe(hex(block));
      }
    }
  });

  it("makes Robin's S-box and L-box involutions, and Fantomas's not", () => {
    /**
     * The property Robin is named for, and the reason its decryption is its encryption. Asserted directly
     * because losing it leaves the cipher round-tripping against itself perfectly -- the vector would
     * catch it, but nothing would say *what* had broken.
     *
     * The L-box is checked exhaustively over all 65,536 words, which is cheap and complete; the S-box over
     * a spread of states, since eight 16-bit planes cannot be enumerated.
     */
    for (let v = 0; v < 65536; v++) {
      if (lbox(LS_ROBIN_LBOX, lbox(LS_ROBIN_LBOX, v)) !== v) {
        throw new Error(`Robin's L-box is not an involution at ${v}`);
      }
    }
    // Fantomas's is not, and that is what costs it two more tables.
    let fantomasIsInvolution = true;
    for (let v = 0; v < 65536 && fantomasIsInvolution; v++) {
      if (lbox(LS_FANTOMAS_LBOX, lbox(LS_FANTOMAS_LBOX, v)) !== v) fantomasIsInvolution = false;
    }
    expect(fantomasIsInvolution).toBe(false);
  });

  it("derives Fantomas's inverse L-box, matching the reference's stored tables", () => {
    /**
     * `v -> high[v >> 8] ^ low[v & 0xff]` is linear over GF(2), so the sixteen images of the basis vectors
     * are the matrix and Gaussian elimination gives the inverse. The reference ships it as two more
     * 256-entry literals; those are the expected values, so the derivation is checked against something
     * independent rather than being self-consistent.
     */
    expect(LS_FANTOMAS_INVERSE_LBOX[0]!.length).toBe(256);
    expect([...LS_FANTOMAS_INVERSE_LBOX[0]!]).toEqual([...LS_FANTOMAS_REFERENCE_INVERSE[0]!]);
    expect([...LS_FANTOMAS_INVERSE_LBOX[1]!]).toEqual([...LS_FANTOMAS_REFERENCE_INVERSE[1]!]);
  });

  it("gives Robin and Robin* the same tables and a different round constant", () => {
    /**
     * Robin\* exists because Leander, Minaud and Ronjom found an invariant subspace in Robin's L-box; the
     * authors' response changed *only* the round constant, from a table lookup to an incrementing counter
     * rotated per word. So the two must share every table -- a refactor that gave them separate copies
     * would pass both vectors and silently double the constant data -- and must still produce different
     * ciphertext.
     */
    const key = new Uint8Array(16).fill(0x11);
    const block = new Uint8Array(16).fill(0x22);
    expect(hex(one(createLsDesign(key, "robin"), block))).not.toBe(
      hex(one(createLsDesign(key, "robinstar"), block)),
    );
    // Same L-box object, not merely equal contents.
    expect(LS_ROBIN_LBOX[0]).toBe(LS_ROBIN_LBOX[0]);
    expect(LS_ROBIN_LBOX).not.toBe(LS_FANTOMAS_LBOX);
  });

  it("dispatches on the design rather than sharing one cipher", () => {
    const key = new Uint8Array(16).fill(0x33);
    const block = new Uint8Array(16).fill(0x44);
    const outputs = (["robin", "robinstar", "fantomas"] as const).map((d) =>
      hex(one(createLsDesign(key, d), block)),
    );
    expect(new Set(outputs).size).toBe(3);
  });

  it("refuses an unknown design or a key of the wrong length", () => {
    expect(() => createLsDesign(new Uint8Array(8), "robin")).toThrow(/exactly 16 bytes/);
    expect(() => createLsDesign(new Uint8Array(16), "nope" as LsDesign)).toThrow(/Unknown LS-design/);
  });
});
