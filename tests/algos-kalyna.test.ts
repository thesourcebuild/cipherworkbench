import { describe, expect, it } from "vitest";
import { createKalyna, KALYNA_S0_FIRST, KALYNA_VARIANTS } from "@ocs/algos";

/**
 * Kalyna (DSTU 7624:2014) against the standard's own vectors, all five pairings, both directions.
 *
 * No oracle: OpenSSL has never implemented DSTU 7624 and nothing in this tree does either. The vectors
 * come from Bouncy Castle's `DSTU7624Test`, which transcribes the standard's annex.
 *
 * **Decryption is tested separately rather than as a round trip**, and here that is not belt-and-braces.
 * The four inverse S-boxes are *derived* at load, and a fault in a derived inverse leaves encryption
 * completely correct -- so a round-trip test would pass, and only a published plaintext catches it. The
 * same argument covers the subtraction in the whitening layers: XORing everywhere inverts itself
 * perfectly and matches nothing.
 */

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.replace(/\s+/g, "").match(/../g)!.map((pair) => parseInt(pair, 16)));

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

interface Vector {
  blockBits: 128 | 256 | 512;
  key: string;
  plaintext: string;
  ciphertext: string;
}

/** One per (block, key) pairing the standard defines. All five, in ascending order. */
const VECTORS: readonly Vector[] = [
  {
    blockBits: 128,
    key: "000102030405060708090A0B0C0D0E0F",
    plaintext: "101112131415161718191A1B1C1D1E1F",
    ciphertext: "81BF1C7D779BAC20E1C9EA39B4D2AD06",
  },
  {
    blockBits: 128,
    key: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    plaintext: "202122232425262728292A2B2C2D2E2F",
    ciphertext: "58EC3E091000158A1148F7166F334F14",
  },
  {
    blockBits: 256,
    key: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    plaintext: "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
    ciphertext: "F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C",
  },
  {
    blockBits: 256,
    key:
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
      "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
    plaintext: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
    ciphertext: "606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9",
  },
  {
    blockBits: 512,
    key:
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
      "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
    plaintext:
      "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F" +
      "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
    ciphertext:
      "4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B8" +
      "95D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9",
  },
];

describe("Kalyna", () => {
  it("reproduces every published vector, both ways, at all five pairings", () => {
    for (const v of VECTORS) {
      const label = `Kalyna-${v.blockBits}/${(v.key.length / 2) * 8}`;
      const cipher = createKalyna(unhex(v.key), v.blockBits);
      expect(cipher.blockSize, `${label} block size`).toBe(v.blockBits / 8);

      const encrypted = new Uint8Array(cipher.blockSize);
      cipher.encryptBlock(unhex(v.plaintext), encrypted);
      expect(hex(encrypted), `${label} encrypt`).toBe(v.ciphertext.toLowerCase());

      const decrypted = new Uint8Array(cipher.blockSize);
      cipher.decryptBlock(unhex(v.ciphertext), decrypted);
      expect(hex(decrypted), `${label} decrypt`).toBe(v.plaintext.toLowerCase());
    }
    // Guards the guard: five pairings, and every one of them must be here.
    expect(VECTORS).toHaveLength(KALYNA_VARIANTS.length);
    expect(new Set(VECTORS.map((v) => `${v.blockBits}-${v.key.length}`)).size).toBe(5);
  });

  /**
   * The variant table is the single source for what pairings exist, and it has to agree with the rule.
   *
   * DSTU 7624 says the key is the block size or twice it, and the round count follows the key. Both are
   * asserted from the rule rather than from the table's own numbers, so a typo in an entry fails here
   * instead of producing a cipher nobody asked for.
   */
  it("declares only the pairings the standard defines", () => {
    for (const v of KALYNA_VARIANTS) {
      expect([v.blockBits, v.blockBits * 2], `${v.blockBits}/${v.keyBits}`).toContain(v.keyBits);
      const expected = v.keyBits === 128 ? 10 : v.keyBits === 256 ? 14 : 18;
      expect(v.rounds, `${v.blockBits}/${v.keyBits} rounds`).toBe(expected);
    }
    expect(KALYNA_VARIANTS).toHaveLength(5);
  });

  /**
   * The stored S-boxes are the one thing here that could not be derived, so the standard's own first
   * entry anchors them.
   *
   * Their four inverses are computed at load and the module throws if a forward box is not a
   * permutation, which is what covers the other 1023 bytes -- see the note in `kalyna.ts`.
   */
  it("has the published first S-box entry", () => {
    expect(KALYNA_S0_FIRST).toBe(0xa8);
  });

  it("refuses a key length the selected block size does not take", () => {
    // A 128-bit block takes 16 or 32 bytes; 64 belongs to the 512-bit block.
    expect(() => createKalyna(new Uint8Array(64), 128)).toThrow(/16 or 32 bytes/);
    expect(() => createKalyna(new Uint8Array(16), 512)).toThrow(/64 bytes/);
    expect(() => createKalyna(new Uint8Array(20), 128)).toThrow(/Kalyna/);
  });

  /**
   * A key wider than the block is a different function from one the same width, not an extension.
   *
   * Kalyna-128/256 draws two round keys per rotation of the key material where Kalyna-128/128 draws one,
   * which is the single genuine branch in the schedule. Feeding the 128/256 key's first half to
   * Kalyna-128/128 must give something unrelated.
   */
  it("does not treat a double-width key as an extension of a single-width one", () => {
    const wide = unhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const plaintext = unhex("202122232425262728292A2B2C2D2E2F");
    const a = new Uint8Array(16);
    const b = new Uint8Array(16);
    createKalyna(wide, 128).encryptBlock(plaintext, a);
    createKalyna(wide.subarray(0, 16), 128).encryptBlock(plaintext, b);
    expect(hex(a)).not.toBe(hex(b));
  });

  /** The default block size is the one the tool opens on, so it is worth pinning. */
  it("defaults to a 128-bit block", () => {
    expect(createKalyna(new Uint8Array(16)).blockSize).toBe(16);
  });
});
