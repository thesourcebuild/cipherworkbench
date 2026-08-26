/**
 * BelT against STB 34.101.31's own test annex.
 *
 * There is no oracle: OpenSSL has no BelT, no dependency here implements it, and the standard is not
 * one anything in this tree would carry by accident. So the checks are the standard's published
 * values, and they are chosen to fail *separately* -- the H-block derivation, then the block cipher
 * in both directions, then the hash. A wrong table breaks all three; a wrong round function breaks
 * the last two; a wrong padding rule breaks only the hash.
 *
 * The three hash vectors are 13, 32 and 48 bytes on purpose. belt-hash has no padding byte at all:
 * a short final block is zero-filled and the bit length is folded in by a separate final
 * compression, so those three lengths are a partial block, an exact block, and a block plus a
 * partial one -- every branch of the rule. An implementation that dropped the length compression
 * would produce stable, plausible, wrong output for all of them, which is the same trap Snefru and
 * GOST R 34.11-94 set.
 */
import { describe, expect, it } from "vitest";
import { BELT_H, beltHash, beltKeyExpand, createBelt, createBeltHash } from "@ocs/algos";

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** The standard's tests take their inputs from the H-block itself, at these offsets. */
const h = (from: number, to: number): Uint8Array => BELT_H.slice(from, to);

describe("BelT's H-block", () => {
  it("derives to the published table", () => {
    /**
     * The reference ships 256 literal bytes; the generator that produces them is in a comment beside
     * the table. Deriving means nothing here can be mistyped -- but it also means the derivation
     * itself needs a published check value, which is the first and last rows of that table.
     */
    expect(hex(BELT_H.subarray(0, 16))).toBe("b194bac80a08f53b366d008e584a5de4");
    expect(hex(BELT_H.subarray(240, 256))).toBe("d4efd9b43a622875911410ea776cda1d");
  });

  it("is a permutation of the 256 byte values", () => {
    // What makes it an S-box at all, and the property the generator's wrap-around could break: it
    // fills positions 10..255 and then 0..9, so an off-by-one leaves two entries equal.
    expect(new Set(BELT_H).size).toBe(256);
  });

  it("seeds at the two positions the generator names", () => {
    expect(BELT_H[10]).toBe(0x00);
    expect(BELT_H[11]).toBe(0x8e);
  });
});

describe("belt-block", () => {
  it("test A.1 — encrypts", () => {
    const cipher = createBelt(h(128, 160));
    const out = new Uint8Array(16);
    cipher.encryptBlock(h(0, 16), out);
    expect(hex(out)).toBe("69cca1c93557c9e3d66bc3e0fa88fa6e");
  });

  it("test A.4 — decrypts", () => {
    /**
     * A separate published vector for the inverse rather than a round trip. The register shuffle and
     * the subkey order both differ between the two directions and are *not* reverses of each other,
     * so a round trip can pass with both wrong in matching ways.
     */
    const cipher = createBelt(h(160, 192));
    const out = new Uint8Array(16);
    cipher.decryptBlock(h(64, 80), out);
    expect(hex(out)).toBe("0dc5300600cab840b38448e5e993f421");
  });

  it("round-trips at all three key lengths", () => {
    for (const keyLen of [16, 24, 32]) {
      const cipher = createBelt(h(128, 128 + keyLen));
      const encrypted = new Uint8Array(16);
      const decrypted = new Uint8Array(16);
      cipher.encryptBlock(h(0, 16), encrypted);
      cipher.decryptBlock(encrypted, decrypted);
      expect(hex(decrypted), `key length ${keyLen}`).toBe(hex(h(0, 16)));
    }
  });

  it("widens a short key by the standard's rule", () => {
    // A 128-bit key is repeated, so it must give the same eight words as the 256-bit key formed by
    // concatenating it with itself. That is what makes the two indistinguishable to the cipher.
    const short = beltKeyExpand(h(128, 144));
    const doubled = new Uint8Array(32);
    doubled.set(h(128, 144), 0);
    doubled.set(h(128, 144), 16);
    expect([...short]).toEqual([...beltKeyExpand(doubled)]);
    expect(() => createBelt(new Uint8Array(20))).toThrow(/16, 24 or 32/);
  });
});

describe("belt-hash", () => {
  const CASES: readonly [number, string][] = [
    [13, "abef9725d4c5a83597a367d14494cc2542f20f659ddfecc961a3ec550cba8c75"],
    [32, "749e4c3653aece5e48db4761227742eb6dbe13f4a80f7beff1a9cf8d10ee7786"],
    [48, "9d02ee446fb6a29fe5c982d4b13af9d3e90861bc4cef27cf306bfb0b174a154a"],
  ];

  for (const [length, digest] of CASES) {
    it(`test A.23 — ${length} bytes`, () => {
      expect(hex(beltHash(h(0, length)))).toBe(digest);
    });
  }

  it("streams, and survives being digested partway through", () => {
    /**
     * STB's test A.23-3 does exactly this: hash 11 bytes, take a digest, then feed the remaining 37
     * and take another. It is the reason `digest()` works on copies -- an implementation that
     * finalised in place would pass the two one-shot vectors above and fail here.
     */
    const state = createBeltHash();
    state.update(h(0, 11));
    const partway = state.digest();
    expect(hex(partway)).toBe(hex(beltHash(h(0, 11))));
    state.update(h(11, 48));
    expect(hex(state.digest())).toBe(
      "9d02ee446fb6a29fe5c982d4b13af9d3e90861bc4cef27cf306bfb0b174a154a",
    );
  });

  it("agrees with the one-shot call at every awkward chunk size", () => {
    const message = h(0, 100);
    for (const chunk of [1, 7, 31, 32, 33, 64]) {
      const state = createBeltHash();
      for (let at = 0; at < message.length; at += chunk) {
        state.update(message.subarray(at, Math.min(at + chunk, message.length)));
      }
      expect(hex(state.digest()), `chunk ${chunk}`).toBe(hex(beltHash(message)));
    }
  });

  it("distinguishes a message from the same message plus a zero byte", () => {
    // The property the final length compression exists to provide. Without it the zero-filled final
    // block would make these two identical.
    const shorter = beltHash(h(0, 13));
    const padded = new Uint8Array(14);
    padded.set(h(0, 13));
    expect(hex(beltHash(padded))).not.toBe(hex(shorter));
  });
});
