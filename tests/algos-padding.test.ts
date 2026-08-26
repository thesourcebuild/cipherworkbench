import { describe, expect, it } from "vitest";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { unsafe } from "@noble/ciphers/aes.js";
import {
  decryptBlockMode,
  encryptBlockMode,
  padBlocks,
  unpadBlocks,
  type BlockCipher,
  type PaddingScheme,
} from "@ocs/algos";

/**
 * AES as a bare block permutation, the same shape `tests/algos-aead-modes.test.ts` builds.
 *
 * Duplicated rather than imported for the reason that file gives: this tests `@ocs/algos`, which knows
 * nothing about the tool layer -- and the scratch copy is load-bearing, because `unsafe.encryptBlock`
 * overwrites whatever buffer it is handed.
 */
function aesBlockCipher(key: Uint8Array): BlockCipher {
  const encKey = unsafe.expandKeyLE(key);
  const decKey = unsafe.expandKeyDecLE(key);
  const scratch = new Uint8Array(16);
  return {
    blockSize: 16,
    encryptBlock: (src, dst) => {
      scratch.set(src);
      dst.set(unsafe.encryptBlock(encKey, scratch));
    },
    decryptBlock: (src, dst) => {
      scratch.set(src);
      dst.set(unsafe.decryptBlock(decKey, scratch));
    },
  };
}

/**
 * The four padding schemes ECB and CBC offer.
 *
 * What stands behind them is unusual for this repo and worth stating, because there is no "published
 * padding vector" to cite. The padding is checked two ways:
 *
 * 1. **Its bytes are asserted directly.** Every scheme here is short and fully determined -- PKCS#7 is
 *    the count repeated, ISO 9797-1 method 2 is `0x80` then zeros, ANSI X9.23 is zeros then the count
 *    -- so the padded block can be written out and compared. That is stronger than a round trip, which
 *    the same mistake in both directions passes.
 * 2. **Against OpenSSL with auto-padding off.** `node:crypto` will not do anything but PKCS#7, so it
 *    cannot pad for us -- but it can encrypt a plaintext *we* padded, with `setAutoPadding(false)`. Our
 *    padded mode has to produce the same ciphertext. The cipher is then OpenSSL's and the padding is
 *    the only thing under test, which is exactly the isolation wanted.
 *
 * Zero padding and ISO 10126 are not implemented and there is a test below asserting the type does not
 * admit them, because both produce a wrong answer rather than a different one.
 */

const KEY = Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 1);
const IV = Uint8Array.from({ length: 16 }, (_, i) => 255 - i * 3);
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const hex = toHex;

describe("padding schemes", () => {
  it("writes the bytes each scheme defines, including a whole block when already aligned", () => {
    const five = Uint8Array.from([1, 2, 3, 4, 5]);

    expect(toHex(padBlocks(five, 8, "pkcs7"))).toBe("01020304050303" + "03");
    expect(toHex(padBlocks(five, 8, "iso7816"))).toBe("0102030405800000");
    expect(toHex(padBlocks(five, 8, "x923"))).toBe("0102030405000003");

    /*
     * Already aligned, and every padding scheme still adds a full block. That is not waste: without it
     * a message ending in a padding-shaped byte could not be told from a padded one. `none` is the
     * exception and refuses instead of guessing.
     */
    const eight = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    for (const scheme of ["pkcs7", "pkcs5", "iso7816", "x923", "zero"] as const) {
      expect(padBlocks(eight, 8, scheme).length, scheme).toBe(16);
    }
    expect(padBlocks(eight, 8, "none")).toBe(eight);
    expect(() => padBlocks(five, 8, "none")).toThrow(/whole number of 8-byte blocks/);
  });

  it("round-trips every scheme at every length across a block boundary", () => {
    // `zero` is excluded on purpose: it is the one scheme whose round trip legitimately fails, for a
    // plaintext ending in zeros, which the seven-scheme test above pins directly.
    for (const scheme of ["pkcs7", "pkcs5", "iso7816", "x923"] as const) {
      for (let length = 0; length <= 33; length++) {
        const data = Uint8Array.from({ length }, (_, i) => (i * 11) % 256);
        const padded = padBlocks(data, 16, scheme);
        expect(padded.length % 16, `${scheme} @ ${length}`).toBe(0);
        expect(toHex(unpadBlocks(padded, 16, scheme)), `${scheme} @ ${length}`).toBe(
          toHex(data),
        );
      }
    }
  });

  /**
   * Unpadding validates rather than believing the last byte.
   *
   * Returning whatever it claims would turn a wrong key into a plausible short plaintext instead of an
   * error, which is the failure a round-trip test cannot see.
   */
  it("refuses padding that does not say what it should", () => {
    const bad = new Uint8Array(16);
    bad[15] = 17; // longer than the block
    expect(() => unpadBlocks(bad, 16, "pkcs7")).toThrow(/not valid/);
    expect(() => unpadBlocks(bad, 16, "x923")).toThrow(/not valid/);

    // X9.23 covers three bytes but one of them is not zero.
    const x923 = new Uint8Array(16);
    x923[13] = 9;
    x923[15] = 3;
    expect(() => unpadBlocks(x923, 16, "x923")).toThrow(/not valid/);

    // ISO 9797-1 with no 0x80 marker anywhere in the final block.
    expect(() => unpadBlocks(new Uint8Array(16), 16, "iso7816")).toThrow(/not valid/);

    // And a ciphertext that is not whole blocks at all.
    expect(() => unpadBlocks(new Uint8Array(17), 16, "pkcs7")).toThrow(/whole number/);
  });

  /**
   * The OpenSSL check: it encrypts a plaintext we padded, with its own padding switched off.
   *
   * So the cipher is OpenSSL's and the padding is ours, which is what isolates the thing under test.
   * `node:crypto` implements no scheme but PKCS#7, so this is the only way to get an independent
   * opinion on the other two.
   */
  it("agrees with OpenSSL over a plaintext padded by each scheme", () => {
    const cipher = aesBlockCipher(KEY);
    for (const scheme of ["pkcs7", "pkcs5", "iso7816", "x923", "zero"] as const) {
      for (const length of [0, 1, 15, 16, 17, 31, 32, 33]) {
        /*
         * `+ 1` so no length ends in a zero byte, which matters only for `zero` padding and matters a
         * lot: at length 1 the old pattern was a single 0x00, and zero-unpadding correctly strips it,
         * so the round trip below failed on the scheme working as designed. The lossy case is pinned
         * deliberately in the seven-scheme test above rather than tripped over here.
         */
        const data = Uint8Array.from({ length }, (_, i) => (i * 37 + 1) % 256);

        const ours = encryptBlockMode(cipher, "cbc", data, { iv: IV, padding: scheme });

        const reference = createCipheriv("aes-128-cbc", KEY, IV);
        reference.setAutoPadding(false);
        const theirs = Buffer.concat([
          reference.update(Buffer.from(padBlocks(data, 16, scheme))),
          reference.final(),
        ]);

        expect(toHex(ours), `${scheme} @ ${length}`).toBe(theirs.toString("hex"));

        // And back, through our own unpadding.
        const back = decryptBlockMode(cipher, "cbc", ours, { iv: IV, padding: scheme });
        expect(toHex(back), `${scheme} @ ${length} decrypt`).toBe(toHex(data));
      }
    }
  });

  /**
   * `none` reproduces OpenSSL with auto-padding off on both sides, which is what it is for: NIST's
   * SP 800-38A ECB and CBC examples are block-aligned and published unpadded.
   */
  it("none matches OpenSSL with auto-padding disabled", () => {
    const cipher = aesBlockCipher(KEY);
    const data = Uint8Array.from({ length: 32 }, (_, i) => i * 5);

    const ours = encryptBlockMode(cipher, "cbc", data, { iv: IV, padding: "none" });
    const reference = createCipheriv("aes-128-cbc", KEY, IV);
    reference.setAutoPadding(false);
    const theirs = Buffer.concat([reference.update(Buffer.from(data)), reference.final()]);
    expect(toHex(ours)).toBe(theirs.toString("hex"));

    const opener = createDecipheriv("aes-128-cbc", KEY, IV);
    opener.setAutoPadding(false);
    const plain = Buffer.concat([opener.update(Buffer.from(ours)), opener.final()]);
    expect(toHex(decryptBlockMode(cipher, "cbc", ours, { iv: IV, padding: "none" }))).toBe(
      plain.toString("hex"),
    );
  });

  /**
   * All seven, and what each of the three added later costs.
   *
   * This replaces a test asserting that zero padding and ISO 10126 were *absent*, with a
   * `@ts-expect-error` to keep them out. That premise was wrong on this repo's own terms: the checksum
   * family lists schemes that coincide rather than hiding one behind the other, and the family rule is
   * to refuse only what an algorithm genuinely cannot do and diagnose the rest. So they are here, and
   * what used to be an omission is now `C009` and `C010`.
   */
  it("implements all seven schemes, with PKCS#5 identical to PKCS#7", () => {
    const schemes: PaddingScheme[] = [
      "pkcs7",
      "pkcs5",
      "iso7816",
      "x923",
      "iso10126",
      "zero",
      "none",
    ];
    expect(schemes).toHaveLength(7);

    const data = Uint8Array.from([1, 2, 3, 4, 5]);

    // PKCS#5 *is* PKCS#7. Asserted rather than assumed, because it is the reason both are offered:
    // someone who tries each and gets one answer has to be able to trust that.
    expect(hex(padBlocks(data, 8, "pkcs5"))).toBe(hex(padBlocks(data, 8, "pkcs7")));

    // Zero padding: zeros, and removal takes the trailing zeros of the plaintext with it.
    expect(hex(padBlocks(data, 8, "zero"))).toBe("0102030405000000");
    const endsInZero = Uint8Array.from([1, 2, 0, 0]);
    expect(
      hex(unpadBlocks(padBlocks(endsInZero, 8, "zero"), 8, "zero")),
      "the plaintext's own zeros are lost, which is what C009 warns about",
    ).toBe("0102");

    /*
     * ISO 10126: random filler, fixed count. Two draws must differ -- and the count byte must not, or
     * unpadding would be guessing. A generator is required rather than defaulted, because padding with
     * predictable bytes would be a different, weaker scheme under this one's name.
     */
    const random = (n: number) => Uint8Array.from({ length: n }, () => 0xcd);
    const padded = padBlocks(data, 8, "iso10126", random);
    expect(hex(padded)).toBe("0102030405cdcd03");
    expect(hex(unpadBlocks(padded, 8, "iso10126"))).toBe(hex(data));
    expect(() => padBlocks(data, 8, "iso10126")).toThrow(/no generator/);

    let differed = false;
    for (let i = 0; i < 20 && !differed; i++) {
      const a = padBlocks(data, 8, "iso10126", (n) => Uint8Array.from({ length: n }, () => i));
      const b = padBlocks(data, 8, "iso10126", (n) =>
        Uint8Array.from({ length: n }, () => i + 1),
      );
      differed = hex(a) !== hex(b);
      expect(a[a.length - 1], "the count is fixed whatever the filler").toBe(b[b.length - 1]);
    }
    expect(differed, "different filler must give different padding").toBe(true);
  });
});
