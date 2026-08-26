/**
 * Camellia and ARIA, against OpenSSL and against their own RFCs.
 *
 * Two national-standard block ciphers implemented here from RFC 3713 and RFC 5794 -- see the headers
 * of `camellia.ts` and `aria.ts` for why they are in this repo at all. Neither has a pure-ESM
 * library, and both have an OpenSSL implementation, which is the combination that makes them safe to
 * add: the tables came out of the RFC text by script, and this file re-checks their effect on every
 * run against a second implementation.
 *
 * Three layers of check, deliberately:
 *
 * 1. The **published vectors** in each RFC's appendix, for all three key sizes. These pin the
 *    absolute answer, and the 192-bit case is the one that matters most -- Camellia's KR is built by
 *    complementing half the key there, and getting that wrong leaves 128 and 256 correct.
 * 2. **ARIA's key schedule directly**, against the W and ek values RFC 5794 prints. A wrong rotation
 *    is invisible in a round trip and says nothing useful in a ciphertext comparison.
 * 3. **OpenSSL across every mode and length**, which is what would catch a single wrong S-box entry.
 */
import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import {
  ARIA_KEY_SIZES,
  CAMELLIA_KEY_SIZES,
  ariaKeySchedule,
  createAria,
  createCamellia,
  decryptBlockMode,
  encryptBlockMode,
  type BlockCipher,
  type BlockMode,
} from "@ocs/algos";

const fromHex = (hex: string) =>
  Uint8Array.from(hex.replace(/\s+/g, "").match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** Deterministic filler; `Math.random` is banned in this repo and a fixed pattern is reproducible. */
function pattern(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 7 + seed * 31 + 13) & 0xff;
  return out;
}

/** One block, straight through the primitive with no mode wrapper. */
function encryptOneBlock(cipher: BlockCipher, block: Uint8Array): Uint8Array {
  const out = new Uint8Array(cipher.blockSize);
  cipher.encryptBlock(block, out);
  return out;
}

describe("Camellia -- RFC 3713 appendix A", () => {
  // The appendix uses the same plaintext for all three key sizes, and for the 128-bit case the key
  // is that same value again.
  const PLAINTEXT = "0123456789abcdeffedcba9876543210";

  const CASES = [
    { bits: 128, key: PLAINTEXT, ciphertext: "67673138549669730857065648eabe43" },
    {
      bits: 192,
      key: PLAINTEXT + "0011223344556677",
      ciphertext: "b4993401b3e996f84ee5cee7d79b09b9",
    },
    {
      bits: 256,
      key: PLAINTEXT + "00112233445566778899aabbccddeeff",
      ciphertext: "9acc237dff16d76c20ef7c919e3a7509",
    },
  ];

  for (const { bits, key, ciphertext } of CASES) {
    it(`encrypts the published block under a ${bits}-bit key`, () => {
      const cipher = createCamellia(fromHex(key));
      expect(toHex(encryptOneBlock(cipher, fromHex(PLAINTEXT)))).toBe(ciphertext);
    });

    it(`decrypts the published block under a ${bits}-bit key`, () => {
      const cipher = createCamellia(fromHex(key));
      const out = new Uint8Array(16);
      cipher.decryptBlock(fromHex(ciphertext), out);
      expect(toHex(out)).toBe(PLAINTEXT);
    });
  }

  it("refuses a key length the cipher does not have", () => {
    expect(() => createCamellia(new Uint8Array(20))).toThrow(/16, 24 or 32/);
    expect(CAMELLIA_KEY_SIZES).toEqual([16, 24, 32]);
  });
});

describe("ARIA -- RFC 5794 appendix A", () => {
  const PLAINTEXT = "00112233445566778899aabbccddeeff";
  const KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

  const CASES = [
    { bits: 128, bytes: 16, ciphertext: "d718fbd6ab644c739da95f3be6451778" },
    { bits: 192, bytes: 24, ciphertext: "26449c1805dbe7aa25a468ce263a9e79" },
    { bits: 256, bytes: 32, ciphertext: "f92bd7c79fb72e2f2b8f80c1972d24fc" },
  ];

  for (const { bits, bytes, ciphertext } of CASES) {
    it(`encrypts the published block under a ${bits}-bit key`, () => {
      const cipher = createAria(fromHex(KEY).subarray(0, bytes));
      expect(toHex(encryptOneBlock(cipher, fromHex(PLAINTEXT)))).toBe(ciphertext);
    });

    it(`decrypts the published block under a ${bits}-bit key`, () => {
      const cipher = createAria(fromHex(KEY).subarray(0, bytes));
      const out = new Uint8Array(16);
      cipher.decryptBlock(fromHex(ciphertext), out);
      expect(toHex(out)).toBe(PLAINTEXT);
    });
  }

  it("derives the round keys RFC 5794 appendix A.1 prints", () => {
    /**
     * The 13 encryption round keys for the 128-bit case, verbatim from the RFC.
     *
     * This is the check that makes generating the keys from a rotation pattern -- rather than
     * transcribing seventeen lines -- a safe trade. Nothing else in this file distinguishes a wrong
     * rotation constant from a wrong S-box.
     */
    const EXPECTED = [
      "d415a75c794b85c5e0d2a0b3cb793bf6",
      "369c65e4b11777ab713a3e1e6601b8f4",
      "0368d4f13d14497b6529ad7ac809e7d0",
      "c644552b549a263fb8d0b50906229eec",
      "5f9c434951f2d2ef342787b1a781794c",
      "afea2c0ce71db6de42a47461f4323c54",
      "324286db44ba4db6c44ac306f2a84b2c",
      "7f9fa93574d842b9101a58063771eb7b",
      "aab9c57731fcd213ad5677458fcfe6d4",
      "2f4423bb06465abada5694a19eb88459",
      "9f8772808f5d580d810ef8ddac13abeb",
      "8684946a155be77ef810744847e35fad",
      "0f0aa16daee61bd7dfee5a599970fb35",
    ];

    const derived = ariaKeySchedule(fromHex(KEY).subarray(0, 16));
    // 17 keys are always derived; a 12-round ARIA uses the first 13.
    expect(derived).toHaveLength(17);
    expect(derived.slice(0, 13).map(toHex)).toEqual(EXPECTED);
  });

  it("refuses a key length the cipher does not have", () => {
    expect(() => createAria(new Uint8Array(20))).toThrow(/16, 24 or 32/);
    expect(ARIA_KEY_SIZES).toEqual([16, 24, 32]);
  });
});

/**
 * The differential pass. Every mode, every key size, thirteen lengths.
 *
 * Same harness shape as `algos-blockciphers.test.ts` uses for DES and SM4: the mode layer is shared,
 * so what is really under test here is the block permutation and the key schedule -- but running the
 * modes anyway costs nothing and catches a mode that was wired to the wrong block size.
 */
describe("Camellia and ARIA against OpenSSL", () => {
  const LENGTHS = [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100];
  const MODES: readonly BlockMode[] = ["ecb", "cbc", "cfb", "ofb", "ctr"];

  const FAMILIES = [
    { label: "camellia", openssl: "camellia", create: createCamellia },
    { label: "aria", openssl: "aria", create: createAria },
  ];

  for (const family of FAMILIES) {
    for (const keyBytes of [16, 24, 32]) {
      for (const mode of MODES) {
        const name = `${family.openssl}-${keyBytes * 8}-${mode}`;

        it(`matches ${name}`, () => {
          const key = pattern(keyBytes, 3);
          const iv = pattern(16, 9);
          const cipher = family.create(key);

          for (const length of LENGTHS) {
            const plaintext = pattern(length, length);
            const options = mode === "ecb" ? {} : { iv };
            const ours = encryptBlockMode(cipher, mode, plaintext, options);

            const openssl = crypto.createCipheriv(name, key, mode === "ecb" ? null : iv);
            // Our ECB and CBC pad; OpenSSL's do too, and both use PKCS#7.
            openssl.setAutoPadding(mode === "ecb" || mode === "cbc");
            const expected = Buffer.concat([openssl.update(plaintext), openssl.final()]);

            expect(toHex(ours), `${name} @ ${length}`).toBe(expected.toString("hex"));

            const back = decryptBlockMode(cipher, mode, ours, options);
            expect(toHex(back), `${name} round trip @ ${length}`).toBe(toHex(plaintext));
          }
        });
      }
    }
  }

  it("covers every mode OpenSSL offers for these two ciphers", () => {
    /**
     * A completeness gate, in the spirit of `openssl-parity.test.ts`.
     *
     * OpenSSL also exposes `cfb1`, `cfb8` and, for ARIA, the AEAD modes. Those are deliberately not
     * implemented -- `cfb1`/`cfb8` are bit- and byte-wide variants of CFB that no one asks a workbench
     * for, and an AEAD mode over a self-implemented block cipher would mean hand-writing GHASH. What
     * this asserts is that every mode the app *does* offer has an OpenSSL name behind it, so no test
     * above is silently skipped.
     */
    const available = new Set(crypto.getCiphers());
    for (const family of ["camellia", "aria"]) {
      for (const bits of [128, 192, 256]) {
        for (const mode of MODES) {
          expect(available.has(`${family}-${bits}-${mode}`), `${family}-${bits}-${mode}`).toBe(true);
        }
      }
    }
  });
});
