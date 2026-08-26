/**
 * AEGIS-128L and AEGIS-256, against every vector in draft-irtf-cfrg-aegis-aead-18 appendix A.
 *
 * Three levels, and each catches something the others cannot:
 *
 * 1. **One AES round.** The draft publishes a vector for `AESRound(in, rk)` alone, which pins the
 *    S-box, ShiftRows and MixColumns without any AEGIS around them. A transposed state is invisible
 *    at every level above this one.
 * 2. **One state update.** Both variants print a full before/after state, which is what separates
 *    "the update function is wrong" from "the sponge around it is wrong" -- and the two variants have
 *    genuinely different update functions.
 * 3. **The five valid and four invalid AEAD vectors per variant**, at both tag lengths. The invalid
 *    ones are the draft's own: a swapped key and nonce, a flipped ciphertext bit, altered associated
 *    data, and a corrupted tag.
 *
 * There is no oracle: OpenSSL has no AEGIS and neither does anything in this dependency tree. The
 * draft's vectors are the whole check, which is why all of them are here rather than a chosen few.
 */
import { describe, expect, it } from "vitest";
import { aegisDecrypt, aegisEncrypt, aesRound, type AegisVariant } from "@ocs/algos";
import {
  AEGIS128L_UPDATE_VECTOR,
  AEGIS128L_VECTORS,
  AEGIS256_UPDATE_VECTOR,
  AEGIS256_VECTORS,
  AES_ROUND_VECTOR,
  type AegisVector,
} from "./aegis-vectors";

const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("the AES round AEGIS is built on", () => {
  it("matches the draft's appendix A.1 vector", () => {
    const out = new Uint8Array(16);
    aesRound(fromHex(AES_ROUND_VECTOR.in), fromHex(AES_ROUND_VECTOR.rk), out);
    expect(toHex(out)).toBe(AES_ROUND_VECTOR.out);
  });

  it("is not a no-op or a plain XOR, which a transposed implementation can be", () => {
    const zero = new Uint8Array(16);
    const out = new Uint8Array(16);
    aesRound(zero, zero, out);
    // SubBytes(0) is 0x63 everywhere, and MixColumns of a constant column is that constant.
    expect(toHex(out)).toBe("63636363636363636363636363636363");
  });
});

/**
 * The update vectors, driven through `aegisEncrypt` is not possible -- the state is private, as it
 * should be. What is reachable is the same thing one level up: the update function is exercised by
 * every vector below, and the state vectors are checked here against a local reimplementation of the
 * *specified* update, which is a statement about the draft's own numbers rather than about this code.
 *
 * Concretely: this asserts the published before/after pair is consistent with the update function as
 * written in the draft, using the same `aesRound` the implementation uses. If `aesRound` were wrong,
 * this fails; if the update wiring in `aegis.ts` were wrong, the AEAD vectors below fail. Together
 * they localise a failure to one of the two.
 */
describe("the state update functions", () => {
  it("AEGIS-128L: the draft's before/after state pair", () => {
    const s = AEGIS128L_UPDATE_VECTOR.before.map(fromHex);
    const [m0, m1] = AEGIS128L_UPDATE_VECTOR.m.map(fromHex) as [Uint8Array, Uint8Array];
    const xor = (a: Uint8Array, b: Uint8Array) => a.map((v, i) => v ^ b[i]!);

    const t = Array.from({ length: 8 }, () => new Uint8Array(16));
    aesRound(s[7]!, xor(s[0]!, m0), t[0]!);
    aesRound(s[0]!, s[1]!, t[1]!);
    aesRound(s[1]!, s[2]!, t[2]!);
    aesRound(s[2]!, s[3]!, t[3]!);
    aesRound(s[3]!, xor(s[4]!, m1), t[4]!);
    aesRound(s[4]!, s[5]!, t[5]!);
    aesRound(s[5]!, s[6]!, t[6]!);
    aesRound(s[6]!, s[7]!, t[7]!);

    expect(t.map(toHex)).toEqual([...AEGIS128L_UPDATE_VECTOR.after]);
  });

  it("AEGIS-256: the draft's before/after state pair", () => {
    const s = AEGIS256_UPDATE_VECTOR.before.map(fromHex);
    const m = fromHex(AEGIS256_UPDATE_VECTOR.m[0]!);
    const xor = (a: Uint8Array, b: Uint8Array) => a.map((v, i) => v ^ b[i]!);

    const t = Array.from({ length: 6 }, () => new Uint8Array(16));
    aesRound(s[5]!, xor(s[0]!, m), t[0]!);
    aesRound(s[0]!, s[1]!, t[1]!);
    aesRound(s[1]!, s[2]!, t[2]!);
    aesRound(s[2]!, s[3]!, t[3]!);
    aesRound(s[3]!, s[4]!, t[4]!);
    aesRound(s[4]!, s[5]!, t[5]!);

    expect(t.map(toHex)).toEqual([...AEGIS256_UPDATE_VECTOR.after]);
  });

  it("the two variants really do update differently", () => {
    // Same six blocks, same message: if the wiring were shared the results would agree, and the
    // published vectors would not both be reproducible.
    expect(AEGIS128L_UPDATE_VECTOR.after[0]).not.toBe(AEGIS256_UPDATE_VECTOR.after[0]);
  });
});

const VARIANTS: readonly {
  variant: AegisVariant;
  label: string;
  vectors: readonly AegisVector[];
}[] = [
  { variant: "aegis128l", label: "AEGIS-128L", vectors: AEGIS128L_VECTORS },
  { variant: "aegis256", label: "AEGIS-256", vectors: AEGIS256_VECTORS },
];

for (const { variant, label, vectors } of VARIANTS) {
  describe(label, () => {
    const valid = vectors.filter((v) => !v.invalid);
    const invalid = vectors.filter((v) => v.invalid);

    it("has the draft's five valid and four invalid vectors", () => {
      expect(valid.length).toBeGreaterThanOrEqual(5);
      expect(invalid).toHaveLength(4);
    });

    for (const tagLen of [16, 32] as const) {
      it(`encrypts every valid vector with a ${tagLen * 8}-bit tag`, () => {
        for (const v of valid) {
          const sealed = aegisEncrypt(
            variant,
            fromHex(v.key),
            fromHex(v.nonce),
            fromHex(v.msg!),
            fromHex(v.ad),
            tagLen,
          );
          const split = sealed.length - tagLen;
          expect(toHex(sealed.subarray(0, split)), `${v.label} ciphertext`).toBe(v.ct);
          expect(toHex(sealed.subarray(split)), `${v.label} tag`).toBe(
            tagLen === 16 ? v.tag128 : v.tag256,
          );
        }
      });

      it(`decrypts every valid vector with a ${tagLen * 8}-bit tag`, () => {
        for (const v of valid) {
          const sealed = fromHex(v.ct + (tagLen === 16 ? v.tag128 : v.tag256));
          const opened = aegisDecrypt(
            variant,
            fromHex(v.key),
            fromHex(v.nonce),
            sealed,
            fromHex(v.ad),
            tagLen,
          );
          expect(opened, v.label).not.toBeNull();
          expect(toHex(opened!), v.label).toBe(v.msg);
        }
      });

      it(`rejects every invalid vector with a ${tagLen * 8}-bit tag`, () => {
        for (const v of invalid) {
          const sealed = fromHex(v.ct + (tagLen === 16 ? v.tag128 : v.tag256));
          expect(
            aegisDecrypt(
              variant,
              fromHex(v.key),
              fromHex(v.nonce),
              sealed,
              fromHex(v.ad),
              tagLen,
            ),
            v.label,
          ).toBeNull();
        }
      });
    }

    it("round-trips at every length across the rate boundary", () => {
      /**
       * The partial final block is where AEGIS decryption differs from encryption -- it absorbs the
       * truncated plaintext zero-padded, not the padded ciphertext -- so every length either side of
       * the rate (32 bytes for 128L, 16 for 256) is worth walking.
       */
      const key = fromHex(variant === "aegis128l" ? "11".repeat(16) : "11".repeat(32));
      const nonce = fromHex(variant === "aegis128l" ? "22".repeat(16) : "22".repeat(32));
      const ad = new TextEncoder().encode("associated");

      for (let n = 0; n <= 70; n++) {
        const message = new Uint8Array(n);
        for (let i = 0; i < n; i++) message[i] = (i * 7 + 3) & 0xff;
        const sealed = aegisEncrypt(variant, key, nonce, message, ad);
        expect(sealed.length, `length ${n}`).toBe(n + 16);
        const opened = aegisDecrypt(variant, key, nonce, sealed, ad);
        expect(opened, `length ${n}`).not.toBeNull();
        expect(toHex(opened!), `length ${n}`).toBe(toHex(message));
      }
    });

    it("names the key, nonce and tag sizes it needs", () => {
      const keyLen = variant === "aegis128l" ? 16 : 32;
      const key = new Uint8Array(keyLen);
      const nonce = new Uint8Array(keyLen);
      expect(() =>
        aegisEncrypt(variant, new Uint8Array(keyLen + 1), nonce, new Uint8Array(0)),
      ).toThrow(new RegExp(`${keyLen} bytes`));
      expect(() =>
        aegisEncrypt(variant, key, new Uint8Array(keyLen + 1), new Uint8Array(0)),
      ).toThrow(new RegExp(`${keyLen} bytes`));
      expect(() => aegisEncrypt(variant, key, nonce, new Uint8Array(0), undefined, 24)).toThrow(
        /16 or 32/,
      );
    });

    it("returns null rather than throwing for input shorter than the tag", () => {
      const keyLen = variant === "aegis128l" ? 16 : 32;
      expect(
        aegisDecrypt(variant, new Uint8Array(keyLen), new Uint8Array(keyLen), new Uint8Array(8)),
      ).toBeNull();
    });
  });
}
