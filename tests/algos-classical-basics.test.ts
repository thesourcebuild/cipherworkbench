import { describe, expect, it } from "vitest";
import {
  a1z26Decode,
  a1z26Encode,
  affineDecrypt,
  affineEncrypt,
  atbash,
  polybiusDecode,
  polybiusEncode,
  rot5,
  rot13,
  rot18,
  rot47,
  rotTransform,
} from "@ocs/algos";

describe("basic classical transformations", () => {
  it("matches the published affine a=5, b=8 vector", () => {
    const options = { multiplier: 5, offset: 8 };
    expect(affineEncrypt("AFFINECIPHER", options)).toBe("IHHWVCSWFRCP");
    expect(affineDecrypt("IHHWVCSWFRCP", options)).toBe("AFFINECIPHER");
  });

  it("preserves affine case and non-ASCII-alphabet characters", () => {
    const options = { multiplier: 5, offset: 8 };
    const plaintext = "Affine cipher: cafe, cafe! 123";
    expect(affineDecrypt(affineEncrypt(plaintext, options), options)).toBe(plaintext);
    expect(affineEncrypt("\u00e9 \u03a9 123", options)).toBe("\u00e9 \u03a9 123");
  });

  it("rejects affine keys without an inverse modulo 26", () => {
    expect(() => affineEncrypt("TEST", { multiplier: 2, offset: 8 })).toThrow(/not coprime/);
    expect(() => affineDecrypt("TEST", { multiplier: 5.5, offset: 8 })).toThrow(/integers/);
  });

  it("matches the conventional Atbash alphabet and is reciprocal", () => {
    expect(atbash("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe("ZYXWVUTSRQPONMLKJIHGFEDCBA");
    expect(atbash("Hello, World!")).toBe("Svool, Dliow!");
    expect(atbash(atbash("Attack at dawn!"))).toBe("Attack at dawn!");
  });

  it("matches the standard Polybius I/J-square vector", () => {
    expect(polybiusEncode("HELLO")).toBe("23 15 31 31 34");
    expect(polybiusDecode("23 15 31 31 34")).toBe("HELLO");
    expect(polybiusEncode("IJ")).toBe("24 24");
    expect(polybiusDecode("24 24")).toBe("II");
    expect(polybiusEncode("\u00df")).toBe("");
  });

  it("rejects malformed Polybius coordinates instead of skipping them", () => {
    for (const malformed of ["10", "56", "2315", "23 XX", "23,15"]) {
      expect(() => polybiusDecode(malformed), malformed).toThrow(/Invalid Polybius coordinate/);
    }
  });

  it("matches A1Z26 notation and preserves normalized word boundaries", () => {
    const encoded = "1-20-20-1-3-11 1-20 4-1-23-14";
    expect(a1z26Encode("ATTACK AT DAWN")).toBe(encoded);
    expect(a1z26Decode(encoded)).toBe("ATTACK AT DAWN");
    expect(a1z26Encode("Attack, at dawn!")).toBe(encoded);
    expect(a1z26Encode("\u00df")).toBe("");
  });

  it("rejects malformed and out-of-range A1Z26 input", () => {
    for (const malformed of ["0", "27", "1--2", "-1", "1-", "1,2", "A-1"]) {
      expect(() => a1z26Decode(malformed), malformed).toThrow(/Invalid A1Z26 input/);
    }
  });

  it("matches the conventional ROT5, ROT13, ROT18 and ROT47 vectors", () => {
    expect(rot5("Phone: 0123456789")).toBe("Phone: 5678901234");
    expect(rot13("Hello 123")).toBe("Uryyb 123");
    expect(rot18("Hello 123")).toBe("Uryyb 678");
    expect(rot47("Hello, World!")).toBe("w6==@[ (@C=5P");
  });

  it("keeps every ROT variant reciprocal and rejects unknown variants", () => {
    const message = "Printable ASCII: Hello 123!";
    for (const variant of ["rot5", "rot13", "rot18", "rot47"] as const) {
      expect(rotTransform(rotTransform(message, variant), variant), variant).toBe(message);
    }
    expect(() => rotTransform(message, "rot99" as never)).toThrow(/Unknown ROT variant/);
  });
});
