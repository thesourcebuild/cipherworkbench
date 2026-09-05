import { describe, expect, it } from "vitest";
import { gmac, umac, cbcMac, lightMac } from "@ocs/algos";

describe("Advanced & Universal MACs", () => {
  const key16 = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]);
  const data = new TextEncoder().encode("Hello world! Authenticated banking data.");

  describe("GMAC (NIST SP 800-38D)", () => {
    it("computes 16-byte authentication tag over data with nonce", () => {
      const nonce = new Uint8Array(12);
      nonce[0] = 1;
      const tag1 = gmac(key16, data, { nonce });
      expect(tag1.length).toBe(16);

      // Deterministic
      const tag2 = gmac(key16, data, { nonce });
      expect(tag1).toEqual(tag2);

      // Sensitive to data change
      const modifiedData = new Uint8Array(data);
      modifiedData[0]! ^= 1;
      const tagDiff = gmac(key16, modifiedData, { nonce });
      expect(tagDiff).not.toEqual(tag1);

      // Sensitive to nonce change
      const diffNonce = new Uint8Array(12);
      diffNonce[0] = 2;
      const tagDiffNonce = gmac(key16, data, { nonce: diffNonce });
      expect(tagDiffNonce).not.toEqual(tag1);
    });
  });

  describe("UMAC (RFC 4418)", () => {
    it("computes 64-bit and 128-bit MAC tags", () => {
      const nonce = new Uint8Array(8);
      const tag64 = umac(key16, data, { nonce, tagLength: 8 });
      expect(tag64.length).toBe(8);

      const tag128 = umac(key16, data, { nonce, tagLength: 16 });
      expect(tag128.length).toBe(16);

      // Sensitive to message modification
      const modified = new Uint8Array(data);
      modified[1]! ^= 0xff;
      const tagMod = umac(key16, modified, { nonce, tagLength: 8 });
      expect(tagMod).not.toEqual(tag64);
    });
  });

  describe("CBC-MAC / DAA (ANSI X9.9 / FIPS 113)", () => {
    it("computes DES CBC-MAC (DAA)", () => {
      const desKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const tag = cbcMac(desKey, data, { cipher: "des", padding: "zeros" });
      expect(tag.length).toBe(8);

      // Deterministic
      const tag2 = cbcMac(desKey, data, { cipher: "des", padding: "zeros" });
      expect(tag).toEqual(tag2);
    });

    it("computes AES CBC-MAC", () => {
      const tag = cbcMac(key16, data, { cipher: "aes", padding: "iso7816" });
      expect(tag.length).toBe(16);
    });
  });

  describe("LightMAC (ISO/IEC 29192-6)", () => {
    it("computes lightweight block-counter authenticated MAC", () => {
      const tag = lightMac(key16, data, { counterBits: 64, tagLength: 16 });
      expect(tag.length).toBe(16);

      // Deterministic
      const tag2 = lightMac(key16, data, { counterBits: 64, tagLength: 16 });
      expect(tag).toEqual(tag2);

      // Sensitive to tamper
      const modified = new Uint8Array(data);
      modified[0]! ^= 1;
      const tagMod = lightMac(key16, modified, { counterBits: 64, tagLength: 16 });
      expect(tagMod).not.toEqual(tag);
    });
  });
});
