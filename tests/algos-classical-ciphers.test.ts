import { describe, expect, it } from "vitest";
import {
  autokeyEncrypt,
  autokeyDecrypt,
  beaufortEncrypt,
  beaufortDecrypt,
  variantBeaufortEncrypt,
  variantBeaufortDecrypt,
  columnarTranspositionEncrypt,
  columnarTranspositionDecrypt,
  twoSquareCrypt,
  fractionatedMorseEncrypt,
  fractionatedMorseDecrypt,
  scytaleEncrypt,
  scytaleDecrypt,
} from "@ocs/algos";

describe("Advanced Classical Ciphers", () => {
  describe("Autokey Cipher", () => {
    it("round-trips correctly with plaintext autokey", () => {
      const plain = "MEET AT THE SECRET LOCATION AT DAWN";
      const key = "QUEENLY";
      const cipher = autokeyEncrypt(plain, key);
      expect(cipher).not.toBe(plain);
      const decrypted = autokeyDecrypt(cipher, key);
      expect(decrypted).toBe(plain);
    });
  });

  describe("Beaufort Cipher", () => {
    it("is reciprocal and decrypts back to original", () => {
      const plain = "DEFEND THE EAST WALL OF THE CASTLE";
      const key = "FORTIFICATION";
      const cipher = beaufortEncrypt(plain, key);
      expect(cipher).not.toBe(plain);
      // Reciprocal: encrypting ciphertext with same key yields plaintext
      const decrypted = beaufortEncrypt(cipher, key);
      expect(decrypted).toBe(plain);
      expect(beaufortDecrypt(cipher, key)).toBe(plain);
    });

    it("supports variant Beaufort", () => {
      const plain = "ATTACK AT ONCE";
      const key = "LEMON";
      const cipher = variantBeaufortEncrypt(plain, key);
      const decrypted = variantBeaufortDecrypt(cipher, key);
      expect(decrypted).toBe(plain);
    });
  });

  describe("Columnar Transposition", () => {
    it("transposes message according to alphabetical key order", () => {
      const plain = "WE ARE DISCOVERED FLEE AT ONCE";
      const key = "ZEBRAS";
      const cipher = columnarTranspositionEncrypt(plain, key);
      expect(cipher).not.toBe(plain);
      const decrypted = columnarTranspositionDecrypt(cipher, key);
      expect(decrypted).toBe(plain);
    });
  });

  describe("Two-Square Cipher", () => {
    it("encrypts and decrypts with two separate keyword grids", () => {
      const plain = "HELP ME";
      const key1 = "EXAMPLE";
      const key2 = "KEYWORD";
      const cipher = twoSquareCrypt(plain, key1, key2, "encrypt");
      expect(cipher).not.toBe(plain);
      // Decrypt explicitly — two-square with different keys is not self-reciprocal
      const decrypted = twoSquareCrypt(cipher, key1, key2, "decrypt");
      expect(decrypted.replace(/X$/, "").trim()).toBe("HELPME");
    });
  });

  describe("Fractionated Morse", () => {
    it("encodes into morse trigrams and recovers original message", () => {
      const plain = "ROUND TABLE KNIGHT";
      const key = "EXCALIBUR";
      const cipher = fractionatedMorseEncrypt(plain, key);
      expect(cipher.length).toBeGreaterThan(0);
      const decrypted = fractionatedMorseDecrypt(cipher, key);
      expect(decrypted).toBe(plain);
    });
  });

  describe("Scytale", () => {
    it("encrypts and decrypts with cylinder diameter", () => {
      const plain = "I AM HURT VERY BADLY HELP";
      const diameter = 4;
      const cipher = scytaleEncrypt(plain, diameter);
      expect(cipher).not.toBe(plain);
      const decrypted = scytaleDecrypt(cipher, diameter);
      expect(decrypted).toBe(plain);
    });
  });
});
