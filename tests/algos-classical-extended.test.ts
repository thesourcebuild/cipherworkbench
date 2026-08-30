import { describe, it, expect } from "vitest";
import {
  adfgvxEncrypt,
  adfgvxDecrypt,
  vicEncrypt,
  vicDecrypt,
  hillEncrypt,
  hillDecrypt,
  fourSquareEncrypt,
  fourSquareDecrypt,
  chaoEncrypt,
  chaoDecrypt,
} from "@ocs/algos";

describe("Advanced Classical Ciphers", () => {
  describe("ADFGVX / ADFGX", () => {
    it("encrypts and decrypts ADFGVX alphanumeric text with columnar transposition", () => {
      const plaintext = "ATTACKATDAWN99";
      const key = "SECRET";
      const ct = adfgvxEncrypt(plaintext, key);
      const pt = adfgvxDecrypt(ct, key);
      expect(pt).toBe(plaintext);
    });

    it("encrypts and decrypts ADFGX 5x5 text", () => {
      const plaintext = "HELLOWORLD";
      const key = "GERMAN";
      const ct = adfgvxEncrypt(plaintext, key, undefined, false);
      const pt = adfgvxDecrypt(ct, key, undefined, false);
      expect(pt).toBe(plaintext);
    });
  });

  describe("VIC Cipher", () => {
    it("encodes with straddling checkerboard and decrypts", () => {
      const plaintext = "STRIKEATNOON";
      const key = "73521";
      const ct = vicEncrypt(plaintext, key);
      const pt = vicDecrypt(ct, key);
      expect(pt).toBe(plaintext);
    });
  });

  describe("Hill Cipher", () => {
    it("encrypts and decrypts 2x2 matrix vectors modulo 26", () => {
      const plaintext = "HELP";
      const ct = hillEncrypt(plaintext);
      const pt = hillDecrypt(ct);
      expect(pt).toBe("HELP");
    });
  });

  describe("Four-Square Cipher", () => {
    it("encrypts and decrypts digram pairs", () => {
      const plaintext = "SECRETMEETING";
      const ct = fourSquareEncrypt(plaintext);
      const pt = fourSquareDecrypt(ct);
      expect(pt).toBe("SECRETMEETINGX");
    });
  });

  describe("Chaocipher", () => {
    it("encrypts and decrypts through dynamic dual-rotor permutation", () => {
      const plaintext = "WELLDONEISBETTERTHANWELLSAID";
      const ct = chaoEncrypt(plaintext);
      const pt = chaoDecrypt(ct);
      expect(pt).toBe(plaintext);
    });
  });
});
