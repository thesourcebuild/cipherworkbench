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
  enigmaCrypt,
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

  describe("Enigma Machine (M3/M4)", () => {
    it("preserves digits when digits option is preserve", () => {
      const ct = enigmaCrypt("123456789", { digits: "preserve" });
      expect(ct).toBe("123456789");
    });

    it("expands digits to German words (1=EINS, 2=ZWEI, 3=DREI) and encrypts them", () => {
      const rawGerman = enigmaCrypt("EINSZWEIDREI", { rotors: ["I", "II", "III"], positions: "AAA" });
      const digitGerman = enigmaCrypt("123", { rotors: ["I", "II", "III"], positions: "AAA", digits: "german" });
      expect(digitGerman).toBe(rawGerman);
      expect(digitGerman).not.toBe("123");
    });

    it("expands digits to English words (1=ONE, 2=TWO, 3=THREE) and encrypts them", () => {
      const rawEnglish = enigmaCrypt("ONETWOTHREE", { rotors: ["I", "II", "III"], positions: "AAA" });
      const digitEnglish = enigmaCrypt("123", { rotors: ["I", "II", "III"], positions: "AAA", digits: "english" });
      expect(digitEnglish).toBe(rawEnglish);
      expect(digitEnglish).not.toBe("123");
    });

    it("round-trips letter text under reciprocal reflector settings", () => {
      const msg = "HELLOWORLD";
      const ct = enigmaCrypt(msg, { rotors: ["I", "II", "III"], positions: "AAA" });
      const pt = enigmaCrypt(ct, { rotors: ["I", "II", "III"], positions: "AAA" });
      expect(pt).toBe(msg);
    });
  });
});
