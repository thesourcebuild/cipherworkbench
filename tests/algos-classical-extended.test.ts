import { describe, it, expect } from "vitest";
import {
  adfgvxEncrypt,
  adfgvxDecrypt,
  vicCrypt,
  hillEncrypt,
  hillDecrypt,
  fourSquareEncrypt,
  fourSquareDecrypt,
  chaocipherCrypt,
  enigmaCrypt,
  m209Crypt,
  lorenzCrypt,
  solitaireEncrypt,
  solitaireDecrypt,
  adfgxEncrypt,
  adfgxDecrypt,
  nihilistEncrypt,
  nihilistDecrypt,
  straddlingCheckerboardEncrypt,
  straddlingCheckerboardDecrypt,
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
      const ct = vicCrypt(plaintext, { direction: "encrypt" });
      const pt = vicCrypt(ct, { direction: "decrypt" });
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
      const ct = chaocipherCrypt(plaintext, { direction: "encrypt" });
      const pt = chaocipherCrypt(ct, { direction: "decrypt" });
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

  describe("Hagelin M-209", () => {
    it("encrypts and decrypts reciprocally across 6 pinwheels and drum lugs", () => {
      const msg = "ATTACKATDAWN";
      const ct = m209Crypt(msg, { rotorPositions: "AAAAAA" });
      expect(ct).not.toBe(msg);
      const pt = m209Crypt(ct, { rotorPositions: "AAAAAA" });
      expect(pt).toBe(msg);
    });
  });

  describe("Lorenz SZ40/SZ42", () => {
    it("encrypts and decrypts 5-bit Vernam stream under 12-wheel stepping logic", () => {
      const msg = "SECRETTELEPRINTERREPORT";
      const ct = lorenzCrypt(msg, { wheelPositions: "AAAAAAAAAAAA" });
      expect(ct).not.toBe(msg);
      const pt = lorenzCrypt(ct, { wheelPositions: "AAAAAAAAAAAA" });
      expect(pt).toBe(msg);
    });
  });

  describe("Solitaire (Pontifex)", () => {
    it("encrypts and decrypts through 54-card deck manipulation", () => {
      const msg = "DONOTUSEPCUSEPENCIL";
      const ct = solitaireEncrypt(msg, { passphrase: "CRYPTONOMICON" });
      expect(ct).not.toBe(msg);
      const pt = solitaireDecrypt(ct, { passphrase: "CRYPTONOMICON" });
      expect(pt).toBe(msg);
    });
  });

  describe("ADFGX (5x5)", () => {
    it("encrypts and decrypts fractionating 5x5 grid with columnar transposition", () => {
      const msg = "ATTACKATDAWN";
      const ct = adfgxEncrypt(msg, { gridKey: "GERMAN", transpositionKey: "CIPHER" });
      expect(ct).not.toBe(msg);
      const pt = adfgxDecrypt(ct, { gridKey: "GERMAN", transpositionKey: "CIPHER" });
      expect(pt).toBe(msg);
    });
  });

  describe("Nihilist Cipher", () => {
    it("encrypts to coordinate numbers and decrypts back", () => {
      const msg = "MEETATMIDNIGHT";
      const ct = nihilistEncrypt(msg, { alphabetKey: "RUSSIAN", keyPhrase: "SECRET" });
      expect(ct).toMatch(/^[0-9\s]+$/);
      const pt = nihilistDecrypt(ct, { alphabetKey: "RUSSIAN", keyPhrase: "SECRET" });
      expect(pt).toBe(msg);
    });
  });

  describe("Straddling Checkerboard", () => {
    it("substitutes letters to variable-length digits and reconstructs original text", () => {
      const msg = "AGENTCONFIRMED";
      const ct = straddlingCheckerboardEncrypt(msg, { keyword: "CIPHER" });
      expect(ct).toMatch(/^[0-9]+$/);
      const pt = straddlingCheckerboardDecrypt(ct, { keyword: "CIPHER" });
      expect(pt).toBe(msg);
    });
  });
});
