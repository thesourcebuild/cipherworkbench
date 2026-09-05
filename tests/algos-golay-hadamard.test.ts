import { describe, expect, it } from "vitest";
import {
  golayEncodeWord,
  golayDecodeWord,
  golayEncode,
  golayDecode,
  hadamardEncodeWord,
  hadamardDecodeWord,
  hadamardEncode,
  hadamardDecode,
} from "@ocs/algos";

describe("Advanced Error-Correcting Codes", () => {
  describe("Extended Binary Golay Code G_24", () => {
    it("encodes 12-bit word into 24-bit codeword and decodes cleanly", () => {
      const msg = 0x5a3;
      const codeword = golayEncodeWord(msg);
      expect(codeword >>> 12).toBe(msg);

      const decoded = golayDecodeWord(codeword);
      expect(decoded.valid).toBe(true);
      expect(decoded.data).toBe(msg);
      expect(decoded.correctedErrors).toBe(0);
    });

    it("corrects up to 3 bit errors in a 24-bit codeword", () => {
      const msg = 0x7b2;
      const codeword = golayEncodeWord(msg);

      // Flip 3 bits (e.g. bits 2, 9, 17)
      const corrupted = codeword ^ (1 << 2) ^ (1 << 9) ^ (1 << 17);
      const decoded = golayDecodeWord(corrupted);
      expect(decoded.valid).toBe(true);
      expect(decoded.data).toBe(msg);
      expect(decoded.correctedErrors).toBe(3);
    });

    it("encodes byte stream and decodes without errors", () => {
      const payload = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
      const encoded = golayEncode(payload);
      expect(encoded.length).toBe(payload.length * 2); // 12 bits data -> 24 bits (expansion 200%)

      const decoded = golayDecode(encoded, payload.length);
      expect(decoded).toEqual(payload);
    });
  });

  describe("Walsh-Hadamard Error-Correcting Code", () => {
    it("encodes and decodes word with Hadamard Sylvester transform", () => {
      const msg = 13; // 5-bit message for order 16
      const codeword = hadamardEncodeWord(msg, 16);
      expect(codeword.length).toBe(16);

      const decoded = hadamardDecodeWord(codeword, 16);
      expect(decoded).toBe(msg);
    });

    it("corrects bit errors in Hadamard codeword", () => {
      const msg = 9;
      const codeword = hadamardEncodeWord(msg, 16);

      // Corrupt 2 bits
      codeword[3]! ^= 1;
      codeword[7]! ^= 1;

      const decoded = hadamardDecodeWord(codeword, 16);
      expect(decoded).toBe(msg);
    });

    it("encodes and decodes byte stream", () => {
      const payload = new Uint8Array([42, 99, 127]);
      const encoded = hadamardEncode(payload, 16);
      const decoded = hadamardDecode(encoded, 16, payload.length);
      expect(decoded).toEqual(payload);
    });
  });
});
