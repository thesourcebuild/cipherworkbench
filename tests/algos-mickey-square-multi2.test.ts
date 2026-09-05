import { describe, expect, it } from "vitest";
import {
  mickeyEncrypt,
  mickeyDecrypt,
  SquareCipher,
  squareEncryptEcb,
  squareDecryptEcb,
  Multi2Cipher,
  multi2EncryptEcb,
  multi2DecryptEcb,
  a52Encrypt,
  a52Decrypt,
} from "@ocs/algos";

describe("Specialized Block & Stream Ciphers", () => {
  const text = "The quick brown fox jumps over the lazy dog 1234567890!";
  const data = new TextEncoder().encode(text);

  describe("MICKEY 2.0", () => {
    it("encrypts and decrypts with identical keystream inversion", () => {
      const key = new Uint8Array(10).fill(0x42); // 80-bit key
      const iv = new Uint8Array(4).fill(0x13);
      const ct = mickeyEncrypt(key, iv, data);
      expect(ct).not.toEqual(data);
      expect(ct.length).toBe(data.length);

      const pt = mickeyDecrypt(key, iv, ct);
      expect(new TextDecoder().decode(pt)).toBe(text);
    });
  });

  describe("SQUARE Block Cipher", () => {
    it("round-trips 16-byte block encryption/decryption", () => {
      const key = new Uint8Array(16);
      for (let i = 0; i < 16; i++) key[i] = i * 17;
      const cipher = new SquareCipher(key);

      const block = new Uint8Array(16);
      for (let i = 0; i < 16; i++) block[i] = i;
      const enc = cipher.encryptBlock(block);
      expect(enc).not.toEqual(block);

      const dec = cipher.decryptBlock(enc);
      expect(dec).toEqual(block);
    });

    it("encrypts and decrypts padded ECB stream", () => {
      const key = new Uint8Array(16).fill(0x5a);
      const ct = squareEncryptEcb(key, data);
      expect(ct.length % 16).toBe(0);

      const pt = squareDecryptEcb(key, ct);
      expect(new TextDecoder().decode(pt)).toBe(text);
    });
  });

  describe("MULTI2 Block Cipher", () => {
    it("round-trips 8-byte block encryption/decryption", () => {
      const key = new Uint8Array(32).fill(0xab);
      const cipher = new Multi2Cipher(key, 32);

      const block = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const enc = cipher.encryptBlock(block);
      expect(enc).not.toEqual(block);

      const dec = cipher.decryptBlock(enc);
      expect(dec).toEqual(block);
    });

    it("encrypts and decrypts padded ECB stream", () => {
      const key = new Uint8Array(32).fill(0x7c);
      const ct = multi2EncryptEcb(key, data);
      expect(ct.length % 8).toBe(0);

      const pt = multi2DecryptEcb(key, ct);
      expect(new TextDecoder().decode(pt)).toBe(text);
    });
  });

  describe("GSM A5/2 Stream Cipher", () => {
    it("encrypts and decrypts GSM frame", () => {
      const key = new Uint8Array(8).fill(0xef); // 64-bit key
      const frame = 42;
      const ct = a52Encrypt(key, frame, data);
      expect(ct).not.toEqual(data);
      expect(ct.length).toBe(data.length);

      const pt = a52Decrypt(key, frame, ct);
      expect(new TextDecoder().decode(pt)).toBe(text);
    });
  });
});
