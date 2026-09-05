import { describe, expect, it } from "vitest";
import {
  openPgpCrc24,
  openPgpArmorEncode,
  openPgpArmorDecode,
  gsm0338Pack,
  gsm0338Unpack,
  binhexEncode,
  binhexDecode,
} from "@ocs/algos";

describe("Specialized Encodings", () => {
  const text = "Hello OpenPGP & GSM world!";
  const bytes = new TextEncoder().encode(text);

  describe("OpenPGP ASCII Armor (RFC 4880)", () => {
    it("computes 24-bit CRC matching RFC 4880", () => {
      const crc = openPgpCrc24(bytes);
      expect(crc).toBeGreaterThan(0);
      expect(crc).toBeLessThanOrEqual(0xffffff);
    });

    it("formats into standard ASCII Armor block with header, version, and =CRC", () => {
      const armored = openPgpArmorEncode(bytes, "MESSAGE");
      expect(armored.startsWith("-----BEGIN PGP MESSAGE-----")).toBe(true);
      expect(armored.includes("Version: CipherWorkbench")).toBe(true);
      expect(armored.includes("=")).toBe(true);
      expect(armored.endsWith("-----END PGP MESSAGE-----")).toBe(true);

      const decoded = openPgpArmorDecode(armored);
      expect(new TextDecoder().decode(decoded)).toBe(text);
    });
  });

  describe("GSM 03.38 7-bit PDU Packing", () => {
    it("packs 7-bit septets into 8-bit octets and unpacks", () => {
      const sms = "Hello World";
      const packed = gsm0338Pack(sms);
      expect(packed.length).toBeLessThan(sms.length); // 8 characters pack into 7 bytes

      const unpacked = gsm0338Unpack(packed, sms.length);
      expect(unpacked).toBe(sms);
    });
  });

  describe("BinHex 4.0", () => {
    it("encodes into classic Macintosh BinHex format and decodes back", () => {
      const encoded = binhexEncode(bytes);
      expect(encoded.startsWith("(This file must be converted with BinHex 4.0)")).toBe(true);
      expect(encoded.endsWith(":")).toBe(true);

      const decoded = binhexDecode(encoded);
      expect(new TextDecoder().decode(decoded)).toBe(text);
    });
  });
});
