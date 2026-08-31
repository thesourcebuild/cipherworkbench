import { describe, it, expect } from "vitest";
import {
  hpkeSeal,
  hpkeOpen,
  hpkeDerivePublic,
  entropyToMnemonic,
  mnemonicToSeed,
  createMasterFromSeed,
  deriveChild,
  derivePath,
  formatHkdfLabel,
  hkdfExpandLabel,
} from "@ocs/algos";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";

const hashFn = (d: Uint8Array) => sha256(d);
const hmac512Fn = (k: Uint8Array, d: Uint8Array) => hmac(sha512, k, d);

describe("Modern Key Exchange & Protocols", () => {
  describe("HPKE (RFC 9180)", () => {
    it("seals and opens message with recipient key", () => {
      const recipientPriv = new Uint8Array(32).fill(0x11);
      const recipientPub = hpkeDerivePublic(recipientPriv);
      const ephemPriv = new Uint8Array(32).fill(0x33);
      const info = new TextEncoder().encode("HPKE App Info Context");
      const plaintext = new TextEncoder().encode("Hello HPKE RFC 9180!");

      const sealed = hpkeSeal(hashFn, recipientPub, info, plaintext, ephemPriv);
      expect(sealed.ciphertext.length).toBe(plaintext.length + 16);

      const opened = hpkeOpen(hashFn, recipientPriv, sealed.encapsulatedKey, info, sealed.ciphertext);
      expect(new TextDecoder().decode(opened)).toBe("Hello HPKE RFC 9180!");
    });
  });

  describe("BIP-39 Mnemonic", () => {
    it("converts 128-bit entropy into 12 mnemonic words", () => {
      const entropy = new Uint8Array(16).fill(0x00);
      const words = entropyToMnemonic(entropy).split(" ");
      expect(words.length).toBe(12);
      expect(words[0]).toBe("abandon");
    });

    it("derives 512-bit seed from mnemonic phrase", () => {
      const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      const seed = mnemonicToSeed(mnemonic, "TREZOR");
      expect(seed.length).toBe(64);
    });
  });

  describe("BIP-32 / BIP-44 HD Wallets", () => {
    it("creates master key from seed and derives child path m/44'/0'/0'/0/0", () => {
      const seed = new Uint8Array(64).fill(0x55);
      const master = createMasterFromSeed(seed, hmac512Fn);
      expect(master.depth).toBe(0);
      expect(master.key.length).toBe(32);
      expect(master.chainCode.length).toBe(32);

      const child0 = deriveChild(master, 0, hmac512Fn);
      expect(child0.depth).toBe(1);

      const pathKey = derivePath(master, "m/44'/0'/0'/0/0", hmac512Fn);
      expect(pathKey.depth).toBe(5);
      expect(pathKey.key.length).toBe(32);
    });
  });

  describe("HKDF-Expand-Label (RFC 8446)", () => {
    it("formats structured label payload correctly", () => {
      const formatted = formatHkdfLabel(32, "key", new Uint8Array(0), { labelPrefix: "tls13 " });
      expect(formatted[0]).toBe(0);
      expect(formatted[1]).toBe(32); // length 32
      expect(formatted[2]).toBe(9); // "tls13 key".length = 9
    });

    it("expands secret with label and context", () => {
      const secret = new Uint8Array(32).fill(0x42);
      const mockExpand = (_sec: Uint8Array, info: Uint8Array, len: number) => {
        const out = new Uint8Array(len);
        for (let i = 0; i < len; i++) out[i] = (info[i % info.length]! ^ 0xaa) >>> 0;
        return out;
      };

      const out = hkdfExpandLabel(mockExpand, secret, "derived", new Uint8Array([1, 2, 3]), 32);
      expect(out.length).toBe(32);
    });
  });
});
