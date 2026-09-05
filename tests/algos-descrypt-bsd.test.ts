import { describe, expect, it } from "vitest";
import {
  unixDesCrypt,
  bsdExtendedCrypt,
  lmHash,
  ntlmHash,
  oneStepKdf,
  wpaPsk,
} from "@ocs/algos";

describe("Advanced Password Hashes & Key Derivation Functions", () => {
  describe("Unix DES-Crypt (crypt(3))", () => {
    it("computes standard 13-character crypt string", () => {
      const hash1 = unixDesCrypt("password", "ab");
      expect(hash1.length).toBe(13);
      expect(hash1.startsWith("ab")).toBe(true);

      // Deterministic
      const hash2 = unixDesCrypt("password", "ab");
      expect(hash1).toBe(hash2);

      // Sensitive to password
      const hash3 = unixDesCrypt("different", "ab");
      expect(hash3).not.toBe(hash1);
    });
  });

  describe("BSD Extended Crypt (_ format)", () => {
    it("computes 20-character BSD crypt string with iteration count", () => {
      const hash = bsdExtendedCrypt("password", "abcd", 1000);
      expect(hash.startsWith("_")).toBe(true);
      expect(hash.length).toBe(20);
    });
  });

  describe("LM & NTLM Hash", () => {
    it("computes standard Windows LM and NTLM hashes", () => {
      // Known vector for empty password
      // LM of "": AAD3B435B51404EEAAD3B435B51404EE
      expect(lmHash("").toUpperCase()).toBe("AAD3B435B51404EEAAD3B435B51404EE");

      // NTLM of "": 31D6CFE0D16AE931B73C59D7E0C089C0
      expect(ntlmHash("").toUpperCase()).toBe("31D6CFE0D16AE931B73C59D7E0C089C0");

      // "password"
      const ntlmPass = ntlmHash("password").toUpperCase();
      expect(ntlmPass).toBe("8846F7EAEE8FB117AD06BDD830B7586C");
    });
  });

  describe("One-Step KDF (SP 800-56A / SP 800-56C)", () => {
    it("derives requested key bytes from shared secret and other info", () => {
      const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const otherInfo = new TextEncoder().encode("AlgorithmID||PartyU||PartyV");
      const derived = oneStepKdf(secret, 48, { otherInfo });
      expect(derived.length).toBe(48);

      // Deterministic
      const derived2 = oneStepKdf(secret, 48, { otherInfo });
      expect(derived).toEqual(derived2);
    });
  });

  describe("WPA-PSK", () => {
    it("computes 256-bit PSK using 4096 PBKDF2-SHA1 rounds", () => {
      const psk = wpaPsk("password123", "HomeNetwork");
      expect(psk.length).toBe(32);
    });
  });
});
