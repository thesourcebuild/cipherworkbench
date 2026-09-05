import { describe, expect, it } from "vitest";
import { pearsonHash, murmurHash1, murmurHash2, jenkinsLookup3 } from "@ocs/algos";

describe("Specialized & Historic Non-Cryptographic Hashes", () => {
  const data = new TextEncoder().encode("The quick brown fox jumps over the lazy dog");

  describe("Pearson Hashing", () => {
    it("computes 1-byte and multi-byte Pearson hashes", () => {
      const h1 = pearsonHash(data, 1);
      expect(h1.length).toBe(1);

      const h4 = pearsonHash(data, 4);
      expect(h4.length).toBe(4);

      // Deterministic
      expect(pearsonHash(data, 4)).toEqual(h4);

      // Sensitive to data
      const mod = new Uint8Array(data);
      mod[0]! ^= 1;
      expect(pearsonHash(mod, 4)).not.toEqual(h4);
    });
  });

  describe("MurmurHash1 & MurmurHash2", () => {
    it("computes 32-bit MurmurHash1", () => {
      const h1 = murmurHash1(data);
      expect(typeof h1).toBe("number");
      expect(h1).toBeGreaterThan(0);
      expect(murmurHash1(data)).toBe(h1);
    });

    it("computes 32-bit MurmurHash2", () => {
      const h2 = murmurHash2(data);
      expect(typeof h2).toBe("number");
      expect(h2).toBeGreaterThan(0);
      expect(murmurHash2(data)).toBe(h2);
    });
  });

  describe("Jenkins Lookup3", () => {
    it("computes 32-bit hashlittle hash", () => {
      const h = jenkinsLookup3(data);
      expect(typeof h).toBe("number");
      expect(h).toBeGreaterThan(0);
      expect(jenkinsLookup3(data)).toBe(h);

      const mod = new Uint8Array(data);
      mod[0]! ^= 1;
      expect(jenkinsLookup3(mod)).not.toBe(h);
    });
  });
});
