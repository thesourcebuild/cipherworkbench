import { describe, it, expect } from "vitest";
import {
  shamirSplit,
  shamirCombine,
  slip39Generate,
  pedersenCommit,
  pedersenVerify,
  pedersenAdd,
} from "@ocs/algos";

const mockRng = (len: number) => {
  const buf = new Uint8Array(len);
  for (let i = 0; i < len; i++) buf[i] = (i * 37 + 13) & 0xff;
  return buf;
};

describe("Secret Sharing & Commitments", () => {
  describe("Shamir's Secret Sharing (SSSS)", () => {
    it("splits secret into (3, 5) threshold shares and recovers from any 3 shares", () => {
      const secret = new TextEncoder().encode("TopSecretShamirData123!");
      const shares = shamirSplit(secret, 5, 3, mockRng);
      expect(shares.length).toBe(5);

      // Reconstruct with shares [0, 1, 2]
      const recovered1 = shamirCombine([shares[0]!, shares[1]!, shares[2]!]);
      expect(new TextDecoder().decode(recovered1)).toBe("TopSecretShamirData123!");

      // Reconstruct with shares [1, 3, 4]
      const recovered2 = shamirCombine([shares[1]!, shares[3]!, shares[4]!]);
      expect(new TextDecoder().decode(recovered2)).toBe("TopSecretShamirData123!");

      // Reconstruct with shares [0, 2, 4]
      const recovered3 = shamirCombine([shares[0]!, shares[2]!, shares[4]!]);
      expect(new TextDecoder().decode(recovered3)).toBe("TopSecretShamirData123!");
    });

    it("formats and parses portable share tokens correctly", async () => {
      const secret = new TextEncoder().encode("HelloToken123");
      const { shamirSplit, formatShamirShare, parseShamirShare } = await import("@ocs/algos");
      const shares = shamirSplit(secret, 4, 2, mockRng);
      const token = formatShamirShare(shares[0]!);
      expect(token).toMatch(/^SSSS-1-[0-9a-f]+$/);

      const parsed = parseShamirShare(token);
      expect(parsed).not.toBeNull();
      expect(parsed!.x).toBe(1);
      expect(parsed!.y).toEqual(shares[0]!.y);
    });

    it("detects tampered shares when redundant shares are provided", async () => {
      const secret = new TextEncoder().encode("AuthenticSecretKey");
      const { shamirSplit, detectTamperedShares } = await import("@ocs/algos");
      const shares = shamirSplit(secret, 5, 3, mockRng);

      // Untampered 4 shares (threshold 3)
      const resClean = detectTamperedShares(shares.slice(0, 4), 3);
      expect(resClean.tampered).toBe(false);
      expect(new TextDecoder().decode(resClean.recoveredSecret!)).toBe("AuthenticSecretKey");

      // Corrupt share 2 in 5-share set (threshold 3, 2 redundant shares)
      const corrupted = shares.map((s) => ({ x: s.x, y: new Uint8Array(s.y) }));
      corrupted[1]!.y[0]! ^= 0xff; // flip bits in share #2

      const resTampered = detectTamperedShares(corrupted, 3);
      expect(resTampered.tampered).toBe(true);
      expect(resTampered.tamperedShareIndices).toContain(corrupted[1]!.x);
      expect(new TextDecoder().decode(resTampered.recoveredSecret!)).toBe("AuthenticSecretKey");
    });
  });

  describe("SLIP-0039 Shamir Mnemonic", () => {
    it("generates wordlist mnemonic shares with 10-bit checksums", () => {
      const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
      const shares = slip39Generate(secret, 5, 3, mockRng);
      expect(shares.length).toBe(5);
      expect(shares[0]!.words.length).toBeGreaterThanOrEqual(10);
    });
  });

  describe("Pedersen Commitments", () => {
    it("creates commitment and verifies opening", () => {
      const message = 1337n;
      const blindingFactor = 987654321n;
      const com = pedersenCommit(message, blindingFactor);

      expect(com.commitment).toBeGreaterThan(0n);
      const valid = pedersenVerify(com.commitment, message, blindingFactor);
      expect(valid).toBe(true);

      const invalid = pedersenVerify(com.commitment, 1338n, blindingFactor);
      expect(invalid).toBe(false);
    });

    it("satisfies additive homomorphism: C(m1 + m2, r1 + r2) = C(m1, r1) * C(m2, r2)", () => {
      const c1 = pedersenCommit(100n, 12345n);
      const c2 = pedersenCommit(250n, 67890n);

      const cCombined = pedersenAdd(c1, c2);
      const cDirect = pedersenCommit(350n, 80235n);

      expect(cCombined.commitment).toBe(cDirect.commitment);
    });
  });
});
