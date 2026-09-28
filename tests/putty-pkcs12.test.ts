import { describe, expect, it } from "vitest";
import {
  exportToPpkV3,
  parsePpk,
} from "../packages/tools/certificates/src/crypto/putty";
import {
  encodePkcs12Archive,
  decodePkcs12Archive,
  inspectPkcs12,
  changePkcs12Password,
} from "../packages/tools/certificates/src/asn1/pkcs12";
import { detectInputBytes } from "../packages/tools/certificates/src/asn1/pem";
import {
  RSA_PRIVATE_KEY_PEM,
  RSA_CERTIFICATE_PEM,
  CA_CERTIFICATE_PEM,
} from "../packages/tools/certificates/src/samples";
import { convertCertificate } from "../packages/tools/certificates/src/asn1/converter";

describe("Phase 5: Key Formats & Keystores", () => {
  describe("PuTTY Private Key (.ppk v3) Exporter & Parser", () => {
    it("exports an RSA private key to valid PuTTY v3 format and verifies MAC", () => {
      const res = exportToPpkV3({
        keyInput: RSA_PRIVATE_KEY_PEM,
        comment: "test-rsa-key",
      });

      expect(res.keyType).toBe("ssh-rsa");
      expect(res.comment).toBe("test-rsa-key");
      expect(res.macHex.length).toBe(64);
      expect(res.ppkText).toContain("PuTTY-User-Key-File-3: ssh-rsa");
      expect(res.ppkText).toContain("Encryption: none");
      expect(res.ppkText).toContain("Comment: test-rsa-key");
      expect(res.ppkText).toContain("Public-Lines:");
      expect(res.ppkText).toContain("Private-Lines:");
      expect(res.ppkText).toContain(`Private-MAC: ${res.macHex}`);

      // Parse and cryptographically verify the HMAC-SHA-256 MAC
      const parsed = parsePpk(res.ppkText);
      expect(parsed.version).toBe(3);
      expect(parsed.keyType).toBe("ssh-rsa");
      expect(parsed.comment).toBe("test-rsa-key");
      expect(parsed.isMacValid).toBe(true);
    });

    it("integrates with convertCertificate (pem-to-ppk operation)", async () => {
      const conv = await convertCertificate(
        new TextEncoder().encode(RSA_PRIVATE_KEY_PEM),
        "pem-to-ppk",
      );

      expect(conv.operation).toBe("pem-to-ppk");
      expect(conv.text).toContain("PuTTY-User-Key-File-3: ssh-rsa");
      expect(conv.summary).toContain("PuTTY Private Key v3");
    });

    it("detects tampering with PuTTY PPK private MAC", () => {
      const res = exportToPpkV3({
        keyInput: RSA_PRIVATE_KEY_PEM,
        comment: "tamper-mac-test",
      });

      // Alter the MAC string by 1 hex digit
      const tamperedMac = res.macHex[0] === "a" ? "b" + res.macHex.slice(1) : "a" + res.macHex.slice(1);
      const tamperedPpk = res.ppkText.replace(`Private-MAC: ${res.macHex}`, `Private-MAC: ${tamperedMac}`);

      const parsed = parsePpk(tamperedPpk);
      expect(parsed.isMacValid).toBe(false);
    });

    it("detects payload modification in PuTTY PPK private key lines", () => {
      const res = exportToPpkV3({
        keyInput: RSA_PRIVATE_KEY_PEM,
        comment: "tamper-payload-test",
      });

      // Find a line of private key base64 data and alter characters
      const lines = res.ppkText.split("\n");
      const privLineIdx = lines.findIndex((l) => l.startsWith("Private-Lines:")) + 1;
      expect(privLineIdx).toBeGreaterThan(0);

      const origLine = lines[privLineIdx]!;
      lines[privLineIdx] = origLine.slice(0, 5) + (origLine[5] === "A" ? "B" : "A") + origLine.slice(6);
      const tamperedPpk = lines.join("\n");

      const parsed = parsePpk(tamperedPpk);
      expect(parsed.isMacValid).toBe(false);
    });
  });

  describe("PKCS#12 Keystore Inspector & Rekeying", () => {
    it("inspects PKCS#12 container SafeBags, attributes, and MAC", async () => {
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const keyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

      const pfx = await encodePkcs12Archive({
        certDers: [certDer],
        privateKeyDer: keyDer,
        password: "workbench-pass",
        friendlyName: "Workbench Certificate",
      });

      const inspection = inspectPkcs12(pfx.der);
      expect(inspection.version).toBe(3);
      expect(inspection.hasMac).toBe(true);
      expect(inspection.macIterations).toBe(10000);
      expect(inspection.macSaltHex).toBeDefined();
      expect(inspection.certCount).toBe(1);
      expect(inspection.hasPrivateKey).toBe(true);
      expect(inspection.isEncrypted).toBe(true);

      const friendlyBag = inspection.bags.find((b) => b.friendlyName);
      expect(friendlyBag?.friendlyName).toBe("Workbench Certificate");
    });

    it("changes password of a PKCS#12 container and re-encrypts", async () => {
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const keyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

      const original = await encodePkcs12Archive({
        certDers: [certDer],
        privateKeyDer: keyDer,
        password: "old-password",
      });

      // Change password
      const rekeyed = await changePkcs12Password(
        original.der,
        "old-password",
        "new-strong-password",
        "Rekeyed Cert",
      );

      expect(rekeyed.der.length).toBeGreaterThan(100);

      // Verify with new password
      const decodedNew = await decodePkcs12Archive(rekeyed.der, "new-strong-password");
      expect(decodedNew.certs).toHaveLength(1);
      expect(decodedNew.privateKey).toBeDefined();

      // Verify wrong passwords reject deterministically
      for (const badPass of ["old-password", "wrong", "another-pass", ""]) {
        await expect(decodePkcs12Archive(rekeyed.der, badPass)).rejects.toThrow();
      }
    });

    it("handles unencrypted PKCS#12 containers with plaintext keyBag", async () => {
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const keyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

      const unencrypted = await encodePkcs12Archive({
        certDers: [certDer],
        privateKeyDer: keyDer,
        friendlyName: "Unencrypted Key",
      });

      expect(unencrypted.encrypted).toBe(false);

      const inspection = inspectPkcs12(unencrypted.der);
      expect(inspection.hasMac).toBe(false);
      expect(inspection.isEncrypted).toBe(false);
      expect(inspection.certCount).toBe(1);
      expect(inspection.hasPrivateKey).toBe(true);

      // Unencrypted archive decodes without password
      const decoded = await decodePkcs12Archive(unencrypted.der, "");
      expect(decoded.certs).toHaveLength(1);
      expect(decoded.privateKey).toBeDefined();
      expect(decoded.privateKey?.der.length).toBe(keyDer.length);
    });

    it("supports certificate-only PKCS#12 archives without private keys", async () => {
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const caDer = detectInputBytes(CA_CERTIFICATE_PEM).der;

      const certOnlyPfx = await encodePkcs12Archive({
        certDers: [certDer, caDer],
        password: "bundle-password",
        friendlyName: "Trust Bundle",
      });

      expect(certOnlyPfx.hasPrivateKey).toBe(false);
      expect(certOnlyPfx.certCount).toBe(2);

      const inspection = inspectPkcs12(certOnlyPfx.der);
      expect(inspection.hasPrivateKey).toBe(false);
      expect(inspection.certCount).toBe(2);
      expect(inspection.hasMac).toBe(true);

      // Decode with valid password
      const decoded = await decodePkcs12Archive(certOnlyPfx.der, "bundle-password");
      expect(decoded.certs).toHaveLength(2);
      expect(decoded.privateKey).toBeUndefined();

      // Wrong password fails MAC
      await expect(decodePkcs12Archive(certOnlyPfx.der, "wrong-bundle-pass")).rejects.toThrow();
    });

    it("preserves multi-certificate chains in order", async () => {
      const leafDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const caDer = detectInputBytes(CA_CERTIFICATE_PEM).der;
      const keyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

      const chainPfx = await encodePkcs12Archive({
        certDers: [leafDer, caDer],
        privateKeyDer: keyDer,
        password: "chain-pass",
      });

      const decoded = await decodePkcs12Archive(chainPfx.der, "chain-pass");
      expect(decoded.certs).toHaveLength(2);
      expect(decoded.certs[0]?.der).toEqual(leafDer);
      expect(decoded.certs[1]?.der).toEqual(caDer);
      expect(decoded.privateKey).toBeDefined();
    });

    it("detects cryptographic bit-level tampering in AuthenticatedSafe and MacData", async () => {
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const keyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

      const pfx = await encodePkcs12Archive({
        certDers: [certDer],
        privateKeyDer: keyDer,
        password: "integrity-pass",
      });

      // Tamper 1: Flip a bit in the middle of the payload
      const tamperedPayload = new Uint8Array(pfx.der);
      const flipIdx = Math.floor(tamperedPayload.length / 2);
      tamperedPayload[flipIdx] = tamperedPayload[flipIdx]! ^ 0x01;

      await expect(decodePkcs12Archive(tamperedPayload, "integrity-pass")).rejects.toThrow(
        /MAC verification failed|corrupted/i,
      );

      // Tamper 2: Corrupt the last byte (part of MacData)
      const tamperedMac = new Uint8Array(pfx.der);
      tamperedMac[tamperedMac.length - 2] = tamperedMac[tamperedMac.length - 2]! ^ 0xff;

      await expect(decodePkcs12Archive(tamperedMac, "integrity-pass")).rejects.toThrow();
    });

    it("supports Unicode, emojis, and special character passwords via RFC 7292 BMPString", async () => {
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const keyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;
      const complexPass = "P@ssw0rd!🔑 2026 üñîçødé 🛡️";

      const pfx = await encodePkcs12Archive({
        certDers: [certDer],
        privateKeyDer: keyDer,
        password: complexPass,
      });

      // Correct Unicode password decodes cleanly
      const decoded = await decodePkcs12Archive(pfx.der, complexPass);
      expect(decoded.certs).toHaveLength(1);
      expect(decoded.privateKey).toBeDefined();

      // Slight variant without emoji rejects
      await expect(decodePkcs12Archive(pfx.der, "P@ssw0rd! 2026 unicode")).rejects.toThrow();
    });

    it("stress tests password rejection across 50 attempts to prove 0% padding false positives", async () => {
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const keyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

      const pfx = await encodePkcs12Archive({
        certDers: [certDer],
        privateKeyDer: keyDer,
        password: "correct-master-key",
      });

      // Run 50 distinct incorrect password attempts
      for (let i = 0; i < 50; i++) {
        const candidate = `wrong-guess-#${i}-${Math.random().toString(36).slice(2)}`;
        await expect(decodePkcs12Archive(pfx.der, candidate)).rejects.toThrow();
      }
    });

    it("safely rejects truncated, empty, or malformed archives", async () => {
      // Empty buffer
      await expect(decodePkcs12Archive(new Uint8Array(0), "pass")).rejects.toThrow();

      // Random junk bytes
      const randomJunk = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03]);
      await expect(decodePkcs12Archive(randomJunk, "pass")).rejects.toThrow();

      // Truncated PFX
      const certDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
      const pfx = await encodePkcs12Archive({ certDers: [certDer] });
      const truncated = pfx.der.slice(0, 15);
      await expect(decodePkcs12Archive(truncated)).rejects.toThrow();
    });
  });
});
