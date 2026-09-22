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

      // Verify old password fails
      await expect(decodePkcs12Archive(rekeyed.der, "old-password")).rejects.toThrow();
    });
  });
});
