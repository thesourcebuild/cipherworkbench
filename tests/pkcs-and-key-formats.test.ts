import { describe, expect, it } from "vitest";
import {
  encodePkcs7CertBundle,
  decodePkcs7CertBundle,
} from "../packages/tools/certificates/src/asn1/pkcs7";
import {
  convertCertificate,
} from "../packages/tools/certificates/src/asn1/converter";
import {
  spkiToOpenSsh,
  sshMpint,
  sshString,
} from "../packages/tools/certificates/src/crypto/openssh";
import {
  spkiToJwk,
  computeJwkThumbprint,
  toBase64Url,
} from "../packages/tools/certificates/src/crypto/jwk";
import {
  generateKeyBundle,
} from "../packages/tools/certificates/src/crypto/keys";
import {
  parseCsr,
} from "../packages/tools/certificates/src/asn1/csr";
import { detectInputBytes } from "../packages/tools/certificates/src/asn1/pem";
import {
  RSA_CERTIFICATE_PEM,
  CA_CERTIFICATE_PEM,
  RSA_PRIVATE_KEY_PEM,
  ECDSA_CSR_PEM,
  CERTIFICATE_CHAIN_PEM,
} from "../packages/tools/certificates/src/samples";

describe("PKCS and Keystore Formats Comprehensive Suite", () => {
  const rsaCertDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
  const caCertDer = detectInputBytes(CA_CERTIFICATE_PEM).der;
  const rsaKeyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

  describe("PKCS#7 / CMS (.p7b / .p7c) SignedData Bundles", () => {
    it("encodes and decodes multi-certificate PKCS#7 bundles", () => {
      const bundle = encodePkcs7CertBundle([rsaCertDer, caCertDer]);
      expect(bundle.count).toBe(2);
      expect(bundle.pem).toContain("-----BEGIN PKCS7-----");
      expect(bundle.pem).toContain("-----END PKCS7-----");
      expect(bundle.der.length).toBeGreaterThan(100);

      // Decode from DER
      const extractedFromDer = decodePkcs7CertBundle(bundle.der);
      expect(extractedFromDer).toHaveLength(2);
      expect(extractedFromDer[0]?.der).toEqual(rsaCertDer);
      expect(extractedFromDer[1]?.der).toEqual(caCertDer);
      expect(extractedFromDer[0]?.pem).toContain("-----BEGIN CERTIFICATE-----");

      // Decode from PEM string
      const extractedFromPem = decodePkcs7CertBundle(new TextEncoder().encode(bundle.pem));
      expect(extractedFromPem).toHaveLength(2);
    });

    it("rejects encoding an empty list of certificates", () => {
      expect(() => encodePkcs7CertBundle([])).toThrow(
        /at least one certificate is required/i,
      );
    });

    it("safely handles malformed and truncated PKCS#7 inputs", () => {
      // Empty input
      expect(() => decodePkcs7CertBundle(new Uint8Array(0))).toThrow();

      // Truncated data
      const bundle = encodePkcs7CertBundle([rsaCertDer]);
      const truncated = bundle.der.slice(0, 20);
      expect(() => decodePkcs7CertBundle(truncated)).toThrow();

      // Valid ASN.1 but not PKCS#7 (passing raw certificate instead of SignedData)
      expect(() => decodePkcs7CertBundle(rsaCertDer)).toThrow(
        /unable to locate SignedData structure/i,
      );

      // Passing raw private key instead of SignedData
      expect(() => decodePkcs7CertBundle(rsaKeyDer)).toThrow(
        /unable to locate SignedData structure/i,
      );
    });
  });

  describe("OpenSSH Wire Formatting & Fingerprints", () => {
    it("formats RSA SPKI into ssh-rsa with valid SHA-256 fingerprint", async () => {
      const rsaKey = await generateKeyBundle("rsa-2048");
      const ssh = spkiToOpenSsh(rsaKey.spkiBytes, "rsa-2048", "admin@workbench");

      expect(ssh.keyType).toBe("ssh-rsa");
      expect(ssh.authorizedKeysLine).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ admin@workbench$/);
      expect(ssh.sha256Fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/=]+$/);
      expect(ssh.wireBlob.length).toBeGreaterThan(100);
    });

    it("formats ECDSA SPKI (P-256, P-384, P-521) into ecdsa-sha2-* keys", async () => {
      const p256 = await generateKeyBundle("ecdsa-p256");
      const ssh256 = spkiToOpenSsh(p256.spkiBytes, "ecdsa-p256", "p256@workbench");
      expect(ssh256.keyType).toBe("ecdsa-sha2-nistp256");
      expect(ssh256.authorizedKeysLine).toContain("ecdsa-sha2-nistp256 ");

      const p384 = await generateKeyBundle("ecdsa-p384");
      const ssh384 = spkiToOpenSsh(p384.spkiBytes, "ecdsa-p384", "p384@workbench");
      expect(ssh384.keyType).toBe("ecdsa-sha2-nistp384");

      const p521 = await generateKeyBundle("ecdsa-p521");
      const ssh521 = spkiToOpenSsh(p521.spkiBytes, "ecdsa-p521", "p521@workbench");
      expect(ssh521.keyType).toBe("ecdsa-sha2-nistp521");
    });

    it("formats Ed25519 SPKI into ssh-ed25519 keys", async () => {
      const edKey = await generateKeyBundle("ed25519");
      const ssh = spkiToOpenSsh(edKey.spkiBytes, "ed25519", "ed25519@workbench");

      expect(ssh.keyType).toBe("ssh-ed25519");
      expect(ssh.authorizedKeysLine).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+ ed25519@workbench$/);
      expect(ssh.sha256Fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/=]+$/);
    });

    it("correctly encodes sshString and sshMpint edge cases (RFC 4251)", () => {
      // sshString encodes 4-byte BE length + data
      const s = sshString("hello");
      expect(s).toEqual(new Uint8Array([0, 0, 0, 5, 104, 101, 108, 108, 111]));

      // sshMpint 0n -> 4 zero bytes (length 0)
      expect(sshMpint(0n)).toEqual(new Uint8Array([0, 0, 0, 0]));

      // Positive integer where MSB >= 0x80 requires prepended 0x00
      const msbSet = new Uint8Array([0x80, 0x01]);
      const mpintMsb = sshMpint(msbSet);
      expect(mpintMsb[0]).toBe(0);
      expect(mpintMsb[1]).toBe(0);
      expect(mpintMsb[2]).toBe(0);
      expect(mpintMsb[3]).toBe(3); // length 3
      expect(mpintMsb[4]).toBe(0x00); // prepended zero
      expect(mpintMsb[5]).toBe(0x80);
      expect(mpintMsb[6]).toBe(0x01);

      // Redundant leading zeroes are trimmed
      const padded = new Uint8Array([0x00, 0x00, 0x12, 0x34]);
      const mpintPadded = sshMpint(padded);
      expect(mpintPadded[3]).toBe(2); // length 2
      expect(mpintPadded[4]).toBe(0x12);
      expect(mpintPadded[5]).toBe(0x34);
    });

    it("throws on malformed SPKI input", () => {
      expect(() => spkiToOpenSsh(new Uint8Array([0x01, 0x02, 0x03]))).toThrow();
      expect(() => spkiToOpenSsh(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]))).toThrow(
        /expected SubjectPublicKeyInfo SEQUENCE/i,
      );
    });
  });

  describe("RFC 7517 / RFC 7638 JSON Web Keys (JWK)", () => {
    it("converts RSA SPKI to JWK and computes canonical thumbprint", async () => {
      const rsa = await generateKeyBundle("rsa-2048");
      const jwk = spkiToJwk(rsa.spkiBytes, "rsa-2048");

      expect(jwk.kty).toBe("RSA");
      if (jwk.kty === "RSA") {
        expect(jwk.alg).toBe("RS256");
        expect(jwk.n).toBeDefined();
        expect(jwk.e).toBeDefined();
        expect(jwk.kid).toBeDefined();

        const thumbprint = computeJwkThumbprint(jwk);
        expect(thumbprint).toBe(jwk.kid);
        expect(thumbprint.length).toBeGreaterThan(20);
      }
    });

    it("converts ECDSA SPKI (P-256) to EC JWK with accurate coordinates", async () => {
      const ec = await generateKeyBundle("ecdsa-p256");
      const jwk = spkiToJwk(ec.spkiBytes, "ecdsa-p256");

      expect(jwk.kty).toBe("EC");
      if (jwk.kty === "EC") {
        expect(jwk.crv).toBe("P-256");
        expect(jwk.alg).toBe("ES256");
        expect(jwk.x).toBeDefined();
        expect(jwk.y).toBeDefined();

        const thumbprint = computeJwkThumbprint(jwk);
        expect(thumbprint).toBe(jwk.kid);
      }
    });

    it("converts Ed25519 SPKI to OKP JWK", async () => {
      const ed = await generateKeyBundle("ed25519");
      const jwk = spkiToJwk(ed.spkiBytes, "ed25519");

      expect(jwk.kty).toBe("OKP");
      if (jwk.kty === "OKP") {
        expect(jwk.crv).toBe("Ed25519");
        expect(jwk.alg).toBe("EdDSA");
        expect(jwk.x).toBeDefined();

        const thumbprint = computeJwkThumbprint(jwk);
        expect(thumbprint).toBe(jwk.kid);
      }
    });

    it("correctly encodes base64url without padding", () => {
      const data = new Uint8Array([0xfb, 0xff, 0xbf]);
      const urlSafe = toBase64Url(data);
      expect(urlSafe).not.toContain("+");
      expect(urlSafe).not.toContain("/");
      expect(urlSafe).not.toContain("=");
    });
  });

  describe("Certificate & Keystore Converter Operations", () => {
    it("converts multi-cert PEM to PKCS#7 and back", async () => {
      const p7 = await convertCertificate(
        new TextEncoder().encode(CERTIFICATE_CHAIN_PEM),
        "pem-to-pkcs7",
      );

      expect(p7.operation).toBe("pem-to-pkcs7");
      expect(p7.text).toContain("-----BEGIN PKCS7-----");
      expect(p7.bytes).toBeDefined();

      const pemBack = await convertCertificate(p7.bytes!, "pkcs7-to-pem");
      expect(pemBack.operation).toBe("pkcs7-to-pem");
      expect(pemBack.text).toContain("Certificate 1");
      expect(pemBack.text).toContain("Certificate 2");
    });

    it("rejects pem-to-pkcs7 when no certificates are present in input", async () => {
      await expect(
        convertCertificate(new TextEncoder().encode(RSA_PRIVATE_KEY_PEM), "pem-to-pkcs7"),
      ).rejects.toThrow(/No certificates found/i);
    });

    it("extracts public key from RSA certificate", async () => {
      const res = await convertCertificate(
        new TextEncoder().encode(RSA_CERTIFICATE_PEM),
        "extract-public-key",
      );
      expect(res.operation).toBe("extract-public-key");
      expect(res.text).toContain("-----BEGIN PUBLIC KEY-----");
    });

    it("inspects PKCS#12 archives via converter", async () => {
      // First package to PKCS#12
      const combinedPem = `${RSA_CERTIFICATE_PEM}\n${RSA_PRIVATE_KEY_PEM}`;
      const pfx = await convertCertificate(
        new TextEncoder().encode(combinedPem),
        "pem-to-pkcs12",
        { password: "inspection-pass" },
      );

      const inspection = await convertCertificate(pfx.bytes!, "pkcs12-inspect");
      expect(inspection.operation).toBe("pkcs12-inspect");
      expect(inspection.text).toContain("PKCS#12 Container Inspection Report");
      expect(inspection.text).toContain("SafeBags Structure (2 bags)");
      expect(inspection.text).toContain("**MAC Present**: YES");
    });

    it("splits certificate chain bundle into distinct subject blocks", async () => {
      const res = await convertCertificate(
        new TextEncoder().encode(CERTIFICATE_CHAIN_PEM),
        "split-chain",
      );
      expect(res.operation).toBe("split-chain");
      expect(res.blocks?.length).toBe(2);
      expect(res.blocks![0]!.subject).toBeDefined();
      expect(res.blocks![1]!.subject).toBeDefined();
    });

    it("auto-detects input formats correctly", async () => {
      // 1. Certificate
      const autoCert = await convertCertificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM), "auto");
      expect(autoCert.detectedType).toBe("X.509 Certificate");

      // 2. CSR
      const autoCsr = await convertCertificate(new TextEncoder().encode(ECDSA_CSR_PEM), "auto");
      expect(autoCsr.detectedType).toBe("PKCS#10 Certificate Request");

      // 3. PKCS#7
      const p7 = await convertCertificate(new TextEncoder().encode(CERTIFICATE_CHAIN_PEM), "pem-to-pkcs7");
      const autoP7 = await convertCertificate(p7.bytes!, "auto");
      expect(autoP7.detectedType).toContain("PKCS#7");
    });
  });

  describe("PKCS#10 Certificate Signing Requests (CSR)", () => {
    it("parses ECDSA CSR attributes, SANs, and signature", async () => {
      const parsed = parseCsr(new TextEncoder().encode(ECDSA_CSR_PEM));
      expect(parsed.subject.commonName).toBe("api.workbench.local");
      expect(parsed.subject.organization).toBe("Cipher Workbench");
      expect(parsed.publicKey.algorithmName).toContain("Elliptic Curve");
      expect(parsed.requestedExtensions.sans).toContain("DNS:api.workbench.local");
      const sigResult = await parsed.verifySelfSignature();
      expect(sigResult.valid).toBe(true);
    });

    it("safely handles malformed and truncated CSRs", () => {
      expect(() => parseCsr(new Uint8Array(0))).toThrow();
      expect(() => parseCsr(new Uint8Array([0x30, 0x05, 0x02, 0x01, 0x00]))).toThrow();
    });
  });
});
