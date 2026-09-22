import { describe, expect, it } from "vitest";
import {
  generatePqcKeyPair,
  signWithPqc,
  verifyWithPqc,
  createPqcCertificate,
} from "../packages/tools/certificates/src/crypto/pqc";
import { parseX509Certificate } from "../packages/tools/certificates/src/asn1/x509";
import {
  verifyCertificateSignature,
  verifyCertificateChain,
} from "../packages/tools/certificates/src/asn1/chain-verifier";

describe("Phase 6: Post-Quantum Cryptography in X.509 (FIPS 204 ML-DSA)", () => {
  describe("ML-DSA Key Generation and Signing", () => {
    it("generates standards-compliant ML-DSA-44 key pair and verifies signature", () => {
      const kp = generatePqcKeyPair("ml-dsa-44");
      expect(kp.algorithm).toBe("ml-dsa-44");
      expect(kp.publicKey.length).toBe(1312);
      expect(kp.secretKey.length).toBe(2560);
      expect(kp.publicKeyPem).toContain("-----BEGIN PUBLIC KEY-----");
      expect(kp.privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");

      const message = new TextEncoder().encode("Quantum-safe test payload");
      const sig = signWithPqc("ml-dsa-44", message, kp.secretKey);
      expect(sig.length).toBe(2420);

      const isValid = verifyWithPqc("ml-dsa-44", message, sig, kp.publicKey);
      expect(isValid).toBe(true);

      const isInvalid = verifyWithPqc("ml-dsa-44", new Uint8Array([1, 2, 3]), sig, kp.publicKey);
      expect(isInvalid).toBe(false);
    });

    it("generates standards-compliant ML-DSA-65 key pair", () => {
      const kp = generatePqcKeyPair("ml-dsa-65");
      expect(kp.algorithm).toBe("ml-dsa-65");
      expect(kp.publicKey.length).toBe(1952);
      expect(kp.secretKey.length).toBe(4032);
      expect(kp.oid).toBe("2.16.840.1.101.3.4.3.18");
    });

    it("generates standards-compliant ML-DSA-87 key pair", () => {
      const kp = generatePqcKeyPair("ml-dsa-87");
      expect(kp.algorithm).toBe("ml-dsa-87");
      expect(kp.publicKey.length).toBe(2592);
      expect(kp.secretKey.length).toBe(4896);
      expect(kp.oid).toBe("2.16.840.1.101.3.4.3.19");
    });
  });

  describe("Post-Quantum X.509 Certificate Generation & Verification", () => {
    it("creates, parses, and cryptographically verifies an ML-DSA-65 certificate", async () => {
      const certRes = await createPqcCertificate({
        algorithm: "ml-dsa-65",
        commonName: "quantum.safe.workbench",
        organization: "Cipher Workbench PQC",
        san: "DNS:quantum.safe.workbench, spiffe://cluster.local/ns/pqc/sa/quantum-node",
        validityDays: 90,
        isCa: true,
      });

      expect(certRes.algorithm).toBe("ml-dsa-65");
      expect(certRes.certPem).toContain("-----BEGIN CERTIFICATE-----");
      expect(certRes.privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");

      // Parse with X.509 parser
      const parsed = parseX509Certificate(certRes.certDer);
      expect(parsed.subject.commonName).toBe("quantum.safe.workbench");
      expect(parsed.publicKey.keyType).toBe("ml-dsa-65");
      expect(parsed.publicKey.rawBytes?.length).toBe(1952);
      expect(parsed.signatureAlgorithmName).toBe("ML-DSA-65");
      expect(parsed.extensions.spiffeIds).toContain("spiffe://cluster.local/ns/pqc/sa/quantum-node");

      // Verify self-signature using chain-verifier engine
      const sigVerify = await verifyCertificateSignature(parsed, parsed);
      expect(sigVerify.valid).toBe(true);
      expect(sigVerify.error).toBeUndefined();

      // Verify complete chain
      const chainVerify = await verifyCertificateChain(certRes.certPem);
      expect(chainVerify.isValid).toBe(true);
      expect(chainVerify.isSelfSignedRoot).toBe(true);
      expect(chainVerify.nodes[0]?.signatureValid).toBe(true);
    });

    it("integrates seamlessly into createCertificate engine with ML-DSA-44", async () => {
      const { createCertificate } = await import("../packages/tools/certificates/src/asn1/create-cert");
      const created = await createCertificate({
        commonName: "pqc-leaf.local",
        san: "pqc-leaf.local, www.pqc-leaf.local",
        keyType: "ml-dsa-44",
        hashType: "sha256",
        validityDays: 60,
        isCa: false,
      });

      expect(created.certPem).toContain("-----BEGIN CERTIFICATE-----");
      const parsed = parseX509Certificate(created.certDer);
      expect(parsed.publicKey.keyType).toBe("ml-dsa-44");
      expect(parsed.signatureAlgorithmName).toBe("ML-DSA-44");

      const sigCheck = await verifyCertificateSignature(parsed, parsed);
      expect(sigCheck.valid).toBe(true);
    });

    it("integrates seamlessly into createCsr engine with ML-DSA-65", async () => {
      const { createCsr } = await import("../packages/tools/certificates/src/asn1/create-csr");
      const { parseCsr } = await import("../packages/tools/certificates/src/asn1/csr");

      const createdCsr = await createCsr({
        commonName: "pqc-service.internal",
        san: "pqc-service.internal",
        keyType: "ml-dsa-65",
        hashType: "sha256",
        organization: "",
        organizationalUnit: "",
        country: "",
        state: "",
        locality: "",
      });

      expect(createdCsr.csrPem).toContain("-----BEGIN CERTIFICATE REQUEST-----");
      const parsedCsr = parseCsr(createdCsr.csrDer);
      expect(parsedCsr.subject.commonName).toBe("pqc-service.internal");
      expect(parsedCsr.signatureAlgorithmName).toBe("ML-DSA-65");
    });
  });
});
