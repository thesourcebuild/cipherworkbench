import { describe, expect, it } from "vitest";
import {
  createCertificate,
  createCsr,
  generateMtlsSuite,
  parseCsr,
  parseX509Certificate,
  verifyCertificateChain,
  signCsr,
} from "@ocs/certificates";

describe("SHA-3 Certificates & CSRs (NIST FIPS 202 / CSOR)", () => {
  describe("RSA with SHA3-256, SHA3-384, SHA3-512", () => {
    it("generates and verifies RSA-2048 certificate with SHA3-256", async () => {
      const result = await createCertificate({
        commonName: "rsa-sha3-256.test",
        organization: "Security Lab",
        country: "US",
        keyType: "rsa-2048",
        hashType: "sha3-256",
        validityDays: 365,
        isCa: true,
      });

      expect(result.certPem).toContain("-----BEGIN CERTIFICATE-----");
      expect(result.signatureAlgorithm).toBe("sha3-256WithRSAEncryption");

      const parsed = parseX509Certificate(new TextEncoder().encode(result.certPem));
      expect(parsed.signatureAlgorithmName).toBe("sha3-256WithRSAEncryption");
      expect(parsed.signatureAlgorithmOid).toBe("2.16.840.1.101.3.4.3.14");
      expect(parsed.subject.commonName).toBe("rsa-sha3-256.test");

      const chain = await verifyCertificateChain(result.certPem);
      expect(chain.isValid).toBe(true);
      expect(chain.nodes[0]?.signatureValid).toBe(true);
    });

    it("generates and verifies RSA-2048 certificate with SHA3-384", async () => {
      const result = await createCertificate({
        commonName: "rsa-sha3-384.test",
        organization: "Security Lab",
        country: "US",
        keyType: "rsa-2048",
        hashType: "sha3-384",
        validityDays: 365,
        isCa: true,
      });

      expect(result.signatureAlgorithm).toBe("sha3-384WithRSAEncryption");
      const parsed = parseX509Certificate(new TextEncoder().encode(result.certPem));
      expect(parsed.signatureAlgorithmOid).toBe("2.16.840.1.101.3.4.3.15");

      const chain = await verifyCertificateChain(result.certPem);
      expect(chain.isValid).toBe(true);
      expect(chain.nodes[0]?.signatureValid).toBe(true);
    });

    it("generates and verifies RSA-2048 certificate with SHA3-512", async () => {
      const result = await createCertificate({
        commonName: "rsa-sha3-512.test",
        organization: "Security Lab",
        country: "US",
        keyType: "rsa-2048",
        hashType: "sha3-512",
        validityDays: 365,
        isCa: true,
      });

      expect(result.signatureAlgorithm).toBe("sha3-512WithRSAEncryption");
      const parsed = parseX509Certificate(new TextEncoder().encode(result.certPem));
      expect(parsed.signatureAlgorithmOid).toBe("2.16.840.1.101.3.4.3.16");

      const chain = await verifyCertificateChain(result.certPem);
      expect(chain.isValid).toBe(true);
      expect(chain.nodes[0]?.signatureValid).toBe(true);
    });

    it("generates RSA-2048 CSR with SHA3-256 and verifies self-signature", async () => {
      const result = await createCsr({
        commonName: "rsa-csr-sha3-256.test",
        organization: "Security Lab",
        country: "US",
        keyType: "rsa-2048",
        hashType: "sha3-256",
        san: "DNS:rsa-csr-sha3-256.test, IP:127.0.0.1",
      });

      expect(result.csrPem).toContain("-----BEGIN CERTIFICATE REQUEST-----");
      expect(result.signatureAlgorithm).toBe("sha3-256WithRSAEncryption");
      expect(result.verified).toBe(true);

      const parsed = parseCsr(result.csrPem);
      expect(parsed.signatureAlgorithmName).toBe("sha3-256WithRSAEncryption");
      const sigVerify = await parsed.verifySelfSignature();
      expect(sigVerify.valid).toBe(true);
    });

    it("generates RSA-2048 CSR with SHA3-512 and verifies self-signature", async () => {
      const result = await createCsr({
        commonName: "rsa-csr-sha3-512.test",
        organization: "Security Lab",
        country: "US",
        keyType: "rsa-2048",
        hashType: "sha3-512",
      });

      expect(result.signatureAlgorithm).toBe("sha3-512WithRSAEncryption");
      expect(result.verified).toBe(true);

      const parsed = parseCsr(result.csrPem);
      expect(parsed.signatureAlgorithmName).toBe("sha3-512WithRSAEncryption");
      const sigVerify = await parsed.verifySelfSignature();
      expect(sigVerify.valid).toBe(true);
    });
  });

  describe("ECDSA with SHA3-256, SHA3-384, SHA3-512", () => {
    it("generates and verifies ECDSA P-256 certificate with SHA3-256", async () => {
      const result = await createCertificate({
        commonName: "ec-p256-sha3-256.test",
        organization: "Security Lab",
        country: "US",
        keyType: "ecdsa-p256",
        hashType: "sha3-256",
        validityDays: 365,
        isCa: true,
      });

      expect(result.signatureAlgorithm).toBe("ecdsa-with-SHA3-256");
      const parsed = parseX509Certificate(new TextEncoder().encode(result.certPem));
      expect(parsed.signatureAlgorithmName).toBe("ecdsa-with-SHA3-256");
      expect(parsed.signatureAlgorithmOid).toBe("2.16.840.1.101.3.4.3.10");

      const chain = await verifyCertificateChain(result.certPem);
      expect(chain.isValid).toBe(true);
      expect(chain.nodes[0]?.signatureValid).toBe(true);
    });

    it("generates and verifies ECDSA P-384 certificate with SHA3-384", async () => {
      const result = await createCertificate({
        commonName: "ec-p384-sha3-384.test",
        organization: "Security Lab",
        country: "US",
        keyType: "ecdsa-p384",
        hashType: "sha3-384",
        validityDays: 365,
        isCa: true,
      });

      expect(result.signatureAlgorithm).toBe("ecdsa-with-SHA3-384");
      const parsed = parseX509Certificate(new TextEncoder().encode(result.certPem));
      expect(parsed.signatureAlgorithmName).toBe("ecdsa-with-SHA3-384");
      expect(parsed.signatureAlgorithmOid).toBe("2.16.840.1.101.3.4.3.11");

      const chain = await verifyCertificateChain(result.certPem);
      expect(chain.isValid).toBe(true);
      expect(chain.nodes[0]?.signatureValid).toBe(true);
    });

    it("generates and verifies ECDSA P-521 certificate with SHA3-512", async () => {
      const result = await createCertificate({
        commonName: "ec-p521-sha3-512.test",
        organization: "Security Lab",
        country: "US",
        keyType: "ecdsa-p521",
        hashType: "sha3-512",
        validityDays: 365,
        isCa: true,
      });

      expect(result.signatureAlgorithm).toBe("ecdsa-with-SHA3-512");
      const parsed = parseX509Certificate(new TextEncoder().encode(result.certPem));
      expect(parsed.signatureAlgorithmName).toBe("ecdsa-with-SHA3-512");
      expect(parsed.signatureAlgorithmOid).toBe("2.16.840.1.101.3.4.3.12");

      const chain = await verifyCertificateChain(result.certPem);
      expect(chain.isValid).toBe(true);
      expect(chain.nodes[0]?.signatureValid).toBe(true);
    });

    it("generates ECDSA P-256 CSR with SHA3-256 and verifies self-signature", async () => {
      const result = await createCsr({
        commonName: "ec-csr-sha3-256.test",
        organization: "Security Lab",
        country: "US",
        keyType: "ecdsa-p256",
        hashType: "sha3-256",
        san: "DNS:ec-csr-sha3-256.test",
      });

      expect(result.signatureAlgorithm).toBe("ecdsa-with-SHA3-256");
      expect(result.verified).toBe(true);

      const parsed = parseCsr(result.csrPem);
      expect(parsed.signatureAlgorithmName).toBe("ecdsa-with-SHA3-256");
      const sigVerify = await parsed.verifySelfSignature();
      expect(sigVerify.valid).toBe(true);
    });

    it("generates ECDSA P-384 CSR with SHA3-384 and verifies self-signature", async () => {
      const result = await createCsr({
        commonName: "ec-csr-sha3-384.test",
        organization: "Security Lab",
        country: "US",
        keyType: "ecdsa-p384",
        hashType: "sha3-384",
      });

      expect(result.signatureAlgorithm).toBe("ecdsa-with-SHA3-384");
      expect(result.verified).toBe(true);

      const parsed = parseCsr(result.csrPem);
      expect(parsed.signatureAlgorithmName).toBe("ecdsa-with-SHA3-384");
      const sigVerify = await parsed.verifySelfSignature();
      expect(sigVerify.valid).toBe(true);
    });

    it("generates ECDSA P-521 CSR with SHA3-512 and verifies self-signature", async () => {
      const result = await createCsr({
        commonName: "ec-csr-sha3-512.test",
        organization: "Security Lab",
        country: "US",
        keyType: "ecdsa-p521",
        hashType: "sha3-512",
      });

      expect(result.signatureAlgorithm).toBe("ecdsa-with-SHA3-512");
      expect(result.verified).toBe(true);

      const parsed = parseCsr(result.csrPem);
      expect(parsed.signatureAlgorithmName).toBe("ecdsa-with-SHA3-512");
      const sigVerify = await parsed.verifySelfSignature();
      expect(sigVerify.valid).toBe(true);
    });
  });

  describe("CA Issuance & Chains with SHA-3", () => {
    it("issues CA-signed leaf certificate using RSA with SHA3-256 and verifies full chain", async () => {
      const ca = await createCertificate({
        commonName: "SHA3 RSA Root CA",
        organization: "Lab CA",
        country: "US",
        keyType: "rsa-2048",
        hashType: "sha3-256",
        validityDays: 3650,
        isCa: true,
      });

      const leaf = await createCertificate({
        commonName: "leaf.sha3.local",
        organization: "Lab CA",
        country: "US",
        keyType: "rsa-2048",
        hashType: "sha3-256",
        validityDays: 365,
        isCa: false,
        san: "DNS:leaf.sha3.local",
        issuanceMode: "ca-signed",
        caCertPem: ca.certPem,
        caPrivateKeyPem: ca.privateKeyPem,
      });

      expect(leaf.signatureAlgorithm).toBe("sha3-256WithRSAEncryption");
      const fullChainPem = `${leaf.certPem}\n${ca.certPem}`;
      const chainResult = await verifyCertificateChain(fullChainPem);
      expect(chainResult.isValid).toBe(true);
      expect(chainResult.nodes[0]?.signatureValid).toBe(true);
      expect(chainResult.nodes[1]?.signatureValid).toBe(true);
    });

    it("generates full mTLS Suite with SHA3-256 and verifies chain", async () => {
      const suite = await generateMtlsSuite({
        pkiHierarchy: "2-tier",
        caCommonName: "mTLS SHA3 Root CA",
        serverCommonName: "server.mtls-sha3.internal",
        serverSan: "DNS:server.mtls-sha3.internal, IP:127.0.0.1",
        clientCommonName: "client-sha3",
        rootKeyType: "ecdsa-p256",
        rootHashType: "sha3-256",
        serverKeyType: "ecdsa-p256",
        serverHashType: "sha3-256",
        clientKeyType: "ecdsa-p256",
        clientHashType: "sha3-256",
        validityDays: 365,
        p12Password: "testpass",
      });

      expect(suite.ca.certPem).toContain("-----BEGIN CERTIFICATE-----");
      expect(suite.server.certPem).toContain("-----BEGIN CERTIFICATE-----");
      expect(suite.client.certPem).toContain("-----BEGIN CERTIFICATE-----");

      const serverResult = await verifyCertificateChain(suite.server.chainPem);
      expect(serverResult.isValid).toBe(true);

      const clientResult = await verifyCertificateChain(suite.client.chainPem);
      expect(clientResult.isValid).toBe(true);
    });

    it("signs a CSR using csr-signer with SHA3-256", async () => {
      const csrRes = await createCsr({
        commonName: "signed-leaf.sha3.local",
        keyType: "ecdsa-p256",
        hashType: "sha3-256",
      });

      const signed = await signCsr({
        csrInput: csrRes.csrPem,
        hashType: "sha3-256",
        validityDays: 365,
      });

      expect(signed.certPem).toContain("-----BEGIN CERTIFICATE-----");
      const parsedCert = parseX509Certificate(new TextEncoder().encode(signed.certPem));
      expect(parsedCert.signatureAlgorithmName).toBe("ecdsa-with-SHA3-256");

      const chain = `${signed.certPem}\n${signed.caCertPem}`;
      const chainResult = await verifyCertificateChain(chain);
      expect(chainResult.isValid).toBe(true);
    });

    it("emits standards-compatible SHA3 certificate and CSR metadata", async () => {
      const rsaCert = await createCertificate({
        commonName: "rsa-sha3-256-metadata.test",
        keyType: "rsa-2048",
        hashType: "sha3-256",
        validityDays: 30,
        isCa: true,
      });

      const parsedCert = parseX509Certificate(new TextEncoder().encode(rsaCert.certPem));
      expect(parsedCert.signatureAlgorithmName).toBe("sha3-256WithRSAEncryption");
      expect(parsedCert.signatureAlgorithmOid).toBe("2.16.840.1.101.3.4.3.14");
      expect(parsedCert.subject.commonName).toBe("rsa-sha3-256-metadata.test");

      const ecCsr = await createCsr({
        commonName: "ec-sha3-256-metadata.test",
        keyType: "ecdsa-p256",
        hashType: "sha3-256",
      });

      const parsedCsr = parseCsr(ecCsr.csrPem);
      expect(parsedCsr.signatureAlgorithmName).toBe("ecdsa-with-SHA3-256");
      expect(parsedCsr.subject.commonName).toBe("ec-sha3-256-metadata.test");
      await expect(parsedCsr.verifySelfSignature()).resolves.toMatchObject({ valid: true });
    });
  });
});
