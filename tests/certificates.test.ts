import { describe, expect, it } from "vitest";
import {
  CA_CERTIFICATE_PEM,
  CERTIFICATE_CHAIN_PEM,
  convertCertificate,
  createCertificate,
  createCsr,
  ECDSA_CSR_PEM,
  parseAsn1,
  parseCsr,
  parseX509Certificate,
  RSA_CERTIFICATE_PEM,
  UniversalTag,
} from "@ocs/certificates";
import { loadTool } from "@ocs/registry";

describe("ASN.1 DER Parser", () => {
  it("decodes primitive integers and sequences", () => {
    // DER bytes for: SEQUENCE { INTEGER 42, BOOLEAN true }
    // 30 06 02 01 2A 01 01 FF
    const bytes = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x2a, 0x01, 0x01, 0xff]);
    const node = parseAsn1(bytes);
    expect(node.tagNumber).toBe(UniversalTag.Sequence);
    expect(node.children.length).toBe(2);
    expect(node.children[0]!.asIntegerNumber()).toBe(42);
    expect(node.children[1]!.asBoolean()).toBe(true);
  });

  it("decodes OIDs correctly", () => {
    // DER bytes for OID: 2.5.4.3 (id-at-commonName) -> 06 03 55 04 03
    const bytes = new Uint8Array([0x06, 0x03, 0x55, 0x04, 0x03]);
    const node = parseAsn1(bytes);
    expect(node.asOid()).toBe("2.5.4.3");
  });

  it("decodes multi-byte long-form lengths", () => {
    // 256 zero bytes in an OCTET STRING: 04 82 01 00 [256 zeros]
    const header = new Uint8Array([0x04, 0x82, 0x01, 0x00]);
    const payload = new Uint8Array(256);
    const combined = new Uint8Array(header.length + payload.length);
    combined.set(header, 0);
    combined.set(payload, header.length);
    const node = parseAsn1(combined);
    expect(node.tagNumber).toBe(UniversalTag.OctetString);
    expect(node.length).toBe(256);
    expect(node.valueBytes.length).toBe(256);
  });
});

describe("X.509 Certificate Parser", () => {
  it("parses RSA TLS certificate and extracts fields", () => {
    const cert = parseX509Certificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM));
    expect(cert.version).toBe(3);
    expect(cert.serialNumber).not.toBe("");
    expect(cert.signatureAlgorithmName).toContain("RSA");

    // Subject DN
    expect(cert.subject.dn).toContain("CN=workbench.local");
    expect(cert.subject.dn).toContain("O=Cipher Workbench");
    expect(cert.subject.dn).toContain("C=US");

    // Issuer DN (self-signed)
    expect(cert.issuer.dn).toBe(cert.subject.dn);

    // Validity
    expect(cert.validity.status).toBe("valid");
    expect(cert.validity.notBefore.getUTCFullYear()).toBe(2026);
    expect(cert.validity.notAfter.getUTCFullYear()).toBe(2036);
    expect(cert.validity.daysRemaining).toBeGreaterThan(3000);

    // Public key
    expect(cert.publicKey.algorithmName).toBe("RSA");
    expect(cert.publicKey.rsaBits).toBe(2048);
    expect(cert.publicKey.spkiPem).toContain("-----BEGIN PUBLIC KEY-----");

    // Extensions
    expect(cert.extensions.sans).toContain("DNS:workbench.local");
    expect(cert.extensions.sans).toContain("DNS:*.workbench.local");
    expect(cert.extensions.sans).toContain("IP:127.0.0.1");

    expect(cert.extensions.basicConstraints?.isCa).toBe(false);
    expect(cert.extensions.keyUsages).toContain("digitalSignature");
    expect(cert.extensions.keyUsages).toContain("keyEncipherment");
    expect(cert.extensions.extendedKeyUsages.some((u) => u.includes("serverAuth"))).toBe(true);

    // Fingerprints
    expect(cert.fingerprints.sha256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(cert.fingerprints.sha1).toMatch(/^([0-9A-F]{2}:){19}[0-9A-F]{2}$/);

    // Text dump
    expect(cert.textDump).toContain("Certificate:");
    expect(cert.textDump).toContain("CN=workbench.local");
  });

  it("parses Root CA certificate", () => {
    const cert = parseX509Certificate(new TextEncoder().encode(CA_CERTIFICATE_PEM));
    expect(cert.subject.dn).toContain("CN=Workbench Root CA");
    expect(cert.extensions.basicConstraints?.isCa).toBe(true);
    expect(cert.extensions.basicConstraints?.pathLenConstraint).toBe(1);
    expect(cert.extensions.keyUsages).toContain("keyCertSign");
    expect(cert.extensions.keyUsages).toContain("cRLSign");
  });
});

describe("PKCS#10 CSR Parser & Verification", () => {
  it("parses ECDSA CSR and verifies self-signature", async () => {
    const csr = parseCsr(new TextEncoder().encode(ECDSA_CSR_PEM));
    expect(csr.version).toBe(0);
    expect(csr.subject.dn).toContain("CN=api.workbench.local");
    expect(csr.subject.dn).toContain("O=Cipher Workbench");

    // Public key
    expect(csr.publicKey.algorithmName).toBe("Elliptic Curve (EC)");
    expect(csr.publicKey.curveName).toContain("P-256");

    // Requested SAN
    expect(csr.requestedExtensions.sans).toContain("DNS:api.workbench.local");

    // Cryptographic self-signature verification
    const verify = await csr.verifySelfSignature();
    expect(verify.valid).toBe(true);

    // Text dump
    expect(csr.textDump).toContain("Certificate Request:");
    expect(csr.textDump).toContain("api.workbench.local");
  });
});

describe("Certificate Format Converter", () => {
  it("converts PEM to DER binary", async () => {
    const res = await convertCertificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM), "pem-to-der");
    expect(res.operation).toBe("pem-to-der");
    expect(res.bytes).toBeDefined();
    expect(res.bytes![0]).toBe(0x30); // ASN.1 SEQUENCE
  });

  it("converts DER binary to PEM", async () => {
    const derRes = await convertCertificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM), "pem-to-der");
    const der = derRes.bytes!;
    const res = await convertCertificate(der, "der-to-pem");
    expect(res.operation).toBe("der-to-pem");
    expect(res.text).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("converts PEM to CER and CER to PEM", async () => {
    const cerRes = await convertCertificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM), "pem-to-cer");
    expect(cerRes.operation).toBe("pem-to-cer");
    expect(cerRes.bytes).toBeDefined();

    const pemRes = await convertCertificate(cerRes.bytes!, "cer-to-pem");
    expect(pemRes.operation).toBe("cer-to-pem");
    expect(pemRes.text).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("packages certificates into PKCS#7 (.p7b) and extracts them back", async () => {
    const p7b = await convertCertificate(new TextEncoder().encode(CERTIFICATE_CHAIN_PEM), "pem-to-pkcs7");
    expect(p7b.operation).toBe("pem-to-pkcs7");
    expect(p7b.text).toContain("-----BEGIN PKCS7-----");
    expect(p7b.bytes).toBeDefined();

    // Extract back
    const extracted = await convertCertificate(p7b.bytes!, "pkcs7-to-pem");
    expect(extracted.operation).toBe("pkcs7-to-pem");
    expect(extracted.text).toContain("Certificate 1");
    expect(extracted.text).toContain("Certificate 2");
    expect(extracted.text).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("packages cert and key into PKCS#12 (.pfx) with password and unpacks it back", async () => {
    // Generate a fresh key and cert
    const created = await createCertificate({
      commonName: "pfx.workbench.local",
      san: "pfx.workbench.local",
      organization: "PKCS12 Test",
      organizationalUnit: "Lab",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 365,
      isCa: false,
    });

    const combinedPem = `${created.certPem}\n${created.privateKeyPem}`;
    const password = "workbench-secret-password-123!";

    // Package to PKCS#12
    const pfx = await convertCertificate(
      new TextEncoder().encode(combinedPem),
      "pem-to-pkcs12",
      { password },
    );
    expect(pfx.operation).toBe("pem-to-pkcs12");
    expect(pfx.bytes).toBeDefined();

    // Unpack from PKCS#12
    const unpacked = await convertCertificate(
      pfx.bytes!,
      "pkcs12-to-pem",
      { password },
    );
    expect(unpacked.operation).toBe("pkcs12-to-pem");
    expect(unpacked.text).toContain("-----BEGIN CERTIFICATE-----");
    expect(unpacked.text).toContain("-----BEGIN PRIVATE KEY-----");
  });

  it("extracts public key from certificate", async () => {
    const res = await convertCertificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM), "extract-public-key");
    expect(res.operation).toBe("extract-public-key");
    expect(res.text).toContain("-----BEGIN PUBLIC KEY-----");
  });

  it("splits multi-certificate chain bundle", async () => {
    const res = await convertCertificate(new TextEncoder().encode(CERTIFICATE_CHAIN_PEM), "split-chain");
    expect(res.operation).toBe("split-chain");
    expect(res.blocks?.length).toBe(2);
    expect(res.blocks![0]!.subject).toContain("workbench.local");
    expect(res.blocks![1]!.subject).toContain("Workbench Root CA");
  });
});

describe("Tool Execution via Registry", () => {
  it("computes X.509 certificate tool", async () => {
    const tool = await loadTool("x509");
    const spec = tool.createSpec();
    const result = await tool.compute(spec, new TextEncoder().encode(RSA_CERTIFICATE_PEM));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("workbench.local");
    expect(result.fields?.some((f) => f.label === "Subject")).toBe(true);
  });

  it("computes CSR tool with self-signature verification", async () => {
    const tool = await loadTool("csr");
    const spec = tool.createSpec();
    const result = await tool.compute(spec, new TextEncoder().encode(ECDSA_CSR_PEM));
    expect(result.error).toBeUndefined();
    expect(result.fields?.some((f) => f.label === "Self-Signature" && f.value.includes("Verified"))).toBe(true);
  });

  it("computes Certificate Converter tool", async () => {
    const tool = await loadTool("cert-converter");
    const spec = tool.createSpec();
    const result = await tool.compute(spec, new TextEncoder().encode(RSA_CERTIFICATE_PEM));
    expect(result.error).toBeUndefined();
    expect(result.bytes).toBeDefined();
  });

  it("returns user-friendly error on invalid certificate input", async () => {
    const tool = await loadTool("x509");
    const spec = tool.createSpec();
    const result = await tool.compute(spec, new TextEncoder().encode("not-a-certificate"));
    expect(result.error).toContain("Not a valid X.509 certificate");
  });

  it("computes Certificate Creator tool without requiring input", async () => {
    const tool = await loadTool("cert-creator");
    const spec = tool.createSpec();
    const result = await tool.compute(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.working).toContain("-----BEGIN PRIVATE KEY-----");
    expect(result.fields?.some((f) => f.label === "Subject")).toBe(true);
  });

  it("computes CSR Creator tool without requiring input", async () => {
    const tool = await loadTool("csr-creator");
    const spec = tool.createSpec();
    const result = await tool.compute(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN CERTIFICATE REQUEST-----");
    expect(result.working).toContain("-----BEGIN PRIVATE KEY-----");
    expect(result.fields?.some((f) => f.label === "Self-Signature" && f.value.includes("Verified"))).toBe(true);
  });
});

describe("Certificate and CSR Creation", () => {
  it("generates a valid self-signed ECDSA P-256 certificate and parses it back", async () => {
    const created = await createCertificate({
      commonName: "test.local",
      san: "test.local, 192.168.1.1",
      organization: "Test Org",
      organizationalUnit: "Security",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 90,
      isCa: false,
    });

    expect(created.certPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(created.privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
    expect(created.subjectDn).toContain("CN=test.local");

    // Cross-verify with our own X.509 parser
    const parsed = parseX509Certificate(created.certDer);
    expect(parsed.subject.commonName).toBe("test.local");
    expect(parsed.issuer.commonName).toBe("test.local");
    expect(parsed.publicKey.keyType).toBe("ec");
    expect(parsed.publicKey.curveName).toContain("P-256");
    expect(parsed.extensions.sans).toContain("DNS:test.local");
    expect(parsed.extensions.sans).toContain("IP:192.168.1.1");
  });

  it("generates a valid self-signed RSA 2048 certificate", async () => {
    const created = await createCertificate({
      commonName: "rsa.workbench",
      san: "rsa.workbench",
      organization: "RSA Test",
      organizationalUnit: "Lab",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "rsa-2048",
      hashType: "sha256",
      validityDays: 365,
      isCa: true,
    });

    expect(created.certPem).toContain("-----BEGIN CERTIFICATE-----");
    const parsed = parseX509Certificate(created.certDer);
    expect(parsed.subject.commonName).toBe("rsa.workbench");
    expect(parsed.publicKey.algorithmName).toBe("RSA");
    expect(parsed.extensions.basicConstraints?.isCa).toBe(true);
  });

  it("generates a valid self-signed Ed25519 certificate", async () => {
    const created = await createCertificate({
      commonName: "ed25519.workbench",
      san: "ed25519.workbench",
      organization: "Ed25519 Test",
      organizationalUnit: "Lab",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ed25519",
      hashType: "sha256",
      validityDays: 30,
      isCa: false,
    });

    expect(created.certPem).toContain("-----BEGIN CERTIFICATE-----");
    const parsed = parseX509Certificate(created.certDer);
    expect(parsed.subject.commonName).toBe("ed25519.workbench");
    expect(parsed.publicKey.algorithmName).toBe("Ed25519");
  });

  it("generates a valid ECDSA P-256 CSR and cryptographically verifies self-signature", async () => {
    const created = await createCsr({
      commonName: "api.example.com",
      san: "api.example.com, www.example.com",
      organization: "Example Corp",
      organizationalUnit: "DevOps",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ecdsa-p256",
      hashType: "sha256",
    });

    expect(created.csrPem).toContain("-----BEGIN CERTIFICATE REQUEST-----");
    expect(created.verified).toBe(true);

    // Parse and re-verify
    const parsed = parseCsr(created.csrDer);
    expect(parsed.subject.commonName).toBe("api.example.com");
    expect(parsed.requestedExtensions.sans).toContain("DNS:api.example.com");
    const verification = await parsed.verifySelfSignature();
    expect(verification.valid).toBe(true);
  });

  it("generates a valid RSA 2048 CSR with verified self-signature", async () => {
    const created = await createCsr({
      commonName: "rsa.example.com",
      san: "rsa.example.com",
      organization: "Example Corp",
      organizationalUnit: "DevOps",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "rsa-2048",
      hashType: "sha256",
    });

    expect(created.csrPem).toContain("-----BEGIN CERTIFICATE REQUEST-----");
    expect(created.verified).toBe(true);
  });

  it("generates a valid Ed25519 CSR", async () => {
    const created = await createCsr({
      commonName: "ed25519.example.com",
      san: "ed25519.example.com",
      organization: "Example Corp",
      organizationalUnit: "DevOps",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ed25519",
      hashType: "sha256",
    });

    expect(created.csrPem).toContain("-----BEGIN CERTIFICATE REQUEST-----");
    expect(created.verified).toBe(true);
  });
});
