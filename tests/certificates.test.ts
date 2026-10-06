import { describe, expect, it } from "vitest";
import {
  CA_CERTIFICATE_PEM,
  CERTIFICATE_CHAIN_PEM,
  certificateStudioFilenames,
  convertCertificate,
  createCertificate,
  createCsr,
  decodePkcs12Archive,
  ECDSA_CSR_PEM,
  generateMtlsSuite,
  OPTION_CA_CERT,
  OPTION_CA_KEY_TYPE,
  OPTION_CA_PRIVATE_KEY,
  OPTION_KEY_TYPE,
  OPTION_PRIVATE_KEY,
  parseAsn1,
  parseCsr,
  parseX509Certificate,
  RSA_CERTIFICATE_PEM,
  UniversalTag,
} from "@ocs/certificates";
import { isAvailableOn } from "@ocs/engine";
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
    const res = await convertCertificate(
      new TextEncoder().encode(RSA_CERTIFICATE_PEM),
      "pem-to-der",
    );
    expect(res.operation).toBe("pem-to-der");
    expect(res.bytes).toBeDefined();
    expect(res.bytes![0]).toBe(0x30); // ASN.1 SEQUENCE
  });

  it("converts DER binary to PEM", async () => {
    const derRes = await convertCertificate(
      new TextEncoder().encode(RSA_CERTIFICATE_PEM),
      "pem-to-der",
    );
    const der = derRes.bytes!;
    const res = await convertCertificate(der, "der-to-pem");
    expect(res.operation).toBe("der-to-pem");
    expect(res.text).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("converts PEM to CER and CER to PEM", async () => {
    const cerRes = await convertCertificate(
      new TextEncoder().encode(RSA_CERTIFICATE_PEM),
      "pem-to-cer",
    );
    expect(cerRes.operation).toBe("pem-to-cer");
    expect(cerRes.bytes).toBeDefined();

    const pemRes = await convertCertificate(cerRes.bytes!, "cer-to-pem");
    expect(pemRes.operation).toBe("cer-to-pem");
    expect(pemRes.text).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("packages certificates into PKCS#7 (.p7b) and extracts them back", async () => {
    const p7b = await convertCertificate(
      new TextEncoder().encode(CERTIFICATE_CHAIN_PEM),
      "pem-to-pkcs7",
    );
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
    const unpacked = await convertCertificate(pfx.bytes!, "pkcs12-to-pem", { password });
    expect(unpacked.operation).toBe("pkcs12-to-pem");
    expect(unpacked.text).toContain("-----BEGIN CERTIFICATE-----");
    expect(unpacked.text).toContain("-----BEGIN PRIVATE KEY-----");
  });

  it("extracts public key from certificate", async () => {
    const res = await convertCertificate(
      new TextEncoder().encode(RSA_CERTIFICATE_PEM),
      "extract-public-key",
    );
    expect(res.operation).toBe("extract-public-key");
    expect(res.text).toContain("-----BEGIN PUBLIC KEY-----");
  });

  it("splits multi-certificate chain bundle", async () => {
    const res = await convertCertificate(
      new TextEncoder().encode(CERTIFICATE_CHAIN_PEM),
      "split-chain",
    );
    expect(res.operation).toBe("split-chain");
    expect(res.blocks?.length).toBe(2);
    expect(res.blocks![0]!.subject).toContain("workbench.local");
    expect(res.blocks![1]!.subject).toContain("Workbench Root CA");
  });
});

describe("Tool Execution via Registry", () => {
  it("shows custom CA credentials only when CSR Signer selects Custom CA", async () => {
    const tool = await loadTool("csr-signer");
    const spec = tool.createSpec();
    const caCertificate = tool.catalogue.get(OPTION_CA_CERT)!;
    const caKeyType = tool.catalogue.get(OPTION_CA_KEY_TYPE)!;
    const caPrivateKey = tool.catalogue.get(OPTION_CA_PRIVATE_KEY)!;

    expect(isAvailableOn(caCertificate, tool.variantTag?.(spec))).toBe(false);
    expect(isAvailableOn(caPrivateKey, tool.variantTag?.(spec))).toBe(false);
    expect(isAvailableOn(caKeyType, tool.variantTag?.(spec))).toBe(true);

    const customCaSpec = {
      ...spec,
      options: { ...spec.options, caMode: "custom-ca" },
    };
    expect(isAvailableOn(caCertificate, tool.variantTag?.(customCaSpec))).toBe(true);
    expect(isAvailableOn(caPrivateKey, tool.variantTag?.(customCaSpec))).toBe(true);
    expect(isAvailableOn(caKeyType, tool.variantTag?.(customCaSpec))).toBe(false);
  });

  it("keeps the applicant key algorithm available in CSR Creator", async () => {
    const tool = await loadTool("csr-creator");
    const spec = tool.createSpec();
    const keyType = tool.catalogue.get(OPTION_KEY_TYPE)!;

    expect(isAvailableOn(keyType, tool.variantTag?.(spec))).toBe(true);
    expect(spec.options[OPTION_KEY_TYPE]).toBe("ecdsa-p256");
  });

  it("shows secondary private key input only when Certificate Converter selects PEM to PKCS#12", async () => {
    const tool = await loadTool("cert-converter");
    const spec = tool.createSpec();
    const privateKeyOpt = tool.catalogue.get(OPTION_PRIVATE_KEY)!;

    // Default operation is pem-to-der; private key should not be available
    expect(isAvailableOn(privateKeyOpt, tool.variantTag?.(spec))).toBe(false);

    // Only when switched to pem-to-pkcs12 should the secondary private key input be available
    const pkcs12Spec = {
      ...spec,
      options: { ...spec.options, converterOp: "pem-to-pkcs12" },
    };
    expect(isAvailableOn(privateKeyOpt, tool.variantTag?.(pkcs12Spec))).toBe(true);
  });

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
    expect(
      result.fields?.some((f) => f.label === "Self-Signature" && f.value.includes("Verified")),
    ).toBe(true);
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
    expect(
      result.fields?.some((f) => f.label === "Self-Signature" && f.value.includes("Verified")),
    ).toBe(true);
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
    expect(created.issuanceMode).toBe("self-signed");
    expect(created.opensslCommand).toContain(
      "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.key",
    );
    expect(created.opensslCommand).toContain(
      "-subj '/C=US/ST=California/L=San Francisco/O=RSA Test/OU=Lab/CN=rsa.workbench'",
    );
    expect(created.opensslCommand).toContain("-addext 'subjectAltName=DNS:rsa.workbench'");
    expect(created.opensslCommand).toContain("-out certificate.crt");
    expect(created.opensslCommand).not.toContain("key.pem");
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
    expect(created.opensslCommand).toContain(
      "-subj '/C=US/ST=California/L=San Francisco/O=Example Corp/OU=DevOps/CN=api.example.com'",
    );
    expect(created.opensslCommand).toContain(
      "-addext 'subjectAltName=DNS:api.example.com,DNS:www.example.com'",
    );
    expect(created.opensslCommand).toContain("-out request.csr");
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

describe("CA-Signed Certificate Issuance", () => {
  it("refuses CA-signed issuance without a complete CA keypair", async () => {
    const options = {
      commonName: "child.internal",
      keyType: "ecdsa-p256" as const,
      hashType: "sha256" as const,
      validityDays: 365,
      isCa: false,
      issuanceMode: "ca-signed" as const,
    };

    await expect(createCertificate(options)).rejects.toThrow(
      "CA-signed issuance requires both a CA certificate and its matching private key.",
    );
    await expect(createCertificate({ ...options, caCertPem: "certificate" })).rejects.toThrow(
      "CA-signed issuance requires the issuing CA private key.",
    );
    await expect(createCertificate({ ...options, caPrivateKeyPem: "key" })).rejects.toThrow(
      "CA-signed issuance requires the issuing CA certificate.",
    );
  });

  it("generates a Root CA and issues a child certificate signed by that CA", async () => {
    // 1. Generate Root CA
    const ca = await createCertificate({
      commonName: "Test Root CA",
      organization: "Test Org",
      organizationalUnit: "Security",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 3650,
      isCa: true,
      san: "",
    });

    const parsedCa = parseX509Certificate(ca.certDer);
    expect(parsedCa.extensions.basicConstraints?.isCa).toBe(true);
    expect(parsedCa.extensions.keyUsages).toContain("keyCertSign");

    // 2. Issue child certificate signed by this Root CA
    const child = await createCertificate({
      commonName: "child.internal",
      organization: "Test Org",
      organizationalUnit: "Engineering",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 365,
      isCa: false,
      san: "child.internal, 10.0.0.1",
      serverAuth: true,
      clientAuth: false,
      issuanceMode: "ca-signed",
      caCertPem: ca.certPem,
      caPrivateKeyPem: ca.privateKeyPem,
    });

    expect(child.chainPem).toContain(child.certPem);
    expect(child.chainPem).toContain(ca.certPem);

    // 3. Inspect child certificate
    const parsedChild = parseX509Certificate(child.certDer);
    expect(parsedChild.subject.commonName).toBe("child.internal");
    expect(parsedChild.issuer.commonName).toBe("Test Root CA");
    expect(parsedChild.extensions.basicConstraints?.isCa).toBe(false);
    expect(parsedChild.extensions.sans).toContain("DNS:child.internal");
    expect(parsedChild.extensions.sans).toContain("IP:10.0.0.1");
    expect(
      parsedChild.extensions.extendedKeyUsages.some((u) =>
        u.includes("TLS Web Server Authentication"),
      ),
    ).toBe(true);
    expect(parsedChild.extensions.authorityKeyIdentifier).toBe(
      parsedCa.extensions.subjectKeyIdentifier,
    );
    expect(child.issuanceMode).toBe("ca-signed");
    expect(child.opensslCommand).toContain("openssl req -new -key private.key");
    expect(child.opensslCommand).toContain(
      "-addext 'subjectAltName=DNS:child.internal,IP:10.0.0.1'",
    );
    expect(child.opensslCommand).toContain("-addext 'extendedKeyUsage=serverAuth'");
    expect(child.opensslCommand).toContain("-copy_extensions copy");
    expect(child.opensslCommand).toContain("-out certificate.crt");
  });
});

describe("Full mTLS Suite Generator", () => {
  it("uses one canonical filename set for each Certificate Studio flow", () => {
    const flows = [
      {
        name: "single standalone",
        creatorMode: "single-cert",
        singleMode: "standalone",
        hierarchy: "2-tier",
        expected: ["ca.key", "ca.crt", "private.key", "certificate.csr", "server.crt"],
      },
      {
        name: "single generated 2-tier",
        creatorMode: "single-cert",
        singleMode: "generated-ca",
        hierarchy: "2-tier",
        expected: [
          "root-ca.key",
          "root-ca.crt",
          "private.key",
          "certificate.csr",
          "server.crt",
        ],
      },
      {
        name: "single generated 3-tier",
        creatorMode: "single-cert",
        singleMode: "generated-ca",
        hierarchy: "3-tier",
        expected: [
          "root-ca.key",
          "root-ca.crt",
          "intermediate.key",
          "intermediate.crt",
          "private.key",
          "certificate.csr",
          "server.crt",
        ],
      },
      {
        name: "single existing CA 2-tier",
        creatorMode: "single-cert",
        singleMode: "existing-ca",
        hierarchy: "2-tier",
        expected: ["ca.key", "ca.crt", "private.key", "certificate.csr", "server.crt"],
      },
      {
        name: "single existing CA 3-tier",
        creatorMode: "single-cert",
        singleMode: "existing-ca",
        hierarchy: "3-tier",
        expected: [
          "root-ca.key",
          "root-ca.crt",
          "intermediate.key",
          "intermediate.crt",
          "private.key",
          "certificate.csr",
          "server.crt",
        ],
      },
      {
        name: "mTLS 2-tier",
        creatorMode: "mtls-suite",
        singleMode: "standalone",
        hierarchy: "2-tier",
        expected: ["ca.key", "ca.crt", "server.key", "server.csr", "server.crt"],
      },
      {
        name: "mTLS 3-tier",
        creatorMode: "mtls-suite",
        singleMode: "standalone",
        hierarchy: "3-tier",
        expected: [
          "ca.key",
          "ca.crt",
          "intermediate.key",
          "intermediate.crt",
          "server.key",
          "server.csr",
          "server.crt",
        ],
      },
    ] as const;

    for (const flow of flows) {
      const files = certificateStudioFilenames(
        flow.creatorMode,
        flow.singleMode,
        flow.hierarchy,
      );
      const actual = [
        files.rootKey,
        files.rootCertificate,
        ...(flow.hierarchy === "3-tier" ? [files.issuerKey, files.issuerCertificate] : []),
        files.leafKey,
        files.leafCsr,
        files.leafCertificate,
      ];
      expect(actual, flow.name).toEqual(flow.expected);
    }
  });

  it("defaults Certificate Creator to a valid self-signed workflow", async () => {
    const def = await loadTool("cert-creator");
    const spec = def.createSpec();

    expect(spec.options.singleCertificateMode).toBe("standalone");
    expect(spec.options).toMatchObject({
      rootKeyType: "ecdsa-p256",
      rootHashType: "sha256",
      intermediateKeyType: "ecdsa-p256",
      intermediateHashType: "sha256",
      serverKeyType: "ecdsa-p256",
      serverHashType: "sha256",
      clientKeyType: "ecdsa-p256",
      clientHashType: "sha256",
    });
    const result = await def.compute(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();
    expect(result.working).toContain("(Self-Signed)");
    expect(result.working).toContain("#### Equivalent OpenSSL Workflow:");
    const commands = result.files?.find((file) => file.name === "commands.sh")?.content;
    expect(commands).toContain("-key private.key");
    expect(commands).toContain("-out server.crt");
  });

  it("does not label an incomplete CA-signed request as a generated certificate", async () => {
    const def = await loadTool("cert-creator");
    const spec = def.createSpec();
    spec.options = { ...spec.options, singleCertificateMode: "existing-ca" };

    const result = await def.compute(spec, new Uint8Array(0));
    expect(result.text).toBeUndefined();
    expect(result.error).toContain(
      "CA-signed issuance requires both a CA certificate and its matching private key.",
    );
  });

  it("generates complete 3-tier mTLS suite with Root CA, Server Cert, Client Cert, and PKCS#12 archive", async () => {
    const mtls = await generateMtlsSuite({
      caCommonName: "mTLS Root CA",
      serverCommonName: "secure.internal",
      serverSan: "secure.internal, 192.168.1.100",
      clientCommonName: "client-alice",
      rootKeyType: "ecdsa-p256",
      rootHashType: "sha256",
      serverKeyType: "ecdsa-p256",
      serverHashType: "sha256",
      clientKeyType: "ecdsa-p256",
      clientHashType: "sha256",
      validityDays: 365,
      p12Password: "mtls-secret-pass",
    });

    // 1. Root CA
    const parsedCa = parseX509Certificate(mtls.ca.certDer);
    expect(parsedCa.subject.commonName).toBe("mTLS Root CA");
    expect(parsedCa.extensions.basicConstraints?.isCa).toBe(true);
    expect(parsedCa.extensions.keyUsages).toContain("keyCertSign");

    // 2. Server Certificate
    const parsedServer = parseX509Certificate(mtls.server.certDer);
    expect(parsedServer.subject.commonName).toBe("secure.internal");
    expect(parsedServer.issuer.commonName).toBe("mTLS Root CA");
    expect(parsedServer.extensions.sans).toContain("DNS:secure.internal");
    expect(parsedServer.extensions.sans).toContain("IP:192.168.1.100");
    expect(
      parsedServer.extensions.extendedKeyUsages.some((u) =>
        u.includes("TLS Web Server Authentication"),
      ),
    ).toBe(true);

    // 3. Client Certificate
    const parsedClient = parseX509Certificate(mtls.client.certDer);
    expect(parsedClient.subject.commonName).toBe("client-alice");
    expect(parsedClient.issuer.commonName).toBe("mTLS Root CA");
    expect(
      parsedClient.extensions.extendedKeyUsages.some((u) =>
        u.includes("TLS Web Client Authentication"),
      ),
    ).toBe(true);

    // 4. Client PKCS#12 archive decodes with password
    const p12Decoded = await decodePkcs12Archive(mtls.client.p12Der, "mtls-secret-pass");
    expect(p12Decoded.certs.length).toBeGreaterThanOrEqual(1);
    expect(p12Decoded.certs[0]!.pem).toBe(mtls.client.certPem);
    expect(p12Decoded.privateKey?.pem).toBe(mtls.client.keyPem);

    // 5. Verification Commands
    expect(mtls.commands.curlPem).toContain(
      "--cacert ca.crt --cert client.crt --key client.key",
    );
    expect(mtls.commands.curlP12).toContain("client.p12:mtls-secret-pass");
    expect(mtls.commands.opensslServer).toContain("-Verify 1");
    expect(mtls.commands.nginxConfig).toContain("ssl_verify_client       on;");

    // 6. All-in-one text contains all artifacts
    expect(mtls.allInOneText).toContain("ROOT CERTIFICATE AUTHORITY");
    expect(mtls.allInOneText).toContain("SERVER CERTIFICATE");
    expect(mtls.allInOneText).toContain("CLIENT CERTIFICATE");
    expect(mtls.allInOneText).toContain("CLIENT PKCS#12 ARCHIVE");
  });

  it("uses independent key algorithms and signature hashes across an mTLS hierarchy", async () => {
    const mtls = await generateMtlsSuite({
      pkiHierarchy: "3-tier",
      rootKeyType: "ecdsa-p256",
      rootHashType: "sha256",
      intermediateKeyType: "rsa-2048",
      intermediateHashType: "sha384",
      serverKeyType: "ed25519",
      serverHashType: "sha256",
      clientKeyType: "ecdsa-p384",
      clientHashType: "sha512",
    });

    const root = parseX509Certificate(mtls.ca.certDer);
    const intermediate = parseX509Certificate(mtls.intermediate!.certDer);
    const server = parseX509Certificate(mtls.server.certDer);
    const client = parseX509Certificate(mtls.client.certDer);

    expect(root.publicKey.curveName).toContain("P-256");
    expect(root.signatureAlgorithmName).toBe("ecdsa-with-SHA256");
    expect(intermediate.publicKey.keyType).toBe("rsa");
    expect(intermediate.signatureAlgorithmName).toBe("ecdsa-with-SHA384");
    expect(server.publicKey.keyType).toBe("ed25519");
    expect(server.signatureAlgorithmName).toBe("sha256WithRSAEncryption");
    expect(client.publicKey.curveName).toContain("P-384");
    expect(client.signatureAlgorithmName).toBe("sha512WithRSAEncryption");

    expect(mtls.ca).toMatchObject({ keyType: "ecdsa-p256", signatureHash: "sha256" });
    expect(mtls.intermediate).toMatchObject({
      keyType: "rsa-2048",
      signatureHash: "sha384",
    });
    expect(mtls.server).toMatchObject({ keyType: "ed25519", signatureHash: "sha256" });
    expect(mtls.client).toMatchObject({ keyType: "ecdsa-p384", signatureHash: "sha512" });
    expect(mtls.rawServer.opensslCommand).toContain("openssl x509 -req");
    expect(mtls.rawServer.opensslCommand).toContain("-sha256");
    expect(mtls.rawClient.opensslCommand).toContain("-sha512");
  });

  it("computes mTLS suite through Certificate Creator tool definition", async () => {
    const def = await loadTool("cert-creator");
    expect(def).toBeDefined();

    const spec = def.createSpec();
    spec.options = {
      creatorMode: "mtls-suite",
      commonName: "api.service.internal",
      clientCommonName: "client-agent-01",
      mtlsP12Password: "pass456",
    };

    const result = await def.compute(spec, new Uint8Array(0));

    expect(result.error).toBeUndefined();
    expect(result.text).toContain("ROOT CERTIFICATE AUTHORITY");
    expect(result.text).toContain("SERVER CERTIFICATE");
    expect(result.text).toContain("CLIENT CERTIFICATE");
    expect(result.fields?.some((f) => f.label === "Suite Mode")).toBe(true);
    expect(result.fields?.some((f) => f.label === "Root CA")).toBe(true);
    expect(result.fields?.some((f) => f.label === "Server Certificate")).toBe(true);
    expect(result.fields?.some((f) => f.label === "Client Certificate")).toBe(true);
  });

  it("provides distinct, tool-specific Info fields for all certificate tools", async () => {
    const { CERTIFICATE_TOOL_IDS } = await import("@ocs/certificates");
    for (const toolId of CERTIFICATE_TOOL_IDS) {
      const def = await loadTool(toolId);
      expect(def).toBeDefined();
      expect(def.info).toBeDefined();

      const spec = def.createSpec();
      const fields = def.info!(spec);

      expect(fields.length).toBeGreaterThanOrEqual(2);
      expect(fields.some((f) => f.label === "Execution Engine")).toBe(true);

      // Verify tool-specific fields are present rather than generic placeholders
      if (toolId === "cert-matcher") {
        expect(
          fields.some((f) => f.label === "Operation" && f.value.includes("Keypair Matcher")),
        ).toBe(true);
      } else if (toolId === "cert-diff") {
        expect(fields.some((f) => f.label === "Operation" && f.value.includes("Diff"))).toBe(
          true,
        );
      } else if (toolId === "cert-creator") {
        expect(fields.some((f) => f.label === "Certificate Type")).toBe(true);
      } else if (toolId === "x509") {
        expect(fields.some((f) => f.label === "Standard" && f.value.includes("X.509"))).toBe(
          true,
        );
      } else if (toolId === "acme") {
        expect(fields.some((f) => f.label === "Standard" && f.value.includes("ACME"))).toBe(
          true,
        );
      }
    }
  });

  it("hides mTLS Suite Settings group in single-cert mode and reveals it in mtls-suite mode", async () => {
    const { isAvailableOn } = await import("@ocs/engine");
    const def = await loadTool("cert-creator");
    expect(def).toBeDefined();
    expect(def.variantTag).toBeDefined();

    // 1. Single Certificate Mode (Self-Signed)
    const singleSpec = def.createSpec();
    expect(singleSpec.options["serverAuth"]).toBe(true);
    expect(singleSpec.options["clientAuth"]).toBe(false);
    singleSpec.options = {
      ...singleSpec.options,
      creatorMode: "single-cert",
      singleCertificateMode: "standalone",
    };
    const singleTag = def.variantTag!(singleSpec);
    expect(singleTag).toEqual(["single-cert", "standalone"]);

    const mtlsOptions = def.catalogue.inGroup("mtls");
    expect(mtlsOptions.length).toBeGreaterThan(0);
    for (const opt of mtlsOptions) {
      expect(isAvailableOn(opt, singleTag)).toBe(false);
    }

    // Client Auth extension must remain visible in single-cert mode
    const clientAuthOpt = def.catalogue
      .inGroup("extensions")
      .find((o) => o.id === "clientAuth");
    expect(clientAuthOpt).toBeDefined();
    expect(isAvailableOn(clientAuthOpt!, singleTag)).toBe(true);

    // 2. Full mTLS Suite Mode
    const mtlsSpec = def.createSpec();
    mtlsSpec.options = { ...mtlsSpec.options, creatorMode: "mtls-suite" };
    const mtlsTag = def.variantTag!(mtlsSpec);
    expect(mtlsTag).toEqual(["mtls-suite"]);

    for (const opt of mtlsOptions) {
      expect(isAvailableOn(opt, mtlsTag)).toBe(true);
    }
    expect(isAvailableOn(clientAuthOpt!, mtlsTag)).toBe(true);
  });

  describe("Algorithm-Aware Key Usages and Dual-Stack IPv6 SANs", () => {
    it("emits digitalSignature-only for EC leaf certificates without keyEncipherment", async () => {
      const created = await createCertificate({
        commonName: "localhost",
        san: "localhost, 127.0.0.1, ::1",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 365,
        isCa: false,
      });

      const parsed = parseX509Certificate(created.certDer);
      expect(parsed.extensions.keyUsages).toEqual(["digitalSignature"]);
      expect(parsed.extensions.keyUsages).not.toContain("keyEncipherment");
      expect(parsed.extensions.keyUsages).not.toContain("keyAgreement");
      expect(parsed.extensions.basicConstraints?.isCa).toBe(false);

      // Verify IPv6 SAN parsing
      expect(parsed.extensions.sans).toContain("DNS:localhost");
      expect(parsed.extensions.sans).toContain("IP:127.0.0.1");
      expect(parsed.extensions.sans).toContain("IP:::1");

      // OpenSSL workflow verification
      expect(created.opensslCommand).toContain("keyUsage=critical,digitalSignature");
      expect(created.opensslCommand).toContain(
        "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
      );
      expect(created.opensslCommand).toContain("subjectKeyIdentifier=hash");
    });

    it("emits digitalSignature and keyEncipherment for RSA leaf certificates", async () => {
      const created = await createCertificate({
        commonName: "rsa-leaf.local",
        san: "rsa-leaf.local, 127.0.0.1",
        keyType: "rsa-2048",
        hashType: "sha256",
        validityDays: 365,
        isCa: false,
      });

      const parsed = parseX509Certificate(created.certDer);
      expect(parsed.extensions.keyUsages).toContain("digitalSignature");
      expect(parsed.extensions.keyUsages).toContain("keyEncipherment");
      expect(parsed.extensions.basicConstraints?.isCa).toBe(false);

      expect(created.opensslCommand).toContain(
        "keyUsage=critical,digitalSignature,keyEncipherment",
      );
    });

    it("emits keyCertSign and cRLSign for CA certificates", async () => {
      const created = await createCertificate({
        commonName: "Root CA",
        san: "",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 3650,
        isCa: true,
      });

      const parsed = parseX509Certificate(created.certDer);
      expect(parsed.extensions.basicConstraints?.isCa).toBe(true);
      expect(parsed.extensions.keyUsages).toContain("keyCertSign");
      expect(parsed.extensions.keyUsages).toContain("cRLSign");
      expect(parsed.extensions.keyUsages).toContain("digitalSignature");

      expect(created.opensslCommand).toContain("basicConstraints=critical,CA:TRUE");
      expect(created.opensslCommand).toContain(
        "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
      );
    });
  });

  describe("Certificate Transparency SCT Decoder and CA/B Forum 2026 Rules", () => {
    it("parses and decodes RFC 6962 Signed Certificate Timestamp (SCT) list", async () => {
      const { parseSctList } = await import("../packages/tools/certificates/src/asn1/x509");
      // Build sample serialized SCT list
      // Total list length: 2 bytes
      // SCT 1 length: 2 bytes
      // SCT 1 data: 1 byte version (0), 32 bytes log_id, 8 bytes timestamp (ms), 2 bytes ext_len (0), 1 byte hash (4 = SHA256), 1 byte sig (3 = ECDSA), 2 bytes sig_len, sig bytes
      const logIdHex = "293c519654c83965baaa50fc5807d4b76fbf587a2972dcaaa813083ba7658cfa"; // Cloudflare Nimbus
      const logIdBytes = new Uint8Array(logIdHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
      const nowMs = 1775000000000n; // 2026 timestamp

      const sctData = new Uint8Array(43 + 4 + 64);
      sctData[0] = 0x00; // v1
      sctData.set(logIdBytes, 1);
      for (let i = 0; i < 8; i++) {
        sctData[33 + i] = Number((nowMs >> BigInt((7 - i) * 8)) & 0xffn);
      }
      sctData[41] = 0x00; // ext len MSB
      sctData[42] = 0x00; // ext len LSB
      sctData[43] = 0x04; // SHA-256
      sctData[44] = 0x03; // ECDSA
      sctData[45] = 0x00; // sig len MSB
      sctData[46] = 64; // sig len LSB (64 bytes)
      sctData.fill(0xaa, 47, 47 + 64);

      const listBuffer = new Uint8Array(2 + 2 + sctData.length);
      const totalLen = 2 + sctData.length;
      listBuffer[0] = (totalLen >> 8) & 0xff;
      listBuffer[1] = totalLen & 0xff;
      listBuffer[2] = (sctData.length >> 8) & 0xff;
      listBuffer[3] = sctData.length & 0xff;
      listBuffer.set(sctData, 4);

      const decoded = parseSctList(listBuffer);
      expect(decoded.length).toBe(1);
      expect(decoded[0]!.version).toBe(0);
      expect(decoded[0]!.logId).toBe(logIdHex);
      expect(decoded[0]!.logName).toBe("Cloudflare 'Nimbus2026'");
      expect(decoded[0]!.hashAlgorithm).toBe("SHA-256");
      expect(decoded[0]!.signatureAlgorithm).toBe("ECDSA");
      expect(decoded[0]!.timestamp.getTime()).toBe(Number(nowMs));
    });

    it("triggers CERT011 warning when validity exceeds CA/B 2026 90-day target", async () => {
      const { RULES } = await import("../packages/tools/certificates/src/lint/rules");
      const rule = RULES.find((r) => r.code === "CERT011");
      expect(rule).toBeDefined();

      const spec = {
        specVersion: 1 as const,
        variant: "cert-creator" as const,
        options: {
          creatorMode: "single-cert",
          isCa: "false",
          validityDays: "180",
        },
      };

      const diagnostics = rule!.check(spec);
      expect(diagnostics.length).toBe(1);
      expect(diagnostics[0]!.level).toBe("info");
      expect(diagnostics[0]!.message).toContain("exceeds the 2026 CA/B Forum 90-day target");
      expect(diagnostics[0]!.fix).toBeDefined();

      const fixed = diagnostics[0]!.fix!.apply(spec);
      expect(fixed.options["validityDays"]).toBe("90");
    });
  });

  describe("Single Certificate Creation Flows", () => {
    it("generates a 2-tier private CA and server certificate", async () => {
      const tool = await loadTool("cert-creator");
      const spec = tool.createSpec();
      spec.options = {
        ...spec.options,
        creatorMode: "single-cert",
        singleCertificateMode: "generated-ca",
        pkiHierarchy: "2-tier",
        commonName: "service.internal",
        caCommonName: "Private Root CA",
      };

      const result = await tool.compute(spec, new Uint8Array(0));
      expect(result.error).toBeUndefined();
      const fileMap = new Map((result.files ?? []).map((file) => [file.name, file.content]));
      expect(fileMap.has("root-ca.crt")).toBe(true);
      expect(fileMap.has("root-ca.key")).toBe(true);
      expect(fileMap.has("intermediate.crt")).toBe(false);
      expect(fileMap.get("commands.sh")).toContain("-out certificate.csr");
      expect(fileMap.get("commands.sh")).toContain("-CA root-ca.crt");
      expect(fileMap.get("commands.sh")).toContain("-CAkey root-ca.key");

      const server = parseX509Certificate(
        new TextEncoder().encode(fileMap.get("server.crt") as string),
      );
      const root = parseX509Certificate(
        new TextEncoder().encode(fileMap.get("root-ca.crt") as string),
      );
      expect(server.issuer.commonName).toBe("Private Root CA");
      expect(root.subject.commonName).toBe("Private Root CA");
      expect(root.extensions.basicConstraints?.pathLenConstraint).toBe(0);
    });

    it("generates a private 3-tier hierarchy (Root CA ➔ Intermediate CA ➔ Server)", async () => {
      const tool = await loadTool("cert-creator");
      const spec = tool.createSpec();
      spec.options = {
        ...spec.options,
        creatorMode: "single-cert",
        singleCertificateMode: "generated-ca",
        pkiHierarchy: "3-tier",
        commonName: "api.internal.service",
        caCommonName: "Internal Enterprise Root CA",
        intermediateCommonName: "Internal Enterprise Issuing CA",
        keyType: "ecdsa-p256",
        rootKeyType: "ecdsa-p256",
        intermediateKeyType: "ecdsa-p256",
      };

      const result = await tool.compute(spec, new Uint8Array(0));
      expect(result.files).toBeDefined();

      const fileMap = new Map((result.files ?? []).map((f) => [f.name, f.content]));
      expect(fileMap.has("server.crt")).toBe(true);
      expect(fileMap.has("private.key")).toBe(true);
      expect(fileMap.has("intermediate.crt")).toBe(true);
      expect(fileMap.has("intermediate.key")).toBe(true);
      expect(fileMap.has("root-ca.crt")).toBe(true);
      expect(fileMap.has("root-ca.key")).toBe(true);
      expect(fileMap.has("server-chain.pem")).toBe(true);
      expect(fileMap.get("commands.sh")).toContain("-out certificate.csr");
      expect(fileMap.get("commands.sh")).toContain("-CA intermediate.crt");
      expect(fileMap.get("commands.sh")).toContain("-CAkey intermediate.key");

      // Verify certificate structures
      const leafParsed = parseX509Certificate(
        new TextEncoder().encode(fileMap.get("server.crt") as string),
      );
      const interParsed = parseX509Certificate(
        new TextEncoder().encode(fileMap.get("intermediate.crt") as string),
      );
      const rootParsed = parseX509Certificate(
        new TextEncoder().encode(fileMap.get("root-ca.crt") as string),
      );

      expect(rootParsed.extensions.basicConstraints?.isCa).toBe(true);
      expect(rootParsed.extensions.basicConstraints?.pathLenConstraint).toBe(1);

      expect(interParsed.extensions.basicConstraints?.isCa).toBe(true);
      expect(interParsed.extensions.basicConstraints?.pathLenConstraint).toBe(0);

      expect(leafParsed.extensions.basicConstraints?.isCa).toBe(false);

      // Verify Subject/Issuer linkage
      expect(leafParsed.issuer.commonName).toBe("Internal Enterprise Issuing CA");
      expect(interParsed.issuer.commonName).toBe("Internal Enterprise Root CA");
      expect(rootParsed.issuer.commonName).toBe("Internal Enterprise Root CA");

      // Verify visual hierarchy diagram in working
      expect(result.working).toContain("Visual Trust Hierarchy");
      expect(result.working).toContain("Internal Enterprise Root CA");
      expect(result.working).toContain("Internal Enterprise Issuing CA");
      expect(result.working).toContain("api.internal.service");
    });

    it("signs a server certificate directly with an existing CA in 2-tier mode", async () => {
      const ca = await createCertificate({
        commonName: "Existing Root CA",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 3650,
        isCa: true,
        pathLenConstraint: 0,
      });
      const tool = await loadTool("cert-creator");
      const spec = tool.createSpec();
      spec.options = {
        ...spec.options,
        creatorMode: "single-cert",
        singleCertificateMode: "existing-ca",
        pkiHierarchy: "2-tier",
        commonName: "direct.internal",
        caCert: ca.certPem,
        caPrivateKey: ca.privateKeyPem,
      };

      const result = await tool.compute(spec, new Uint8Array(0));
      expect(result.error).toBeUndefined();
      const fileMap = new Map((result.files ?? []).map((file) => [file.name, file.content]));
      const server = parseX509Certificate(
        new TextEncoder().encode(fileMap.get("server.crt") as string),
      );
      expect(server.issuer.commonName).toBe("Existing Root CA");
      expect(fileMap.has("intermediate.crt")).toBe(false);
      expect(fileMap.has("server-chain.pem")).toBe(false);
      expect(fileMap.get("commands.sh")).toContain("-out certificate.csr");
      expect(fileMap.get("commands.sh")).toContain("-CA ca.crt");
      expect(fileMap.get("commands.sh")).toContain("-CAkey ca.key");
    });

    it("uses explicit Intermediate and Root CA inputs to produce a complete 3-tier chain", async () => {
      // 1. Create a Root CA
      const root = await createCertificate({
        commonName: "Custom Enterprise Root CA",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 3650,
        isCa: true,
        pathLenConstraint: 1,
      });

      // 2. Create an Intermediate CA signed by Root CA
      const intermediate = await createCertificate({
        commonName: "Custom Operational Subordinate CA",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 1825,
        isCa: true,
        pathLenConstraint: 0,
        issuanceMode: "ca-signed",
        caCertPem: root.certPem,
        caPrivateKeyPem: root.privateKeyPem,
      });

      const tool = await loadTool("cert-creator");
      const spec = tool.createSpec();
      spec.options = {
        ...spec.options,
        creatorMode: "single-cert",
        singleCertificateMode: "existing-ca",
        pkiHierarchy: "3-tier",
        commonName: "vault.company.lan",
        caCert: intermediate.certPem,
        caPrivateKey: intermediate.privateKeyPem,
        rootCaCert: root.certPem,
      };

      const result = await tool.compute(spec, new Uint8Array(0));
      const fileMap = new Map((result.files ?? []).map((f) => [f.name, f.content]));

      expect(fileMap.has("server.crt")).toBe(true);
      expect(fileMap.has("private.key")).toBe(true);
      expect(fileMap.has("chain.pem")).toBe(true);
      expect(fileMap.has("server-chain.pem")).toBe(true);
      expect(fileMap.get("commands.sh")).toContain("-out certificate.csr");
      expect(fileMap.get("commands.sh")).toContain("-CA intermediate.crt");
      expect(fileMap.get("commands.sh")).toContain("-CAkey intermediate.key");

      const chainContent = fileMap.get("chain.pem") as string;
      // Chain must contain 3 certificate PEM blocks
      const certCount = (chainContent.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
      expect(certCount).toBe(3);

      // Verify leaf is signed by intermediate
      const leafParsed = parseX509Certificate(
        new TextEncoder().encode(fileMap.get("server.crt") as string),
      );
      expect(leafParsed.issuer.commonName).toBe("Custom Operational Subordinate CA");

      // Verify visual hierarchy in working
      expect(result.working).toContain("Visual Trust Hierarchy");
      expect(result.working).toContain("Custom Enterprise Root CA");
      expect(result.working).toContain("Custom Operational Subordinate CA");
      expect(result.working).toContain("vault.company.lan");
    });
  });
});
