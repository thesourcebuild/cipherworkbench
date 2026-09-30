import { describe, expect, it } from "vitest";
import { createCertificate } from "../packages/tools/certificates/src/asn1/create-cert";
import { importCaSigner } from "../packages/tools/certificates/src/crypto/keys";
import {
  createCrl,
  parseX509Crl,
  CrlReasonCode,
} from "../packages/tools/certificates/src/asn1/crl";

describe("RFC 5280 X.509 v2 CRL Generator & Parser", () => {
  it("creates and parses an RFC 5280 v2 CRL with multiple revoked serial numbers", async () => {
    // 1. Generate Root CA
    const caCert = await createCertificate({
      commonName: "Enterprise Test Root CA",
      organization: "Acme Corp",
      isCa: true,
      keyType: "rsa-2048",
      hashType: "sha256",
      validityDays: 365,
    });

    const caSigner = await importCaSigner(caCert.certDer, caCert.privateKeyDer);

    // 2. Generate CRL revoking 2 certificates
    const revocationTime1 = new Date("2026-03-01T12:00:00Z");
    const revocationTime2 = new Date("2026-03-02T15:30:00Z");

    const crlResult = await createCrl({
      signer: caSigner,
      crlNumber: 7,
      thisUpdate: new Date("2026-03-03T00:00:00Z"),
      nextUpdate: new Date("2026-04-03T00:00:00Z"),
      revokedCertificates: [
        {
          serialNumber: "0x1A2B3C",
          revocationDate: revocationTime1,
          reasonCode: CrlReasonCode.KeyCompromise,
        },
        {
          serialNumber: "998877",
          revocationDate: revocationTime2,
          reasonCode: CrlReasonCode.Superseded,
        },
      ],
    });

    expect(crlResult.crlPem).toContain("-----BEGIN X509 CRL-----");
    expect(crlResult.crlPem).toContain("-----END X509 CRL-----");
    expect(crlResult.revokedCount).toBe(2);

    // 3. Parse CRL from DER bytes
    const parsedDer = parseX509Crl(crlResult.crlDer);
    expect(parsedDer.version).toBe(2);
    expect(parsedDer.crlNumber).toBe(7);
    expect(parsedDer.issuerDn).toContain("Enterprise Test Root CA");
    expect(parsedDer.revokedCertificates).toHaveLength(2);

    const entry1 = parsedDer.revokedCertificates[0]!;
    expect(entry1.serialNumberHex).toBe("1A2B3C");
    expect(entry1.reasonCode).toBe(CrlReasonCode.KeyCompromise);
    expect(entry1.reasonText).toBe("Key Compromise");
    expect(entry1.revocationDate.toISOString()).toBe(revocationTime1.toISOString());

    const entry2 = parsedDer.revokedCertificates[1]!;
    expect(entry2.serialNumberDec).toBe("998877");
    expect(entry2.reasonCode).toBe(CrlReasonCode.Superseded);
    expect(entry2.reasonText).toBe("Superseded");

    // 4. Parse CRL from PEM string
    const parsedPem = parseX509Crl(crlResult.crlPem);
    expect(parsedPem.version).toBe(2);
    expect(parsedPem.crlNumber).toBe(7);
    expect(parsedPem.authorityKeyIdentifierHex).toBeDefined();
  });

  it("handles ECDSA CA issuing an empty CRL without errors", async () => {
    const caCert = await createCertificate({
      commonName: "ECDSA Root CA",
      organization: "Acme Corp",
      isCa: true,
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 180,
    });

    const caSigner = await importCaSigner(caCert.certDer, caCert.privateKeyDer);

    const crlResult = await createCrl({
      signer: caSigner,
      crlNumber: 1,
      revokedCertificates: [],
    });

    const parsed = parseX509Crl(crlResult.crlDer);
    expect(parsed.version).toBe(2);
    expect(parsed.crlNumber).toBe(1);
    expect(parsed.revokedCertificates).toHaveLength(0);
    expect(parsed.issuerDn).toContain("ECDSA Root CA");
  });

  it("provides valid and parseable samples for CRL tool", async () => {
    const { samplesFor } = await import("../packages/tools/certificates/src/samples");
    const samples = samplesFor("crl");
    expect(samples.length).toBeGreaterThan(0);

    const crlSample = samples[0]!;
    expect(crlSample.id).toBe("crl-sample");
    const parsed = parseX509Crl(crlSample.text);
    expect(parsed.version).toBe(2);
    expect(parsed.revokedCertificates.length).toBeGreaterThan(0);
    expect(parsed.issuerDn).toContain("Workbench Root CA");
  });

  it("creates a clean RFC 5280 v2 CRL with ephemeral Micro-CA via computeCertificate", async () => {
    const { computeCertificate } = await import(
      "../packages/tools/certificates/src/compute"
    );
    const { createSpec } = await import(
      "../packages/tools/certificates/src/create-spec"
    );

    const spec = createSpec({ variant: "crl" });
    spec.options.crlOp = "create-crl";
    spec.options.crlCaMode = "ephemeral-ca";
    spec.options.crlCaKeyType = "ecdsa-p256";
    spec.options.crlHashType = "sha256";
    spec.options.crlNumber = "1";
    spec.options.crlValidityDays = "30";

    const result = await computeCertificate(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN X509 CRL-----");
    expect(result.text).toContain("-----END X509 CRL-----");
    expect(result.bytes).toBeDefined();

    const parsed = parseX509Crl(result.text!);
    expect(parsed.version).toBe(2);
    expect(parsed.crlNumber).toBe(1);
    expect(parsed.revokedCertificates).toHaveLength(0);
    expect(parsed.issuerDn).toContain("CipherWorkbench CRL Root CA");
    expect(parsed.signatureAlgorithmName).toContain("ecdsa");

    // Check export files
    const fileNames = result.files?.map((f) => f.name) ?? [];
    expect(fileNames).toContain("ca.crl");
    expect(fileNames).toContain("ca.crt");
    expect(fileNames).toContain("ca.key");
    expect(fileNames).toContain("commands.sh");
  });

  it("creates a CRL with revoked serial numbers and reason codes via computeCertificate", async () => {
    const { computeCertificate } = await import(
      "../packages/tools/certificates/src/compute"
    );
    const { createSpec } = await import(
      "../packages/tools/certificates/src/create-spec"
    );

    const spec = createSpec({ variant: "crl" });
    spec.options.crlOp = "create-crl";
    spec.options.crlCaMode = "ephemeral-ca";
    spec.options.crlNumber = "5";

    const revocationInput = [
      "# Serial numbers to revoke",
      "0x1A2B3C:keyCompromise",
      "998877:superseded",
      "0xDEADBEEF:cessationOfOperation",
    ].join("\n");

    const result = await computeCertificate(
      spec,
      new TextEncoder().encode(revocationInput),
    );
    expect(result.error).toBeUndefined();

    const parsed = parseX509Crl(result.text!);
    expect(parsed.version).toBe(2);
    expect(parsed.crlNumber).toBe(5);
    expect(parsed.revokedCertificates).toHaveLength(3);

    const r1 = parsed.revokedCertificates[0]!;
    expect(r1.serialNumberHex).toBe("1A2B3C");
    expect(r1.reasonCode).toBe(CrlReasonCode.KeyCompromise);
    expect(r1.reasonText).toBe("Key Compromise");

    const r2 = parsed.revokedCertificates[1]!;
    expect(r2.serialNumberDec).toBe("998877");
    expect(r2.reasonCode).toBe(CrlReasonCode.Superseded);
    expect(r2.reasonText).toBe("Superseded");

    const r3 = parsed.revokedCertificates[2]!;
    expect(r3.serialNumberHex).toBe("DEADBEEF");
    expect(r3.reasonCode).toBe(CrlReasonCode.CessationOfOperation);
  });

  it("creates a CRL by revoking pasted PEM certificates via computeCertificate", async () => {
    const { computeCertificate } = await import(
      "../packages/tools/certificates/src/compute"
    );
    const { createSpec } = await import(
      "../packages/tools/certificates/src/create-spec"
    );
    const { RSA_CERTIFICATE_PEM } = await import(
      "../packages/tools/certificates/src/samples"
    );

    const spec = createSpec({ variant: "crl" });
    spec.options.crlOp = "create-crl";
    spec.options.crlCaMode = "ephemeral-ca";
    spec.options.crlReason = "1"; // Key Compromise default

    const result = await computeCertificate(
      spec,
      new TextEncoder().encode(RSA_CERTIFICATE_PEM),
    );
    expect(result.error).toBeUndefined();

    const parsed = parseX509Crl(result.text!);
    expect(parsed.version).toBe(2);
    expect(parsed.revokedCertificates).toHaveLength(1);
    expect(parsed.revokedCertificates[0]!.reasonCode).toBe(
      CrlReasonCode.KeyCompromise,
    );
  });

  it("creates a CRL signed by a custom CA via computeCertificate", async () => {
    const { computeCertificate } = await import(
      "../packages/tools/certificates/src/compute"
    );
    const { createSpec } = await import(
      "../packages/tools/certificates/src/create-spec"
    );

    // 1. Create a custom Root CA
    const caCert = await createCertificate({
      commonName: "Custom Corporate Security CA",
      organization: "Acme Enterprise",
      isCa: true,
      keyType: "rsa-2048",
      hashType: "sha256",
      validityDays: 365,
    });

    const spec = createSpec({ variant: "crl" });
    spec.options.crlOp = "create-crl";
    spec.options.crlCaMode = "custom-ca";
    spec.options.caCert = caCert.certPem;
    spec.options.caPrivateKey = caCert.privateKeyPem;
    spec.options.crlNumber = "42";

    const result = await computeCertificate(
      spec,
      new TextEncoder().encode("0x112233:keyCompromise"),
    );
    expect(result.error).toBeUndefined();

    const parsed = parseX509Crl(result.text!);
    expect(parsed.version).toBe(2);
    expect(parsed.crlNumber).toBe(42);
    expect(parsed.issuerDn).toContain("Custom Corporate Security CA");
    expect(parsed.signatureAlgorithmName.toLowerCase()).toContain("rsa");
    expect(parsed.revokedCertificates).toHaveLength(1);
  });
});

