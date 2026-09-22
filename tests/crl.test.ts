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
});
