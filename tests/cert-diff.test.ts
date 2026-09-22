import { describe, expect, it } from "vitest";
import { diffCertificates } from "../packages/tools/certificates/src/asn1/cert-diff";
import {
  RSA_CERTIFICATE_PEM,
  SAMPLE_2TIER_SERVER_PEM,
  SAMPLE_ROOT_CA_PEM,
} from "../packages/tools/certificates/src/samples";

describe("Certificate Diff Tool", () => {
  it("detects identical certificates", () => {
    const result = diffCertificates(RSA_CERTIFICATE_PEM, RSA_CERTIFICATE_PEM);

    expect(result.isIdentical).toBe(true);
    expect(result.keyRolledOver).toBe(false);
    expect(result.addedSans).toHaveLength(0);
    expect(result.removedSans).toHaveLength(0);
    expect(result.summary).toContain("IDENTICAL");
    expect(result.markdownTable).toContain("| Property | Certificate 1 (Base) | Certificate 2 (Target) | Status | Notes |");
  });

  it("handles two certificates passed in a combined PEM string", () => {
    const combined = `${RSA_CERTIFICATE_PEM}\n\n${SAMPLE_2TIER_SERVER_PEM}`;
    const result = diffCertificates(combined);

    expect(result.isIdentical).toBe(false);
    expect(result.attributes.length).toBeGreaterThan(5);
    expect(result.markdownTable).toBeDefined();
  });

  it("detects public key rollover between two different certificates", () => {
    const result = diffCertificates(RSA_CERTIFICATE_PEM, SAMPLE_2TIER_SERVER_PEM);

    expect(result.isIdentical).toBe(false);
    expect(result.keyRolledOver).toBe(true);
    const keyAttr = result.attributes.find((a) => a.name === "Public Key SHA-256");
    expect(keyAttr).toBeDefined();
    expect(keyAttr?.status).toBe("changed");
  });

  it("accurately diffs Subject DN and Issuer DN", () => {
    const result = diffCertificates(SAMPLE_2TIER_SERVER_PEM, SAMPLE_ROOT_CA_PEM);

    const subjectAttr = result.attributes.find((a) => a.name === "Subject DN");
    expect(subjectAttr).toBeDefined();
    expect(subjectAttr?.status).toBe("changed");

    const caAttr = result.attributes.find((a) => a.name === "Is CA (Basic Constraints)");
    expect(caAttr).toBeDefined();
    expect(caAttr?.cert1Value).toContain("Leaf");
    expect(caAttr?.cert2Value).toContain("TRUE");
  });

  it("throws when only one certificate is provided and no second certificate is found", () => {
    expect(() => diffCertificates(RSA_CERTIFICATE_PEM)).toThrow(/requires two certificates/i);
  });
});
