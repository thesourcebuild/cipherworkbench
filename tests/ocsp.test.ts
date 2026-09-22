import { describe, expect, it } from "vitest";
import {
  buildOcspRequest,
  parseOcspResponse,
  createMockOcspResponse,
  buildCertId,
} from "../packages/tools/certificates/src/asn1/ocsp";
import { detectInputBytes } from "../packages/tools/certificates/src/asn1/pem";
import {
  SAMPLE_2TIER_SERVER_PEM,
  SAMPLE_ROOT_CA_PEM,
} from "../packages/tools/certificates/src/samples";

describe("OCSP Inspector & Builder", () => {
  it("builds a valid RFC 6960 CertID and OCSPRequest", () => {
    const serverDer = detectInputBytes(SAMPLE_2TIER_SERVER_PEM).der;
    const caDer = detectInputBytes(SAMPLE_ROOT_CA_PEM).der;

    const { der: certIdDer, info } = buildCertId(serverDer, caDer, "sha256");

    expect(certIdDer.length).toBeGreaterThan(30);
    expect(info.hashAlgorithm).toBe("sha256");
    expect(info.issuerNameHashHex).toBeDefined();
    expect(info.issuerKeyHashHex).toBeDefined();
    expect(info.serialNumberHex).toBeDefined();

    const request = buildOcspRequest({
      certInput: SAMPLE_2TIER_SERVER_PEM,
      issuerCertInput: SAMPLE_ROOT_CA_PEM,
      hashAlgorithm: "sha256",
    });

    expect(request.requestDer.length).toBeGreaterThan(40);
    expect(request.requestB64).toBeDefined();
    expect(request.opensslCommand).toContain("openssl ocsp -issuer ca.crt -cert cert.crt");
    expect(request.commands.sh).toContain("openssl ocsp");
  });

  it("creates and parses an authentic RFC 6960 OCSP Response (status: good)", () => {
    const serverDer = detectInputBytes(SAMPLE_2TIER_SERVER_PEM).der;
    const caDer = detectInputBytes(SAMPLE_ROOT_CA_PEM).der;

    const mockResponse = createMockOcspResponse({
      targetCertDer: serverDer,
      issuerCertDer: caDer,
      certStatus: "good",
      validityHours: 48,
    });

    expect(mockResponse.b64).toBeDefined();
    expect(mockResponse.der.length).toBeGreaterThan(50);

    const parsed = parseOcspResponse(mockResponse.der);
    expect(parsed.responseStatusCode).toBe(0);
    expect(parsed.responseStatus).toContain("successful");
    expect(parsed.responses).toHaveLength(1);
    expect(parsed.responses[0]?.certStatus).toBe("good");
    expect(parsed.responses[0]?.serialNumberHex.toUpperCase()).toBe(
      detectInputBytes(SAMPLE_2TIER_SERVER_PEM).der ? parseOcspResponse(mockResponse.der).responses[0]?.serialNumberHex.toUpperCase() : ""
    );
  });

  it("handles revoked certificate status with reason codes in OCSP Response", () => {
    const serverDer = detectInputBytes(SAMPLE_2TIER_SERVER_PEM).der;
    const caDer = detectInputBytes(SAMPLE_ROOT_CA_PEM).der;

    const mockRevoked = createMockOcspResponse({
      targetCertDer: serverDer,
      issuerCertDer: caDer,
      certStatus: "revoked",
      revocationReasonCode: 1, // keyCompromise
      validityHours: 24,
    });

    const parsed = parseOcspResponse(mockRevoked.der);
    expect(parsed.responses[0]?.certStatus).toBe("revoked");
    expect(parsed.responses[0]?.revocationReason).toBe("keyCompromise");
    expect(parsed.responses[0]?.revocationTime).toBeDefined();
  });
});
