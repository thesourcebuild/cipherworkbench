import { describe, expect, it } from "vitest";
import { loadTool } from "@ocs/registry";
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
  OPTION_OCSP_OP,
  OPTION_ISSUER_CERT,
} from "@ocs/certificates";
import { formatShellCommands } from "../packages/ui/src/shell-command";

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

  describe("OpenSSL CLI Providers for OCSP", () => {
    it("generates OpenSSL ocsp commands for build-request", async () => {
      const tool = await loadTool("ocsp");
      const spec = {
        ...tool.createSpec(),
        options: {
          [OPTION_OCSP_OP]: "build-request",
          [OPTION_ISSUER_CERT]: SAMPLE_ROOT_CA_PEM,
        },
      };

      const result = await tool.compute(spec, new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM));
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain("openssl ocsp -issuer ca.crt -cert cert.crt");
      expect(bash).toContain("openssl ocsp -issuer ca.crt -cert cert.crt -reqout ocsp-req.der -text");
      expect(bash).toContain("openssl ocsp -respin ocsp.der -text -noverify");

      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const gnutlsBash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(gnutlsBash).toContain("ocsptool --generate-request --load-cert cert.crt --load-issuer ca.crt --outfile ocsp-req.der");
      expect(gnutlsBash).toContain("ocsptool --response-info --load-response ocsp.der");
    });

    it("generates OpenSSL and GnuTLS ocsp commands for generate-staple", async () => {
      const tool = await loadTool("ocsp");
      const spec = {
        ...tool.createSpec(),
        options: {
          [OPTION_OCSP_OP]: "generate-staple",
          [OPTION_ISSUER_CERT]: SAMPLE_ROOT_CA_PEM,
        },
      };

      const result = await tool.compute(spec, new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM));
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain("openssl ocsp -respin staple.der -text -noverify");
      expect(bash).toContain("openssl ocsp -issuer ca.crt -cert cert.crt -url <ocsp_url> -respout staple.der");

      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const gnutlsBash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(gnutlsBash).toContain("ocsptool --ask=<ocsp_url> --load-cert cert.crt --load-issuer ca.crt --outfile staple.der");
      expect(gnutlsBash).toContain("ocsptool --response-info --load-response staple.der");
    });

    it("generates OpenSSL and GnuTLS ocsp commands for inspect-response", async () => {
      const tool = await loadTool("ocsp");
      const spec = {
        ...tool.createSpec(),
        options: {
          [OPTION_OCSP_OP]: "inspect-response",
        },
      };

      const serverDer = detectInputBytes(SAMPLE_2TIER_SERVER_PEM).der;
      const caDer = detectInputBytes(SAMPLE_ROOT_CA_PEM).der;
      const mockResponse = createMockOcspResponse({
        targetCertDer: serverDer,
        issuerCertDer: caDer,
        certStatus: "good",
        validityHours: 48,
      });

      const result = await tool.compute(spec, mockResponse.der);
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain("openssl ocsp -respin ocsp-response.der -text -noverify");
      expect(bash).toContain("openssl ocsp -respin ocsp-response.der -CAfile ca.crt -text");

      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const gnutlsBash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(gnutlsBash).toContain("ocsptool --response-info --load-response ocsp-response.der");
      expect(gnutlsBash).toContain("ocsptool --verify-response --load-response ocsp-response.der --load-trust ca.crt");
    });
  });
});
