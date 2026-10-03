import { describe, expect, it } from "vitest";
import { loadTool } from "@ocs/registry";
import { formatShellCommands } from "../packages/ui/src/shell-command";
import {
  generateCertConverterCliProviders,
  generateOcspCliProviders,
  generateCertCommandScripts,
  generateCsrCommandScripts,
  generateCrlCommandScripts,
  generateMtlsCommandScripts,
  SAMPLE_2TIER_SERVER_PEM,
  SAMPLE_ROOT_CA_PEM,
  SAMPLE_CRL_PEM,
  RSA_CERTIFICATE_PEM,
  ECDSA_CSR_PEM,
  OPTION_CREATOR_MODE,
  OPTION_COMPARISON_CERT,
} from "@ocs/certificates";

describe("GnuTLS Tooling Integration", () => {
  describe("Certificate & Key Converter GnuTLS CLI Provider", () => {
    it("generates certtool commands for pem-to-pkcs12", () => {
      const providers = generateCertConverterCliProviders("pem-to-pkcs12", {
        detectedType: "x509-pem",
        password: "secret123",
      });
      const gnutls = providers.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      expect(gnutls!.label).toBe("GnuTLS (certtool)");
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --to-p12");
      expect(bash).toContain("--load-certificate cert.pem");
      expect(bash).toContain("--load-privkey key.pem");
      expect(bash).toContain("--outfile bundle.p12");
    });

    it("generates certtool commands for pkcs12-to-pem and pkcs12-inspect", () => {
      const providers = generateCertConverterCliProviders("pkcs12-inspect", { detectedType: "pkcs12" });
      const gnutls = providers.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --p12-info --infile bundle.p12");
    });

    it("generates certtool commands for pkcs7 bundle operations", () => {
      const providers = generateCertConverterCliProviders("pkcs7-to-pem", { detectedType: "pkcs7" });
      const gnutls = providers.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --p7-info --infile certs.p7b");
    });

    it("generates certtool commands for X.509 DER/PEM format conversions and SPKI public key export", () => {
      const providers = generateCertConverterCliProviders("pem-to-der", { detectedType: "x509-pem" });
      const gnutls = providers.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --certificate-info --infile cert.pem --outder --outfile cert.der");
      expect(bash).toContain("certtool --certificate-info --infile cert.der --inder --outfile cert.pem");
      expect(bash).toContain("certtool --pubkey-info --load-certificate cert.pem --outfile pubkey.pem");
    });
  });

  describe("OCSP Responder & Stapling GnuTLS CLI Provider (ocsptool)", () => {
    it("generates ocsptool query and request creation commands for build-request", () => {
      const providers = generateOcspCliProviders("build-request");
      const gnutls = providers.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      expect(gnutls!.label).toBe("GnuTLS (ocsptool)");
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("ocsptool --generate-request --load-cert cert.crt --load-issuer ca.crt --outfile ocsp-req.der");
      expect(bash).toContain("ocsptool --response-info --load-response ocsp.der");
    });

    it("generates ocsptool commands for generate-staple", () => {
      const providers = generateOcspCliProviders("generate-staple");
      const gnutls = providers.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("ocsptool --ask=<ocsp_url> --load-cert cert.crt --load-issuer ca.crt --outfile staple.der");
      expect(bash).toContain("ocsptool --response-info --load-response staple.der");
    });

    it("generates ocsptool response verification commands for inspect-response", () => {
      const providers = generateOcspCliProviders("inspect-response");
      const gnutls = providers.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("ocsptool --response-info --load-response ocsp-response.der");
      expect(bash).toContain("ocsptool --verify-response --load-response ocsp-response.der --load-trust ca.crt");
    });
  });

  describe("TLS Grader, Cert Expiry, and Universal Decoder GnuTLS Providers", () => {
    it("provides GnuTLS gnutls-cli command in tls-grader", async () => {
      const grader = await loadTool("tls-grader");
      const result = await grader.compute(
        grader.createSpec(),
        new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM),
      );
      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      expect(gnutls!.label).toBe("GnuTLS (gnutls-cli)");
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("gnutls-cli --print-cert -p 443 host </dev/null");
      expect(bash).toContain("certtool --certificate-info --infile cert.pem");

      const ps = formatShellCommands(gnutls!.commands, "powershell", "single-line");
      expect(ps).toContain("gnutls-cli --print-cert -p 443 host");
    });

    it("provides GnuTLS certtool command in cert-expiry", async () => {
      const expiry = await loadTool("cert-expiry");
      const result = await expiry.compute(
        expiry.createSpec(),
        new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM),
      );
      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      expect(gnutls!.label).toBe("GnuTLS (certtool)");
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --certificate-info --infile cert.pem");
      expect(bash).toContain("gnutls-cli --print-cert -p 443 example.com");
    });

    it("provides GnuTLS certtool command for X.509 certificate in universal-decoder", async () => {
      const decoder = await loadTool("universal-decoder");
      const result = await decoder.compute(
        decoder.createSpec(),
        new TextEncoder().encode(RSA_CERTIFICATE_PEM),
      );
      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      expect(gnutls!.label).toBe("GnuTLS (certtool)");
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --certificate-info --infile cert.pem");
    });

    it("provides GnuTLS certtool command for CSR in universal-decoder", async () => {
      const decoder = await loadTool("universal-decoder");
      const result = await decoder.compute(
        decoder.createSpec(),
        new TextEncoder().encode(ECDSA_CSR_PEM),
      );
      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --crq-info --infile request.csr");
    });

    it("provides GnuTLS p11tool command for PKCS#11 URI in universal-decoder", async () => {
      const decoder = await loadTool("universal-decoder");
      const pkcs11Uri = "pkcs11:token=TestToken;object=TestKey;type=private";
      const result = await decoder.compute(
        decoder.createSpec(),
        new TextEncoder().encode(pkcs11Uri),
      );
      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      expect(gnutls!.label).toBe("GnuTLS (p11tool)");
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("p11tool --info");
    });

    it("handles JWT gracefully without suggesting certtool in universal-decoder", async () => {
      const decoder = await loadTool("universal-decoder");
      const jwtToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MzQwMjMwMDd9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const result = await decoder.compute(
        decoder.createSpec(),
        new TextEncoder().encode(jwtToken),
      );
      const gnutls = result.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).not.toContain("certtool --certificate-info");
      expect(bash).toContain("jwt.io");
    });
  });

  describe("Export Script Generation with GnuTLS Actions", () => {
    it("includes gnutls action in certificate verification scripts", () => {
      const scripts = generateCertCommandScripts({
        certFile: "server.crt",
        keyFile: "server.key",
        chainFile: "ca.crt",
        opensslCommand: "openssl x509 -in server.crt -text -noout",
      });

      expect(scripts.sh).toContain("certtool --certificate-info --infile \"server.crt\"");
      expect(scripts.sh).toContain("certtool --key-info --infile \"server.key\"");
      expect(scripts.sh).toContain("certtool --verify-chain --load-ca-certificate \"ca.crt\" --infile \"server.crt\"");

      // In PowerShell, verify & operator prefix for certtool
      expect(scripts.ps1).toContain("& certtool --certificate-info --infile \"server.crt\"");
      expect(scripts.ps1).toContain("& certtool --key-info --infile \"server.key\"");
    });

    it("includes gnutls action in mTLS verification scripts", () => {
      const scripts = generateMtlsCommandScripts({
        pkiHierarchy: "2-tier",
        opensslServer: "openssl s_server",
        curlPem: "curl https://localhost:8443",
        curlP12: "curl -E client.p12",
      });

      expect(scripts.sh).toContain("certtool --certificate-info --infile server.crt");
      expect(scripts.sh).toContain("gnutls-cli --x509cafile ca.crt --x509certfile client.crt");
      expect(scripts.ps1).toContain("& gnutls-cli --x509cafile ca.crt --x509certfile client.crt");
    });

    it("includes gnutls action in CSR and CRL verification scripts", () => {
      const csrScripts = generateCsrCommandScripts({
        csrFile: "request.csr",
        keyFile: "private.key",
        opensslCommand: "openssl req -in request.csr -text -noout",
      });
      expect(csrScripts.sh).toContain("certtool --crq-info --infile \"request.csr\"");
      expect(csrScripts.ps1).toContain("& certtool --crq-info --infile \"request.csr\"");

      const crlScripts = generateCrlCommandScripts({
        crlFile: "revoked.crl",
        caCertFile: "ca.crt",
      });
      expect(crlScripts.sh).toContain("certtool --crl-info --infile \"revoked.crl\"");
      expect(crlScripts.ps1).toContain("& certtool --crl-info --infile \"revoked.crl\"");
    });
  });

  describe("Certificate Tools GnuTLS Providers", () => {
    it("provides certtool commands in cert-creator (single cert mode)", async () => {
      const tool = await loadTool("cert-creator");
      const res = await tool.compute(tool.createSpec(), new Uint8Array(0));
      const gnutls = res.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      expect(gnutls!.label).toBe("GnuTLS (certtool)");
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --certificate-info --infile certificate.crt");
      expect(bash).toContain("certtool --key-info --infile private.key");
    });

    it("provides certtool & gnutls-cli commands in cert-creator (mTLS mode)", async () => {
      const tool = await loadTool("cert-creator");
      const spec = tool.createSpec();
      spec.options = { [OPTION_CREATOR_MODE]: "mtls-suite" };
      const res = await tool.compute(spec, new Uint8Array(0));
      const gnutls = res.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --p12-info --infile client.p12");
      expect(bash).toContain("gnutls-cli --x509cafile ca.crt");
    });

    it("provides certtool commands in csr-creator", async () => {
      const tool = await loadTool("csr-creator");
      const res = await tool.compute(tool.createSpec(), new Uint8Array(0));
      const gnutls = res.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --crq-info --infile request.csr");
    });

    it("provides certtool commands in cert-matcher", async () => {
      const tool = await loadTool("cert-matcher");
      const res = await tool.compute(tool.createSpec(), new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM));
      const gnutls = res.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --pubkey-info --infile cert.pem");
    });

    it("provides certtool commands in cert-diff", async () => {
      const tool = await loadTool("cert-diff");
      const spec = tool.createSpec();
      spec.options = { [OPTION_COMPARISON_CERT]: SAMPLE_ROOT_CA_PEM };
      const res = await tool.compute(spec, new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM));
      const gnutls = res.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --certificate-info --infile cert1.pem");
    });

    it("provides certtool commands in csr-signer", async () => {
      const tool = await loadTool("csr-signer");
      const res = await tool.compute(tool.createSpec(), new TextEncoder().encode(ECDSA_CSR_PEM));
      const gnutls = res.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --generate-certificate");
      expect(bash).toContain("certtool --verify");
    });

    it("provides certtool commands in crl parser", async () => {
      const tool = await loadTool("crl");
      const res = await tool.compute(tool.createSpec(), new TextEncoder().encode(SAMPLE_CRL_PEM));
      const gnutls = res.cliProviders?.find((p) => p.id === "gnutls");
      expect(gnutls).toBeDefined();
      const bash = formatShellCommands(gnutls!.commands, "bash", "single-line");
      expect(bash).toContain("certtool --crl-info --infile crl.pem");
    });
  });
});
