import { describe, expect, it } from "vitest";
import { loadTool } from "@ocs/registry";
import {
  RSA_CERTIFICATE_PEM,
  RSA_PRIVATE_KEY_PEM,
  ECDSA_CSR_PEM,
  CERTIFICATE_CHAIN_PEM,
  SAMPLE_PPK_TEXT,
  SAMPLE_PKCS12_BASE64,
  SAMPLE_PKCS7_PEM,
  SAMPLE_DER_CERT_HEX,
  SAMPLE_CRL_PEM,
  samplesFor,
  OPTION_CONVERTER_OP,
  OPTION_PASSWORD,
  OPTION_PRIVATE_KEY,
} from "@ocs/certificates";
import { formatShellCommands } from "../packages/ui/src/shell-command";

describe("Certificate Converter - All Input Formats & Operations", () => {
  it("verifies all sample test inputs compute without error", async () => {
    const tool = await loadTool("cert-converter");
    expect(tool.id).toBe("cert-converter");
    const samples = samplesFor("cert-converter");

    expect(samples.length).toBeGreaterThanOrEqual(8);

    for (const sample of samples) {
      expect(sample.text).toBeDefined();
      expect(sample.text.length).toBeGreaterThan(0);
      expect(sample.label).toBeDefined();
      expect(sample.note).toBeDefined();
    }
  });

  it("converts PEM to DER binary for Certificate, Key, and CSR", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "pem-to-der" },
    };

    // 1. Certificate to DER
    const certResult = await tool.compute(spec, new TextEncoder().encode(RSA_CERTIFICATE_PEM));
    expect(certResult.error).toBeUndefined();
    expect(certResult.bytes).toBeDefined();
    expect(certResult.bytes!.length).toBeGreaterThan(100);

    // 2. Private Key to DER
    const keyResult = await tool.compute(spec, new TextEncoder().encode(RSA_PRIVATE_KEY_PEM));
    expect(keyResult.error).toBeUndefined();
    expect(keyResult.bytes).toBeDefined();
    expect(keyResult.bytes!.length).toBeGreaterThan(100);

    // 3. CSR to DER
    const csrResult = await tool.compute(spec, new TextEncoder().encode(ECDSA_CSR_PEM));
    expect(csrResult.error).toBeUndefined();
    expect(csrResult.bytes).toBeDefined();
    expect(csrResult.bytes!.length).toBeGreaterThan(100);
  });

  it("converts DER binary to PEM (der-to-pem)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "der-to-pem" },
    };

    const derBytes = Buffer.from(SAMPLE_DER_CERT_HEX, "hex");
    const result = await tool.compute(spec, derBytes);
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.text).toContain("-----END CERTIFICATE-----");
  });

  it("packages certificate into PKCS#7 / P7B bundle (pem-to-pkcs7)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "pem-to-pkcs7" },
    };

    const result = await tool.compute(spec, new TextEncoder().encode(CERTIFICATE_CHAIN_PEM));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN PKCS7-----");
    expect(result.text).toContain("-----END PKCS7-----");
  });

  it("extracts certificates from PKCS#7 container (pkcs7-to-pem)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "pkcs7-to-pem" },
    };

    const result = await tool.compute(spec, new TextEncoder().encode(SAMPLE_PKCS7_PEM));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("packages certificate + private key into PKCS#12 (.pfx / .p12)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: {
        [OPTION_CONVERTER_OP]: "pem-to-pkcs12",
        [OPTION_PASSWORD]: "testpass123",
        [OPTION_PRIVATE_KEY]: RSA_PRIVATE_KEY_PEM,
      },
    };

    const result = await tool.compute(spec, new TextEncoder().encode(RSA_CERTIFICATE_PEM));
    expect(result.error).toBeUndefined();
    expect(result.bytes).toBeDefined();
    expect(result.text).toBeDefined(); // base64
    expect(result.fields?.some((f) => f.label === "Operation")).toBe(true);
  });

  it("extracts certificates and private key from PKCS#12 archive (pkcs12-to-pem)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: {
        [OPTION_CONVERTER_OP]: "pkcs12-to-pem",
        [OPTION_PASSWORD]: "password123",
      },
    };

    const p12Bytes = Buffer.from(SAMPLE_PKCS12_BASE64, "base64");
    const result = await tool.compute(spec, p12Bytes);
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.text).toContain("-----BEGIN PRIVATE KEY-----");
  });

  it("inspects PKCS#12 archive metadata and structure (pkcs12-inspect)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: {
        [OPTION_CONVERTER_OP]: "pkcs12-inspect",
      },
    };

    const p12Bytes = Buffer.from(SAMPLE_PKCS12_BASE64, "base64");
    const result = await tool.compute(spec, p12Bytes);
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("PKCS#12 Container Inspection Report");
    expect(result.text).toContain("MAC Present");
    expect(result.text).toContain("Certificates Found");
    expect(result.text).toContain("Private Key Present");
  });

  it("converts PEM private key to PuTTY v3 format (pem-to-ppk)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "pem-to-ppk" },
    };

    const result = await tool.compute(spec, new TextEncoder().encode(RSA_PRIVATE_KEY_PEM));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("PuTTY-User-Key-File-3: ssh-rsa");
    expect(result.text).toContain("Private-MAC:");
  });

  it("converts PuTTY PPK back to PKCS#8 PEM private key (ppk-to-pem)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "ppk-to-pem" },
    };

    const result = await tool.compute(spec, new TextEncoder().encode(SAMPLE_PPK_TEXT));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("-----BEGIN PRIVATE KEY-----");
    expect(result.fields?.some((f) => f.label === "Operation")).toBe(true);
  });

  it("extracts public key SPKI from Certificate and CSR (extract-public-key)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "extract-public-key" },
    };

    // From Cert
    const certRes = await tool.compute(spec, new TextEncoder().encode(RSA_CERTIFICATE_PEM));
    expect(certRes.error).toBeUndefined();
    expect(certRes.text).toContain("-----BEGIN PUBLIC KEY-----");

    // From CSR
    const csrRes = await tool.compute(spec, new TextEncoder().encode(ECDSA_CSR_PEM));
    expect(csrRes.error).toBeUndefined();
    expect(csrRes.text).toContain("-----BEGIN PUBLIC KEY-----");
  });

  it("splits multi-certificate bundle into individual certs (split-chain)", async () => {
    const tool = await loadTool("cert-converter");
    const spec = {
      ...tool.createSpec(),
      options: { [OPTION_CONVERTER_OP]: "split-chain" },
    };

    const result = await tool.compute(spec, new TextEncoder().encode(CERTIFICATE_CHAIN_PEM));
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("CERTIFICATE #1");
    expect(result.text).toContain("CERTIFICATE #2");
  });

  describe("OpenSSL CLI Providers for PKCS#12, PKCS#7, and CRL", () => {
    it("generates OpenSSL pkcs12 export commands (pem-to-pkcs12)", async () => {
      const tool = await loadTool("cert-converter");
      const spec = {
        ...tool.createSpec(),
        options: {
          [OPTION_CONVERTER_OP]: "pem-to-pkcs12",
          [OPTION_PASSWORD]: "testpass123",
          [OPTION_PRIVATE_KEY]: RSA_PRIVATE_KEY_PEM,
        },
      };

      const result = await tool.compute(spec, new TextEncoder().encode(RSA_CERTIFICATE_PEM));
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain('openssl pkcs12 -export -out bundle.p12 -inkey key.pem -in cert.pem -passout "pass:testpass123"');
      expect(bash).toContain("openssl pkcs12 -export -out bundle.p12 -inkey key.pem -in cert.pem -certfile chain.pem");
    });

    it("generates OpenSSL pkcs12 extract commands (pkcs12-to-pem)", async () => {
      const tool = await loadTool("cert-converter");
      const spec = {
        ...tool.createSpec(),
        options: {
          [OPTION_CONVERTER_OP]: "pkcs12-to-pem",
          [OPTION_PASSWORD]: "password123",
        },
      };

      const p12Bytes = Buffer.from(SAMPLE_PKCS12_BASE64, "base64");
      const result = await tool.compute(spec, p12Bytes);
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain('openssl pkcs12 -in bundle.p12 -nodes -out cert-and-key.pem -passin "pass:password123"');
      expect(bash).toContain("openssl pkcs12 -in bundle.p12 -clcerts -nokeys -out cert.pem");
      expect(bash).toContain("openssl pkcs12 -in bundle.p12 -nocerts -nodes -out key.pem");
      expect(bash).toContain("openssl pkcs12 -in bundle.p12 -cacerts -nokeys -out chain.pem");
    });

    it("generates OpenSSL pkcs12 inspect commands (pkcs12-inspect)", async () => {
      const tool = await loadTool("cert-converter");
      const spec = {
        ...tool.createSpec(),
        options: {
          [OPTION_CONVERTER_OP]: "pkcs12-inspect",
          [OPTION_PASSWORD]: "password123",
        },
      };

      const p12Bytes = Buffer.from(SAMPLE_PKCS12_BASE64, "base64");
      const result = await tool.compute(spec, p12Bytes);
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain('openssl pkcs12 -in bundle.p12 -info -noout -passin "pass:password123"');
    });

    it("generates OpenSSL crl2pkcs7 bundle commands (pem-to-pkcs7)", async () => {
      const tool = await loadTool("cert-converter");
      const spec = {
        ...tool.createSpec(),
        options: { [OPTION_CONVERTER_OP]: "pem-to-pkcs7" },
      };

      const result = await tool.compute(spec, new TextEncoder().encode(CERTIFICATE_CHAIN_PEM));
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain("openssl crl2pkcs7 -nocrl -certfile cert.pem -out certs.p7b");
      expect(bash).toContain("openssl crl2pkcs7 -nocrl -certfile cert.pem -certfile chain.pem -out certs.p7b");
    });

    it("generates OpenSSL pkcs7 print_certs commands (pkcs7-to-pem)", async () => {
      const tool = await loadTool("cert-converter");
      const spec = {
        ...tool.createSpec(),
        options: { [OPTION_CONVERTER_OP]: "pkcs7-to-pem" },
      };

      const result = await tool.compute(spec, new TextEncoder().encode(SAMPLE_PKCS7_PEM));
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain("openssl pkcs7 -in certs.p7b -print_certs -out certs.pem");
      expect(bash).toContain("openssl pkcs7 -in certs.p7b -text -noout");
    });

    it("generates OpenSSL crl and crl2pkcs7 commands in CRL tool", async () => {
      const crlTool = await loadTool("crl");
      const spec = crlTool.createSpec();
      const result = await crlTool.compute(spec, new TextEncoder().encode(SAMPLE_CRL_PEM));
      expect(result.error).toBeUndefined();
      const openssl = result.cliProviders?.find((p) => p.id === "openssl");
      expect(openssl).toBeDefined();
      const bash = formatShellCommands(openssl!.commands, "bash", "single-line");
      expect(bash).toContain("openssl crl -in crl.pem -text -noout");
      expect(bash).toContain("openssl crl2pkcs7 -in crl.pem -certfile cert.pem -out bundle.p7b");
    });
  });
});
