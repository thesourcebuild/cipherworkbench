import { describe, expect, it } from "vitest";
import { createSpec } from "../packages/tools/certificates/src/create-spec";
import { lint } from "../packages/tools/certificates/src/lint/run";

describe("Certificates Lint Rules & CAB Forum Compliance", () => {
  it("flags leaf certificate validity exceeding 398 days (CERT002)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      creatorMode: "single-cert",
      isCa: false,
      validityDays: "825", // > 398 days
      commonName: "example.com",
      san: "example.com",
    };

    const { diagnostics } = lint(spec);
    const cert002 = diagnostics.find((d) => d.code === "CERT002");
    expect(cert002).toBeDefined();
    expect(cert002?.level).toBe("warning");
    expect(cert002?.message).toContain("398 days");
  });

  it("does not flag CA certificate with > 398 days validity (CERT002)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      creatorMode: "single-cert",
      isCa: true,
      validityDays: "3650", // 10 years for Root CA
      commonName: "Internal Root CA",
      san: "",
    };

    const { diagnostics } = lint(spec);
    const cert002 = diagnostics.find((d) => d.code === "CERT002");
    expect(cert002).toBeUndefined();
  });

  it("flags empty Subject Alternative Name for leaf certificate (CERT003)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      creatorMode: "single-cert",
      isCa: false,
      san: "",
    };

    const { diagnostics } = lint(spec);
    const cert003 = diagnostics.find((d) => d.code === "CERT003");
    expect(cert003).toBeDefined();
    expect(cert003?.level).toBe("warning");
    expect(cert003?.message).toContain("Subject Alternative Name (SAN) is empty");
  });

  it("flags leaf certificate having no Extended Key Usages selected (CERT005)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      creatorMode: "single-cert",
      isCa: false,
      serverAuth: false,
      clientAuth: false,
      codeSigning: false,
      san: "localhost",
      validityDays: "365",
    };

    const { diagnostics } = lint(spec);
    const cert005 = diagnostics.find((d) => d.code === "CERT005");
    expect(cert005).toBeDefined();
    expect(cert005?.level).toBe("warning");
    expect(cert005?.message).toContain("No Extended Key Usage (EKU) is selected");
  });

  it("flags weak RSA key size below 2048 bits (CERT006)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      keyType: "rsa-1024",
    };

    const { diagnostics } = lint(spec);
    const cert006 = diagnostics.find((d) => d.code === "CERT006");
    expect(cert006).toBeDefined();
    expect(cert006?.level).toBe("error");
    expect(cert006?.message).toContain("Insecure RSA key size");
  });

  it("flags deprecated signature digest like SHA-1 or MD5 (CERT007)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      hashType: "sha1",
    };

    const { diagnostics } = lint(spec);
    const cert007 = diagnostics.find((d) => d.code === "CERT007");
    expect(cert007).toBeDefined();
    expect(cert007?.level).toBe("error");
    expect(cert007?.message).toContain("Insecure signature digest algorithm");
  });

  it("flags illegal wildcard TLD in SAN (CERT008)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      san: "*.com",
    };

    const { diagnostics } = lint(spec);
    const cert008 = diagnostics.find((d) => d.code === "CERT008");
    expect(cert008).toBeDefined();
    expect(cert008?.level).toBe("error");
    expect(cert008?.message).toContain("Illegal wildcard SAN");
  });

  it("flags malformed IPv4 address in SAN (CERT008)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      san: "192.168.1.300",
    };

    const { diagnostics } = lint(spec);
    const cert008 = diagnostics.find((d) => d.code === "CERT008");
    expect(cert008).toBeDefined();
    expect(cert008?.level).toBe("error");
    expect(cert008?.message).toContain("Malformed IPv4 SAN address");
  });

  it("flags negative or excessively large serial numbers (CERT009)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      serialNumber: "-12345",
    };

    const { diagnostics } = lint(spec);
    const cert009 = diagnostics.find((d) => d.code === "CERT009");
    expect(cert009).toBeDefined();
    expect(cert009?.level).toBe("error");
    expect(cert009?.message).toContain("Serial number must be a positive integer");
  });

  it("flags CA certificate missing BasicConstraints extension (CERT010)", () => {
    const spec = createSpec({ variant: "cert-creator" });
    spec.options = {
      ...spec.options,
      isCa: true,
      basicConstraints: "false",
    };

    const { diagnostics } = lint(spec);
    const cert010 = diagnostics.find((d) => d.code === "CERT010");
    expect(cert010).toBeDefined();
    expect(cert010?.level).toBe("error");
    expect(cert010?.message).toContain("Certificate Authority must have BasicConstraints");
  });
});
