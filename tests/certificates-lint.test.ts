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
});
