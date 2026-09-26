import { describe, expect, it } from "vitest";
import { signCsr } from "../packages/tools/certificates/src/asn1/csr-signer";
import { verifyCertificateChain } from "../packages/tools/certificates/src/asn1/chain-verifier";
import { parseX509Certificate } from "../packages/tools/certificates/src/asn1/x509";
import { ECDSA_CSR_PEM } from "../packages/tools/certificates/src/samples";

describe("CSR Signer & Micro-CA", () => {
  it("requires both custom CA credentials instead of falling back to an ephemeral CA", async () => {
    await expect(
      signCsr({
        csrInput: ECDSA_CSR_PEM,
        caMode: "custom-ca",
      }),
    ).rejects.toThrow("Custom CA signing requires both a CA certificate");
  });

  it("signs a CSR with an ephemeral Micro-CA and produces a cryptographically verifiable chain", async () => {
    const result = await signCsr({
      csrInput: ECDSA_CSR_PEM,
      caMode: "ephemeral-ca",
      validityDays: 180,
    });

    expect(result.certPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.caCertPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.bundlePem).toContain(result.certPem);
    expect(result.bundlePem).toContain(result.caCertPem);
    expect(result.subjectDn).toContain("api.workbench.local");
    expect(result.issuerDn).toContain("CipherWorkbench Micro-CA Root");
    expect(result.validityDays).toBe(180);
    expect(result.sans.some((s) => s.includes("api.workbench.local"))).toBe(true);

    // Parse issued leaf certificate
    const parsedLeaf = parseX509Certificate(result.certDer);
    expect(parsedLeaf.subject.commonName).toBe("api.workbench.local");
    expect(parsedLeaf.extensions.basicConstraints?.isCa).toBe(false);

    // Verify cryptographic signature across the 2-tier chain
    const chainVerification = await verifyCertificateChain(result.bundlePem);
    expect(chainVerification.isValid).toBe(true);
    expect(chainVerification.isSelfSignedRoot).toBe(true);
    expect(chainVerification.nodes).toHaveLength(2);
    expect(chainVerification.nodes[0]?.signatureValid).toBe(true);
    expect(chainVerification.nodes[1]?.signatureValid).toBe(true);
  });

  it("uses the selected ephemeral Micro-CA key algorithm", async () => {
    const result = await signCsr({
      csrInput: ECDSA_CSR_PEM,
      caMode: "ephemeral-ca",
      caKeyType: "ecdsa-p384",
    });

    expect(result.applicantKeyAlgorithm).toContain("Elliptic Curve");
    expect(result.caKeyType).toBe("ecdsa-p384");
    const verification = await verifyCertificateChain(result.bundlePem);
    expect(verification.isValid, JSON.stringify(verification)).toBe(true);
  });

  it("generates cross-platform verification scripts (sh, ps1, bat)", async () => {
    const result = await signCsr({
      csrInput: ECDSA_CSR_PEM,
      caMode: "ephemeral-ca",
    });

    expect(result.commands.sh).toContain("#!/usr/bin/env bash");
    expect(result.commands.sh).toContain("openssl verify -CAfile");
    expect(result.commands.ps1).toContain("Get-Command openssl");
    expect(result.commands.ps1).toContain("openssl verify -CAfile");
    expect(result.commands.bat).toContain("@echo off");
    expect(result.commands.bat).toContain("where /q openssl");

    const shFile = result.exportFiles.find((f) => f.name === "commands.sh");
    const ps1File = result.exportFiles.find((f) => f.name === "commands.ps1");
    const batFile = result.exportFiles.find((f) => f.name === "commands.bat");
    expect(shFile).toBeDefined();
    expect(ps1File).toBeDefined();
    expect(batFile).toBeDefined();
  });

  it("allows overriding and extending SANs during signing", async () => {
    const result = await signCsr({
      csrInput: ECDSA_CSR_PEM,
      overrideSan: "custom.domain.net, 10.0.0.1",
    });

    expect(result.sans).toContain("custom.domain.net");
    expect(result.sans).toContain("10.0.0.1");

    const parsed = parseX509Certificate(result.certDer);
    expect(parsed.extensions.sans.some((s) => s.includes("custom.domain.net"))).toBe(true);
  });
});
