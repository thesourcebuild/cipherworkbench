import { describe, expect, it } from "vitest";
import {
  gradeCertificate,
  auditCertificateExpiry,
  decodeUniversalArtifact,
  parseX509Certificate,
  RSA_CERTIFICATE_PEM,
  ECDSA_CSR_PEM,
  SAMPLE_ROOT_CA_PEM,
  SAMPLE_2TIER_SERVER_PEM,
  EXPIRED_CERTIFICATE_PEM,
  EXPIRING_SOON_CERTIFICATE_PEM,
  WILDCARD_SAN_CERTIFICATE_PEM,
  SAMPLE_FLEET_BUNDLE_PEM,
} from "@ocs/certificates";
import { getManifest, loadTool } from "@ocs/registry";
import { formatShellCommands, type CliTool } from "../packages/ui/src/shell-command";

describe("TLS & Certificate Health Grader (Inspired by sslx grade)", () => {
  it("grades a standard modern production TLS certificate as A/A+", () => {
    const result = gradeCertificate(SAMPLE_2TIER_SERVER_PEM);

    expect(["A+", "A"]).toContain(result.grade);
    expect(result.score).toBeGreaterThanOrEqual(85);
    expect(result.asciiBanner).toContain("Grade:");
    expect(result.sslxCommand).toContain("sslx grade");
    expect(result.checks.length).toBeGreaterThanOrEqual(5);

    // Verify individual checks
    const sigCheck = result.checks.find((c) => c.category === "signature");
    expect(sigCheck?.status).toBe("pass");

    const keyCheck = result.checks.find((c) => c.category === "key");
    expect(keyCheck?.status).toBe("pass");
  });

  it("evaluates complete chain bundles in TLS Grader", () => {
    const chainBundle = `${SAMPLE_2TIER_SERVER_PEM}\n\n${SAMPLE_ROOT_CA_PEM}`;
    const result = gradeCertificate(chainBundle);

    expect(["A+", "A"]).toContain(result.grade);
    expect(result.chainCerts).toBeDefined();
    expect(result.chainCerts?.length).toBe(2);

    const chainCheck = result.checks.find((c) => c.id === "chain-completeness");
    expect(chainCheck?.status).toBe("pass");
    expect(chainCheck?.title).toContain("Complete Chain Provided");
  });

  it("calculates visual progress bar and CA/B Forum compliance on X.509 certificates", () => {
    const cert = parseX509Certificate(new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM));

    expect(cert.validity.visualProgressBar).toMatch(/\[[█░]{10}\]\s+\d+%/);
    expect(cert.validity.percentElapsed).toBeGreaterThanOrEqual(0);
    expect(cert.validity.percentElapsed).toBeLessThanOrEqual(100);
    expect(cert.validity.totalDays).toBeGreaterThan(0);
    expect(cert.validity.cabForumCompliance).toBeDefined();
  });
});

describe("Multi-Host Certificate Expiry Auditor (Inspired by sslx expiry)", () => {
  it("audits single and multi-certificate PEM bundles with status gauges", () => {
    const bundle = `${SAMPLE_2TIER_SERVER_PEM}\n\n${RSA_CERTIFICATE_PEM}\n\n${SAMPLE_ROOT_CA_PEM}`;
    const report = auditCertificateExpiry(bundle);

    expect(report.totalCount).toBe(3);
    expect(report.items).toHaveLength(3);
    expect(report.asciiTable).toContain("Expires");
    expect(report.asciiTable).toContain("Lifespan Gauge");
    expect(report.asciiTable).toContain("Days Left");

    // Verify JSON & CSV exports
    expect(report.jsonExport).toContain('"total": 3');
    expect(report.csvExport).toContain("Subject,Issuer,Expires");

    // Verify Prometheus alert rule snippet
    expect(report.prometheusSnippet).toContain("CertificateExpiringSoon");
    expect(report.prometheusSnippet).toContain("CertificateCriticalExpiry");

    // Verify sslx CLI command only includes valid hostnames, never space-separated CA names
    expect(report.sslxCommand).toContain("sslx expiry");
    expect(report.sslxCommand).not.toContain("Root CA");
    expect(report.sslxCommand).not.toMatch(/sslx expiry .*\s[A-Z][a-z]+ [A-Z]/);
  });

  it("accurately detects already-expired certificates with 100% progress gauge and alert status", () => {
    const report = auditCertificateExpiry(EXPIRED_CERTIFICATE_PEM);

    expect(report.totalCount).toBe(1);
    const item = report.items[0]!;
    expect(item.isExpired).toBe(true);
    expect(item.status).toBe("EXPIRED");
    expect(item.percentElapsed).toBe(100);
    expect(item.visualProgressBar).toContain("[██████████] 100%");
    expect(item.daysRemaining).toBeLessThan(0);
    expect(item.subjectCn).toContain("expired.example.com");
  });

  it("flags certificates expiring soon (< 30 days) with warning status and high gauge", () => {
    const report = auditCertificateExpiry(EXPIRING_SOON_CERTIFICATE_PEM);

    expect(report.totalCount).toBe(1);
    const item = report.items[0]!;
    expect(item.isExpired).toBe(false);
    expect(item.daysRemaining).toBeLessThanOrEqual(30);
    expect(["EXPIRING_SOON", "CRITICAL"]).toContain(item.status);
    expect(item.percentElapsed).toBeGreaterThanOrEqual(80);
    expect(item.subjectCn).toContain("api.expiring-soon.internal");
  });

  it("audits enterprise multi-domain wildcard certificate and extracts SAN coverage", () => {
    const report = auditCertificateExpiry(WILDCARD_SAN_CERTIFICATE_PEM);

    expect(report.totalCount).toBe(1);
    const item = report.items[0]!;
    expect(item.isExpired).toBe(false);
    expect(item.subjectCn).toContain("*.workbench.internal");
    expect(item.sans).toContain("DNS:*.workbench.internal");
    expect(item.sans).toContain("DNS:auth.workbench.internal");
  });

  it("audits a heterogeneous 5-certificate production fleet bundle with mixed lifespans", () => {
    const report = auditCertificateExpiry(SAMPLE_FLEET_BUNDLE_PEM);

    expect(report.totalCount).toBe(5);
    expect(report.items).toHaveLength(5);

    // Verify mix of expired, active, and warning certificates
    const expiredCount = report.items.filter((i) => i.isExpired).length;
    const activeCount = report.items.filter((i) => !i.isExpired).length;
    expect(expiredCount).toBeGreaterThanOrEqual(1);
    expect(activeCount).toBeGreaterThanOrEqual(3);

    // Check JSON export contains all 5 certificates
    const parsedJson = JSON.parse(report.jsonExport);
    expect(parsedJson.summary.total).toBe(5);
    expect(parsedJson.certificates).toHaveLength(5);

    // Check CSV export headers and row counts
    const csvLines = report.csvExport.trim().split("\n");
    expect(csvLines.length).toBe(6); // 1 header line + 5 data rows
  });
});

describe("Universal Cryptographic Artifact Sniffer (Inspired by sslx decode)", () => {
  it("detects and unpacks JWT tokens with human-readable expiration", () => {
    const sampleJwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MzQwMjMwMDd9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const decoded = decodeUniversalArtifact(sampleJwt);

    expect(decoded.kind).toBe("jwt");
    expect(decoded.kindLabel).toContain("JWT");
    expect(decoded.recommendedToolId).toBe("jwt");
    expect(decoded.properties.find((p) => p.label === "Subject")?.value).toBe("1234567890");
    expect(decoded.formattedDump).toContain("JSON Web Token");
    expect(decoded.sslxCommand).toContain("sslx decode");
  });

  it("detects X.509 certificates and provides navigation shortcuts", () => {
    const decoded = decodeUniversalArtifact(RSA_CERTIFICATE_PEM);

    expect(decoded.kind).toBe("x509-certificate");
    expect(decoded.recommendedToolId).toBe("x509");
    expect(decoded.properties.find((p) => p.label === "Subject")?.value).toContain("workbench.local");
  });

  it("detects multi-certificate chain bundles and breaks down each certificate in the chain", () => {
    const chainBundle = `${SAMPLE_2TIER_SERVER_PEM}\n\n${SAMPLE_ROOT_CA_PEM}`;
    const decoded = decodeUniversalArtifact(chainBundle);

    expect(decoded.kind).toBe("x509-bundle");
    expect(decoded.kindLabel).toContain("X.509 Certificate");
    expect(decoded.properties.find((p) => p.label === "Bundle Size")?.value).toBe("2 Certificates");
    expect(decoded.formattedDump).toContain("[1] Leaf (Server):");
    expect(decoded.formattedDump).toContain("[2] Root CA:");
  });

  it("detects PKCS#10 CSRs", () => {
    const decoded = decodeUniversalArtifact(ECDSA_CSR_PEM);

    expect(decoded.kind).toBe("pkcs10-csr");
    expect(decoded.recommendedToolId).toBe("csr");
    expect(decoded.properties.find((p) => p.label === "Public Key")?.value).toContain("EC");
  });

  it("detects WireGuard Curve25519 keys", () => {
    const wgKey = "YAMV8tC6h+v88cZbD1BqY7T3zO9IeK+gL2mM5mN4oP8=";
    const decoded = decodeUniversalArtifact(wgKey);

    expect(decoded.kind).toBe("wireguard-key");
    expect(decoded.recommendedToolId).toBe("ed25519");
  });

  it("detects OpenSSH public keys", () => {
    const sshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestingOnly user@workstation";
    const decoded = decodeUniversalArtifact(sshKey);

    expect(decoded.kind).toBe("ssh-public-key");
    expect(decoded.properties.find((p) => p.label === "Comment")?.value).toBe("user@workstation");
  });
});

describe("Registry integration for new Certificate tools", () => {
  it("successfully loads tls-grader, cert-expiry, and universal-decoder via registry loadTool", async () => {
    const graderManifest = getManifest("tls-grader");
    expect(graderManifest).toBeDefined();
    expect(graderManifest?.family).toBe("certificates");
    expect(graderManifest?.id).toBe("tls-grader");

    const expiryManifest = getManifest("cert-expiry");
    expect(expiryManifest).toBeDefined();
    expect(expiryManifest?.id).toBe("cert-expiry");

    const decoderManifest = getManifest("universal-decoder");
    expect(decoderManifest).toBeDefined();
    expect(decoderManifest?.id).toBe("universal-decoder");

    const grader = await loadTool("tls-grader");
    expect(grader).toBeDefined();

    const expiry = await loadTool("cert-expiry");
    expect(expiry).toBeDefined();

    const decoder = await loadTool("universal-decoder");
    expect(decoder).toBeDefined();
  });

  it("computes tool results for tls-grader, cert-expiry, and universal-decoder", async () => {
    const grader = await loadTool("tls-grader");
    const gradeResult = await grader.compute(
      grader.createSpec(),
      new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM),
    );
    expect(gradeResult.text).toContain("Grade:");
    expect(gradeResult.cliProviders).toBeDefined();
    expect(gradeResult.cliProviders?.some((p) => p.id === "sslx")).toBe(true);
    expect(gradeResult.cliProviders?.some((p) => p.id === "openssl")).toBe(true);
    expect(gradeResult.cliProviders?.some((p) => p.id === "gnutls")).toBe(true);

    const expiry = await loadTool("cert-expiry");
    const expiryResult = await expiry.compute(
      expiry.createSpec(),
      new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM),
    );
    expect(expiryResult.text).toContain("Expires");
    expect(expiryResult.cliProviders?.some((p) => p.id === "sslx")).toBe(true);
    expect(expiryResult.cliProviders?.some((p) => p.id === "gnutls")).toBe(true);

    const decoder = await loadTool("universal-decoder");
    const decodeResult = await decoder.compute(
      decoder.createSpec(),
      new TextEncoder().encode(RSA_CERTIFICATE_PEM),
    );
    expect(decodeResult.text).toContain("X.509 Certificate");
    expect(decodeResult.cliProviders?.some((p) => p.id === "sslx")).toBe(true);
    expect(decodeResult.cliProviders?.some((p) => p.id === "gnutls")).toBe(true);

    const x509 = await loadTool("x509");
    const x509Result = await x509.compute(
      x509.createSpec(),
      new TextEncoder().encode(SAMPLE_2TIER_SERVER_PEM),
    );
    expect(x509Result.cliProviders).toBeDefined();
    expect(x509Result.cliProviders?.map((p) => p.id)).toEqual(["openssl", "sslx", "gnutls"]);

    const sha256 = await loadTool("sha256");
    const shaResult = await sha256.compute(
      sha256.createSpec(),
      new TextEncoder().encode("hello world"),
    );
    expect(shaResult.cliProviders).toBeDefined();
    expect(shaResult.cliProviders?.map((p) => p.id)).toEqual(["coreutils", "openssl", "python"]);
  });

  it("formats commands properly for OpenSSL and sslx CLI tools", () => {
    const tools: CliTool[] = ["openssl", "sslx"];
    expect(tools).toContain("openssl");
    expect(tools).toContain("sslx");

    const formatted = formatShellCommands(
      [{ parts: ["sslx inspect cert.pem"] }],
      "bash",
      "single-line",
    );
    expect(formatted).toBe("sslx inspect cert.pem");
  });

  it("formats shell commands accurately for bash, powershell, and cmd (including stdin piping)", async () => {
    const sha256 = await loadTool("sha256");
    const shaResult = await sha256.compute(
      sha256.createSpec(),
      new TextEncoder().encode("123456789"),
    );

    const opensslProvider = shaResult.cliProviders?.find((p) => p.id === "openssl");
    expect(opensslProvider).toBeDefined();

    // 1. Command Prompt (cmd): <nul set /p ="123456789" | openssl dgst -sha256
    const cmdFormatted = formatShellCommands(opensslProvider!.commands, "cmd", "single-line");
    expect(cmdFormatted).toContain('<nul set /p ="123456789" | openssl dgst -sha256');

    // 2. PowerShell: cmd /c '<nul set /p ="123456789" | openssl dgst -sha256'
    const psFormatted = formatShellCommands(opensslProvider!.commands, "powershell", "single-line");
    expect(psFormatted).toContain("cmd /c '<nul set /p =\"123456789\" | openssl dgst -sha256'");

    // 3. Bash / zsh: printf "%s" '123456789' | openssl dgst -sha256
    const bashFormatted = formatShellCommands(opensslProvider!.commands, "bash", "single-line");
    expect(bashFormatted).toContain("printf \"%s\" '123456789' | openssl dgst -sha256");

    // Also verify GNU coreutils:
    const coreutilsProvider = shaResult.cliProviders?.find((p) => p.id === "coreutils");
    expect(coreutilsProvider).toBeDefined();
    expect(formatShellCommands(coreutilsProvider!.commands, "cmd", "single-line")).toContain(
      '<nul set /p ="123456789" | sha256sum',
    );
    expect(formatShellCommands(coreutilsProvider!.commands, "powershell", "single-line")).toContain(
      "cmd /c '<nul set /p =\"123456789\" | sha256sum'",
    );
    expect(formatShellCommands(coreutilsProvider!.commands, "bash", "single-line")).toContain(
      "printf \"%s\" '123456789' | sha256sum",
    );
  });

  it("formats file-based shell commands when source is a file (e.g. openssl dgst -sha256 file.txt)", async () => {
    const sha256 = await loadTool("sha256");
    const stream = sha256.createStream!(sha256.createSpec());
    stream.update(new Uint8Array([1, 2, 3]));
    const result = stream.finish();

    expect(result.cliProviders).toBeDefined();

    const opensslProvider = result.cliProviders?.find((p) => p.id === "openssl");
    expect(opensslProvider).toBeDefined();

    // Verify openssl dgst -sha256 file.txt across bash, powershell, and cmd
    expect(formatShellCommands(opensslProvider!.commands, "bash", "single-line")).toContain(
      "openssl dgst -sha256 file.txt",
    );
    expect(formatShellCommands(opensslProvider!.commands, "powershell", "single-line")).toContain(
      "openssl dgst -sha256 file.txt",
    );
    expect(formatShellCommands(opensslProvider!.commands, "cmd", "single-line")).toContain(
      "openssl dgst -sha256 file.txt",
    );

    // Verify GNU coreutils sha256sum file.txt
    const coreutilsProvider = result.cliProviders?.find((p) => p.id === "coreutils");
    expect(coreutilsProvider).toBeDefined();
    expect(formatShellCommands(coreutilsProvider!.commands, "bash", "single-line")).toContain(
      "sha256sum file.txt",
    );

    // Verify OS Native tools (certutil in cmd, Get-FileHash in powershell, shasum in bash)
    const nativeProvider = result.cliProviders?.find((p) => p.id === "native");
    expect(nativeProvider).toBeDefined();
    expect(formatShellCommands(nativeProvider!.commands, "cmd", "single-line")).toContain(
      "certutil -hashfile file.txt SHA256",
    );
    expect(formatShellCommands(nativeProvider!.commands, "powershell", "single-line")).toContain(
      "Get-FileHash -Algorithm SHA256 file.txt",
    );
    expect(formatShellCommands(nativeProvider!.commands, "bash", "single-line")).toContain(
      "shasum -a 256 file.txt",
    );
  });
});


