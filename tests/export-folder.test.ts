import { describe, expect, it } from "vitest";
import { loadTool } from "@ocs/registry";
import type { ToolManifest } from "@ocs/engine";
import { calcCrc32, createZipArchive, collectExportFiles, type ExportableFile } from "../apps/web/app/export-folder";

describe("export-folder: CRC32 and PKZIP generation", () => {
  it("calculates standard IEEE 802.3 CRC-32 checksums", () => {
    // Standard test vector: "123456789" => 0xcbf43926 (3421780262)
    const testVector = new TextEncoder().encode("123456789");
    expect(calcCrc32(testVector)).toBe(0xcbf43926);

    // Empty buffer
    expect(calcCrc32(new Uint8Array(0))).toBe(0);
  });

  it("creates a valid uncompressed PKZIP 2.0 binary archive", () => {
    const files: ExportableFile[] = [
      { name: "hello.txt", content: "Hello, World!" },
      { name: "data.bin", content: new Uint8Array([0x00, 0x01, 0x02, 0xff]) },
    ];

    const zipBytes = createZipArchive(files);
    expect(zipBytes.length).toBeGreaterThan(0);

    const view = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);

    // 1. First local file header signature: 0x04034b50 (PK\x03\x04)
    expect(view.getUint32(0, true)).toBe(0x04034b50);

    // Check UTF-8 flag (bit 11: 0x0800) and compression method 0
    expect(view.getUint16(6, true)).toBe(0x0800);
    expect(view.getUint16(8, true)).toBe(0);

    // End of central directory record signature: 0x06054b50 (PK\x05\x06)
    const eocdSignature = 0x06054b50;
    let foundEocd = false;
    for (let i = 0; i <= zipBytes.length - 22; i++) {
      if (view.getUint32(i, true) === eocdSignature) {
        foundEocd = true;
        // Total entries: 2
        expect(view.getUint16(i + 8, true)).toBe(2);
        expect(view.getUint16(i + 10, true)).toBe(2);
        break;
      }
    }
    expect(foundEocd).toBe(true);
  });
});

describe("export-folder: Certificate and mTLS Suite File Exports", () => {
  it("exports all individual files for a Single Certificate", async () => {
    const def = await loadTool("cert-creator");
    const spec = def.createSpec();
    spec.options = {
      creatorMode: "self-signed",
      commonName: "single.local",
      organization: "Single Org",
    };

    const result = await def.compute(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();
    expect(result.files).toBeDefined();

    const files = collectExportFiles(result, undefined, spec);
    expect(files.length).toBeGreaterThanOrEqual(5);

    const fileNames = files.map((f) => f.name);
    expect(fileNames).toContain("certificate.crt");
    expect(fileNames).toContain("private.key");
    expect(fileNames).toContain("public.key");
    expect(fileNames).toContain("commands.sh");
    expect(fileNames).toContain("commands.ps1");
    expect(fileNames).toContain("commands.bat");
    expect(fileNames).toContain("cert-info.txt");

    // Check content
    const certFile = files.find((f) => f.name === "certificate.crt")!;
    expect(typeof certFile.content).toBe("string");
    expect(certFile.content).toContain("-----BEGIN CERTIFICATE-----");

    const keyFile = files.find((f) => f.name === "private.key")!;
    expect(typeof keyFile.content).toBe("string");
    expect(keyFile.content).toContain("-----BEGIN PRIVATE KEY-----");

    const shFile = files.find((f) => f.name === "commands.sh")!;
    expect(typeof shFile.content).toBe("string");
    expect(shFile.content).toContain("command -v openssl");

    const ps1File = files.find((f) => f.name === "commands.ps1")!;
    expect(typeof ps1File.content).toBe("string");
    expect(ps1File.content).toContain("Get-Command openssl");

    const batFile = files.find((f) => f.name === "commands.bat")!;
    expect(typeof batFile.content).toBe("string");
    expect(batFile.content).toContain("where /q openssl");

    // Verify ZIP archive generation
    const zipBytes = createZipArchive(files);
    expect(zipBytes.length).toBeGreaterThan(500);

    // Verify .sh files receive POSIX executable attributes (0o755) in ZIP
    const textDecoder = new TextDecoder();
    for (let i = 0; i < zipBytes.length - 46; i++) {
      if (
        zipBytes[i] === 0x50 &&
        zipBytes[i + 1] === 0x4b &&
        zipBytes[i + 2] === 0x01 &&
        zipBytes[i + 3] === 0x02
      ) {
        const view = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
        const nameLen = view.getUint16(i + 28, true);
        const fileName = textDecoder.decode(zipBytes.slice(i + 46, i + 46 + nameLen));
        const extAttr = view.getUint32(i + 38, true);
        if (fileName === "commands.sh") {
          expect(extAttr).toBe(0x81ed0000); // 0o100755
        } else if (fileName === "certificate.crt") {
          expect(extAttr).toBe(0x81a40000); // 0o100644
        }
      }
    }
  });

  it("exports all individual files for a Full mTLS Suite", async () => {
    const def = await loadTool("cert-creator");
    const spec = def.createSpec();
    spec.options = {
      creatorMode: "mtls-suite",
      commonName: "gateway.internal",
      clientCommonName: "agent-007",
      mtlsP12Password: "export-pass-123",
    };

    const result = await def.compute(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();
    expect(result.files).toBeDefined();

    const files = collectExportFiles(result, undefined, spec);
    expect(files.length).toBe(22);

    const fileNames = files.map((f) => f.name);
    // Root CA
    expect(fileNames).toContain("ca.crt");
    expect(fileNames).toContain("ca.key");
    expect(fileNames).toContain("ca.crl");
    // Server
    expect(fileNames).toContain("server.crt");
    expect(fileNames).toContain("server.key");
    expect(fileNames).toContain("server-chain.pem");
    // Client
    expect(fileNames).toContain("client.crt");
    expect(fileNames).toContain("client.key");
    expect(fileNames).toContain("client-chain.pem");
    expect(fileNames).toContain("client.p12");
    // Keys & Compliance
    expect(fileNames).toContain("authorized_keys");
    expect(fileNames).toContain("jwks.json");
    // Devops / verification scripts & configs
    expect(fileNames).toContain("commands.sh");
    expect(fileNames).toContain("commands.ps1");
    expect(fileNames).toContain("commands.bat");
    expect(fileNames).toContain("nginx.conf");
    expect(fileNames).toContain("k8s-tls-secret.yaml");
    expect(fileNames).toContain("caddy.Caddyfile");
    expect(fileNames).toContain("traefik.yaml");
    expect(fileNames).toContain("haproxy.cfg");
    expect(fileNames).toContain("envoy.yaml");
    expect(fileNames).toContain("README.txt");

    // Client PKCS#12 is binary Uint8Array
    const p12File = files.find((f) => f.name === "client.p12")!;
    expect(p12File.content instanceof Uint8Array).toBe(true);
    expect((p12File.content as Uint8Array).length).toBeGreaterThan(100);

    // Verify ZIP archive generation with all 22 files
    const zipBytes = createZipArchive(files);
    expect(zipBytes.length).toBeGreaterThan(7000);

    // End-of-central-directory should reflect exactly 22 entries
    const view = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
    let foundEocd = false;
    for (let i = 0; i <= zipBytes.length - 22; i++) {
      if (view.getUint32(i, true) === 0x06054b50) {
        foundEocd = true;
        expect(view.getUint16(i + 8, true)).toBe(22);
        expect(view.getUint16(i + 10, true)).toBe(22);
        break;
      }
    }
    expect(foundEocd).toBe(true);
  });

  it("exports all individual files for a 3-Tier Enterprise mTLS Suite", async () => {
    const def = await loadTool("cert-creator");
    const spec = def.createSpec();
    spec.options = {
      creatorMode: "mtls-suite",
      pkiHierarchy: "3-tier",
      commonName: "gateway.internal",
      intermediateCommonName: "Issuing Sub-CA",
      clientCommonName: "agent-007",
      mtlsP12Password: "export-pass-123",
    };

    const result = await def.compute(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();
    expect(result.files).toBeDefined();

    const files = collectExportFiles(result, undefined, spec);
    expect(files.length).toBe(24);

    const fileNames = files.map((f) => f.name);
    expect(fileNames).toContain("ca.crt");
    expect(fileNames).toContain("ca.key");
    expect(fileNames).toContain("ca.crl");
    expect(fileNames).toContain("intermediate.crt");
    expect(fileNames).toContain("intermediate.key");
    expect(fileNames).toContain("server.crt");
    expect(fileNames).toContain("server.key");
    expect(fileNames).toContain("server-chain.pem");
    expect(fileNames).toContain("client.crt");
    expect(fileNames).toContain("client.key");
    expect(fileNames).toContain("client-chain.pem");
    expect(fileNames).toContain("client.p12");
    expect(fileNames).toContain("authorized_keys");
    expect(fileNames).toContain("jwks.json");
    expect(fileNames).toContain("commands.sh");
    expect(fileNames).toContain("commands.ps1");
    expect(fileNames).toContain("commands.bat");
  });

  it("exports individual files for CSR Creator", async () => {
    const def = await loadTool("csr-creator");
    const spec = def.createSpec();
    spec.options = {
      commonName: "csr.example.com",
    };

    const result = await def.compute(spec, new Uint8Array(0));
    expect(result.error).toBeUndefined();

    const files = collectExportFiles(result, undefined, spec);
    expect(files.length).toBe(6);
    const fileNames = files.map((f) => f.name);
    expect(fileNames).toContain("request.csr");
    expect(fileNames).toContain("private.key");
    expect(fileNames).toContain("public.key");
    expect(fileNames).toContain("commands.sh");
    expect(fileNames).toContain("commands.ps1");
    expect(fileNames).toContain("commands.bat");
  });

  it("synthesizes export files for generic tools without explicit files", () => {
    const genericResult = {
      text: "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
      bytes: new Uint8Array([1, 2, 3, 4]),
    };
    const files = collectExportFiles(genericResult, { id: "sha256" } as unknown as ToolManifest, undefined);
    expect(files.length).toBe(2);
    expect(files[0]?.name).toBe("sha256.txt");
    expect(files[1]?.name).toBe("sha256.bin");
  });

  it("returns empty file list when result has error", () => {
    const errorResult = {
      error: "Something went wrong",
    };
    const files = collectExportFiles(errorResult, { id: "test" } as unknown as ToolManifest, undefined);
    expect(files).toEqual([]);
  });
});
