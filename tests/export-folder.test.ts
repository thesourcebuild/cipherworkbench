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
    expect(fileNames).toContain("cert-info.txt");

    // Check content
    const certFile = files.find((f) => f.name === "certificate.crt")!;
    expect(typeof certFile.content).toBe("string");
    expect(certFile.content).toContain("-----BEGIN CERTIFICATE-----");

    const keyFile = files.find((f) => f.name === "private.key")!;
    expect(typeof keyFile.content).toBe("string");
    expect(keyFile.content).toContain("-----BEGIN PRIVATE KEY-----");

    // Verify ZIP archive generation
    const zipBytes = createZipArchive(files);
    expect(zipBytes.length).toBeGreaterThan(500);
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
    expect(files.length).toBe(11);

    const fileNames = files.map((f) => f.name);
    // Root CA
    expect(fileNames).toContain("ca.crt");
    expect(fileNames).toContain("ca.key");
    // Server
    expect(fileNames).toContain("server.crt");
    expect(fileNames).toContain("server.key");
    expect(fileNames).toContain("server-chain.pem");
    // Client
    expect(fileNames).toContain("client.crt");
    expect(fileNames).toContain("client.key");
    expect(fileNames).toContain("client.p12");
    // Devops / verification scripts & configs
    expect(fileNames).toContain("commands.sh");
    expect(fileNames).toContain("nginx.conf");
    expect(fileNames).toContain("README.txt");

    // Client PKCS#12 is binary Uint8Array
    const p12File = files.find((f) => f.name === "client.p12")!;
    expect(p12File.content instanceof Uint8Array).toBe(true);
    expect((p12File.content as Uint8Array).length).toBeGreaterThan(100);

    // Verify ZIP archive generation with all 11 files
    const zipBytes = createZipArchive(files);
    expect(zipBytes.length).toBeGreaterThan(4000);

    // End-of-central-directory should reflect exactly 11 entries
    const view = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
    let foundEocd = false;
    for (let i = 0; i <= zipBytes.length - 22; i++) {
      if (view.getUint32(i, true) === 0x06054b50) {
        foundEocd = true;
        expect(view.getUint16(i + 8, true)).toBe(11);
        expect(view.getUint16(i + 10, true)).toBe(11);
        break;
      }
    }
    expect(foundEocd).toBe(true);
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
    expect(files.length).toBe(4);
    const fileNames = files.map((f) => f.name);
    expect(fileNames).toContain("request.csr");
    expect(fileNames).toContain("private.key");
    expect(fileNames).toContain("public.key");
    expect(fileNames).toContain("commands.sh");
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
