import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  certificateStudioFilenames,
  parseX509Certificate,
  verifyCertificateSignature,
} from "@ocs/certificates";
import {
  CERTIFICATE_STUDIO_EXAMPLES,
  generateCertificateStudioExample,
} from "../examples/certificates/studio-flow-examples";

function textFile(files: ReadonlyMap<string, string | Uint8Array>, name: string): string {
  const content = files.get(name);
  if (content === undefined) throw new Error(`Missing example file: ${name}`);
  return typeof content === "string" ? content : new TextDecoder().decode(content);
}

function certificate(files: ReadonlyMap<string, string | Uint8Array>, name: string) {
  return parseX509Certificate(new TextEncoder().encode(textFile(files, name)));
}

describe("Certificate Studio examples", () => {
  it("provides one documented runnable directory for every Studio member", () => {
    expect(CERTIFICATE_STUDIO_EXAMPLES).toHaveLength(7);
    expect(new Set(CERTIFICATE_STUDIO_EXAMPLES.map((example) => example.id)).size).toBe(7);

    for (const example of CERTIFICATE_STUDIO_EXAMPLES) {
      const directory = path.resolve("examples/certificates", example.directory);
      expect(fs.existsSync(path.join(directory, "README.md")), example.label).toBe(true);
      expect(fs.existsSync(path.join(directory, "run.ts")), example.label).toBe(true);
    }
  });

  for (const example of CERTIFICATE_STUDIO_EXAMPLES) {
    it(`generates and validates ${example.label}`, async () => {
      const generated = await generateCertificateStudioExample(example.id);
      const { files } = generated;

      for (const name of example.expectedFiles) {
        expect(files.has(name), `${example.label}: ${name}`).toBe(true);
      }

      const names = certificateStudioFilenames(
        example.creatorMode,
        example.singleMode,
        example.hierarchy,
      );
      const commands = textFile(files, "commands.sh");
      expect(commands).toContain(names.leafCertificate);
      expect(commands).toContain(names.leafKey);

      if (example.creatorMode === "single-cert") {
        const leaf = certificate(files, names.leafCertificate);
        expect(files.has("certificate.crt")).toBe(false);
        for (const content of files.values()) {
          if (typeof content === "string") expect(content).not.toContain("certificate.crt");
        }
        expect(leaf.extensions.basicConstraints?.isCa).toBe(false);
        expect(
          leaf.extensions.extendedKeyUsages.some((usage) => usage.includes("serverAuth")),
        ).toBe(true);
        expect(
          leaf.extensions.extendedKeyUsages.some((usage) => usage.includes("clientAuth")),
        ).toBe(false);

        if (example.singleMode === "standalone") {
          expect(leaf.issuer.dn).toBe(leaf.subject.dn);
          expect((await verifyCertificateSignature(leaf, leaf)).valid).toBe(true);
          return;
        }

        expect(commands).toContain(names.issuerCertificate);
        expect(commands).toContain(names.issuerKey);

        if (example.hierarchy === "2-tier") {
          const root = certificate(files, names.rootCertificate);
          expect(root.extensions.basicConstraints?.isCa).toBe(true);
          expect(root.extensions.basicConstraints?.pathLenConstraint).toBe(0);
          expect(leaf.issuer.dn).toBe(root.subject.dn);
          expect((await verifyCertificateSignature(root, root)).valid).toBe(true);
          expect((await verifyCertificateSignature(leaf, root)).valid).toBe(true);
          expect(
            textFile(files, "chain.pem").match(/-----BEGIN CERTIFICATE-----/g),
          ).toHaveLength(2);
          return;
        }

        const root = certificate(files, names.rootCertificate);
        const intermediate = certificate(files, names.issuerCertificate);
        expect(root.extensions.basicConstraints?.pathLenConstraint).toBe(1);
        expect(intermediate.extensions.basicConstraints?.pathLenConstraint).toBe(0);
        expect(intermediate.issuer.dn).toBe(root.subject.dn);
        expect(leaf.issuer.dn).toBe(intermediate.subject.dn);
        expect((await verifyCertificateSignature(root, root)).valid).toBe(true);
        expect((await verifyCertificateSignature(intermediate, root)).valid).toBe(true);
        expect((await verifyCertificateSignature(leaf, intermediate)).valid).toBe(true);
        expect(textFile(files, "chain.pem").match(/-----BEGIN CERTIFICATE-----/g)).toHaveLength(
          3,
        );
        return;
      }

      const root = certificate(files, names.rootCertificate);
      const server = certificate(files, names.leafCertificate);
      const client = certificate(files, "client.crt");
      expect(root.extensions.basicConstraints?.isCa).toBe(true);
      expect(
        server.extensions.extendedKeyUsages.some((usage) => usage.includes("serverAuth")),
      ).toBe(true);
      expect(
        server.extensions.extendedKeyUsages.some((usage) => usage.includes("clientAuth")),
      ).toBe(false);
      expect(
        client.extensions.extendedKeyUsages.some((usage) => usage.includes("serverAuth")),
      ).toBe(false);
      expect(
        client.extensions.extendedKeyUsages.some((usage) => usage.includes("clientAuth")),
      ).toBe(true);

      if (example.hierarchy === "2-tier") {
        expect(server.issuer.dn).toBe(root.subject.dn);
        expect(client.issuer.dn).toBe(root.subject.dn);
        expect((await verifyCertificateSignature(root, root)).valid).toBe(true);
        expect((await verifyCertificateSignature(server, root)).valid).toBe(true);
        expect((await verifyCertificateSignature(client, root)).valid).toBe(true);
      } else {
        const intermediate = certificate(files, names.issuerCertificate);
        expect(intermediate.issuer.dn).toBe(root.subject.dn);
        expect(server.issuer.dn).toBe(intermediate.subject.dn);
        expect(client.issuer.dn).toBe(intermediate.subject.dn);
        expect((await verifyCertificateSignature(root, root)).valid).toBe(true);
        expect((await verifyCertificateSignature(intermediate, root)).valid).toBe(true);
        expect((await verifyCertificateSignature(server, intermediate)).valid).toBe(true);
        expect((await verifyCertificateSignature(client, intermediate)).valid).toBe(true);
      }
    });
  }
});
