import fs from "node:fs";
import path from "node:path";
import {
  computeCertificate,
  createCertificate,
  createSpec,
  type CreatorModeOption,
  type PkiHierarchyOption,
  type SingleCertificateModeOption,
} from "../../packages/tools/certificates/src/index";

export const CERTIFICATE_STUDIO_EXAMPLES = [
  {
    id: "single-self-signed-standalone",
    directory: "single-self-signed-standalone",
    label: "Single (Self-Signed | Standalone)",
    creatorMode: "single-cert",
    singleMode: "standalone",
    hierarchy: "2-tier",
    expectedFiles: ["private.key", "server.crt"],
  },
  {
    id: "single-self-signed-2-tier",
    directory: "single-self-signed-2-tier",
    label: "Single (Self-Signed | 2-Tier)",
    creatorMode: "single-cert",
    singleMode: "generated-ca",
    hierarchy: "2-tier",
    expectedFiles: ["root-ca.key", "root-ca.crt", "private.key", "server.crt", "chain.pem"],
  },
  {
    id: "single-self-signed-3-tier",
    directory: "single-self-signed-3-tier",
    label: "Single (Self-Signed | 3-Tier)",
    creatorMode: "single-cert",
    singleMode: "generated-ca",
    hierarchy: "3-tier",
    expectedFiles: [
      "root-ca.key",
      "root-ca.crt",
      "intermediate.key",
      "intermediate.crt",
      "private.key",
      "server.crt",
      "server-chain.pem",
      "chain.pem",
    ],
  },
  {
    id: "single-ca-signed-2-tier",
    directory: "single-ca-signed-2-tier",
    label: "Single (CA-Signed | 2-Tier)",
    creatorMode: "single-cert",
    singleMode: "existing-ca",
    hierarchy: "2-tier",
    expectedFiles: ["ca.key", "ca.crt", "private.key", "server.crt", "chain.pem"],
  },
  {
    id: "single-ca-signed-3-tier",
    directory: "single-ca-signed-3-tier",
    label: "Single (CA-Signed | 3-Tier)",
    creatorMode: "single-cert",
    singleMode: "existing-ca",
    hierarchy: "3-tier",
    expectedFiles: [
      "root-ca.crt",
      "intermediate.key",
      "intermediate.crt",
      "private.key",
      "server.crt",
      "server-chain.pem",
      "chain.pem",
    ],
  },
  {
    id: "mtls-2-tier",
    directory: "mtls-2-tier",
    label: "mTLS (2-Tier)",
    creatorMode: "mtls-suite",
    singleMode: "standalone",
    hierarchy: "2-tier",
    expectedFiles: [
      "ca.key",
      "ca.crt",
      "server.key",
      "server.crt",
      "server-chain.pem",
      "client.key",
      "client.crt",
      "client-chain.pem",
      "client.p12",
    ],
  },
  {
    id: "mtls-enterprise-3-tier",
    directory: "mtls-enterprise-3-tier",
    label: "mTLS Enterprise (3-Tier)",
    creatorMode: "mtls-suite",
    singleMode: "standalone",
    hierarchy: "3-tier",
    expectedFiles: [
      "ca.key",
      "ca.crt",
      "intermediate.key",
      "intermediate.crt",
      "server.key",
      "server.crt",
      "server-chain.pem",
      "client.key",
      "client.crt",
      "client-chain.pem",
      "client.p12",
    ],
  },
] as const satisfies readonly {
  id: string;
  directory: string;
  label: string;
  creatorMode: CreatorModeOption;
  singleMode: SingleCertificateModeOption;
  hierarchy: PkiHierarchyOption;
  expectedFiles: readonly string[];
}[];

export type CertificateStudioExampleId = (typeof CERTIFICATE_STUDIO_EXAMPLES)[number]["id"];

export function requireCertificateStudioExample(id: CertificateStudioExampleId) {
  const example = CERTIFICATE_STUDIO_EXAMPLES.find((candidate) => candidate.id === id);
  if (!example) throw new Error(`Unknown Certificate Studio example: ${id}`);
  return example;
}

export async function generateCertificateStudioExample(id: CertificateStudioExampleId) {
  const example = requireCertificateStudioExample(id);
  const spec = createSpec({ variant: "cert-creator" });
  spec.options = {
    ...spec.options,
    creatorMode: example.creatorMode,
    singleCertificateMode: example.singleMode,
    pkiHierarchy: example.hierarchy,
    commonName: "localhost",
    san: "localhost, 127.0.0.1, ::1",
    caCommonName: `${example.label} Root CA`,
    intermediateCommonName: `${example.label} Issuing CA`,
    clientCommonName: "cipherworkbench-example-client",
    serverAuth: true,
    validityDays: "365",
    mtlsP12Password: "changeit",
  };

  const suppliedFiles = new Map<string, string | Uint8Array>();
  if (example.creatorMode === "single-cert" && example.singleMode === "existing-ca") {
    const root = await createCertificate({
      commonName: `${example.label} External Root CA`,
      organization: "External Example Authority",
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 3650,
      isCa: true,
      pathLenConstraint: example.hierarchy === "3-tier" ? 1 : 0,
    });

    if (example.hierarchy === "3-tier") {
      const intermediate = await createCertificate({
        commonName: `${example.label} External Issuing CA`,
        organization: "External Example Authority",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 1825,
        isCa: true,
        pathLenConstraint: 0,
        issuanceMode: "ca-signed",
        caCertPem: root.certPem,
        caPrivateKeyPem: root.privateKeyPem,
      });
      spec.options.rootCaCert = root.certPem;
      spec.options.caCert = intermediate.certPem;
      spec.options.caPrivateKey = intermediate.privateKeyPem;
      suppliedFiles.set("root-ca.crt", root.certPem);
      suppliedFiles.set("intermediate.crt", intermediate.certPem);
      suppliedFiles.set("intermediate.key", intermediate.privateKeyPem);
    } else {
      spec.options.caCert = root.certPem;
      spec.options.caPrivateKey = root.privateKeyPem;
      suppliedFiles.set("ca.crt", root.certPem);
      suppliedFiles.set("ca.key", root.privateKeyPem);
    }
  }

  const result = await computeCertificate(spec, new Uint8Array(0));
  if (result.error) throw new Error(`${example.label} failed: ${result.error}`);

  const files = new Map(suppliedFiles);
  for (const file of result.files ?? []) files.set(file.name, file.content);

  return { example, spec, result, files };
}

export function writeCertificateStudioExample(
  outputDirectory: string,
  files: ReadonlyMap<string, string | Uint8Array>,
): void {
  fs.mkdirSync(outputDirectory, { recursive: true });
  for (const [name, content] of files) {
    const filePath = path.join(outputDirectory, name);
    fs.writeFileSync(filePath, typeof content === "string" ? content : Buffer.from(content));
  }
}

export async function runCertificateStudioExample(
  id: CertificateStudioExampleId,
  outputDirectory: string,
): Promise<void> {
  const generated = await generateCertificateStudioExample(id);
  writeCertificateStudioExample(outputDirectory, generated.files);

  console.log(generated.example.label);
  console.log(`Hierarchy: ${generated.example.hierarchy}`);
  for (const name of generated.example.expectedFiles) {
    if (!generated.files.has(name)) throw new Error(`Missing expected file: ${name}`);
    console.log(`  ${name}`);
  }
}
