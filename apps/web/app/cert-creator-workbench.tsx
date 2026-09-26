"use client";

import { useMemo, useState } from "react";
import type { OptionValue, OptionValues } from "@ocs/contracts";
import type { ToolDefinition, ToolSpecBase } from "@ocs/engine";
import {
  Button,
  CopyIconButton,
  SecretField,
  ShellCommandBlock,
  cn,
  type CommandShell,
  type ShellCommand,
  type ShellCommandVariants,
} from "@ocs/ui";
import { OptionsForm } from "./options-form";
import type { ComputeState } from "./use-compute";
import {
  createCertificate,
  OPTION_CA_CERT,
  OPTION_CA_PRIVATE_KEY,
  OPTION_CREATOR_MODE,
  OPTION_ISSUANCE_MODE,
  OPTION_PKI_HIERARCHY,
  OPTION_CA_COMMON_NAME,
  OPTION_COMMON_NAME,
  OPTION_SAN,
  OPTION_ORGANIZATION,
  OPTION_ORG_UNIT,
  OPTION_COUNTRY,
  OPTION_STATE,
  OPTION_LOCALITY,
  OPTION_KEY_TYPE,
  OPTION_HASH_TYPE,
  OPTION_ROOT_KEY_TYPE,
  OPTION_ROOT_HASH_TYPE,
  OPTION_INTERMEDIATE_KEY_TYPE,
  OPTION_INTERMEDIATE_HASH_TYPE,
  OPTION_SERVER_KEY_TYPE,
  OPTION_SERVER_HASH_TYPE,
  OPTION_CLIENT_KEY_TYPE,
  OPTION_CLIENT_HASH_TYPE,
  OPTION_VALIDITY_DAYS,
  OPTION_IS_CA,
  OPTION_SERVER_AUTH,
  OPTION_CLIENT_AUTH,
  OPTION_CODE_SIGNING,
  OPTION_CLIENT_COMMON_NAME,
  OPTION_MTLS_P12_PASSWORD,
  OPTION_INTERMEDIATE_COMMON_NAME,
  readCaCert,
  readCaPrivateKey,
  readCreatorMode,
  readIssuanceMode,
  readPkiHierarchy,
} from "@ocs/certificates";

export interface CertCreatorWorkbenchProps {
  tool: ToolDefinition<ToolSpecBase>;
  spec: ToolSpecBase;
  setOptionValue: (id: string, value: OptionValue | undefined) => void;
  recompute: () => void;
  canRecompute: boolean;
  state: ComputeState;
  tag?: string | readonly string[];
  generateLength?: (optionId: string) => number | undefined;
  acceptedByteLengths?: (optionId: string) => readonly number[] | undefined;
}

interface StepDefinition {
  id: string;
  stepNum: number;
  label: string;
  title: string;
  fileProduced: string;
  purpose: string;
  groups?: readonly string[];
  optionIds?: readonly string[];
  isCaStep?: boolean;
  guideKind?:
    | "deploy"
    | "trust"
    | "trust-ca"
    | "single-key"
    | "single-csr"
    | "single-sign"
    | "mtls-root-ca"
    | "mtls-server-csr"
    | "mtls-server-sign"
    | "mtls-client-sign"
    | "mtls-trust"
    | "inter-csr"
    | "inter-sign"
    | "server-chain"
    | "3tier-deploy";
}

function CodeSnippet({ code, title }: { code: string; title: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    void navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-900 p-3 text-xs text-slate-100 font-mono dark:border-slate-800">
      <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-800 text-[11px] font-sans font-medium text-slate-400">
        <span>{title}</span>
        <button
          type="button"
          onClick={handleCopy}
          className="rounded px-2 py-0.5 text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap">{code}</pre>
    </div>
  );
}

interface CertificateCommandOptions {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  state: string;
  locality: string;
  keyType: string;
  hashType: string;
  rootKeyType: string;
  rootHashType: string;
  intermediateKeyType: string;
  intermediateHashType: string;
  serverKeyType: string;
  serverHashType: string;
  clientKeyType: string;
  clientHashType: string;
  validityDays: number;
  san: string;
  isCa: boolean;
  serverAuth: boolean;
  clientAuth: boolean;
  codeSigning: boolean;
  caCommonName: string;
  intermediateCommonName: string;
  clientCommonName: string;
  p12Password: string;
}

function optionString(options: OptionValues, id: string, fallback: string): string {
  const value = options[id];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function optionBoolean(options: OptionValues, id: string, fallback: boolean): boolean {
  const value = options[id];
  return typeof value === "boolean" ? value : fallback;
}

function readCommandOptions(options: OptionValues): CertificateCommandOptions {
  const validity = Number.parseInt(optionString(options, OPTION_VALIDITY_DAYS, "365"), 10);
  return {
    commonName: optionString(options, OPTION_COMMON_NAME, "localhost"),
    organization: optionString(options, OPTION_ORGANIZATION, "Cipher Workbench"),
    organizationalUnit: optionString(options, OPTION_ORG_UNIT, "Security"),
    country: optionString(options, OPTION_COUNTRY, "US"),
    state: optionString(options, OPTION_STATE, "California"),
    locality: optionString(options, OPTION_LOCALITY, "San Francisco"),
    keyType: optionString(options, OPTION_KEY_TYPE, "ecdsa-p256"),
    hashType: optionString(options, OPTION_HASH_TYPE, "sha256"),
    rootKeyType: optionString(options, OPTION_ROOT_KEY_TYPE, "ecdsa-p256"),
    rootHashType: optionString(options, OPTION_ROOT_HASH_TYPE, "sha256"),
    intermediateKeyType: optionString(options, OPTION_INTERMEDIATE_KEY_TYPE, "ecdsa-p256"),
    intermediateHashType: optionString(options, OPTION_INTERMEDIATE_HASH_TYPE, "sha256"),
    serverKeyType: optionString(options, OPTION_SERVER_KEY_TYPE, "ecdsa-p256"),
    serverHashType: optionString(options, OPTION_SERVER_HASH_TYPE, "sha256"),
    clientKeyType: optionString(options, OPTION_CLIENT_KEY_TYPE, "ecdsa-p256"),
    clientHashType: optionString(options, OPTION_CLIENT_HASH_TYPE, "sha256"),
    validityDays: Number.isFinite(validity) && validity > 0 ? validity : 365,
    san: optionString(options, OPTION_SAN, "localhost, 127.0.0.1"),
    isCa: optionBoolean(options, OPTION_IS_CA, false),
    serverAuth: optionBoolean(options, OPTION_SERVER_AUTH, true),
    clientAuth: optionBoolean(options, OPTION_CLIENT_AUTH, true),
    codeSigning: optionBoolean(options, OPTION_CODE_SIGNING, false),
    caCommonName: optionString(options, OPTION_CA_COMMON_NAME, "Internal Root CA"),
    intermediateCommonName: optionString(
      options,
      OPTION_INTERMEDIATE_COMMON_NAME,
      "Internal Issuing CA",
    ),
    clientCommonName: optionString(options, OPTION_CLIENT_COMMON_NAME, "client-app-01"),
    p12Password: optionString(options, OPTION_MTLS_P12_PASSWORD, "changeit"),
  };
}

function shellQuote(value: string, shell: CommandShell): string {
  if (shell === "powershell") return `'${value.replaceAll("'", "''")}'`;
  if (shell === "cmd") return `"${value.replaceAll('"', '""')}"`;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function shellVariants(
  build: (shell: CommandShell) => readonly ShellCommand[],
): ShellCommandVariants {
  return {
    bash: build("bash"),
    powershell: build("powershell"),
    cmd: build("cmd"),
  };
}

function keyCommand(file: string, keyType: string, comment: string): ShellCommand {
  if (keyType === "rsa-2048" || keyType === "rsa-4096") {
    const bits = keyType.slice(4);
    return {
      comment,
      parts: [
        "openssl genpkey -algorithm RSA",
        `-pkeyopt rsa_keygen_bits:${bits}`,
        `-out ${file}`,
      ],
    };
  }
  if (keyType === "ecdsa-p384") {
    return {
      comment,
      parts: [
        "openssl genpkey -algorithm EC",
        "-pkeyopt ec_paramgen_curve:secp384r1",
        `-out ${file}`,
      ],
    };
  }
  if (keyType === "ed25519") {
    return { comment, parts: [`openssl genpkey -algorithm ED25519 -out ${file}`] };
  }
  if (keyType.startsWith("ml-dsa-")) {
    return {
      comment,
      parts: [`openssl genpkey -algorithm ${keyType.toUpperCase()} -out ${file}`],
    };
  }
  return {
    comment,
    parts: [
      "openssl genpkey -algorithm EC",
      "-pkeyopt ec_paramgen_curve:prime256v1",
      `-out ${file}`,
    ],
  };
}

function digestFlag(keyType: string, hashType: string): string | undefined {
  if (keyType === "ed25519" || keyType.startsWith("ml-dsa-")) return undefined;
  return `-${hashType}`;
}

function digestArgs(keyType: string, hashType: string): string[] {
  const digest = digestFlag(keyType, hashType);
  return digest ? [digest] : [];
}

function opensslDnValue(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("/", "\\/");
}

function subject(options: CertificateCommandOptions, commonName: string): string {
  return [
    ["C", options.country],
    ["ST", options.state],
    ["L", options.locality],
    ["O", options.organization],
    ["OU", options.organizationalUnit],
    ["CN", commonName],
  ]
    .map(([key, value]) => `/${key}=${opensslDnValue(value!)}`)
    .join("");
}

function sanExtension(value: string): string {
  const entries = value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      if (entry.includes("@")) return `email:${entry}`;
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(entry) || entry.includes(":")) return `IP:${entry}`;
      return `DNS:${entry}`;
    });
  return entries.join(",");
}

function ekuExtension(options: CertificateCommandOptions, clientOnly = false): string {
  const usages = clientOnly
    ? options.clientAuth
      ? ["clientAuth"]
      : []
    : [
        options.serverAuth ? "serverAuth" : undefined,
        options.clientAuth ? "clientAuth" : undefined,
        options.codeSigning ? "codeSigning" : undefined,
      ].filter((usage): usage is string => usage !== undefined);
  return usages.join(",");
}

function passwordEnvironmentCommand(password: string, shell: CommandShell): ShellCommand {
  if (shell === "powershell") {
    return {
      comment: "Keep the PKCS#12 password out of the OpenSSL process arguments",
      parts: [`$env:CLIENT_P12_PASSWORD = ${shellQuote(password, shell)}`],
    };
  }
  if (shell === "cmd") {
    return {
      comment: "Keep the PKCS#12 password out of the OpenSSL process arguments",
      parts: [`set "CLIENT_P12_PASSWORD=${password.replaceAll('"', '""')}"`],
    };
  }
  return {
    comment: "Keep the PKCS#12 password out of the OpenSSL process arguments",
    parts: [`export CLIENT_P12_PASSWORD=${shellQuote(password, shell)}`],
  };
}

export function CertCreatorWorkbench({
  tool,
  spec,
  setOptionValue,
  recompute,
  canRecompute,
  state,
  tag,
  generateLength,
  acceptedByteLengths,
}: CertCreatorWorkbenchProps) {
  const creatorMode = readCreatorMode(spec.options);
  const issuanceMode = readIssuanceMode(spec.options);
  const pkiHierarchy = readPkiHierarchy(spec.options);
  const commandOptions = readCommandOptions(spec.options);
  const rootPrefix =
    creatorMode === "mtls-suite" && pkiHierarchy === "3-tier" ? "root-ca" : "ca";

  const [isGeneratingCa, setIsGeneratingCa] = useState(false);

  const caCertVal = readCaCert(spec.options);
  const caKeyVal = readCaPrivateKey(spec.options);
  const hasCaCert = Boolean(caCertVal && caCertVal.trim().length > 0);
  const hasCaKey = Boolean(caKeyVal && caKeyVal.trim().length > 0);
  const missingCaCredentials =
    creatorMode === "single-cert" && issuanceMode === "ca-signed" && (!hasCaCert || !hasCaKey);

  // Generate a test CA certificate & private key pair
  const handleGenerateTestCa = async () => {
    try {
      setIsGeneratingCa(true);
      const caResult = await createCertificate({
        commonName: "Cipher Workbench Test CA",
        organization: "Test Certificate Authority",
        country: "US",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 3650,
        isCa: true,
      });
      setOptionValue(OPTION_CA_CERT, caResult.certPem);
      setOptionValue(OPTION_CA_PRIVATE_KEY, caResult.privateKeyPem);
    } finally {
      setIsGeneratingCa(false);
    }
  };

  // Generate a standalone fresh CA private key
  const handleGenerateCaKeyOnly = async () => {
    try {
      setIsGeneratingCa(true);
      const caResult = await createCertificate({
        commonName: "Cipher Workbench CA Key",
        organization: "Test Certificate Authority",
        country: "US",
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 3650,
        isCa: true,
      });
      setOptionValue(OPTION_CA_PRIVATE_KEY, caResult.privateKeyPem);
    } finally {
      setIsGeneratingCa(false);
    }
  };

  const handleClearCa = () => {
    setOptionValue(OPTION_CA_CERT, undefined);
    setOptionValue(OPTION_CA_PRIVATE_KEY, undefined);
  };

  // Exact step definitions matching Tables 1, 2, and 3
  const wizardSteps: StepDefinition[] = useMemo(() => {
    if (creatorMode === "mtls-suite") {
      if (pkiHierarchy === "3-tier") {
        // Table 3: mTLS — 3-Tier Enterprise Architecture (Root CA ➔ Intermediate CA ➔ Leaves)
        return [
          {
            id: "step-root-ca",
            stepNum: 1,
            label: "1. Root CA",
            title: "Step 1: Create Root CA",
            fileProduced: "root-ca.key, root-ca.crt",
            purpose:
              "Generate offline root key and self-signed root certificate (CA:TRUE, pathlen:1) acting as top-level trust anchor.",
            optionIds: [
              OPTION_PKI_HIERARCHY,
              OPTION_CA_COMMON_NAME,
              OPTION_ORGANIZATION,
              OPTION_COUNTRY,
              OPTION_ROOT_KEY_TYPE,
              OPTION_ROOT_HASH_TYPE,
            ],
            guideKind: "mtls-root-ca",
          },
          {
            id: "step-inter-csr",
            stepNum: 2,
            label: "2. Intermediate CSR",
            title: "Step 2: Generate Intermediate Key & CSR",
            fileProduced: "intermediate.key, intermediate.csr",
            purpose: "Generate keypair and CSR for the operational issuing authority.",
            optionIds: [OPTION_INTERMEDIATE_COMMON_NAME, OPTION_INTERMEDIATE_KEY_TYPE],
            guideKind: "inter-csr",
          },
          {
            id: "step-inter-sign",
            stepNum: 3,
            label: "3. Sign Intermediate",
            title: "Step 3: Sign Intermediate with Root CA",
            fileProduced: "intermediate.crt",
            purpose:
              "Root CA delegates signing authority (CA:TRUE, keyCertSign, cRLSign). Root key can now go offline.",
            optionIds: [OPTION_INTERMEDIATE_HASH_TYPE],
            guideKind: "inter-sign",
          },
          {
            id: "step-server-chain",
            stepNum: 4,
            label: "4. Server Cert & Chain",
            title: "Step 4: Generate & Sign Server Cert",
            fileProduced: "server.key, server.crt, server-chain.pem",
            purpose:
              "Intermediate CA signs the server cert (serverAuth). Server chain bundles server.crt + intermediate.crt.",
            optionIds: [
              OPTION_COMMON_NAME,
              OPTION_SAN,
              OPTION_VALIDITY_DAYS,
              OPTION_SERVER_AUTH,
              OPTION_SERVER_KEY_TYPE,
              OPTION_SERVER_HASH_TYPE,
            ],
            guideKind: "server-chain",
          },
          {
            id: "step-client-p12",
            stepNum: 5,
            label: "5. Client Cert & P12",
            title: "Step 5: Generate & Sign Client Cert",
            fileProduced: "client.key, client.crt, client.p12",
            purpose:
              "Intermediate CA signs the client cert (clientAuth). Packaged with intermediate.crt into .p12.",
            optionIds: [
              OPTION_CLIENT_COMMON_NAME,
              OPTION_CLIENT_AUTH,
              OPTION_MTLS_P12_PASSWORD,
              OPTION_CLIENT_KEY_TYPE,
              OPTION_CLIENT_HASH_TYPE,
            ],
            guideKind: "mtls-client-sign",
          },
          {
            id: "step-deploy-chains",
            stepNum: 6,
            label: "6. Deploy Chains & Test",
            title: "Step 6: Deploy Chains & Truststores",
            fileProduced: "Deploy chains & root-ca.crt",
            purpose:
              "Server serves server-chain.pem; Client & Server trust root-ca.crt to validate the full chain.",
            guideKind: "3tier-deploy",
          },
        ];
      }

      // Table 2: mTLS — 2-Tier Architecture (Root CA ➔ Leaves)
      return [
        {
          id: "step-root-ca",
          stepNum: 1,
          label: "1. Root CA",
          title: "Step 1: Create a Root CA",
          fileProduced: "ca.key, ca.crt",
          purpose:
            "Generate a private key and a self-signed root certificate (ca.pem or ca.crt). This acts as your trust anchor. Both the server and the client will trust this CA to verify each other.",
          optionIds: [
            OPTION_PKI_HIERARCHY,
            OPTION_CA_COMMON_NAME,
            OPTION_ORGANIZATION,
            OPTION_ORG_UNIT,
            OPTION_COUNTRY,
            OPTION_STATE,
            OPTION_LOCALITY,
            OPTION_ROOT_KEY_TYPE,
            OPTION_ROOT_HASH_TYPE,
          ],
          guideKind: "mtls-root-ca",
        },
        {
          id: "step-server-csr",
          stepNum: 2,
          label: "2. Server Key & CSR",
          title: "Step 2: Generate the Server Key and CSR",
          fileProduced: "server.key, server.csr",
          purpose:
            "Create a private key for your server and a Certificate Signing Request (CSR) with your server's domain name or IP address.",
          optionIds: [OPTION_COMMON_NAME, OPTION_SAN, OPTION_SERVER_KEY_TYPE],
          guideKind: "mtls-server-csr",
        },
        {
          id: "step-server-sign",
          stepNum: 3,
          label: "3. Sign Server Cert",
          title: "Step 3: Sign the Server Certificate",
          fileProduced: "server.crt",
          purpose:
            "Use your Root CA key and certificate to sign the server's CSR, producing the official server certificate (server.crt).",
          optionIds: [OPTION_VALIDITY_DAYS, OPTION_SERVER_AUTH, OPTION_SERVER_HASH_TYPE],
          guideKind: "mtls-server-sign",
        },
        {
          id: "step-client-sign",
          stepNum: 4,
          label: "4. Client Certificate",
          title: "Step 4: Generate and Sign the Client Certificate",
          fileProduced: "client.key, client.csr, client.crt, client.p12",
          purpose:
            "Create a separate private key and CSR for the client, then sign it with your Root CA to produce the client certificate (client.crt) configured for client authentication.",
          optionIds: [
            OPTION_CLIENT_COMMON_NAME,
            OPTION_CLIENT_AUTH,
            OPTION_CLIENT_KEY_TYPE,
            OPTION_CLIENT_HASH_TYPE,
            OPTION_MTLS_P12_PASSWORD,
          ],
          guideKind: "mtls-client-sign",
        },
        {
          id: "step-truststores",
          stepNum: 5,
          label: "5. Truststores & Test",
          title: "Step 5: Configure Server and Client Truststores",
          fileProduced: "Distribute ca.crt",
          purpose:
            "Install the Root CA public certificate into the server's truststore (so it trusts the client) and into the client's truststore (so it trusts the server).",
          guideKind: "mtls-trust",
        },
      ];
    }

    // Table 1: Single Certificate (CA-Signed or Self-Signed)
    if (issuanceMode === "ca-signed") {
      return [
        {
          id: "step-root-ca",
          stepNum: 1,
          label: "1. Root CA",
          title: "Step 1: Create a Root CA",
          fileProduced: "ca.key, ca.crt",
          purpose:
            "Generate a private key and a self-signed root certificate (ca.pem or ca.crt). This acts as your trust anchor.",
          isCaStep: true,
          guideKind: "mtls-root-ca",
        },
        {
          id: "step-server-csr",
          stepNum: 2,
          label: "2. Server Key & CSR",
          title: "Step 2: Generate the Server Key and CSR",
          fileProduced: "server.key, server.csr",
          purpose:
            "Create a private key for your server and a Certificate Signing Request (CSR) with your server's domain name or IP address.",
          optionIds: [
            OPTION_COMMON_NAME,
            OPTION_SAN,
            OPTION_ORGANIZATION,
            OPTION_ORG_UNIT,
            OPTION_COUNTRY,
            OPTION_STATE,
            OPTION_LOCALITY,
            OPTION_KEY_TYPE,
          ],
          guideKind: "mtls-server-csr",
        },
        {
          id: "step-server-sign",
          stepNum: 3,
          label: "3. Sign Server Cert",
          title: "Step 3: Sign the Server Certificate",
          fileProduced: "server.crt",
          purpose:
            "Use your Root CA key and certificate to sign the server's CSR, producing the official server certificate (server.crt).",
          optionIds: [
            OPTION_VALIDITY_DAYS,
            OPTION_SERVER_AUTH,
            OPTION_CLIENT_AUTH,
            OPTION_CODE_SIGNING,
            OPTION_HASH_TYPE,
          ],
          guideKind: "mtls-server-sign",
        },
        {
          id: "step-deploy",
          stepNum: 4,
          label: "4. Deploy Certificate",
          title: "Step 4: Deploy the CA-Signed Certificate",
          fileProduced: "cert.key, cert.crt, ca.crt",
          purpose:
            "Configure the service with the generated private key and CA-signed certificate. Include the issuing chain where required.",
          guideKind: "deploy",
        },
        {
          id: "step-trust",
          stepNum: 5,
          label: "5. Trust & Verify",
          title: "Step 5: Trust the Issuing CA and Verify",
          fileProduced: "Install ca.crt",
          purpose:
            "Install the issuing CA certificate in client truststores and verify the deployed certificate chain.",
          guideKind: "trust-ca",
        },
      ];
    }

    return [
      {
        id: "step-root-ca",
        stepNum: 1,
        label: "1. Root CA / Mode",
        title: "Step 1: Create a Root CA / Authority Mode",
        fileProduced: "Self-Signed Trust Anchor",
        purpose:
          "Generate a private key and self-signed certificate that acts as its own root trust anchor, or switch to CA-Signed mode.",
        isCaStep: true,
        guideKind: "single-key",
      },
      {
        id: "step-server-csr",
        stepNum: 2,
        label: "2. Server Key & CSR",
        title: "Step 2: Generate the Server Key and CSR",
        fileProduced: "server.key, server.csr",
        purpose:
          "Create a private key for your server and a Certificate Signing Request (CSR) with your server's domain name or IP address.",
        optionIds: [
          OPTION_COMMON_NAME,
          OPTION_SAN,
          OPTION_ORGANIZATION,
          OPTION_ORG_UNIT,
          OPTION_COUNTRY,
          OPTION_STATE,
          OPTION_LOCALITY,
          OPTION_KEY_TYPE,
        ],
        guideKind: "mtls-server-csr",
      },
      {
        id: "step-server-sign",
        stepNum: 3,
        label: "3. Self-Sign Cert",
        title: "Step 3: Self-Sign the Certificate",
        fileProduced: "server.crt",
        purpose: "Signs the certificate using its own private key (Issuer = Subject).",
        optionIds: [
          OPTION_VALIDITY_DAYS,
          OPTION_IS_CA,
          OPTION_SERVER_AUTH,
          OPTION_CLIENT_AUTH,
          OPTION_CODE_SIGNING,
          OPTION_HASH_TYPE,
        ],
        guideKind: "single-sign",
      },
      {
        id: "step-deploy",
        stepNum: 4,
        label: "4. Deploy Key & Cert",
        title: "Step 4: Deploy Key & Cert",
        fileProduced: "Deploy to service",
        purpose: "Configure the service (e.g. Nginx, Node.js) with server.crt and server.key.",
        guideKind: "deploy",
      },
      {
        id: "step-trust",
        stepNum: 5,
        label: "5. Trust & Generate",
        title: "Step 5: Trust on Client Side & Generate",
        fileProduced: "Import cert.crt",
        purpose:
          "Since there is no external CA, clients/browsers must manually trust cert.crt to avoid security warnings.",
        guideKind: "trust",
      },
    ];
  }, [creatorMode, issuanceMode, pkiHierarchy]);

  const isComputing = state.status === "computing";

  // Render CA Authority Signing section (Manual entry + 1-Click Auto-Generate)
  const renderCaAuthoritySection = () => (
    <div className="space-y-4 mb-4">
      {/* Mode Selector Pill Buttons */}
      <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-3 dark:border-slate-800 dark:bg-slate-900/60">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
            Signing Authority Mode
          </span>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {issuanceMode === "self-signed"
              ? "Self-signed certificate"
              : "CA-signed certificate"}
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <button
            type="button"
            onClick={() => setOptionValue(OPTION_ISSUANCE_MODE, "self-signed")}
            className={cn(
              "flex flex-col items-start p-2.5 rounded-lg border text-left transition-all",
              issuanceMode === "self-signed"
                ? "border-indigo-600 bg-white ring-2 ring-indigo-500/20 dark:bg-slate-800 dark:border-indigo-400"
                : "border-slate-200 bg-white/50 hover:bg-white text-slate-600 dark:border-slate-800 dark:bg-slate-900/40",
            )}
          >
            <span className="text-xs font-bold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
              <span>🛡️</span> Self-Signed (Standalone)
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
              Certificate signs itself using its own private key. Issuer = Subject.
            </span>
          </button>

          <button
            type="button"
            onClick={() => setOptionValue(OPTION_ISSUANCE_MODE, "ca-signed")}
            className={cn(
              "flex flex-col items-start p-2.5 rounded-lg border text-left transition-all",
              issuanceMode === "ca-signed"
                ? "border-indigo-600 bg-white ring-2 ring-indigo-500/20 dark:bg-slate-800 dark:border-indigo-400"
                : "border-slate-200 bg-white/50 hover:bg-white text-slate-600 dark:border-slate-800 dark:bg-slate-900/40",
            )}
          >
            <span className="text-xs font-bold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
              <span>🏛️</span> CA-Signed (Manual &amp; Generate)
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
              Sign using an Issuing CA. Supports manual PEM paste, file upload, or 1-click test
              CA generation.
            </span>
          </button>
        </div>
      </div>

      {/* When CA-Signed: Show CA Authority Card with Auto-Generate AND Manual Inputs */}
      {issuanceMode === "ca-signed" ? (
        <div className="space-y-3 rounded-xl border border-indigo-200 bg-gradient-to-r from-indigo-50/70 to-purple-50/50 p-4 dark:border-indigo-900/50 dark:from-indigo-950/30 dark:to-purple-950/20">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-indigo-100 pb-3 dark:border-indigo-900/40">
            <div>
              <h4 className="text-xs font-bold text-indigo-950 dark:text-indigo-200 flex items-center gap-1.5">
                <span>🏛️</span>
                <span>Issuing CA Credentials</span>
                <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-700 dark:bg-indigo-900/60 dark:text-indigo-300">
                  Manual + Generate
                </span>
              </h4>
              <p className="mt-0.5 text-[11px] text-slate-600 dark:text-slate-400">
                Paste or upload your CA certificate &amp; private key manually below, or click
                below to generate a matching test CA pair.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <Button
                size="sm"
                variant="primary"
                onClick={handleGenerateTestCa}
                disabled={isGeneratingCa}
                className="gap-1.5 font-semibold shadow-xs"
              >
                {isGeneratingCa ? "Generating..." : "⚡ Generate CA (Key & Cert)"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={handleGenerateCaKeyOnly}
                disabled={isGeneratingCa}
                title="Generate a fresh private key for CA"
              >
                🔑 Generate Key
              </Button>
              {(hasCaCert || hasCaKey) && (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleClearCa}
                  title="Clear both CA fields for manual entry"
                >
                  Clear
                </Button>
              )}
            </div>
          </div>

          {/* Status helper text */}
          <div className="flex items-center justify-between text-[11px] text-slate-600 dark:text-slate-400">
            <span>
              {hasCaCert && hasCaKey ? (
                <span className="text-emerald-700 dark:text-emerald-400 font-medium">
                  ✓ CA Certificate and Private Key configured (editable below)
                </span>
              ) : hasCaCert ? (
                <span className="text-amber-700 dark:text-amber-400 font-medium">
                  ⚠ CA Certificate entered, but CA Private Key is required to sign
                </span>
              ) : (
                <span>✍️ Enter your CA Certificate and Private Key manually below:</span>
              )}
            </span>
            <span className="font-mono text-[10px] text-slate-400">
              Format: X.509 PEM / PKCS#8
            </span>
          </div>

          {/* CA Certificate PEM — plain resizable textarea */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-slate-700 dark:text-slate-300">
                CA Certificate (PEM)
              </label>
              <div className="flex items-center gap-1.5">
                {hasCaCert && (
                  <CopyIconButton
                    value={() => String(caCertVal ?? "")}
                    aria-label="Copy CA certificate"
                  />
                )}
              </div>
            </div>
            <textarea
              value={String(caCertVal ?? "")}
              onChange={(e) => setOptionValue(OPTION_CA_CERT, e.target.value)}
              rows={6}
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
              className="w-full min-w-0 resize-y rounded-md border border-slate-300 bg-white px-2 py-1.5 font-mono text-xs text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-blue-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 whitespace-pre"
            />
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Issuing CA certificate in PEM format.
            </p>
          </div>

          {/* CA Private Key PEM — SecretField (masked, click to reveal) */}
          <SecretField
            label="CA Private Key (PEM)"
            value={String(caKeyVal ?? "")}
            onValueChange={(v) => setOptionValue(OPTION_CA_PRIVATE_KEY, v)}
            multiline
            rows={6}
            hint="Issuing CA's private key to sign the child certificate."
            action={
              hasCaKey ? (
                <CopyIconButton
                  value={() => String(caKeyVal ?? "")}
                  aria-label="Copy CA private key"
                />
              ) : undefined
            }
          />
        </div>
      ) : (
        /* When Self-Signed: Simple status card */
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
          <div className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
            <span>✓</span>
            <span>Self-Signed Mode Active</span>
          </div>
          <p className="mt-1 text-[11px]">
            The certificate will be signed directly by the private key generated in Step 1.
            Issuer DN will match Subject DN. No external CA certificate is required.
          </p>
        </div>
      )}
    </div>
  );

  // Render guide content for specific steps
  const renderStepGuide = (kind: StepDefinition["guideKind"]) => {
    switch (kind) {
      case "deploy":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Install the generated certificate and private key in your web server or
              application runtime:
            </p>
            <CodeSnippet
              title="Nginx TLS Configuration"
              code={`server {
    listen 443 ssl http2;
    server_name ${commandOptions.commonName};

    ssl_certificate     /etc/ssl/certs/cert.crt;
    ssl_certificate_key /etc/ssl/private/cert.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
}`}
            />
            <CodeSnippet
              title="Node.js / Express HTTPS Server"
              code={`import https from 'node:https';
import fs from 'node:fs';
import express from 'express';

const app = express();
const options = {
  key: fs.readFileSync('cert.key'),
  cert: fs.readFileSync('cert.crt')
};

https.createServer(options, app).listen(8443, () => {
  console.log('Secure server running at https://localhost:8443');
});`}
            />
          </div>
        );

      case "trust":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Since self-signed certificates lack an established Certificate Authority, trust
              the certificate on client machines:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <ShellCommandBlock
                title="Install in the System Trust Store"
                commands={{
                  bash: [
                    {
                      comment: "Linux (Ubuntu / Debian)",
                      parts: ["sudo cp cert.crt /usr/local/share/ca-certificates/"],
                    },
                    { parts: ["sudo update-ca-certificates"] },
                    {
                      comment: "macOS",
                      parts: [
                        "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.crt",
                      ],
                    },
                  ],
                  powershell: [
                    {
                      parts: [
                        "Import-Certificate -FilePath cert.crt -CertStoreLocation Cert:\\LocalMachine\\Root",
                      ],
                    },
                  ],
                  cmd: [{ parts: ['certutil -addstore -f "Root" cert.crt'] }],
                }}
              />
              <ShellCommandBlock
                title="cURL with Custom Certificate"
                commands={[
                  {
                    parts: [
                      "curl",
                      "--cacert cert.crt",
                      `https://${commandOptions.commonName}:8443`,
                    ],
                  },
                ]}
              />
            </div>
          </div>
        );

      case "trust-ca":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Since this certificate was signed by your Certificate Authority, install the Root
              CA certificate (`ca.crt`) in client truststores to validate all certificates
              issued by it:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <ShellCommandBlock
                title="cURL with CA Certificate"
                commands={[
                  {
                    parts: [
                      "curl",
                      "--cacert ca.crt",
                      `https://${commandOptions.commonName}:8443`,
                    ],
                  },
                ]}
              />
              <ShellCommandBlock
                title="Install CA in the System Trust Store"
                commands={{
                  bash: [
                    {
                      comment: "Linux (Ubuntu / Debian)",
                      parts: ["sudo cp ca.crt /usr/local/share/ca-certificates/"],
                    },
                    { parts: ["sudo update-ca-certificates"] },
                    {
                      comment: "macOS",
                      parts: [
                        "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt",
                      ],
                    },
                  ],
                  powershell: [
                    {
                      parts: [
                        "Import-Certificate -FilePath ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root",
                      ],
                    },
                  ],
                  cmd: [{ parts: ['certutil -addstore -f "Root" ca.crt'] }],
                }}
              />
            </div>
          </div>
        );

      case "single-key":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Generate the private key for the certificate using RSA or ECDSA:
            </p>
            <ShellCommandBlock
              title="OpenSSL — Step 1: Generate Private Key"
              commands={[
                keyCommand(
                  "cert.key",
                  commandOptions.keyType,
                  `Generate the selected ${commandOptions.keyType} private key`,
                ),
              ]}
            />
          </div>
        );

      case "single-csr":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Generate the Certificate Signing Request (CSR) specifying Subject DN and identity:
            </p>
            <ShellCommandBlock
              title="OpenSSL — Step 2: Generate CSR"
              commands={shellVariants((shell) => [
                {
                  parts: [
                    "openssl req -new",
                    "-key cert.key",
                    "-out cert.csr",
                    `-subj ${shellQuote(subject(commandOptions, commandOptions.commonName), shell)}`,
                    `-addext ${shellQuote(`subjectAltName=${sanExtension(commandOptions.san)}`, shell)}`,
                  ],
                },
              ])}
            />
          </div>
        );

      case "single-sign":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              {issuanceMode === "ca-signed"
                ? "Sign the CSR using your issuing Certificate Authority (Root or Intermediate CA):"
                : "Self-sign the certificate using its own private key:"}
            </p>
            <ShellCommandBlock
              title={
                issuanceMode === "ca-signed"
                  ? "OpenSSL — Step 3: Sign CSR with CA"
                  : "OpenSSL — Step 3: Self-Sign Certificate"
              }
              commands={shellVariants((shell) => {
                const digest = digestFlag(commandOptions.keyType, commandOptions.hashType);
                const eku = ekuExtension(commandOptions);
                return issuanceMode === "ca-signed"
                  ? [
                      {
                        parts: [
                          "openssl x509 -req",
                          "-in cert.csr",
                          "-CA ca.crt",
                          "-CAkey ca.key",
                          "-CAcreateserial",
                          "-copy_extensions copy",
                          "-out cert.crt",
                          `-days ${commandOptions.validityDays}`,
                          ...(digest ? [digest] : []),
                        ],
                      },
                    ]
                  : [
                      {
                        parts: [
                          "openssl req -x509 -new",
                          "-key cert.key",
                          ...(digest ? [digest] : []),
                          `-days ${commandOptions.validityDays}`,
                          "-out cert.crt",
                          `-subj ${shellQuote(subject(commandOptions, commandOptions.commonName), shell)}`,
                          `-addext ${shellQuote(`subjectAltName=${sanExtension(commandOptions.san)}`, shell)}`,
                          `-addext ${shellQuote(`basicConstraints=critical,CA:${commandOptions.isCa ? "TRUE" : "FALSE"}`, shell)}`,
                          ...(eku
                            ? [`-addext ${shellQuote(`extendedKeyUsage=${eku}`, shell)}`]
                            : []),
                        ],
                      },
                    ];
              })}
            />
          </div>
        );

      case "mtls-root-ca":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The Root CA acts as your private certificate provider. Both the server and the
              client will trust this CA to verify each other:
            </p>
            <ShellCommandBlock
              title="OpenSSL — Step 1: Create the Root Certificate Authority (CA)"
              commands={shellVariants((shell) => {
                const digest = digestFlag(
                  commandOptions.rootKeyType,
                  commandOptions.rootHashType,
                );
                return [
                  keyCommand(
                    `${rootPrefix}.key`,
                    commandOptions.rootKeyType,
                    "Generate the Root CA private key",
                  ),
                  {
                    comment: "Generate the self-signed Root CA certificate",
                    parts: [
                      "openssl req -x509 -new",
                      `-key ${rootPrefix}.key`,
                      ...(digest ? [digest] : []),
                      `-days ${commandOptions.validityDays}`,
                      `-out ${rootPrefix}.crt`,
                      `-subj ${shellQuote(subject(commandOptions, commandOptions.caCommonName), shell)}`,
                      `-addext ${shellQuote(`basicConstraints=critical,CA:TRUE,pathlen:${pkiHierarchy === "3-tier" ? 1 : 0}`, shell)}`,
                      `-addext ${shellQuote("keyUsage=critical,keyCertSign,cRLSign", shell)}`,
                    ],
                  },
                ];
              })}
            />
          </div>
        );

      case "mtls-server-csr":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The server needs its own identity. Create a private key and a Certificate Signing
              Request (CSR):
            </p>
            <ShellCommandBlock
              title="OpenSSL — Step 2: Generate the Server Key and CSR"
              commands={shellVariants((shell) => {
                const eku = ekuExtension(commandOptions);
                return [
                  keyCommand(
                    "server.key",
                    commandOptions.serverKeyType,
                    "Generate the Server private key",
                  ),
                  {
                    comment: "Generate the Server Certificate Signing Request (CSR)",
                    parts: [
                      "openssl req -new",
                      "-key server.key",
                      "-out server.csr",
                      `-subj ${shellQuote(subject(commandOptions, commandOptions.commonName), shell)}`,
                      `-addext ${shellQuote(`subjectAltName=${sanExtension(commandOptions.san)}`, shell)}`,
                      ...(eku
                        ? [`-addext ${shellQuote(`extendedKeyUsage=${eku}`, shell)}`]
                        : []),
                    ],
                  },
                ];
              })}
            />
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              The subject and SAN values above update from this step&apos;s current options.
            </p>
          </div>
        );

      case "mtls-server-sign":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Use the Root CA (
              <code className="font-mono text-indigo-600 dark:text-indigo-400">ca.key</code> and{" "}
              <code className="font-mono text-indigo-600 dark:text-indigo-400">ca.crt</code>) to
              sign the server&apos;s CSR, turning it into a valid server certificate (
              <code className="font-mono text-indigo-600 dark:text-indigo-400">server.crt</code>
              ):
            </p>
            <ShellCommandBlock
              title="OpenSSL — Step 3: Sign the Server Certificate"
              commands={[
                {
                  parts: [
                    "openssl x509 -req",
                    "-in server.csr",
                    `-CA ${pkiHierarchy === "3-tier" ? "intermediate.crt" : "ca.crt"}`,
                    `-CAkey ${pkiHierarchy === "3-tier" ? "intermediate.key" : "ca.key"}`,
                    "-CAcreateserial",
                    "-copy_extensions copy",
                    "-out server.crt",
                    `-days ${commandOptions.validityDays}`,
                    ...digestArgs(
                      pkiHierarchy === "3-tier"
                        ? commandOptions.intermediateKeyType
                        : commandOptions.rootKeyType,
                      commandOptions.serverHashType,
                    ),
                  ],
                },
              ]}
            />
          </div>
        );

      case "mtls-client-sign":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Just like the server, the client needs its own keypair to authenticate itself back
              to the server. Sign the client CSR with the Root CA:
            </p>
            <ShellCommandBlock
              title="OpenSSL — Step 4: Generate and Sign the Client Certificate"
              commands={shellVariants((shell) => {
                const issuer = pkiHierarchy === "3-tier" ? "intermediate" : "ca";
                const digest = digestFlag(
                  pkiHierarchy === "3-tier"
                    ? commandOptions.intermediateKeyType
                    : commandOptions.rootKeyType,
                  commandOptions.clientHashType,
                );
                const eku = ekuExtension(commandOptions, true);
                return [
                  keyCommand(
                    "client.key",
                    commandOptions.clientKeyType,
                    "Generate the Client private key",
                  ),
                  {
                    comment: "Generate the Client CSR",
                    parts: [
                      "openssl req -new",
                      "-key client.key",
                      "-out client.csr",
                      `-subj ${shellQuote(subject(commandOptions, commandOptions.clientCommonName), shell)}`,
                      ...(eku
                        ? [`-addext ${shellQuote(`extendedKeyUsage=${eku}`, shell)}`]
                        : []),
                    ],
                  },
                  {
                    comment: `Sign the Client CSR using the ${pkiHierarchy === "3-tier" ? "Intermediate" : "Root"} CA`,
                    parts: [
                      "openssl x509 -req",
                      "-in client.csr",
                      `-CA ${issuer}.crt`,
                      `-CAkey ${issuer}.key`,
                      "-CAcreateserial",
                      "-copy_extensions copy",
                      "-out client.crt",
                      `-days ${commandOptions.validityDays}`,
                      ...(digest ? [digest] : []),
                    ],
                  },
                  passwordEnvironmentCommand(commandOptions.p12Password, shell),
                  {
                    comment: "Export the Client key and certificate as PKCS#12",
                    parts: [
                      "openssl pkcs12 -export",
                      "-out client.p12",
                      "-inkey client.key",
                      "-in client.crt",
                      `-certfile ${issuer}.crt`,
                      "-passout env:CLIENT_P12_PASSWORD",
                    ],
                  },
                ];
              })}
            />
          </div>
        );

      case "inter-csr":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Generate private key and CSR for the Intermediate Issuing Certificate Authority:
            </p>
            <ShellCommandBlock
              title="OpenSSL — Step 2: Generate Intermediate Key & CSR"
              commands={shellVariants((shell) => [
                keyCommand(
                  "intermediate.key",
                  commandOptions.intermediateKeyType,
                  "Generate the Intermediate CA private key",
                ),
                {
                  comment: "Generate the Intermediate CA CSR",
                  parts: [
                    "openssl req -new",
                    "-key intermediate.key",
                    "-out intermediate.csr",
                    `-subj ${shellQuote(subject(commandOptions, commandOptions.intermediateCommonName), shell)}`,
                    `-addext ${shellQuote("basicConstraints=critical,CA:TRUE,pathlen:0", shell)}`,
                    `-addext ${shellQuote("keyUsage=critical,keyCertSign,cRLSign", shell)}`,
                  ],
                },
              ])}
            />
          </div>
        );

      case "inter-sign":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The Root CA delegates signing authority with{" "}
              <code className="font-mono text-indigo-600 dark:text-indigo-400">
                CA:TRUE, pathlen:0
              </code>{" "}
              so the Root CA private key can be securely stored offline.
            </p>
            <ShellCommandBlock
              title="OpenSSL Intermediate Delegation Reference"
              commands={[
                {
                  parts: [
                    "openssl x509 -req",
                    "-in intermediate.csr",
                    "-CA root-ca.crt",
                    "-CAkey root-ca.key",
                    "-CAcreateserial",
                    "-copy_extensions copy",
                    "-out intermediate.crt",
                    `-days ${commandOptions.validityDays}`,
                    ...digestArgs(
                      commandOptions.rootKeyType,
                      commandOptions.intermediateHashType,
                    ),
                  ],
                },
              ]}
            />
          </div>
        );

      case "server-chain":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The Intermediate CA signs the server certificate. The resulting bundle contains
              both the leaf certificate and the issuing intermediate certificate:
            </p>
            <ShellCommandBlock
              title="OpenSSL — Generate and Sign the Server Chain"
              commands={shellVariants((shell) => {
                const digest = digestFlag(
                  commandOptions.intermediateKeyType,
                  commandOptions.serverHashType,
                );
                const eku = ekuExtension(commandOptions);
                const chainCommand =
                  shell === "powershell"
                    ? "Get-Content server.crt, intermediate.crt | Set-Content server-chain.pem"
                    : shell === "cmd"
                      ? "type server.crt intermediate.crt > server-chain.pem"
                      : "cat server.crt intermediate.crt > server-chain.pem";
                return [
                  keyCommand(
                    "server.key",
                    commandOptions.serverKeyType,
                    "Generate the Server private key",
                  ),
                  {
                    comment:
                      "Generate the Server CSR with the selected identity and extensions",
                    parts: [
                      "openssl req -new",
                      "-key server.key",
                      "-out server.csr",
                      `-subj ${shellQuote(subject(commandOptions, commandOptions.commonName), shell)}`,
                      `-addext ${shellQuote(`subjectAltName=${sanExtension(commandOptions.san)}`, shell)}`,
                      ...(eku
                        ? [`-addext ${shellQuote(`extendedKeyUsage=${eku}`, shell)}`]
                        : []),
                    ],
                  },
                  {
                    comment: "Sign the Server CSR with the Intermediate CA",
                    parts: [
                      "openssl x509 -req",
                      "-in server.csr",
                      "-CA intermediate.crt",
                      "-CAkey intermediate.key",
                      "-CAcreateserial",
                      "-copy_extensions copy",
                      "-out server.crt",
                      `-days ${commandOptions.validityDays}`,
                      ...(digest ? [digest] : []),
                    ],
                  },
                  { comment: "Build the deployable certificate chain", parts: [chainCommand] },
                ];
              })}
            />
          </div>
        );

      case "mtls-trust":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Install the Root CA into both the server and client truststores so they mutually
              authenticate each other:
            </p>
            <div className="space-y-2">
              <ShellCommandBlock
                title="cURL mTLS Client Test Command"
                commands={[
                  {
                    parts: [
                      "curl",
                      "--cacert ca.crt",
                      "--cert client.crt",
                      "--key client.key",
                      `https://${commandOptions.commonName}:8443`,
                    ],
                  },
                ]}
              />
              <CodeSnippet
                title="Nginx mTLS Server Block (/etc/nginx/conf.d/mtls.conf)"
                code={`server {
    listen 8443 ssl;
    server_name ${commandOptions.commonName};

    ssl_certificate        /etc/ssl/certs/server.crt;
    ssl_certificate_key    /etc/ssl/private/server.key;

    # Require and verify client certificate against Root CA
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client      on;
    ssl_verify_depth       2;
}`}
              />
              <CodeSnippet
                title="Node.js mTLS HTTPS Server"
                code={`const https = require('https');
const fs = require('fs');

https.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt'),
  ca: fs.readFileSync('ca.crt'),
  requestCert: true,
  rejectUnauthorized: true,
}, (req, res) => {
  res.writeHead(200);
  res.end('mTLS connection verified! Client CN: ' + req.socket.getPeerCertificate().subject.CN);
}).listen(8443);`}
              />
              <ShellCommandBlock
                title="Install Root CA into OS Truststores"
                commands={{
                  bash: [
                    {
                      comment: "Linux (Debian / Ubuntu)",
                      parts: ["sudo cp ca.crt /usr/local/share/ca-certificates/ca.crt"],
                    },
                    { parts: ["sudo update-ca-certificates"] },
                    {
                      comment: "macOS",
                      parts: [
                        "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt",
                      ],
                    },
                  ],
                  powershell: [
                    {
                      parts: [
                        "Import-Certificate -FilePath ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root",
                      ],
                    },
                  ],
                  cmd: [{ parts: ['certutil -addstore -f "Root" ca.crt'] }],
                }}
              />
              <ShellCommandBlock
                title="Kubernetes Generic Secret"
                commands={[
                  {
                    parts: [
                      "kubectl create secret generic mtls-certs",
                      "--from-file=ca.crt=ca.crt",
                      "--from-file=server.crt=server.crt",
                      "--from-file=server.key=server.key",
                    ],
                  },
                ]}
              />
            </div>
          </div>
        );

      case "3tier-deploy":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Enterprise 3-Tier verification and deployment. Clients and servers establish
              cryptographic trust via the Root CA:
            </p>
            <div className="space-y-2">
              <ShellCommandBlock
                title="Verify Complete Certificate Chain"
                commands={[
                  {
                    parts: [
                      "openssl verify",
                      "-CAfile root-ca.crt",
                      "-untrusted intermediate.crt",
                      "server.crt",
                    ],
                  },
                ]}
              />
              <CodeSnippet
                title="Nginx Enterprise Chain Deployment"
                code={`ssl_certificate         /etc/ssl/certs/server-chain.pem;
ssl_certificate_key     /etc/ssl/private/server.key;
ssl_client_certificate  /etc/ssl/certs/root-ca.crt;
ssl_verify_client       on;`}
              />
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Architecture Bar & Workflow Layout Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white/80 p-3.5 shadow-xs backdrop-blur-xs dark:border-slate-800 dark:bg-slate-900/80">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-600 text-white shadow-xs dark:bg-indigo-500">
            <svg
              className="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">
              Certificate &amp; PKI Studio
            </h2>
            <div className="flex flex-wrap items-center gap-1.5 mt-0.5">
              {/* Architecture Switcher */}
              <button
                type="button"
                onClick={() => {
                  setOptionValue(OPTION_CREATOR_MODE, "single-cert");
                  setOptionValue(OPTION_ISSUANCE_MODE, "self-signed");
                }}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                  creatorMode === "single-cert" && issuanceMode === "self-signed"
                    ? "bg-indigo-100 text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300 font-semibold"
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
                )}
              >
                Single (Self-Signed)
              </button>
              <span className="text-slate-300 dark:text-slate-700">|</span>
              <button
                type="button"
                onClick={() => {
                  setOptionValue(OPTION_CREATOR_MODE, "single-cert");
                  setOptionValue(OPTION_ISSUANCE_MODE, "ca-signed");
                }}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                  creatorMode === "single-cert" && issuanceMode === "ca-signed"
                    ? "bg-indigo-100 text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300 font-semibold"
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
                )}
              >
                Single (CA-Signed)
              </button>
              <span className="text-slate-300 dark:text-slate-700">|</span>
              <button
                type="button"
                onClick={() => {
                  setOptionValue(OPTION_CREATOR_MODE, "mtls-suite");
                  setOptionValue(OPTION_PKI_HIERARCHY, "2-tier");
                }}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                  creatorMode === "mtls-suite" && pkiHierarchy === "2-tier"
                    ? "bg-indigo-100 text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300 font-semibold"
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
                )}
              >
                mTLS (2-Tier)
              </button>
              <span className="text-slate-300 dark:text-slate-700">|</span>
              <button
                type="button"
                onClick={() => {
                  setOptionValue(OPTION_CREATOR_MODE, "mtls-suite");
                  setOptionValue(OPTION_PKI_HIERARCHY, "3-tier");
                }}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                  creatorMode === "mtls-suite" && pkiHierarchy === "3-tier"
                    ? "bg-indigo-100 text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300 font-semibold"
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
                )}
              >
                mTLS Enterprise (3-Tier)
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {wizardSteps.map((step) => (
          <div
            key={step.id}
            className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900"
          >
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-2 dark:border-slate-800">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                  {step.title}
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">{step.purpose}</p>
              </div>
              <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-mono text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                Produces: {step.fileProduced}
              </span>
            </div>

            {/* CA Authority Section for CA panel (single-cert only) — full manual + generate UI */}
            {step.isCaStep && creatorMode !== "mtls-suite" && renderCaAuthoritySection()}

            {/* Options Form — render either if step has groups or optionIds */}
            {((step.groups &&
              step.groups.length > 0 &&
              step.groups.filter((g) => g !== "ca").length > 0) ||
              (step.optionIds && step.optionIds.length > 0)) && (
              <OptionsForm
                catalogue={tool.catalogue}
                groups={tool.groups}
                options={spec.options}
                tag={tag}
                groupIds={step.groups?.filter((g) => g !== "ca")}
                optionIds={step.optionIds}
                headings={false}
                generateLength={generateLength}
                acceptedByteLengths={acceptedByteLengths}
                onChange={setOptionValue}
              />
            )}

            {step.guideKind && renderStepGuide(step.guideKind)}
          </div>
        ))}

        {/* Sticky Bottom Action Card */}
        <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white p-3.5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div>
            <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
              {missingCaCredentials ? "CA Credentials Required" : "Ready to Generate"}
            </span>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              {creatorMode === "mtls-suite"
                ? `Generate complete ${pkiHierarchy.toUpperCase()} mTLS suite (Root CA, Leaf certs, and client PKCS#12 bundle)`
                : missingCaCredentials
                  ? "Provide both the issuing CA certificate and its matching private key."
                  : issuanceMode === "ca-signed"
                    ? "Generate CA-signed certificate and private key"
                    : "Generate self-signed certificate and private key with all configured parameters"}
            </p>
          </div>
          <Button
            size="md"
            variant="primary"
            disabled={!canRecompute || isComputing || missingCaCredentials}
            onClick={recompute}
            className="gap-2 font-semibold shadow-xs"
          >
            {isComputing ? (
              "Generating..."
            ) : (
              <>
                <span>⚡</span>
                <span>
                  {creatorMode === "mtls-suite"
                    ? "Generate mTLS Suite"
                    : issuanceMode === "ca-signed"
                      ? "Generate CA-Signed Cert"
                      : "Generate Certificate"}
                </span>
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
