"use client";

import type { ReactNode } from "react";
import type { OptionValue, OptionValues } from "@ocs/contracts";
import type { ToolDefinition, ToolSpecBase } from "@ocs/engine";
import {
  OPTION_CA_CERT,
  OPTION_CA_KEY_TYPE,
  OPTION_CA_MODE,
  OPTION_CA_PRIVATE_KEY,
  OPTION_CLIENT_AUTH,
  OPTION_CODE_SIGNING,
  OPTION_COMMON_NAME,
  OPTION_COUNTRY,
  OPTION_HASH_TYPE,
  OPTION_KEY_TYPE,
  OPTION_LOCALITY,
  OPTION_ORGANIZATION,
  OPTION_ORG_UNIT,
  OPTION_SAN,
  OPTION_SERVER_AUTH,
  OPTION_STATE,
  OPTION_VALIDITY_DAYS,
} from "@ocs/certificates";
import {
  Button,
  ShellCommandBlock,
  cn,
  type CommandShell,
  type ShellCommand,
  type ShellCommandVariants,
} from "@ocs/ui";
import { OptionsForm } from "./options-form";
import type { ComputeState } from "./use-compute";

interface CsrWorkbenchProps {
  tool: ToolDefinition<ToolSpecBase>;
  spec: ToolSpecBase;
  setOptionValue: (id: string, value: OptionValue | undefined) => void;
  recompute: () => void;
  canRecompute: boolean;
  state: ComputeState;
  tag?: string | readonly string[];
  inputStep?: ReactNode;
  generateLength?: (optionId: string) => number | undefined;
  acceptedByteLengths?: (optionId: string) => readonly number[] | undefined;
}

interface CsrStep {
  id: string;
  title: string;
  purpose: string;
  fileProduced: string;
  optionIds?: readonly string[];
  content?: ReactNode;
}

function optionString(options: OptionValues, id: string, fallback: string): string {
  const value = options[id];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function optionBoolean(options: OptionValues, id: string, fallback: boolean): boolean {
  const value = options[id];
  return typeof value === "boolean" ? value : fallback;
}

function shellQuote(value: string, shell: CommandShell): string {
  if (shell === "cmd") return `"${value.replaceAll('"', '""')}"`;
  return `'${value.replaceAll("'", shell === "powershell" ? "''" : `'"'"'`)}'`;
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

function keyCommand(keyType: string, output = "private.key", role = "applicant"): ShellCommand {
  if (keyType.startsWith("rsa-")) {
    return {
      comment: `Generate the ${role} private key`,
      parts: [
        "openssl genpkey -algorithm RSA",
        `-pkeyopt rsa_keygen_bits:${keyType.slice(4)}`,
        `-out ${output}`,
      ],
    };
  }
  if (keyType === "ecdsa-p384" || keyType === "ecdsa-p521") {
    return {
      comment: `Generate the ${role} private key`,
      parts: [
        "openssl genpkey -algorithm EC",
        `-pkeyopt ec_paramgen_curve:${keyType === "ecdsa-p384" ? "secp384r1" : "secp521r1"}`,
        `-out ${output}`,
      ],
    };
  }
  if (keyType === "ed25519") {
    return {
      comment: `Generate the ${role} private key`,
      parts: ["openssl genpkey -algorithm ED25519", `-out ${output}`],
    };
  }
  if (keyType.startsWith("ml-dsa-")) {
    return {
      comment: `Generate the ${role} private key (requires OpenSSL ML-DSA support)`,
      parts: [`openssl genpkey -algorithm ${keyType.toUpperCase()}`, `-out ${output}`],
    };
  }
  return {
    comment: `Generate the ${role} private key`,
    parts: [
      "openssl genpkey -algorithm EC",
      "-pkeyopt ec_paramgen_curve:prime256v1",
      `-out ${output}`,
    ],
  };
}

function digestFlag(keyType: string, hashType: string): string[] {
  return keyType === "ed25519" || keyType.startsWith("ml-dsa-") ? [] : [`-${hashType}`];
}

function subject(options: OptionValues): string {
  const values: readonly (readonly [string, string])[] = [
    ["C", optionString(options, OPTION_COUNTRY, "US").slice(0, 2).toUpperCase()],
    ["ST", optionString(options, OPTION_STATE, "California")],
    ["L", optionString(options, OPTION_LOCALITY, "San Francisco")],
    ["O", optionString(options, OPTION_ORGANIZATION, "Cipher Workbench")],
    ["OU", optionString(options, OPTION_ORG_UNIT, "Engineering")],
    ["CN", optionString(options, OPTION_COMMON_NAME, "example.com")],
  ];
  return values
    .map(([key, value]) => `/${key}=${value.replaceAll("\\", "\\\\").replaceAll("/", "\\/")}`)
    .join("");
}

function sanValue(options: OptionValues): string {
  const commonName = optionString(options, OPTION_COMMON_NAME, "example.com");
  return optionString(options, OPTION_SAN, commonName)
    .split(/[\n,;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const lower = entry.toLowerCase();
      if (lower.startsWith("dns:") || lower.startsWith("ip:") || lower.startsWith("uri:")) {
        return entry;
      }
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(entry)) return `IP:${entry}`;
      return `DNS:${entry}`;
    })
    .join(",");
}

function ekuValue(options: OptionValues): string | undefined {
  const values = [
    optionBoolean(options, OPTION_SERVER_AUTH, true) ? "serverAuth" : undefined,
    optionBoolean(options, OPTION_CLIENT_AUTH, true) ? "clientAuth" : undefined,
    optionBoolean(options, OPTION_CODE_SIGNING, false) ? "codeSigning" : undefined,
  ].filter((value): value is string => value !== undefined);
  return values.length > 0 ? values.join(",") : undefined;
}

function CsrCreatorCommands({ options }: { options: OptionValues }) {
  const keyType = optionString(options, OPTION_KEY_TYPE, "ecdsa-p256");
  const hashType = optionString(options, OPTION_HASH_TYPE, "sha256");
  const eku = ekuValue(options);

  return (
    <div className="space-y-3">
      <ShellCommandBlock
        title="OpenSSL - Generate Key and CSR"
        commands={shellVariants((shell) => [
          keyCommand(keyType),
          {
            comment: "Create the PKCS#10 request with the selected identity and extensions",
            parts: [
              "openssl req -new",
              "-key private.key",
              "-out request.csr",
              ...digestFlag(keyType, hashType),
              `-subj ${shellQuote(subject(options), shell)}`,
              `-addext ${shellQuote(`subjectAltName=${sanValue(options)}`, shell)}`,
              ...(eku ? [`-addext ${shellQuote(`extendedKeyUsage=${eku}`, shell)}`] : []),
            ],
          },
          {
            comment: "Verify proof of possession and inspect the request",
            parts: ["openssl req -in request.csr -noout -verify -text"],
          },
        ])}
      />
      <p className="text-[11px] text-slate-500 dark:text-slate-400">
        Ed25519 and ML-DSA use intrinsic signing parameters, so no digest flag is emitted for
        those key types.
      </p>
    </div>
  );
}

function CsrSignerCommands({ options }: { options: OptionValues }) {
  const caMode = optionString(options, OPTION_CA_MODE, "ephemeral-ca");
  const caKeyType = optionString(options, OPTION_CA_KEY_TYPE, "ecdsa-p256");
  const hashType = optionString(options, OPTION_HASH_TYPE, "sha256");
  const validityDays = optionString(options, OPTION_VALIDITY_DAYS, "365");

  return (
    <div className="space-y-3">
      <ShellCommandBlock
        title="OpenSSL - Issue and Verify Certificate"
        commands={shellVariants((shell) => [
          ...(caMode === "ephemeral-ca"
            ? [
                keyCommand(caKeyType, "ca.key", "Micro-CA"),
                {
                  comment: "Create the ephemeral Root CA certificate",
                  parts: [
                    "openssl req -x509 -new",
                    "-key ca.key",
                    "-out ca.crt",
                    "-days 3650",
                    ...digestFlag(caKeyType, hashType),
                    `-subj ${shellQuote("/O=CipherWorkbench Internal PKI/OU=Security Operations/CN=CipherWorkbench Micro-CA Root", shell)}`,
                    `-addext ${shellQuote("basicConstraints=critical,CA:TRUE,pathlen:0", shell)}`,
                    `-addext ${shellQuote("keyUsage=critical,keyCertSign,cRLSign", shell)}`,
                  ],
                },
              ]
            : []),
          {
            comment: `Sign the CSR with the ${caMode === "custom-ca" ? "provided" : "ephemeral"} CA`,
            parts: [
              "openssl x509 -req",
              "-in request.csr",
              "-CA ca.crt",
              "-CAkey ca.key",
              "-CAcreateserial",
              "-copy_extensions copy",
              "-out cert.crt",
              `-days ${validityDays}`,
              ...(caMode === "ephemeral-ca"
                ? digestFlag(caKeyType, hashType)
                : [`-${hashType}`]),
            ],
          },
          {
            comment: "Verify the issued certificate against its CA",
            parts: ["openssl verify -CAfile ca.crt cert.crt"],
          },
        ])}
      />
      <p className="text-[11px] text-slate-500 dark:text-slate-400">
        The in-browser signer applies the selected SAN and EKU policy. This compact OpenSSL
        equivalent copies extensions from the CSR; use an OpenSSL extfile when enforcing
        override values. For a custom Ed25519 CA, omit the digest flag because Ed25519 has
        intrinsic signing parameters.
      </p>
    </div>
  );
}

function StudioHeader({
  signer,
  caMode,
  setOptionValue,
}: {
  signer: boolean;
  caMode: string;
  setOptionValue: CsrWorkbenchProps["setOptionValue"];
}) {
  return (
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
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5l5 5v11a2 2 0 01-2 2z"
            />
          </svg>
        </div>
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            CSR &amp; Issuance Studio
          </h2>
          {signer ? (
            <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => setOptionValue(OPTION_CA_MODE, "ephemeral-ca")}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                  caMode === "ephemeral-ca"
                    ? "bg-indigo-100 font-semibold text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300"
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
                )}
              >
                Ephemeral Micro-CA
              </button>
              <span className="text-slate-300 dark:text-slate-700">|</span>
              <button
                type="button"
                onClick={() => setOptionValue(OPTION_CA_MODE, "custom-ca")}
                className={cn(
                  "rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                  caMode === "custom-ca"
                    ? "bg-indigo-100 font-semibold text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300"
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
                )}
              >
                Existing Custom CA
              </button>
            </div>
          ) : (
            <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
              PKCS#10 identity, key, extensions, and proof-of-possession workflow
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export function CsrWorkbench({
  tool,
  spec,
  setOptionValue,
  recompute,
  canRecompute,
  state,
  tag,
  inputStep,
  generateLength,
  acceptedByteLengths,
}: CsrWorkbenchProps) {
  const signer = tool.id === "csr-signer";
  const caMode = optionString(spec.options, OPTION_CA_MODE, "ephemeral-ca");
  const missingCustomCa =
    signer &&
    caMode === "custom-ca" &&
    (!optionString(spec.options, OPTION_CA_CERT, "") ||
      !optionString(spec.options, OPTION_CA_PRIVATE_KEY, ""));
  const isComputing = state.status === "computing" || state.status === "pending";

  const steps: readonly CsrStep[] = signer
    ? [
        {
          id: "csr-input",
          title: "Step 1: Load and Verify the CSR",
          purpose:
            "Paste or upload the applicant's PKCS#10 request. Its embedded public key proves possession of the corresponding private key.",
          fileProduced: "Validated request.csr",
          content: inputStep,
        },
        {
          id: "ca-authority",
          title: "Step 2: Choose the Signing Authority",
          purpose:
            "Generate a temporary in-browser Micro-CA or provide an existing CA certificate and matching private key.",
          fileProduced: caMode === "custom-ca" ? "Uses ca.crt and ca.key" : "ca.crt and ca.key",
          optionIds: [
            OPTION_CA_MODE,
            OPTION_CA_KEY_TYPE,
            OPTION_CA_CERT,
            OPTION_CA_PRIVATE_KEY,
          ],
        },
        {
          id: "signing-policy",
          title: "Step 3: Define the Issuance Policy",
          purpose:
            "Choose certificate lifetime, signature hash, SAN overrides, and permitted extended key usages.",
          fileProduced: "Issuance policy",
          optionIds: [
            OPTION_HASH_TYPE,
            OPTION_VALIDITY_DAYS,
            OPTION_SAN,
            OPTION_SERVER_AUTH,
            OPTION_CLIENT_AUTH,
            OPTION_CODE_SIGNING,
          ],
        },
        {
          id: "issue-certificate",
          title: "Step 4: Sign, Verify, and Export",
          purpose:
            "Issue the leaf certificate, verify it against the selected CA, and export the certificate chain and verification scripts.",
          fileProduced: "cert.crt, ca.crt, bundle.crt",
          content: <CsrSignerCommands options={spec.options} />,
        },
      ]
    : [
        {
          id: "subject-identity",
          title: "Step 1: Define the Subject Identity",
          purpose:
            "Describe the applicant using a Common Name and optional Distinguished Name attributes.",
          fileProduced: "Subject DN",
          optionIds: [
            OPTION_COMMON_NAME,
            OPTION_ORGANIZATION,
            OPTION_ORG_UNIT,
            OPTION_COUNTRY,
            OPTION_STATE,
            OPTION_LOCALITY,
          ],
        },
        {
          id: "key-signature",
          title: "Step 2: Choose Key and Signature Algorithms",
          purpose:
            "Generate the applicant keypair and select the digest used for the CSR proof-of-possession signature.",
          fileProduced: "private.key and public.key",
          optionIds: [OPTION_KEY_TYPE, OPTION_HASH_TYPE],
        },
        {
          id: "requested-extensions",
          title: "Step 3: Request SANs and Extended Key Usages",
          purpose:
            "Declare the identities and intended purposes that the issuing CA should review before signing.",
          fileProduced: "Requested extensions",
          optionIds: [OPTION_SAN, OPTION_SERVER_AUTH, OPTION_CLIENT_AUTH, OPTION_CODE_SIGNING],
        },
        {
          id: "generate-request",
          title: "Step 4: Generate and Verify the CSR",
          purpose:
            "Create the PKCS#10 request, verify its self-signature, and export the request with its keypair.",
          fileProduced: "request.csr, private.key, public.key",
          content: <CsrCreatorCommands options={spec.options} />,
        },
      ];

  return (
    <div className="space-y-4">
      <StudioHeader signer={signer} caMode={caMode} setOptionValue={setOptionValue} />

      <div className="space-y-4">
        {steps.map((step) => (
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
              <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                Produces: {step.fileProduced}
              </span>
            </div>

            {step.optionIds && (
              <OptionsForm
                catalogue={tool.catalogue}
                groups={tool.groups}
                options={spec.options}
                tag={tag}
                optionIds={step.optionIds}
                headings={false}
                generateLength={generateLength}
                acceptedByteLengths={acceptedByteLengths}
                onChange={setOptionValue}
              />
            )}
            {step.content}
          </div>
        ))}

        <div className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-3.5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div>
            <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
              {missingCustomCa
                ? "CA Credentials Required"
                : signer
                  ? "Ready to Sign"
                  : "Ready to Generate"}
            </span>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              {missingCustomCa
                ? "Provide both the custom CA certificate and its matching private key."
                : signer
                  ? "Issue a certificate from the loaded CSR and export its verification bundle."
                  : "Generate a private key and cryptographically self-signed PKCS#10 request."}
            </p>
          </div>
          <Button
            size="md"
            variant="primary"
            disabled={!canRecompute || isComputing || missingCustomCa}
            onClick={recompute}
            className="gap-2 font-semibold shadow-xs"
          >
            {isComputing ? (
              signer ? (
                "Signing..."
              ) : (
                "Generating..."
              )
            ) : (
              <span>{signer ? "Sign CSR" : "Generate CSR"}</span>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
