"use client";

import { useMemo, useState } from "react";
import type { OptionValue } from "@ocs/contracts";
import type { ToolDefinition, ToolSpecBase } from "@ocs/engine";
import { Button, CopyIconButton, SecretField, cn } from "@ocs/ui";
import { OptionsForm } from "./options-form";
import type { ComputeState } from "./use-compute";
import {
  createCertificate,
  OPTION_CA_CERT,
  OPTION_CA_PRIVATE_KEY,
  OPTION_CREATOR_MODE,
  OPTION_ISSUANCE_MODE,
  OPTION_PKI_HIERARCHY,
  OPTION_WORKFLOW_LAYOUT,
  readCaCert,
  readCaPrivateKey,
  readCreatorMode,
  readIssuanceMode,
  readPkiHierarchy,
  readWorkflowLayout,
  type WorkflowLayoutOption,
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
  isCaStep?: boolean;
  guideKind?: "deploy" | "trust" | "trust-ca" | "server-csr" | "server-sign" | "inter-sign" | "server-chain" | "mtls-trust" | "3tier-deploy";
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
  const layout = readWorkflowLayout(spec.options, "wizard");
  const creatorMode = readCreatorMode(spec.options);
  const issuanceMode = readIssuanceMode(spec.options);
  const pkiHierarchy = readPkiHierarchy(spec.options);

  const [activeStep, setActiveStep] = useState(0);
  const [isGeneratingCa, setIsGeneratingCa] = useState(false);

  const caCertVal = readCaCert(spec.options);
  const caKeyVal = readCaPrivateKey(spec.options);
  const hasCaCert = Boolean(caCertVal && caCertVal.trim().length > 0);
  const hasCaKey = Boolean(caKeyVal && caKeyVal.trim().length > 0);

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
            purpose: "Offline trust anchor with CA:TRUE and pathLenConstraint: 1.",
            groups: ["subject", "key"],
          },
          {
            id: "step-inter-csr",
            stepNum: 2,
            label: "2. Intermediate CSR",
            title: "Step 2: Generate Intermediate Key & CSR",
            fileProduced: "intermediate.key, intermediate.csr",
            purpose: "Identity for the online issuing authority.",
            groups: ["mtls"],
          },
          {
            id: "step-inter-sign",
            stepNum: 3,
            label: "3. Sign Intermediate",
            title: "Step 3: Sign Intermediate with Root CA",
            fileProduced: "intermediate.crt",
            purpose: "Root CA delegates signing authority (CA:TRUE, keyCertSign, cRLSign). Root key can now go offline.",
            guideKind: "inter-sign",
          },
          {
            id: "step-server-chain",
            stepNum: 4,
            label: "4. Server Cert & Chain",
            title: "Step 4: Generate & Sign Server Cert",
            fileProduced: "server.key, server.crt, server-chain.pem",
            purpose: "Intermediate CA signs the server cert (serverAuth). Server chain bundles server.crt + intermediate.crt.",
            guideKind: "server-chain",
          },
          {
            id: "step-client-p12",
            stepNum: 5,
            label: "5. Client Cert & P12",
            title: "Step 5: Generate & Sign Client Cert",
            fileProduced: "client.key, client.crt, client.p12",
            purpose: "Intermediate CA signs the client cert (clientAuth). Packaged with intermediate.crt into .p12.",
            groups: ["mtls"],
          },
          {
            id: "step-deploy-chains",
            stepNum: 6,
            label: "6. Deploy Chains & Test",
            title: "Step 6: Deploy Chains & Truststores",
            fileProduced: "Deploy chains & root-ca.crt",
            purpose: "Server serves server-chain.pem; Client & Server trust root-ca.crt to validate the full chain.",
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
          title: "Step 1: Create Root CA",
          fileProduced: "ca.key, ca.crt",
          purpose: "Shared trust anchor with Basic Constraints CA:TRUE.",
          groups: ["subject", "key"],
        },
        {
          id: "step-server-csr",
          stepNum: 2,
          label: "2. Server Key & CSR",
          title: "Step 2: Generate Server Key & CSR",
          fileProduced: "server.key, server.csr",
          purpose: "Server identity specifying domains/IPs in Subject Alternative Names (SANs).",
          guideKind: "server-csr",
        },
        {
          id: "step-server-sign",
          stepNum: 3,
          label: "3. Sign Server Cert",
          title: "Step 3: Sign Server Certificate",
          fileProduced: "server.crt",
          purpose: "Root CA signs the server CSR with id-kp-serverAuth EKU.",
          guideKind: "server-sign",
        },
        {
          id: "step-client-csr",
          stepNum: 4,
          label: "4. Client Key & CSR",
          title: "Step 4: Generate Client Key & CSR",
          fileProduced: "client.key, client.csr",
          purpose: "Client identity (e.g., service name, user ID, or machine name).",
          groups: ["mtls"],
        },
        {
          id: "step-client-sign",
          stepNum: 5,
          label: "5. Sign Client Cert & P12",
          title: "Step 5: Sign Client Certificate & PKCS#12 Bundle",
          fileProduced: "client.crt, client.p12",
          purpose: "Root CA signs the client CSR with id-kp-clientAuth EKU; optionally packages into PKCS#12 bundle.",
          groups: ["mtls"],
        },
        {
          id: "step-truststores",
          stepNum: 6,
          label: "6. Truststores & Test",
          title: "Step 6: Configure Truststores & Generate Suite",
          fileProduced: "Distribute ca.crt",
          purpose: "Client trusts ca.crt to verify the server; Server trusts ca.crt to verify the client.",
          guideKind: "mtls-trust",
        },
      ];
    }

    // Table 1: Single Certificate (Self-Signed or CA-Signed)
    return [
      {
        id: "step-key",
        stepNum: 1,
        label: "1. Private Key",
        title: "Step 1: Generate Private Key",
        fileProduced: "cert.key",
        purpose: "Private cryptographic key for the host/service (RSA or ECDSA).",
        groups: ["key"],
      },
      {
        id: "step-identity",
        stepNum: 2,
        label: "2. Identity & SANs",
        title: "Step 2: Generate CSR / Identity",
        fileProduced: "cert.csr (optional)",
        purpose: "Specifies Subject DN, Hostname/IP in SANs, and key usages.",
        groups: ["subject"],
      },
      {
        id: "step-sign",
        stepNum: 3,
        label: issuanceMode === "ca-signed" ? "3. CA Signing" : "3. Self-Sign Cert",
        title:
          issuanceMode === "ca-signed"
            ? "Step 3: CA Signing Authority & Extensions"
            : "Step 3: Self-Sign the Certificate",
        fileProduced: issuanceMode === "ca-signed" ? "ca.crt, ca.key, cert.crt" : "cert.crt",
        purpose:
          issuanceMode === "ca-signed"
            ? "Configure CA Authority (Manual Entry or 1-Click Generate) and validity/extensions."
            : "Signs the certificate using its own private key (Issuer = Subject).",
        groups: ["extensions"],
        isCaStep: true,
      },
      {
        id: "step-deploy",
        stepNum: 4,
        label: "4. Deploy Key & Cert",
        title: "Step 4: Deploy Key & Cert",
        fileProduced: "Deploy to service",
        purpose: "Configure the service (e.g. Nginx, Node.js) with cert.crt and cert.key.",
        guideKind: "deploy",
      },
      {
        id: "step-trust",
        stepNum: 5,
        label: "5. Trust & Generate",
        title:
          issuanceMode === "ca-signed"
            ? "Step 5: Trust CA on Client Side & Generate"
            : "Step 5: Trust on Client Side & Generate",
        fileProduced: issuanceMode === "ca-signed" ? "Import ca.crt" : "Import cert.crt",
        purpose:
          issuanceMode === "ca-signed"
            ? "Since this cert is CA-signed, clients/browsers trust ca.crt to validate all child certs."
            : "Since there is no CA, clients/browsers must manually trust cert.crt to avoid security warnings.",
        guideKind: issuanceMode === "ca-signed" ? "trust-ca" : "trust",
      },
    ];
  }, [creatorMode, issuanceMode, pkiHierarchy]);

  // Adjust active step if out of bounds
  const currentStepIndex = Math.min(activeStep, wizardSteps.length - 1);
  const currentStep = wizardSteps[currentStepIndex]!;

  const handleLayoutChange = (nextLayout: WorkflowLayoutOption) => {
    setOptionValue(OPTION_WORKFLOW_LAYOUT, nextLayout);
  };

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
            {issuanceMode === "self-signed" ? "Self-signed certificate" : "CA-signed certificate"}
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
              Sign using an Issuing CA. Supports manual PEM paste, file upload, or 1-click test CA generation.
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
                Paste or upload your CA certificate &amp; private key manually below, or click below to generate a matching test CA pair.
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
                {isGeneratingCa ? "Generating..." : "⚡ Generate Test CA (Key & Cert)"}
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
            The certificate will be signed directly by the private key generated in Step 1. Issuer DN will match Subject DN. No external CA certificate is required.
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
              Install the generated certificate and private key in your web server or application runtime:
            </p>
            <CodeSnippet
              title="Nginx TLS Configuration"
              code={`server {
    listen 443 ssl http2;
    server_name localhost;

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
              Since self-signed certificates lack an established Certificate Authority, trust the certificate on client machines:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <CodeSnippet
                title="macOS System Keychain"
                code={`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.crt`}
              />
              <CodeSnippet
                title="Windows Certificate Store"
                code={`certutil -addstore -f "Root" cert.crt`}
              />
              <CodeSnippet
                title="Linux (Ubuntu / Debian)"
                code={`sudo cp cert.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates`}
              />
              <CodeSnippet
                title="cURL with Custom Certificate"
                code={`curl --cacert cert.crt https://localhost:8443`}
              />
            </div>
          </div>
        );

      case "trust-ca":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Since this certificate was signed by your Certificate Authority, install the Root CA certificate (`ca.crt`) in client truststores to validate all certificates issued by it:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <CodeSnippet
                title="cURL with CA Certificate"
                code={`curl --cacert ca.crt https://localhost:8443`}
              />
              <CodeSnippet
                title="Windows Root Store"
                code={`certutil -addstore -f "Root" ca.crt`}
              />
              <CodeSnippet
                title="macOS Root Store"
                code={`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt`}
              />
              <CodeSnippet
                title="Linux CA Certificates"
                code={`sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates`}
              />
            </div>
          </div>
        );

      case "server-csr":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The server certificate requires domain names and IP addresses configured in Subject Alternative Names (SANs) so TLS clients verify host authenticity.
            </p>
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-300">
              <span className="font-semibold text-slate-900 dark:text-slate-100">Files Produced:</span>
              <ul className="mt-1 space-y-1 list-disc list-inside text-slate-600 dark:text-slate-400">
                <li><code className="text-indigo-600 dark:text-indigo-400">server.key</code> — Private key for the server</li>
                <li><code className="text-indigo-600 dark:text-indigo-400">server.csr</code> — Certificate signing request with SANs</li>
              </ul>
            </div>
          </div>
        );

      case "server-sign":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The Root CA signs the server CSR with Extended Key Usage <code className="font-mono text-indigo-600 dark:text-indigo-400">id-kp-serverAuth (1.3.6.1.5.5.7.3.1)</code>.
            </p>
            <CodeSnippet
              title="OpenSSL Signing Reference"
              code={`openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256`}
            />
          </div>
        );

      case "inter-sign":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The Root CA delegates signing authority with <code className="font-mono text-indigo-600 dark:text-indigo-400">CA:TRUE, pathlen:0</code> so the Root CA private key can be securely stored offline.
            </p>
            <CodeSnippet
              title="OpenSSL Intermediate Delegation Reference"
              code={`openssl x509 -req -in intermediate.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out intermediate.crt -days 1825 -extfile intermediate.cnf`}
            />
          </div>
        );

      case "server-chain":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              The Intermediate CA signs the server certificate. The resulting bundle contains both the leaf certificate and the issuing intermediate certificate:
            </p>
            <CodeSnippet
              title="Concatenated Server Certificate Chain"
              code={`cat server.crt intermediate.crt > server-chain.pem`}
            />
          </div>
        );

      case "mtls-trust":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Mutual authentication test commands. Both parties verify each other against the shared trust anchor:
            </p>
            <div className="space-y-2">
              <CodeSnippet
                title="cURL mTLS Client Test"
                code={`curl --cacert ca.crt --cert client.crt --key client.key https://localhost:8443`}
              />
              <CodeSnippet
                title="Nginx mTLS Verification Directives"
                code={`ssl_client_certificate /etc/ssl/certs/ca.crt;
ssl_verify_client       on;
ssl_verify_depth        2;`}
              />
              <CodeSnippet
                title="Kubernetes Generic Secret"
                code={`kubectl create secret generic mtls-certs \\
  --from-file=ca.crt=ca.crt \\
  --from-file=server.crt=server.crt \\
  --from-file=server.key=server.key`}
              />
            </div>
          </div>
        );

      case "3tier-deploy":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Enterprise 3-Tier verification and deployment. Clients and servers establish cryptographic trust via the Root CA:
            </p>
            <div className="space-y-2">
              <CodeSnippet
                title="Verify Complete Certificate Chain"
                code={`openssl verify -CAfile root-ca.crt -untrusted intermediate.crt server.crt`}
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
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
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
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
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
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
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
                    : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                )}
              >
                mTLS Enterprise (3-Tier)
              </button>
            </div>
          </div>
        </div>

        {/* Layout Switcher Pill */}
        <div className="flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-100/90 p-1 dark:border-slate-800 dark:bg-slate-950/80">
          <button
            type="button"
            onClick={() => handleLayoutChange("wizard")}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              layout === "wizard"
                ? "bg-white text-indigo-600 shadow-xs dark:bg-slate-800 dark:text-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <span>🧙</span>
            <span>Step Wizard</span>
          </button>
          <button
            type="button"
            onClick={() => handleLayoutChange("panels")}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              layout === "panels"
                ? "bg-white text-indigo-600 shadow-xs dark:bg-slate-800 dark:text-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <span>📋</span>
            <span>All Panels</span>
          </button>
          <button
            type="button"
            onClick={() => handleLayoutChange("classic")}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              layout === "classic"
                ? "bg-white text-indigo-600 shadow-xs dark:bg-slate-800 dark:text-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <span>⚙️</span>
            <span>Classic</span>
          </button>
        </div>
      </div>

      {/* 1. STEP-BY-STEP WIZARD LAYOUT */}
      {layout === "wizard" && (
        <div className="space-y-4">
          {/* Stepper Progress Bar */}
          <div className="rounded-xl border border-slate-200 bg-white p-3 shadow-xs dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between gap-1 overflow-x-auto pb-1">
              {wizardSteps.map((step, idx) => {
                const isActive = idx === currentStepIndex;
                const isCompleted = idx < currentStepIndex;
                return (
                  <button
                    key={step.id}
                    type="button"
                    onClick={() => setActiveStep(idx)}
                    className={cn(
                      "flex items-center gap-1.5 whitespace-nowrap rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors",
                      isActive
                        ? "bg-indigo-50 text-indigo-700 ring-1 ring-indigo-500/20 dark:bg-indigo-950/40 dark:text-indigo-300 dark:ring-indigo-400/30"
                        : isCompleted
                          ? "text-slate-700 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800/60"
                          : "text-slate-400 hover:bg-slate-50 dark:text-slate-500 dark:hover:bg-slate-800/40",
                    )}
                  >
                    <span
                      className={cn(
                        "flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-semibold",
                        isActive
                          ? "bg-indigo-600 text-white dark:bg-indigo-500"
                          : isCompleted
                            ? "bg-emerald-600 text-white dark:bg-emerald-500"
                            : "bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400",
                      )}
                    >
                      {isCompleted ? "✓" : idx + 1}
                    </span>
                    <span>{step.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Active Step Content */}
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
            {/* Step Header */}
            <div className="mb-4 border-b border-slate-100 pb-3 dark:border-slate-800">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                  {currentStep.title}
                </span>
                <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-mono text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                  Produces: {currentStep.fileProduced}
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {currentStep.purpose}
              </p>
            </div>

            {/* CA Authority Section for Step 3 (single-cert only) — full manual + generate UI */}
            {currentStep.isCaStep && creatorMode !== "mtls-suite" && renderCaAuthoritySection()}

            {/* Extensions/Validity controls always shown on isCaStep too */}
            {currentStep.groups && currentStep.groups.length > 0 && (
              <OptionsForm
                catalogue={tool.catalogue}
                groups={tool.groups}
                options={spec.options}
                tag={tag}
                groupIds={currentStep.groups.filter((g) => g !== "ca")}
                headings={false}
                generateLength={generateLength}
                acceptedByteLengths={acceptedByteLengths}
                onChange={setOptionValue}
              />
            )}

            {/* Step Guide / Snippets */}
            {currentStep.guideKind && renderStepGuide(currentStep.guideKind)}


            {/* Final Step Action Banner */}
            {currentStepIndex === wizardSteps.length - 1 && (
              <div className="mt-5 flex flex-col items-center justify-center gap-2 rounded-lg border border-slate-200 bg-gradient-to-b from-slate-50 to-white p-4 dark:border-slate-800 dark:from-slate-900 dark:to-slate-950">
                <Button
                  size="md"
                  variant="primary"
                  disabled={!canRecompute || isComputing}
                  onClick={recompute}
                  className="w-full max-w-sm gap-2 font-semibold shadow-md"
                >
                  {isComputing ? (
                    <>
                      <span className="inline-block animate-spin">⟳</span>
                      <span>Generating...</span>
                    </>
                  ) : (
                    <>
                      <span>⚡</span>
                      <span>
                        {creatorMode === "mtls-suite"
                          ? `Generate ${pkiHierarchy.toUpperCase()} mTLS Suite`
                          : issuanceMode === "ca-signed"
                            ? "Generate CA-Signed Certificate"
                            : "Generate Certificate & Key"}
                      </span>
                    </>
                  )}
                </Button>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Outputs complete PEM and DER artifacts with zero external dependencies.
                </p>
              </div>
            )}

            {/* Stepper Navigation */}
            <div className="mt-6 flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-800">
              <Button
                size="sm"
                variant="secondary"
                disabled={currentStepIndex === 0}
                onClick={() => setActiveStep((prev) => Math.max(0, prev - 1))}
              >
                ← Back
              </Button>

              <div className="text-xs text-slate-400">
                Step {currentStepIndex + 1} of {wizardSteps.length}
              </div>

              {currentStepIndex < wizardSteps.length - 1 ? (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => setActiveStep((prev) => Math.min(wizardSteps.length - 1, prev + 1))}
                >
                  Next →
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="primary"
                  disabled={!canRecompute || isComputing}
                  onClick={recompute}
                >
                  {isComputing ? "Generating..." : "Generate Now"}
                </Button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 2. ALL PANELS LAYOUT */}
      {layout === "panels" && (
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
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    {step.purpose}
                  </p>
                </div>
                <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-mono text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                  Produces: {step.fileProduced}
                </span>
              </div>

              {/* CA Authority Section for CA panel (single-cert only) — full manual + generate UI */}
              {step.isCaStep && creatorMode !== "mtls-suite" && renderCaAuthoritySection()}

              {/* Options Form — exclude 'ca' group since renderCaAuthoritySection handles it */}
              {step.groups && step.groups.length > 0 && step.groups.filter((g) => g !== "ca").length > 0 && (
                <OptionsForm
                  catalogue={tool.catalogue}
                  groups={tool.groups}
                  options={spec.options}
                  tag={tag}
                  groupIds={step.groups.filter((g) => g !== "ca")}
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
                Ready to Generate
              </span>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {creatorMode === "mtls-suite"
                  ? `Generate complete ${pkiHierarchy.toUpperCase()} mTLS suite (Root CA, Leaf certs, and client PKCS#12 bundle)`
                  : issuanceMode === "ca-signed"
                    ? "Generate CA-signed certificate and private key"
                    : "Generate self-signed certificate and private key with all configured parameters"}
              </p>
            </div>
            <Button
              size="md"
              variant="primary"
              disabled={!canRecompute || isComputing}
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
      )}

      {/* 3. CLASSIC LAYOUT */}
      {layout === "classic" && (
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Generate Certificate
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                All certificate options and parameters are managed in the right sidebar Settings panel.
              </p>
            </div>
            <Button
              size="md"
              variant="primary"
              disabled={!canRecompute || isComputing}
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
      )}
    </div>
  );
}
