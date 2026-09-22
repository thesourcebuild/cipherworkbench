import type { ToolExportFile, ToolResult, ToolResultField } from "@ocs/engine";
import { parseAsn1 } from "./asn1/asn1";
import { convertCertificate } from "./asn1/converter";
import { parseCsr } from "./asn1/csr";
import { detectInputBytes } from "./asn1/pem";
import { parseX509Certificate } from "./asn1/x509";
import { createCertificate } from "./asn1/create-cert";
import { createCsr } from "./asn1/create-csr";
import { generateMtlsSuite } from "./asn1/mtls";
import { parseX509Crl } from "./asn1/crl";
import { verifyCertificateChain } from "./asn1/chain-verifier";
import { verifyCertificateKeyPair } from "./asn1/cert-matcher";
import { diffCertificates } from "./asn1/cert-diff";
import { signCsr } from "./asn1/csr-signer";
import { buildOcspRequest, parseOcspResponse, createMockOcspResponse } from "./asn1/ocsp";
import { calculateAcmeChallenges } from "./crypto/acme";
import { spkiToOpenSsh } from "./crypto/openssh";
import { spkiToJwk } from "./crypto/jwk";
import { generateTerraformConfig, generateAnsiblePlaybook } from "./export/iac";
import {
  generateCertCommandScripts,
  generateMtlsCommandScripts,
  generateCsrCommandScripts,
} from "./export/commands";
import {
  readConverterOp,
  readDetailLevel,
  readVerifyCsrSig,
  readCommonName,
  readOrganization,
  readOrgUnit,
  readCountry,
  readState,
  readLocality,
  readKeyType,
  readHashType,
  readValidityDays,
  readIsCa,
  readSan,
  readServerAuth,
  readClientAuth,
  readCodeSigning,
  readPassword,
  readPrivateKey,
  readCreatorMode,
  readIssuanceMode,
  readCaCert,
  readCaPrivateKey,
  readClientCommonName,
  readMtlsP12Password,
  readPkiHierarchy,
  readIntermediateCommonName,
  readComparisonCert,
  readCaMode,
  readOcspOp,
  readIssuerCert,
  readAcmeDomain,
  readAcmeToken,
  readAcmeAccountKey,
} from "./pure";
import type { CertificateSpec } from "./spec";

export async function computeCertificate(
  spec: CertificateSpec,
  input: Uint8Array,
): Promise<ToolResult> {
  // Creator tools generate certificates/requests directly without requiring input
  if (spec.variant === "cert-creator") {
    try {
      const creatorMode = readCreatorMode(spec.options);
      const commonName = readCommonName(spec.options, "localhost");
      const san = readSan(spec.options, "localhost, 127.0.0.1");
      const organization = readOrganization(spec.options, "Cipher Workbench");
      const organizationalUnit = readOrgUnit(spec.options, "Security");
      const country = readCountry(spec.options, "US");
      const state = readState(spec.options, "California");
      const locality = readLocality(spec.options, "San Francisco");
      const keyType = readKeyType(spec.options, "ecdsa-p256");
      const hashType = readHashType(spec.options, "sha256");
      const validityDays = readValidityDays(spec.options, 365);

      if (creatorMode === "mtls-suite") {
        const pkiHierarchy = readPkiHierarchy(spec.options);
        const intermediateCommonName = readIntermediateCommonName(spec.options, "Internal Issuing CA");
        const clientCommonName = readClientCommonName(spec.options, "client-app-01");
        const p12Password = readMtlsP12Password(spec.options, "changeit");

        const mtls = await generateMtlsSuite({
          pkiHierarchy,
          caCommonName: "Internal Root CA",
          intermediateCommonName,
          organization,
          organizationalUnit,
          country,
          state,
          locality,
          serverCommonName: commonName,
          serverSan: san,
          clientCommonName,
          keyType,
          hashType,
          validityDays,
          p12Password,
        });

        const fields: ToolResultField[] = [
          { label: "Suite Mode", value: `Full mTLS Hierarchy (${pkiHierarchy.toUpperCase()})` },
          { label: "Root CA", value: mtls.ca.subjectDn, hint: `SHA-256: ${mtls.ca.fingerprint}` },
        ];

        if (mtls.intermediate) {
          fields.push({
            label: "Intermediate CA",
            value: mtls.intermediate.subjectDn,
            hint: `SHA-256: ${mtls.intermediate.fingerprint}`,
          });
        }

        fields.push(
          { label: "Server Certificate", value: `${mtls.server.subjectDn} (SANs: ${mtls.server.san})` },
          { label: "Client Certificate", value: `${mtls.client.subjectDn} (Client Auth)` },
          { label: "Client PKCS#12", value: `Protected (.p12) - Password: ${p12Password}` },
          { label: "Key Algorithm", value: keyType.toUpperCase() },
          { label: "Validity", value: `${validityDays} days` },
        );

        const working = [
          `### Full mTLS Suite Generated (${pkiHierarchy.toUpperCase()})`,
          "",
          "#### 1. Root Certificate Authority (`ca.crt`)",
          `- **Subject**: ${mtls.ca.subjectDn}`,
          `- **SHA-256 Fingerprint**: ${mtls.ca.fingerprint}`,
          "",
        ];

        if (mtls.intermediate) {
          working.push(
            "#### 2. Intermediate Issuing CA (`intermediate.crt`)",
            `- **Subject**: ${mtls.intermediate.subjectDn}`,
            `- **Issuer**: ${mtls.intermediate.issuerDn}`,
            `- **SHA-256 Fingerprint**: ${mtls.intermediate.fingerprint}`,
            "",
          );
        }

        working.push(
          `#### ${mtls.intermediate ? "3" : "2"}. Server Certificate (\`server.crt\`) & Key (\`server.key\`)`,
          `- **Subject**: ${mtls.server.subjectDn}`,
          `- **SANs**: ${mtls.server.san}`,
          `- **Issuer**: ${mtls.server.issuerDn}`,
          `- **EKU**: TLS Web Server Authentication (id-kp-serverAuth)`,
          "",
          `#### ${mtls.intermediate ? "4" : "3"}. Client Certificate (\`client.crt\`) & PKCS#12 (\`client.p12\`)`,
          `- **Subject**: ${mtls.client.subjectDn}`,
          `- **Issuer**: ${mtls.client.issuerDn}`,
          `- **EKU**: TLS Web Client Authentication (id-kp-clientAuth)`,
          `- **PKCS#12 Password**: \`${p12Password}\``,
          "",
          "#### Turnkey Verification Commands",
          "",
          "**Start Mock mTLS Server (Requires Client Cert):**",
          "```bash",
          mtls.commands.opensslServer,
          "```",
          "",
          "**Connect with cURL (PEM):**",
          "```bash",
          mtls.commands.curlPem,
          "```",
          "",
          "**Connect with cURL (PKCS#12):**",
          "```bash",
          mtls.commands.curlP12,
          "```",
          "",
          "**NGINX mTLS Configuration Block:**",
          "```nginx",
          mtls.commands.nginxConfig,
          "```",
        );

        const files: ToolExportFile[] = [
          { name: "ca.crt", content: mtls.ca.certPem },
          { name: "ca.key", content: mtls.ca.keyPem },
        ];

        if (mtls.intermediate) {
          files.push(
            { name: "intermediate.crt", content: mtls.intermediate.certPem },
            { name: "intermediate.key", content: mtls.intermediate.keyPem },
          );
        }

        const cmdScripts = generateMtlsCommandScripts({
          pkiHierarchy,
          opensslServer: mtls.commands.opensslServer,
          curlPem: mtls.commands.curlPem,
          curlP12: mtls.commands.curlP12,
        });

        files.push(
          { name: "server.crt", content: mtls.server.certPem },
          { name: "server.key", content: mtls.server.keyPem },
          { name: "server-chain.pem", content: mtls.server.chainPem },
          { name: "client.crt", content: mtls.client.certPem },
          { name: "client.key", content: mtls.client.keyPem },
          { name: "client.p12", content: mtls.client.p12Der },
          { name: "commands.sh", content: cmdScripts.sh },
          { name: "commands.ps1", content: cmdScripts.ps1 },
          { name: "commands.bat", content: cmdScripts.bat },
          { name: "nginx.conf", content: mtls.commands.nginxConfig },
          { name: "k8s-tls-secret.yaml", content: mtls.commands.k8sSecret },
          { name: "caddy.Caddyfile", content: mtls.commands.caddyConfig },
          { name: "traefik.yaml", content: mtls.commands.traefikConfig },
          { name: "haproxy.cfg", content: mtls.commands.haproxyConfig },
          { name: "envoy.yaml", content: mtls.commands.envoyConfig },
          { name: "ca.crl", content: mtls.crl.crlPem },
          { name: "authorized_keys", content: mtls.ssh.authorizedKeysLine },
          { name: "jwks.json", content: mtls.jwksJson },
          {
            name: "README.txt",
            content: [
              "Cipher Workbench - mTLS PKI Suite",
              "==================================",
              `Hierarchy: ${mtls.pkiHierarchy.toUpperCase()}`,
              `Root CA:   ${mtls.ca.subjectDn}`,
              ...(mtls.intermediate ? [`Interm CA: ${mtls.intermediate.subjectDn}`] : []),
              `Server:    ${mtls.server.subjectDn} [${mtls.server.san}]`,
              `Client:    ${mtls.client.subjectDn}`,
              `P12 Pass:  ${p12Password}`,
              "",
              "Certificates:",
              "- ca.crt / ca.key: Root CA certificate & key",
              ...(mtls.intermediate ? ["- intermediate.crt / intermediate.key: Intermediate CA certificate & key"] : []),
              "- server.crt / server.key: Server certificate & key",
              "- server-chain.pem: Server certificate + CA chain",
              "- client.crt / client.key: Client certificate & key",
              "- client.p12: Password-encrypted PKCS#12 container",
              "",
              "Keys & Revocation:",
              "- ca.crl: RFC 5280 v2 Certificate Revocation List",
              "- authorized_keys: OpenSSH client public key (RFC 4253)",
              "- jwks.json: RFC 7517 JSON Web Key Set bundle",
              "",
              "Cloud Deployments & Proxies:",
              "- k8s-tls-secret.yaml: Kubernetes TLS Secret manifest",
              "- caddy.Caddyfile: Caddy 2 reverse proxy with mTLS",
              "- traefik.yaml: Traefik dynamic TLS configuration",
              "- haproxy.cfg: HAProxy mTLS frontend bind",
              "- envoy.yaml: Envoy TransportSocket context",
              "- nginx.conf: NGINX mTLS reverse proxy block",
              "- commands.sh: OpenSSL and cURL test scripts (Bash)",
              "- commands.ps1: OpenSSL and cURL test scripts (PowerShell)",
              "- commands.bat: Windows batch launcher with OpenSSL sanity check",
            ].join("\n"),
          },
        );

        return {
          text: mtls.allInOneText,
          bytes: mtls.client.p12Der,
          fields,
          working: working.join("\n"),
          files,
        };
      }

      // Single Certificate Mode
      const isCa = readIsCa(spec.options, false);
      const serverAuth = readServerAuth(spec.options, true);
      const clientAuth = readClientAuth(spec.options, true);
      const codeSigning = readCodeSigning(spec.options, false);
      const issuanceMode = readIssuanceMode(spec.options);
      const caCertPem = readCaCert(spec.options);
      const caPrivateKeyPem = readCaPrivateKey(spec.options);

      const created = await createCertificate({
        commonName,
        san,
        organization,
        organizationalUnit,
        country,
        state,
        locality,
        keyType,
        hashType,
        validityDays,
        isCa,
        serverAuth,
        clientAuth,
        codeSigning,
        issuanceMode,
        caCertPem: caCertPem || undefined,
        caPrivateKeyPem: caPrivateKeyPem || undefined,
      });

      const fields: ToolResultField[] = [
        { label: "Subject", value: created.subjectDn, hint: "Subject Distinguished Name" },
        {
          label: "Issuer",
          value: created.issuerDn,
          hint: issuanceMode === "ca-signed" ? "Signed by CA Authority" : "Issuer Distinguished Name (Self-Signed)",
        },
        {
          label: "Validity",
          value: `${created.notBefore.toISOString().split("T")[0]} to ${created.notAfter.toISOString().split("T")[0]} (Active, ${validityDays} days)`,
          hint: "Validity period",
        },
        { label: "Serial Number", value: created.serialNumberHex, hint: "Certificate serial number (hex)" },
        { label: "Key Algorithm", value: keyType.toUpperCase() },
        { label: "SHA-256 Fingerprint", value: created.fingerprintSha256 },
      ];

      if (san) {
        fields.push({ label: "Subject Alternative Names", value: san });
      }
      fields.push({
        label: "Basic Constraints",
        value: isCa ? "CA:TRUE (Certificate Authority)" : "CA:FALSE (End-Entity)",
      });

      const working = [
        "### Generated X.509 v3 Certificate",
        `**Subject**: ${created.subjectDn}`,
        `**Issuer**: ${created.issuerDn} (${issuanceMode === "ca-signed" ? "CA-Signed" : "Self-Signed"})`,
        `**Key Type**: ${keyType.toUpperCase()} | **Hash**: ${hashType.toUpperCase()}`,
        `**Serial**: 0x${created.serialNumberHex}`,
        `**Validity**: ${created.notBefore.toISOString()} -> ${created.notAfter.toISOString()} (${validityDays} days)`,
        `**Fingerprint (SHA-256)**: ${created.fingerprintSha256}`,
        "",
        "#### Generated Private Key (PKCS#8 PEM):",
        "```pem",
        created.privateKeyPem,
        "```",
        "",
        created.chainPem
          ? [
              "#### Full Certificate Chain (End-Entity + CA):",
              "```pem",
              created.chainPem,
              "```",
              "",
            ].join("\n")
          : "",
        "#### OpenSSL Command Equivalent:",
        "```bash",
        created.opensslCommand,
        "```",
      ].filter(Boolean).join("\n");

      const cmdScripts = generateCertCommandScripts({
        certFile: "certificate.crt",
        keyFile: "private.key",
        chainFile: created.chainPem ? "chain.pem" : undefined,
        opensslCommand: created.opensslCommand,
      });

      const files: ToolExportFile[] = [
        { name: "certificate.crt", content: created.certPem },
        { name: "private.key", content: created.privateKeyPem },
        { name: "public.key", content: created.publicKeyPem },
        ...(created.chainPem ? [{ name: "chain.pem", content: created.chainPem }] : []),
        { name: "commands.sh", content: cmdScripts.sh },
        { name: "commands.ps1", content: cmdScripts.ps1 },
        { name: "commands.bat", content: cmdScripts.bat },
        {
          name: "authorized_keys",
          content: spkiToOpenSsh(created.keyBundle.spkiBytes, keyType, commonName).authorizedKeysLine,
        },
        {
          name: "jwk.json",
          content: JSON.stringify(spkiToJwk(created.keyBundle.spkiBytes, keyType), null, 2),
        },
        {
          name: "main.tf",
          content: generateTerraformConfig({ certFilename: "cert.crt", keyFilename: "cert.key", caFilename: "ca.crt" }),
        },
        {
          name: "deploy-playbook.yaml",
          content: generateAnsiblePlaybook({ certFilename: "cert.crt", keyFilename: "cert.key", caFilename: "ca.crt" }),
        },
        {
          name: "cert-info.txt",
          content: [
            `Subject: ${created.subjectDn}`,
            `Issuer:  ${created.issuerDn} (${issuanceMode === "ca-signed" ? "CA-Signed" : "Self-Signed"})`,
            `Serial:  0x${created.serialNumberHex}`,
            `SHA-256 Fingerprint: ${created.fingerprintSha256}`,
            `Validity: ${created.notBefore.toISOString()} -> ${created.notAfter.toISOString()} (${validityDays} days)`,
          ].join("\n"),
        },
      ];

      return {
        text: created.chainPem ?? created.certPem,
        bytes: created.certDer,
        fields,
        working,
        files,
      };
    } catch (err) {
      return {
        error: `Certificate generation failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  if (spec.variant === "csr-creator") {
    try {
      const commonName = readCommonName(spec.options, "example.com");
      const san = readSan(spec.options, "example.com, www.example.com");
      const organization = readOrganization(spec.options, "Cipher Workbench");
      const organizationalUnit = readOrgUnit(spec.options, "Engineering");
      const country = readCountry(spec.options, "US");
      const state = readState(spec.options, "California");
      const locality = readLocality(spec.options, "San Francisco");
      const keyType = readKeyType(spec.options, "ecdsa-p256");
      const hashType = readHashType(spec.options, "sha256");
      const serverAuth = readServerAuth(spec.options, true);
      const clientAuth = readClientAuth(spec.options, true);
      const codeSigning = readCodeSigning(spec.options, false);

      const created = await createCsr({
        commonName,
        san,
        organization,
        organizationalUnit,
        country,
        state,
        locality,
        keyType,
        hashType,
        serverAuth,
        clientAuth,
        codeSigning,
      });

      const fields: ToolResultField[] = [
        { label: "Subject", value: created.subjectDn, hint: "Subject Distinguished Name" },
        { label: "Key Algorithm", value: keyType.toUpperCase() },
        { label: "Signature Algorithm", value: created.signatureAlgorithm },
        {
          label: "Self-Signature",
          value: created.verified ? "Verified (Cryptographically Valid)" : "Failed",
          hint: "Self-signature proof-of-possession verification",
        },
      ];

      if (san) {
        fields.push({ label: "Requested SANs", value: san });
      }

      const working = [
        "### Generated PKCS#10 Certificate Signing Request (CSR)",
        `**Subject**: ${created.subjectDn}`,
        `**Key Type**: ${keyType.toUpperCase()} | **Hash**: ${hashType.toUpperCase()}`,
        `**Signature Algorithm**: ${created.signatureAlgorithm}`,
        `**Self-Signature Verification**: ${created.verified ? "Passed" : "Failed"}`,
        "",
        "#### Generated Private Key (PKCS#8 PEM):",
        "```pem",
        created.privateKeyPem,
        "```",
        "",
        "#### OpenSSL Command Equivalent:",
        "```bash",
        created.opensslCommand,
        "```",
      ].join("\n");

      const cmdScripts = generateCsrCommandScripts({
        csrFile: "request.csr",
        keyFile: "private.key",
        opensslCommand: created.opensslCommand,
      });

      const files: ToolExportFile[] = [
        { name: "request.csr", content: created.csrPem },
        { name: "private.key", content: created.privateKeyPem },
        { name: "public.key", content: created.publicKeyPem },
        { name: "commands.sh", content: cmdScripts.sh },
        { name: "commands.ps1", content: cmdScripts.ps1 },
        { name: "commands.bat", content: cmdScripts.bat },
      ];

      return {
        text: created.csrPem,
        bytes: created.csrDer,
        fields,
        working,
        files,
      };
    } catch (err) {
      return {
        error: `CSR generation failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  if (input.length === 0) {
    return {
      error: "No certificate data provided. Paste a PEM certificate or upload a certificate file.",
    };
  }

  if (spec.variant === "cert-matcher") {
    try {
      const text = new TextDecoder().decode(input);
      const privateKeyOpt = readPrivateKey(spec.options);
      const res = await verifyCertificateKeyPair(text, privateKeyOpt || undefined);

      const fields: ToolResultField[] = [
        {
          label: "Pair Match Status",
          value: res.matches
            ? "MATCHED (Mathematical & Cryptographic Verification Successful)"
            : "MISMATCH (Keys Do Not Match)",
          hint: res.summary,
        },
        {
          label: "Target Type",
          value: res.targetType === "certificate" ? "X.509 Certificate" : "PKCS#10 CSR",
        },
        {
          label: "Key Algorithm",
          value: `${res.keyType.toUpperCase()} (${res.keyDetails})`,
        },
        {
          label: "Cryptographic Probe",
          value: res.details.probeVerified
            ? "PASSED (Live sign & verify challenge verified)"
            : "FAILED",
        },
        {
          label: "Public Key Hash (Cert/CSR)",
          value: res.fingerprints.certOrCsrPublicKeySha256,
          hint: "SHA-256 hash of SubjectPublicKeyInfo (SPKI)",
        },
      ];

      if (res.fingerprints.privateKeyDerivedPublicKeySha256) {
        fields.push({
          label: "Derived Public Key Hash (Key)",
          value: res.fingerprints.privateKeyDerivedPublicKeySha256,
          hint: "SHA-256 hash of public key derived from private key",
        });
      }

      if (res.details.subjectDn) {
        fields.push({ label: "Subject DN", value: res.details.subjectDn });
      }
      if (res.details.serialNumber) {
        fields.push({ label: "Serial Number", value: `0x${res.details.serialNumber}` });
      }
      if (res.details.notAfter) {
        fields.push({ label: "Expires", value: res.details.notAfter });
      }

      const working = [
        "### Certificate & Private Key Matcher Report",
        "",
        `**Status**: ${res.matches ? "VALID KEYPAIR MATCH" : "KEYPAIR MISMATCH"}`,
        "",
        `- **Target Type**: ${res.targetType === "certificate" ? "X.509 Certificate" : "PKCS#10 CSR"}`,
        `- **Key Algorithm**: ${res.keyType.toUpperCase()} (${res.keyDetails})`,
        `- **Cryptographic Challenge**: ${res.details.probeVerified ? "Passed (Real signature challenge verified)" : "Failed"}`,
        `- **Cert/CSR SPKI SHA-256**: \`${res.fingerprints.certOrCsrPublicKeySha256}\``,
        ...(res.fingerprints.privateKeyDerivedPublicKeySha256
          ? [`- **Private Key Derived SPKI SHA-256**: \`${res.fingerprints.privateKeyDerivedPublicKeySha256}\``]
          : []),
        ...(res.details.subjectDn ? [`- **Subject**: ${res.details.subjectDn}`] : []),
        ...(res.details.serialNumber ? [`- **Serial**: \`0x${res.details.serialNumber}\``] : []),
        ...(res.details.notAfter ? [`- **Expiry**: ${res.details.notAfter}`] : []),
        "",
        ...(res.errors.length > 0 ? ["#### Diagnostics / Errors", ...res.errors.map((e) => `- ${e}`)] : []),
      ].join("\n");

      return {
        text: res.summary,
        fields,
        working,
      };
    } catch (err) {
      return {
        error: `Cert/Key matcher failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  if (spec.variant === "cert-diff") {
    try {
      const text = new TextDecoder().decode(input);
      const comparisonOpt = readComparisonCert(spec.options);
      const res = diffCertificates(text, comparisonOpt || undefined);

      const fields: ToolResultField[] = [
        {
          label: "Diff Status",
          value: res.isIdentical ? "Identical Certificates" : "Differences Detected",
          hint: res.summary,
        },
        {
          label: "Renewal Status",
          value: res.isCleanRenewal
            ? "Clean Renewal (Same Subject & SANs, Extended Validity)"
            : res.isIdentical
              ? "Exact Duplicate"
              : "Modified Parameters",
        },
        {
          label: "Public Key Rollover",
          value: res.keyRolledOver
            ? "Key Rolled Over (New Public Key Generated)"
            : "Reused Key (Same SPKI Public Key)",
        },
        {
          label: "SAN Evolution",
          value: `+${res.addedSans.length} added, -${res.removedSans.length} removed, ${res.unchangedSans.length} retained`,
        },
      ];

      return {
        text: res.summary + "\n\n" + res.markdownTable,
        fields,
        working: res.markdownTable,
      };
    } catch (err) {
      return {
        error: `Certificate diff failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  if (spec.variant === "csr-signer") {
    try {
      const caMode = readCaMode(spec.options);
      const caCertPem = readCaCert(spec.options);
      const caPrivateKeyPem = readCaPrivateKey(spec.options);
      const validityDays = readValidityDays(spec.options, 365);
      const overrideSan = readSan(spec.options, "");
      const serverAuth = readServerAuth(spec.options);
      const clientAuth = readClientAuth(spec.options);
      const codeSigning = readCodeSigning(spec.options);

      const res = await signCsr({
        csrInput: input,
        caMode,
        caCertPem,
        caPrivateKeyPem,
        validityDays,
        overrideSan,
        serverAuth,
        clientAuth,
        codeSigning,
      });

      const fields: ToolResultField[] = [
        {
          label: "Status",
          value: "CSR Successfully Signed & Issued",
          hint: `Signed by ${caMode === "custom-ca" ? "Custom CA" : "Ephemeral Micro-CA"}`,
        },
        { label: "Subject", value: res.subjectDn, hint: "Subject DN preserved from CSR" },
        { label: "Issuer", value: res.issuerDn, hint: "Signing Certificate Authority" },
        { label: "Serial Number", value: `0x${res.serialNumberHex}` },
        {
          label: "Validity",
          value: `${validityDays} days (${res.notBefore.toISOString().split("T")[0]} to ${res.notAfter.toISOString().split("T")[0]})`,
        },
        {
          label: "Subject Alternative Names",
          value: res.sans.join(", ") || "(none)",
        },
        {
          label: "Leaf Fingerprint (SHA-256)",
          value: res.fingerprints.certSha256,
        },
        {
          label: "CA Fingerprint (SHA-256)",
          value: res.fingerprints.caSha256,
        },
      ];

      const working = [
        "### Certificate Signing Request (CSR) Signed Successfully",
        "",
        `**CA Mode**: ${caMode === "custom-ca" ? "Custom Certificate Authority" : "Ephemeral In-Browser Micro-CA (ECDSA P-256)"}`,
        "",
        `- **Subject**: ${res.subjectDn}`,
        `- **Issuer**: ${res.issuerDn}`,
        `- **Serial**: \`0x${res.serialNumberHex}\``,
        `- **Validity Period**: ${validityDays} days`,
        `- **Effective**: ${res.notBefore.toISOString()}`,
        `- **Expires**: ${res.notAfter.toISOString()}`,
        `- **SANs**: ${res.sans.join(", ") || "(none)"}`,
        `- **Leaf SHA-256**: \`${res.fingerprints.certSha256}\``,
        `- **CA SHA-256**: \`${res.fingerprints.caSha256}\``,
        "",
        "#### Verification Commands",
        "```bash",
        'openssl verify -CAfile "ca.crt" "cert.crt"',
        "```",
        "",
        "```bash",
        'openssl x509 -in "cert.crt" -text -noout',
        "```",
      ].join("\n");

      const exportFiles = [
        ...res.exportFiles,
        {
          name: "main.tf",
          content: generateTerraformConfig({ certFilename: "cert.crt", keyFilename: "cert.key", caFilename: "ca.crt" }),
        },
        {
          name: "deploy-playbook.yaml",
          content: generateAnsiblePlaybook({ certFilename: "cert.crt", keyFilename: "cert.key", caFilename: "ca.crt" }),
        },
      ];

      return {
        text: res.certPem,
        fields,
        working,
        files: exportFiles,
      };
    } catch (err) {
      return {
        error: `CSR signing failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  if (spec.variant === "ocsp") {
    try {
      const ocspOp = readOcspOp(spec.options);

      if (ocspOp === "build-request") {
        const issuerPem = readIssuerCert(spec.options);
        if (!issuerPem || issuerPem.trim().length === 0) {
          return {
            error: "Building an OCSP Request requires the Issuer CA Certificate. Provide the issuer CA certificate in the options.",
          };
        }
        const req = buildOcspRequest({
          certInput: input,
          issuerCertInput: issuerPem,
          hashAlgorithm: "sha256",
        });

        const fields: ToolResultField[] = [
          { label: "Operation", value: "RFC 6960 OCSP Request Built" },
          { label: "Target Serial", value: `0x${req.certId.serialNumberHex}` },
          { label: "Hash Algorithm", value: req.certId.hashAlgorithm.toUpperCase() },
          { label: "Issuer Name Hash", value: req.certId.issuerNameHashHex },
          { label: "Issuer Key Hash", value: req.certId.issuerKeyHashHex },
          ...(req.ocspUrl ? [{ label: "AIA OCSP URL", value: req.ocspUrl }] : []),
        ];

        const working = [
          "### RFC 6960 OCSP Request Generated",
          "",
          `- **Target Serial Number**: \`0x${req.certId.serialNumberHex}\``,
          `- **Digest Algorithm**: ${req.certId.hashAlgorithm.toUpperCase()}`,
          `- **Issuer Name SHA-256**: \`${req.certId.issuerNameHashHex}\``,
          `- **Issuer Key SHA-256**: \`${req.certId.issuerKeyHashHex}\``,
          ...(req.ocspUrl ? [`- **AIA OCSP Responder URL**: ${req.ocspUrl}`] : []),
          "",
          "#### OpenSSL Query Command",
          "```bash",
          req.opensslCommand,
          "```",
        ].join("\n");

        return {
          text: req.requestB64,
          bytes: req.requestDer,
          fields,
          working,
        };
      }

      if (ocspOp === "generate-staple") {
        const issuerPem = readIssuerCert(spec.options);
        const staple = createMockOcspResponse({
          targetCertDer: detectInputBytes(input).der,
          issuerCertDer: issuerPem ? detectInputBytes(issuerPem).der : detectInputBytes(input).der,
          certStatus: "good",
          validityHours: 48,
        });

        const fields: ToolResultField[] = [
          { label: "Staple Status", value: "Generated Offline OCSP Staple Bundle" },
          { label: "Certificate Status", value: "GOOD (Valid, Not Revoked)" },
          { label: "Validity Window", value: "48 Hours" },
        ];

        return {
          text: staple.b64,
          bytes: staple.der,
          fields,
          working: "### Offline OCSP Staple Generated\n\nUse this binary DER bundle for Web Server TLS Stapling (e.g. `ssl_stapling_file` in Nginx).",
        };
      }

      // Default: inspect-response
      const res = parseOcspResponse(input);
      const fields: ToolResultField[] = [
        { label: "Response Status", value: res.responseStatus },
        { label: "Number of Responses", value: `${res.responses.length}` },
      ];

      if (res.responderId) {
        fields.push({ label: "Responder ID", value: res.responderId });
      }
      if (res.producedAt) {
        fields.push({ label: "Produced At", value: res.producedAt.toISOString() });
      }

      const workingLines = [
        "### RFC 6960 OCSP Response Report",
        "",
        `- **Response Status**: ${res.responseStatus}`,
        ...(res.responderId ? [`- **Responder ID**: ${res.responderId}`] : []),
        ...(res.producedAt ? [`- **Produced At**: ${res.producedAt.toISOString()}`] : []),
        "",
        "#### Certificate Statuses in Response:",
      ];

      for (let i = 0; i < res.responses.length; i++) {
        const r = res.responses[i]!;
        fields.push({
          label: `Cert #${i + 1} Status`,
          value: `${r.certStatus.toUpperCase()} (Serial: 0x${r.serialNumberHex})`,
        });
        workingLines.push(
          `##### Response #${i + 1}`,
          `- **Status**: ${r.certStatus.toUpperCase()}`,
          `- **Serial Number**: \`0x${r.serialNumberHex}\``,
          `- **This Update**: ${r.thisUpdate.toISOString()}`,
          ...(r.nextUpdate ? [`- **Next Update**: ${r.nextUpdate.toISOString()}`] : []),
          ...(r.revocationTime ? [`- **Revocation Time**: ${r.revocationTime.toISOString()}`] : []),
          ...(r.revocationReason ? [`- **Revocation Reason**: ${r.revocationReason}`] : []),
          "",
        );
      }

      return {
        text: res.summary,
        bytes: res.rawDer,
        fields,
        working: workingLines.join("\n"),
      };
    } catch (err) {
      return {
        error: `OCSP processing failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  if (spec.variant === "acme") {
    try {
      const domain = readAcmeDomain(spec.options) || "example.com";
      let token = readAcmeToken(spec.options);
      let accountKey = readAcmeAccountKey(spec.options);

      // If user typed token or key in input text, resolve it
      if (input.length > 0) {
        let inputText = "";
        try {
          inputText = new TextDecoder("utf-8").decode(input).trim();
        } catch {
          // ignore
        }
        if (inputText) {
          if (!token && /^[0-9a-zA-Z_-]{16,}$/.test(inputText)) {
            token = inputText;
          } else if (!accountKey && (inputText.includes("BEGIN") || inputText.startsWith("{"))) {
            accountKey = inputText;
          }
        }
      }

      if (!token) {
        token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
      }
      if (!accountKey) {
        accountKey = "kRLr_6fsVn8_93J9l7Xp89V44W5R5-kZ3v3Y1b2_ABC";
      }

      const res = calculateAcmeChallenges({
        domain,
        token,
        accountKeyOrThumbprint: accountKey,
      });

      const fields: ToolResultField[] = [
        { label: "Target Domain", value: res.domain },
        { label: "DNS-01 TXT Name", value: res.dns01.recordName },
        { label: "DNS-01 TXT Value", value: res.dns01.recordValue },
        { label: "HTTP-01 URL", value: res.http01.fullUrl },
        { label: "JWK Thumbprint", value: res.jwkThumbprint },
        { label: "Key Authorization", value: res.keyAuthorization },
        { label: "TLS-ALPN-01 SHA-256", value: res.tlsAlpn01.sha256Hex },
      ];

      const workingLines = [
        `### RFC 8555 ACME Challenge Verification for \`${res.cleanDomain}\``,
        "",
        `- **Domain**: \`${res.domain}\``,
        `- **Challenge Token**: \`${res.token}\``,
        `- **RFC 7638 JWK Thumbprint**: \`${res.jwkThumbprint}\``,
        `- **Key Authorization**: \`${res.keyAuthorization}\``,
        "",
        "#### 1. DNS-01 Challenge (Recommended for Wildcards)",
        `- **Record Type**: \`TXT\``,
        `- **Record Name**: \`${res.dns01.recordName}\``,
        `- **Record Value**: \`${res.dns01.recordValue}\``,
        "",
        "**RFC 1035 Zone Snippet:**",
        "```text",
        res.dns01.zoneSnippet,
        "```",
        "",
        "**Verification Command:**",
        "```bash",
        res.dns01.digCommand,
        "```",
        "",
        "#### 2. HTTP-01 Challenge",
        `- **URL Path**: \`${res.http01.urlPath}\``,
        `- **Full URL**: ${res.http01.fullUrl}`,
        `- **Expected File Content**: \`${res.http01.keyAuthorization}\``,
        "",
        "**Test Command (cURL):**",
        "```bash",
        res.http01.curlCommand,
        "```",
        "",
        "**Nginx Configuration:**",
        "```nginx",
        res.http01.nginxConfig,
        "```",
        "",
        "#### 3. TLS-ALPN-01 Challenge (RFC 8737)",
        `- **ALPN Protocol**: \`${res.tlsAlpn01.protocol}\``,
        `- **Extension OID**: \`${res.tlsAlpn01.extensionOid}\` (acmeIdentifier)`,
        `- **SHA-256 Digest**: \`${res.tlsAlpn01.sha256Hex}\``,
      ];

      return {
        text: res.dns01.recordValue,
        fields,
        working: workingLines.join("\n"),
        files: res.exportFiles,
      };
    } catch (err) {
      return {
        error: `ACME calculation failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  // Resolve bytes based on auto-detect
  let der: Uint8Array;
  try {
    const detected = detectInputBytes(input);
    der = detected.der;
  } catch (err) {
    return {
      error: `Could not parse input data: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  switch (spec.variant) {
    case "x509": {
      try {
        const cert = parseX509Certificate(der);
        const detailLevel = readDetailLevel(spec.options);

        const fields: ToolResultField[] = [
          { label: "Subject", value: cert.subject.dn, hint: "Subject Distinguished Name" },
          { label: "Issuer", value: cert.issuer.dn, hint: "Certificate Authority (Issuer)" },
          {
            label: "Validity",
            value: `${cert.validity.notBefore.toISOString().split("T")[0]} to ${cert.validity.notAfter.toISOString().split("T")[0]} (${cert.validity.statusLabel})`,
            hint: "Validity period and active status",
          },
          { label: "Serial Number", value: cert.serialNumber, hint: "Certificate serial number (hex)" },
          { label: "Signature Algorithm", value: cert.signatureAlgorithmName },
          { label: "Public Key", value: `${cert.publicKey.algorithmName} (${cert.publicKey.details})` },
        ];

        if (cert.extensions.sans.length > 0) {
          fields.push({
            label: "Subject Alternative Names",
            value: cert.extensions.sans.join(", "),
            hint: "Hostnames, IPs, or domains this certificate protects",
          });
        }

        if (cert.extensions.spiffeIds && cert.extensions.spiffeIds.length > 0) {
          fields.push({
            label: "SPIFFE ID",
            value: cert.extensions.spiffeIds.join(", "),
            hint: "Zero-Trust SPIFFE Identity URI for workload attestation",
          });
        }

        if (cert.extensions.basicConstraints) {
          fields.push({
            label: "Basic Constraints",
            value: `CA:${cert.extensions.basicConstraints.isCa ? "TRUE" : "FALSE"}${cert.extensions.basicConstraints.pathLenConstraint !== undefined ? `, pathlen:${cert.extensions.basicConstraints.pathLenConstraint}` : ""}`,
            hint: "Whether this is a Certificate Authority or end-entity certificate",
          });
        }

        if (cert.extensions.keyUsages.length > 0) {
          fields.push({
            label: "Key Usage",
            value: cert.extensions.keyUsages.join(", "),
            hint: "Permitted cryptographic operations for this key",
          });
        }

        if (cert.extensions.extendedKeyUsages.length > 0) {
          fields.push({
            label: "Extended Key Usage",
            value: cert.extensions.extendedKeyUsages.join("; "),
            hint: "Specific application purposes (e.g. TLS Server, Code Signing)",
          });
        }

        fields.push({
          label: "SHA-256 Fingerprint",
          value: cert.fingerprints.sha256,
          hint: "SHA-256 thumbprint of the full certificate DER",
        });
        fields.push({
          label: "SHA-1 Fingerprint",
          value: cert.fingerprints.sha1,
          hint: "SHA-1 thumbprint of the full certificate DER",
        });

        let textOutput = cert.textDump;
        if (detailLevel === "full-dump") {
          try {
            const root = parseAsn1(der);
            textOutput = root.dump();
          } catch {
            textOutput = cert.textDump;
          }
        }

        return {
          text: textOutput,
          bytes: cert.rawDer,
          fields,
          working: cert.textDump,
        };
      } catch (err) {
        return {
          error: `Not a valid X.509 certificate: ${err instanceof Error ? err.message : String(err)}. Expected PEM block (-----BEGIN CERTIFICATE-----) or DER binary.`,
        };
      }
    }

    case "csr": {
      try {
        const csr = parseCsr(der);
        const shouldVerify = readVerifyCsrSig(spec.options);
        const detailLevel = readDetailLevel(spec.options);

        let verificationStatus = "Verification skipped";
        if (shouldVerify) {
          const verifyResult = await csr.verifySelfSignature();
          verificationStatus = verifyResult.valid
            ? "Verified (Cryptographically valid self-signature)"
            : `FAILED (${verifyResult.error ?? "Signature verification failed"})`;
        }

        const fields: ToolResultField[] = [
          { label: "Subject", value: csr.subject.dn, hint: "Requested Subject Distinguished Name" },
          { label: "Public Key", value: `${csr.publicKey.algorithmName} (${csr.publicKey.details})` },
          { label: "Signature Algorithm", value: csr.signatureAlgorithmName },
          { label: "Self-Signature", value: verificationStatus, hint: "Proof-of-possession of the private key" },
        ];

        if (csr.requestedExtensions.sans.length > 0) {
          fields.push({
            label: "Requested SANs",
            value: csr.requestedExtensions.sans.join(", "),
            hint: "Requested Subject Alternative Names",
          });
        }

        if (csr.requestedExtensions.keyUsages.length > 0) {
          fields.push({
            label: "Requested Key Usage",
            value: csr.requestedExtensions.keyUsages.join(", "),
          });
        }

        if (csr.attributes.length > 0) {
          const otherAttrs = csr.attributes
            .filter((a) => a.oid !== "1.2.840.113549.1.9.14")
            .map((a) => `${a.name}: ${a.valueString}`)
            .join("; ");
          if (otherAttrs) {
            fields.push({ label: "Attributes", value: otherAttrs });
          }
        }

        let textOutput = csr.textDump;
        if (detailLevel === "full-dump") {
          try {
            const root = parseAsn1(der);
            textOutput = root.dump();
          } catch {
            textOutput = csr.textDump;
          }
        }

        return {
          text: textOutput,
          bytes: csr.rawDer,
          fields,
          working: csr.textDump,
        };
      } catch (err) {
        return {
          error: `Not a valid PKCS#10 CSR: ${err instanceof Error ? err.message : String(err)}. Expected PEM block (-----BEGIN CERTIFICATE REQUEST-----) or DER binary.`,
        };
      }
    }

    case "cert-converter": {
      try {
        const op = readConverterOp(spec.options);
        const password = readPassword(spec.options);
        const privateKeyPem = readPrivateKey(spec.options);
        const result = await convertCertificate(input, op, { password, privateKeyPem });

        const fields: ToolResultField[] = [
          { label: "Detected Format", value: result.detectedType },
          { label: "Operation", value: result.summary },
        ];

        if (result.blocks && result.blocks.length > 0) {
          fields.push({
            label: "Certificates in Chain",
            value: `${result.blocks.length} certificates found`,
          });
        }

        const files: ToolExportFile[] = [];
        if (result.blocks && result.blocks.length > 0) {
          result.blocks.forEach((b, idx) => {
            files.push({ name: `cert-${idx + 1}.crt`, content: b.pem });
          });
        } else if (result.bytes) {
          const ext = result.operation.includes("pkcs12")
            ? "p12"
            : result.operation.includes("pkcs7")
              ? "p7b"
              : "der";
          files.push({ name: `certificate.${ext}`, content: result.bytes });
        } else if (result.text) {
          files.push({ name: "certificate.pem", content: result.text });
        }

        return {
          text: result.text,
          bytes: result.bytes,
          fields,
          working: result.text ?? result.summary,
          files: files.length > 0 ? files : undefined,
        };
      } catch (err) {
        return {
          error: `Conversion failed: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    case "crl": {
      try {
        const parsed = parseX509Crl(der);
        const fields: ToolResultField[] = [
          { label: "Issuer", value: parsed.issuerDn, hint: "CA that issued this CRL" },
          { label: "Version", value: `X.509 v${parsed.version} CRL` },
          { label: "Revoked Certificates", value: `${parsed.revokedCertificates.length} certificates` },
          {
            label: "This Update",
            value: parsed.thisUpdate.toISOString().replace("T", " ").replace(/\..+/, " UTC"),
            hint: "Issue date of this CRL",
          },
        ];

        if (parsed.nextUpdate) {
          fields.push({
            label: "Next Update",
            value: parsed.nextUpdate.toISOString().replace("T", " ").replace(/\..+/, " UTC"),
            hint: "Expiry / refresh date of this CRL",
          });
        }

        if (parsed.crlNumber !== undefined) {
          fields.push({ label: "CRL Number", value: String(parsed.crlNumber) });
        }

        fields.push({
          label: "Signature Algorithm",
          value: parsed.signatureAlgorithmName,
        });

        if (parsed.authorityKeyIdentifierHex) {
          fields.push({
            label: "Authority Key Identifier",
            value: parsed.authorityKeyIdentifierHex,
          });
        }

        const workingLines = [
          "### X.509 Certificate Revocation List (CRL)",
          `- **Version**: v${parsed.version}`,
          `- **Issuer**: ${parsed.issuerDn}`,
          `- **This Update**: ${parsed.thisUpdate.toISOString()}`,
          ...(parsed.nextUpdate ? [`- **Next Update**: ${parsed.nextUpdate.toISOString()}`] : []),
          `- **Signature Algorithm**: ${parsed.signatureAlgorithmName}`,
          ...(parsed.crlNumber !== undefined ? [`- **CRL Number**: ${parsed.crlNumber}`] : []),
          "",
          `#### Revoked Certificates (${parsed.revokedCertificates.length}):`,
        ];

        if (parsed.revokedCertificates.length === 0) {
          workingLines.push("*(No certificates revoked in this list - CRL is empty)*");
        } else {
          for (const rev of parsed.revokedCertificates) {
            workingLines.push(
              `- **Serial**: \`0x${rev.serialNumberHex}\` (${rev.serialNumberDec}) | **Date**: ${rev.revocationDate.toISOString()}${rev.reasonText ? ` | **Reason**: ${rev.reasonText}` : ""}`,
            );
          }
        }

        return {
          text: parsed.pem,
          bytes: parsed.rawDer,
          fields,
          working: workingLines.join("\n"),
        };
      } catch (err) {
        return {
          error: `Could not parse X.509 CRL: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    case "cert-verifier": {
      try {
        const result = await verifyCertificateChain(input);
        const fields: ToolResultField[] = [
          {
            label: "Chain Verification",
            value: result.isValid ? "Valid (Trust Path & Signatures Verified)" : "Verification Failed",
            hint: result.summary,
          },
          { label: "Chain Depth", value: `${result.chainDepth} Certificate${result.chainDepth === 1 ? "" : "s"}` },
          { label: "Target / Leaf", value: result.leafSubject },
          { label: "Root / Trust Anchor", value: result.rootSubject },
          { label: "Root Self-Signed", value: result.isSelfSignedRoot ? "Yes (Self-Signed Anchor)" : "No" },
        ];

        const workingLines = [
          "### Certificate Chain Trust Path Verification",
          `**Result**: ${result.isValid ? "Verified Valid" : "Verification Failed"}`,
          `**Summary**: ${result.summary}`,
          "",
          "#### Visual Trust Hierarchy:",
          "```",
          result.treeDiagram,
          "```",
          "",
          "#### Certificate Details in Path:",
        ];

        for (const node of result.nodes) {
          workingLines.push(
            `##### [Tier ${node.index + 1}] ${node.isRoot ? "Root CA" : node.isCa ? "Intermediate CA" : "End-Entity Leaf"}`,
            `- **Subject**: ${node.subjectDn}`,
            `- **Issuer**: ${node.issuerDn}`,
            `- **Serial**: \`0x${node.serialNumber}\``,
            `- **Validity Status**: ${node.datesMessage}`,
            `- **Digital Signature**: ${node.signatureValid ? "VALID" : `FAILED (${node.signatureError})`}`,
            ...(node.akiSkiMatch !== undefined ? [`- **AKI / SKI Match**: ${node.akiSkiMatch ? "MATCHED" : "MISMATCH"}`] : []),
          );
          if (node.errors.length > 0) {
            workingLines.push(`- **Errors**: ${node.errors.join("; ")}`);
          }
          if (node.warnings.length > 0) {
            workingLines.push(`- **Warnings**: ${node.warnings.join("; ")}`);
          }
          workingLines.push("");
        }

        return {
          text: result.summary + "\n\n" + result.treeDiagram,
          fields,
          working: workingLines.join("\n"),
        };
      } catch (err) {
        return {
          error: `Certificate chain verification failed: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    default:
      return { error: `Unknown certificate tool variant: ${spec.variant}` };
  }
}

export function certificateInfo(_spec: CertificateSpec): ToolResultField[] {
  return [
    {
      label: "Engine",
      value: "Pure TypeScript ASN.1 / WebCrypto (100% client-side)",
      hint: "Zero server calls, zero native addons, safe for offline use.",
    },
    {
      label: "Privacy",
      value: "Keys and certificates never leave your machine",
    },
  ];
}
