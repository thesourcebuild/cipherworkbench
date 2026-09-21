import type { ToolExportFile, ToolResult, ToolResultField } from "@ocs/engine";
import { parseAsn1 } from "./asn1/asn1";
import { convertCertificate } from "./asn1/converter";
import { parseCsr } from "./asn1/csr";
import { detectInputBytes } from "./asn1/pem";
import { parseX509Certificate } from "./asn1/x509";
import { createCertificate } from "./asn1/create-cert";
import { createCsr } from "./asn1/create-csr";
import { generateMtlsSuite } from "./asn1/mtls";
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
        const clientCommonName = readClientCommonName(spec.options, "client-app-01");
        const p12Password = readMtlsP12Password(spec.options, "changeit");

        const mtls = await generateMtlsSuite({
          caCommonName: "Internal Root CA",
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
          { label: "Suite Mode", value: "Full Mutual TLS (mTLS) Hierarchy" },
          { label: "Root CA", value: mtls.ca.subjectDn, hint: `SHA-256: ${mtls.ca.fingerprint}` },
          { label: "Server Certificate", value: `${mtls.server.subjectDn} (SANs: ${mtls.server.san})` },
          { label: "Client Certificate", value: `${mtls.client.subjectDn} (Client Auth)` },
          { label: "Client PKCS#12", value: `Protected (.p12) - Password: ${p12Password}` },
          { label: "Key Algorithm", value: keyType.toUpperCase() },
          { label: "Validity", value: `${validityDays} days` },
        ];

        const working = [
          "### Full mTLS Suite Generated",
          "",
          "#### 1. Root Certificate Authority (`ca.crt`)",
          `- **Subject**: ${mtls.ca.subjectDn}`,
          `- **SHA-256 Fingerprint**: ${mtls.ca.fingerprint}`,
          "",
          "#### 2. Server Certificate (`server.crt`) & Key (`server.key`)",
          `- **Subject**: ${mtls.server.subjectDn}`,
          `- **SANs**: ${mtls.server.san}`,
          `- **Issuer**: ${mtls.server.issuerDn}`,
          `- **EKU**: TLS Web Server Authentication (id-kp-serverAuth)`,
          "",
          "#### 3. Client Certificate (`client.crt`) & PKCS#12 (`client.p12`)",
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
        ].join("\n");

        const files: ToolExportFile[] = [
          { name: "ca.crt", content: mtls.ca.certPem },
          { name: "ca.key", content: mtls.ca.keyPem },
          { name: "server.crt", content: mtls.server.certPem },
          { name: "server.key", content: mtls.server.keyPem },
          { name: "server-chain.pem", content: mtls.server.chainPem },
          { name: "client.crt", content: mtls.client.certPem },
          { name: "client.key", content: mtls.client.keyPem },
          { name: "client.p12", content: mtls.client.p12Der },
          {
            name: "commands.sh",
            content: [
              "#!/usr/bin/env bash",
              "# mTLS Verification Commands",
              "",
              "# 1. Start OpenSSL Mock Server:",
              mtls.commands.opensslServer,
              "",
              "# 2. Test Connection with cURL (PEM):",
              mtls.commands.curlPem,
              "",
              "# 3. Test Connection with cURL (PKCS#12):",
              mtls.commands.curlP12,
              "",
            ].join("\n"),
          },
          { name: "nginx.conf", content: mtls.commands.nginxConfig },
          {
            name: "README.txt",
            content: [
              "Cipher Workbench - mTLS PKI Suite",
              "==================================",
              `Root CA:   ${mtls.ca.subjectDn}`,
              `Server:    ${mtls.server.subjectDn} [${mtls.server.san}]`,
              `Client:    ${mtls.client.subjectDn}`,
              `P12 Pass:  ${p12Password}`,
              "",
              "Files in this folder:",
              "- ca.crt: Root CA certificate",
              "- ca.key: Root CA private key (secret)",
              "- server.crt: Server certificate",
              "- server.key: Server private key (secret)",
              "- server-chain.pem: Server certificate + CA chain",
              "- client.crt: Client certificate",
              "- client.key: Client private key (secret)",
              "- client.p12: Password-encrypted PKCS#12 bundle",
              "- commands.sh: Test commands",
              "- nginx.conf: NGINX mTLS block",
            ].join("\n"),
          },
        ];

        return {
          text: mtls.allInOneText,
          bytes: mtls.client.p12Der,
          fields,
          working,
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

      const files: ToolExportFile[] = [
        { name: "certificate.crt", content: created.certPem },
        { name: "private.key", content: created.privateKeyPem },
        { name: "public.key", content: created.publicKeyPem },
        ...(created.chainPem ? [{ name: "chain.pem", content: created.chainPem }] : []),
        { name: "commands.sh", content: created.opensslCommand },
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

      const files: ToolExportFile[] = [
        { name: "request.csr", content: created.csrPem },
        { name: "private.key", content: created.privateKeyPem },
        { name: "public.key", content: created.publicKeyPem },
        { name: "commands.sh", content: created.opensslCommand },
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
