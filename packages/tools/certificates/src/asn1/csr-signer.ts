import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { type ToolExportFile } from "@ocs/engine";
import { parseCsr } from "./csr";
import { createCertificate, encodeSanExtension, encodeKeyUsageBitString } from "./create-cert";
import { detectInputBytes, encodePem } from "./pem";
import { importCaSigner, type CaSigner, type HashAlgorithmType } from "../crypto/keys";
import {
  encodeDerBitString,
  encodeDerBoolean,
  encodeDerContext,
  encodeDerInteger,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  encodeDerTime,
  encodeDistinguishedName,
} from "./encoder";
import { buildVerificationScripts, type CommandScripts } from "../export/commands";

export interface SignCsrOptions {
  csrInput: string | Uint8Array;
  caMode?: "ephemeral-ca" | "custom-ca";
  caCertPem?: string;
  caPrivateKeyPem?: string;
  validityDays?: number;
  customSerialHex?: string;
  overrideSan?: string;
  copyExtensions?: boolean;
  serverAuth?: boolean;
  clientAuth?: boolean;
  codeSigning?: boolean;
  hashType?: HashAlgorithmType;
}

export interface SignCsrResult {
  certPem: string;
  certDer: Uint8Array;
  caCertPem: string;
  caPrivateKeyPem?: string;
  bundlePem: string;
  subjectDn: string;
  issuerDn: string;
  serialNumberHex: string;
  validityDays: number;
  notBefore: Date;
  notAfter: Date;
  sans: string[];
  fingerprints: {
    certSha256: string;
    caSha256: string;
  };
  commands: CommandScripts;
  exportFiles: ToolExportFile[];
}

/**
 * Signs a PKCS#10 Certificate Signing Request (CSR) in-browser using a custom CA or ephemeral Micro-CA.
 */
export async function signCsr(opts: SignCsrOptions): Promise<SignCsrResult> {
  const csrBytes =
    typeof opts.csrInput === "string"
      ? detectInputBytes(opts.csrInput).der
      : opts.csrInput;

  if (csrBytes.length === 0) {
    throw new Error("CSR input is empty. Paste a PKCS#10 Certificate Signing Request (PEM or DER).");
  }

  const parsedCsr = parseCsr(csrBytes);
  const applicantSubjectDn = parsedCsr.subject.dn;
  const applicantSpki = parsedCsr.publicKey.spkiDer;

  // 1. Resolve CA Signer and CA Certificate
  let caSigner: CaSigner;
  let caCertPem: string;
  let caPrivateKeyPem: string | undefined;

  if (
    opts.caMode === "custom-ca" &&
    opts.caCertPem &&
    opts.caCertPem.trim().length > 0 &&
    opts.caPrivateKeyPem &&
    opts.caPrivateKeyPem.trim().length > 0
  ) {
    const caCertDer = detectInputBytes(opts.caCertPem).der;
    const caKeyDer = detectInputBytes(opts.caPrivateKeyPem).der;
    caSigner = await importCaSigner(caCertDer, caKeyDer, opts.hashType);
    caCertPem = opts.caCertPem.trim();
    caPrivateKeyPem = opts.caPrivateKeyPem.trim();
  } else {
    // Ephemeral Micro-CA: generate dedicated ECDSA P-256 Root CA
    const caCertResult = await createCertificate({
      commonName: "CipherWorkbench Micro-CA Root",
      organization: "CipherWorkbench Internal PKI",
      organizationalUnit: "Security Operations",
      country: "US",
      state: "California",
      locality: "San Francisco",
      keyType: "ecdsa-p256",
      hashType: opts.hashType ?? "sha256",
      validityDays: 3650,
      isCa: true,
      customSerialHex: "01CA0001",
    });

    caCertPem = caCertResult.certPem;
    caPrivateKeyPem = caCertResult.privateKeyPem;
    caSigner = await importCaSigner(caCertResult.certDer, caCertResult.privateKeyDer, opts.hashType);
  }

  // 2. Resolve Serial Number (positive 128-bit integer)
  let serialBigInt: bigint;
  if (opts.customSerialHex && /^[0-9a-fA-F]+$/.test(opts.customSerialHex)) {
    serialBigInt = BigInt("0x" + opts.customSerialHex);
  } else {
    const randomBytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(randomBytes);
    randomBytes[0] = (randomBytes[0] ?? 0) & 0x7f; // ensure positive integer
    let hex = "";
    for (let i = 0; i < 16; i++) {
      hex += (randomBytes[i] ?? 0).toString(16).padStart(2, "0");
    }
    serialBigInt = BigInt("0x" + hex);
  }
  const serialNumberHex = serialBigInt.toString(16).toUpperCase();

  // 3. Validity Window
  const validityDays = opts.validityDays ?? 365;
  const now = new Date();
  const notBefore = new Date(now.getTime() - 5 * 60 * 1000); // 5 min clock skew allowance
  const notAfter = new Date(now.getTime() + validityDays * 24 * 60 * 60 * 1000);
  const validityDer = encodeDerSequence([encodeDerTime(notBefore), encodeDerTime(notAfter)]);

  // 4. SAN Resolution (copy from CSR, override, or fallback to CN)
  const sansSet = new Set<string>();
  if (opts.copyExtensions !== false && parsedCsr.requestedExtensions.sans.length > 0) {
    for (const s of parsedCsr.requestedExtensions.sans) sansSet.add(s);
  }
  if (opts.overrideSan && opts.overrideSan.trim().length > 0) {
    const overrideParts = opts.overrideSan.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
    for (const part of overrideParts) sansSet.add(part);
  }
  if (sansSet.size === 0 && parsedCsr.subject.commonName) {
    sansSet.add(parsedCsr.subject.commonName);
  }
  const finalSans = Array.from(sansSet);

  // 5. Extensions
  const extensions: Uint8Array[] = [];

  // 5a. Basic Constraints (CA: FALSE)
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.19"),
      encodeDerBoolean(true), // critical
      encodeDerOctetString(encodeDerSequence([encodeDerBoolean(false)])),
    ]),
  );

  // 5b. Key Usage
  const kuBitString = encodeKeyUsageBitString([0, 2, 4]); // digitalSignature, keyEncipherment, keyAgreement
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.15"),
      encodeDerBoolean(true), // critical
      encodeDerOctetString(kuBitString),
    ]),
  );

  // 5c. Extended Key Usage
  const ekuOids: Uint8Array[] = [];
  if (opts.serverAuth !== false) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.1")); // serverAuth
  if (opts.clientAuth !== false) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.2")); // clientAuth
  if (opts.codeSigning) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.3")); // codeSigning
  if (ekuOids.length > 0) {
    extensions.push(
      encodeDerSequence([
        encodeDerOid("2.5.29.37"),
        encodeDerOctetString(encodeDerSequence(ekuOids)),
      ]),
    );
  }

  // 5d. Subject Alternative Names (SANs)
  if (finalSans.length > 0) {
    const sanDer = encodeSanExtension(finalSans.join(", "));
    if (sanDer) {
      extensions.push(
        encodeDerSequence([
          encodeDerOid("2.5.29.17"),
          encodeDerOctetString(sanDer),
        ]),
      );
    }
  }

  // 5e. Authority Key Identifier (AKI)
  const akiInner = encodeDerSequence([encodeDerContext(0, caSigner.issuerSki, false)]);
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.35"),
      encodeDerOctetString(akiInner),
    ]),
  );

  // Extensions container: [3] EXPLICIT Extensions
  const extensionsContainer = encodeDerContext(3, encodeDerSequence(extensions), true);

  // 6. Build TBSCertificate
  const tbsSequence = encodeDerSequence([
    encodeDerContext(0, encodeDerInteger(2), true), // version 3
    encodeDerInteger(serialBigInt),
    caSigner.signatureAlgorithmDer,
    caSigner.issuerDnDer,
    validityDer,
    parsedCsr.subject.rawDer ??
      encodeDistinguishedName(parsedCsr.subject.attributes.map((a) => ({ oid: a.oid, value: a.value }))),
    applicantSpki,
    extensionsContainer,
  ]);

  // 7. Cryptographically Sign TBSCertificate with CA
  const signatureBytes = await caSigner.signTbs(tbsSequence);
  const signatureBitString = encodeDerBitString(signatureBytes);

  // 8. Assemble Complete Certificate
  const certDer = encodeDerSequence([tbsSequence, caSigner.signatureAlgorithmDer, signatureBitString]);
  const certPem = encodePem("CERTIFICATE", certDer);
  const bundlePem = `${certPem}\n${caCertPem}`;

  const certFingerprint = bytesToHex(sha256(certDer)).toUpperCase().match(/../g)?.join(":") ?? "";
  const caFingerprint = bytesToHex(sha256(detectInputBytes(caCertPem).der)).toUpperCase().match(/../g)?.join(":") ?? "";

  // 9. Cross-Platform Verification Scripts
  const commands = buildVerificationScripts({
    title: "CSR Signer & Micro-CA Verification",
    description: "Verify the issued certificate against the issuing CA and inspect certificate details.",
    actions: [
      {
        id: "verify",
        description: "Cryptographically verify certificate against CA certificate",
        commands: [
          'openssl verify -CAfile "ca.crt" "cert.crt"',
          'openssl x509 -in "cert.crt" -text -noout',
        ],
      },
      {
        id: "inspect-ca",
        description: "Inspect issuing CA certificate",
        commands: ['openssl x509 -in "ca.crt" -text -noout'],
      },
    ],
  });

  const exportFiles: ToolExportFile[] = [
    {
      name: "cert.crt",
      content: certPem,
    },
    {
      name: "ca.crt",
      content: caCertPem,
    },
    {
      name: "bundle.crt",
      content: bundlePem,
    },
    {
      name: "commands.sh",
      content: commands.sh,
    },
    {
      name: "commands.ps1",
      content: commands.ps1,
    },
    {
      name: "commands.bat",
      content: commands.bat,
    },
  ];

  if (caPrivateKeyPem) {
    exportFiles.push({
      name: "ca.key",
      content: caPrivateKeyPem,
    });
  }

  return {
    certPem,
    certDer,
    caCertPem,
    caPrivateKeyPem,
    bundlePem,
    subjectDn: applicantSubjectDn,
    issuerDn: caSigner.issuerDnString,
    serialNumberHex,
    validityDays,
    notBefore,
    notAfter,
    sans: finalSans,
    fingerprints: {
      certSha256: certFingerprint,
      caSha256: caFingerprint,
    },
    commands,
    exportFiles,
  };
}
