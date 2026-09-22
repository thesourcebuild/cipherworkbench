import { parseAsn1 } from "./asn1";
import { parseCsr } from "./csr";
import { detectInputBytes, encodePem, parseAllPem } from "./pem";
import { decodePkcs7CertBundle, encodePkcs7CertBundle } from "./pkcs7";
import { decodePkcs12Archive, encodePkcs12Archive, inspectPkcs12 } from "./pkcs12";
import { parseX509Certificate } from "./x509";
import { exportToPpkV3 } from "../crypto/putty";

export type ConverterOperation =
  | "auto"
  | "pem-to-der"
  | "der-to-pem"
  | "pem-to-cer"
  | "cer-to-pem"
  | "pem-to-pkcs7"
  | "pkcs7-to-pem"
  | "pem-to-pkcs12"
  | "pkcs12-to-pem"
  | "pem-to-ppk"
  | "pkcs12-inspect"
  | "extract-public-key"
  | "split-chain";

export interface ConverterExtraOptions {
  password?: string;
  privateKeyPem?: string;
}

export interface ConversionResult {
  operation: ConverterOperation;
  detectedType: string;
  text?: string;
  bytes?: Uint8Array;
  summary: string;
  blocks?: Array<{ label: string; subject?: string; pem: string }>;
}

/**
 * Converts or extracts certificate/key formats.
 */
export async function convertCertificate(
  input: Uint8Array,
  op: ConverterOperation = "auto",
  extra?: ConverterExtraOptions,
): Promise<ConversionResult> {
  const detected = detectInputBytes(input);
  const der = detected.der;

  // Inspect the ASN.1 structure to identify what kind of object this is
  let detectedType = "Unknown ASN.1 Object";
  let isCert = false;
  let isCsr = false;
  let isPkcs7 = false;
  let isPkcs12 = false;

  try {
    const root = parseAsn1(der);
    if (root.children.length >= 2) {
      const c0 = root.children[0];
      if (c0?.asOid() === "1.2.840.113549.1.7.2") {
        detectedType = "PKCS#7 / CMS Bundle";
        isPkcs7 = true;
      } else if (c0?.tagNumber === 2 && root.children[1]?.children[0]?.asOid() === "1.2.840.113549.1.7.1") {
        detectedType = "PKCS#12 (.pfx / .p12) Archive";
        isPkcs12 = true;
      }
    }
    if (!isPkcs7 && !isPkcs12) {
      if (root.children.length === 3) {
        const first = root.children[0];
        if (first && first.children.length >= 6) {
          detectedType = "X.509 Certificate";
          isCert = true;
        } else if (first && first.children.length >= 3 && first.children[0]?.tagNumber === 2) {
          detectedType = "PKCS#10 Certificate Request";
          isCsr = true;
        }
      } else if (root.children.length === 2 && root.children[0]?.tagNumber === 16) {
        detectedType = "SubjectPublicKeyInfo (Public Key)";
      }
    }
  } catch {
    // Non-ASN.1
  }

  // --- PKCS#7 Operations ---
  if (op === "pem-to-pkcs7") {
    const certDers: Uint8Array[] = [];
    if (detected.kind === "pem" && detected.blocks && detected.blocks.length > 0) {
      for (const block of detected.blocks) {
        if (block.label.includes("CERTIFICATE") && !block.label.includes("REQUEST")) {
          certDers.push(block.bytes);
        }
      }
    } else {
      certDers.push(der);
    }
    if (certDers.length === 0) {
      throw new Error("No certificates found to bundle into PKCS#7.");
    }
    const bundle = encodePkcs7CertBundle(certDers);
    return {
      operation: "pem-to-pkcs7",
      detectedType: `PKCS#7 Bundle (${bundle.count} certificate${bundle.count > 1 ? "s" : ""})`,
      text: bundle.pem,
      bytes: bundle.der,
      summary: `Packaged ${bundle.count} certificate${bundle.count > 1 ? "s" : ""} into PKCS#7 (.p7b) container.`,
    };
  }

  if (op === "pkcs7-to-pem") {
    const certs = decodePkcs7CertBundle(input);
    const combinedPem = certs.map((c, i) => `# Certificate ${i + 1}\n${c.pem}`).join("\n\n");
    return {
      operation: "pkcs7-to-pem",
      detectedType: `PKCS#7 Bundle (${certs.length} certificates)`,
      text: combinedPem,
      summary: `Extracted ${certs.length} certificate${certs.length > 1 ? "s" : ""} from PKCS#7 container into PEM format.`,
    };
  }

  // --- PKCS#12 Operations ---
  if (op === "pem-to-pkcs12") {
    const certDers: Uint8Array[] = [];
    let privateKeyDer: Uint8Array | undefined;

    // Check main input for certificates and private keys
    if (detected.kind === "pem" && detected.blocks) {
      for (const block of detected.blocks) {
        if (block.label.includes("PRIVATE KEY")) {
          privateKeyDer = block.bytes;
        } else if (block.label.includes("CERTIFICATE") && !block.label.includes("REQUEST")) {
          certDers.push(block.bytes);
        }
      }
    } else if (isCert) {
      certDers.push(der);
    }

    // Check extra.privateKeyPem if not found in input
    if (!privateKeyDer && extra?.privateKeyPem) {
      const keyBlocks = parseAllPem(extra.privateKeyPem);
      for (const b of keyBlocks) {
        if (b.label.includes("PRIVATE KEY")) {
          privateKeyDer = b.bytes;
          break;
        }
      }
    }

    if (certDers.length === 0 && !privateKeyDer) {
      throw new Error("Cannot create PKCS#12 archive: at least one certificate or private key is required.");
    }

    const pfx = await encodePkcs12Archive({
      certDers,
      privateKeyDer,
      password: extra?.password,
    });

    return {
      operation: "pem-to-pkcs12",
      detectedType: `PKCS#12 Archive (.pfx)`,
      bytes: pfx.der,
      text: pfx.base64,
      summary: `Created PKCS#12 (.pfx) archive with ${pfx.certCount} certificate(s)${pfx.hasPrivateKey ? " and private key" : ""}${pfx.encrypted ? " (password encrypted)" : " (unencrypted)"}.`,
    };
  }

  if (op === "pkcs12-to-pem") {
    const decoded = await decodePkcs12Archive(input, extra?.password ?? "");
    const parts: string[] = [];
    for (let i = 0; i < decoded.certs.length; i++) {
      parts.push(`# Certificate ${i + 1}\n${decoded.certs[i]!.pem}`);
    }
    if (decoded.privateKey) {
      parts.push(`# Private Key\n${decoded.privateKey.pem}`);
    }
    const combinedText = parts.join("\n\n");
    return {
      operation: "pkcs12-to-pem",
      detectedType: "PKCS#12 Archive",
      text: combinedText,
      summary: `Extracted ${decoded.certs.length} certificate(s)${decoded.privateKey ? " and private key" : ""} from PKCS#12 archive.`,
    };
  }

  if (op === "pem-to-ppk") {
    const ppk = exportToPpkV3({ keyInput: input, comment: "cipherworkbench-key" });
    return {
      operation: "pem-to-ppk",
      detectedType: `PuTTY Private Key (${ppk.keyType})`,
      text: ppk.ppkText,
      summary: `Exported private key to PuTTY Private Key v3 format (${ppk.keyType}, comment: ${ppk.comment}).`,
    };
  }

  if (op === "pkcs12-inspect") {
    const inspection = inspectPkcs12(input);
    const lines = [
      `### PKCS#12 Container Inspection Report`,
      `- **Version**: PKCS#12 v${inspection.version}`,
      `- **MAC Present**: ${inspection.hasMac ? "YES" : "NO"}`,
      ...(inspection.macAlgorithm ? [`- **MAC Algorithm**: ${inspection.macAlgorithm}`] : []),
      ...(inspection.macIterations ? [`- **MAC Iterations**: ${inspection.macIterations}`] : []),
      ...(inspection.macSaltHex ? [`- **MAC Salt (hex)**: \`${inspection.macSaltHex}\``] : []),
      `- **Certificates Found**: ${inspection.certCount}`,
      `- **Private Key Present**: ${inspection.hasPrivateKey ? "YES" : "NO"}`,
      `- **Encrypted Bags**: ${inspection.isEncrypted ? "YES" : "NO"}`,
      "",
      `#### SafeBags Structure (${inspection.bags.length} bags):`,
    ];
    for (let i = 0; i < inspection.bags.length; i++) {
      const b = inspection.bags[i]!;
      lines.push(
        `- **Bag #${i + 1}**: \`${b.bagType}\` (OID: ${b.bagTypeOid})` +
          (b.friendlyName ? ` - FriendlyName: "${b.friendlyName}"` : "") +
          (b.localKeyIdHex ? ` - LocalKeyID: 0x${b.localKeyIdHex}` : ""),
      );
    }
    return {
      operation: "pkcs12-inspect",
      detectedType: "PKCS#12 Archive",
      text: lines.join("\n"),
      summary: inspection.summary,
    };
  }

  // --- CER Aliases ---
  if (op === "pem-to-cer") {
    return {
      operation: "pem-to-cer",
      detectedType,
      bytes: der,
      summary: `Converted PEM certificate to binary DER (.cer) format (${der.length} bytes).`,
    };
  }

  if (op === "cer-to-pem") {
    const pemStr = encodePem("CERTIFICATE", der);
    return {
      operation: "cer-to-pem",
      detectedType,
      text: pemStr,
      summary: `Converted binary (.cer) certificate to PEM text (${der.length} bytes).`,
    };
  }

  // Handle multi-block certificate chains if present
  if (detected.kind === "pem" && detected.blocks && detected.blocks.length > 1) {
    if (op === "split-chain" || op === "auto") {
      const chainBlocks: Array<{ label: string; subject?: string; pem: string }> = [];
      let idx = 1;
      for (const block of detected.blocks) {
        let subj = "";
        try {
          const c = parseX509Certificate(block.bytes);
          subj = c.subject.dn;
        } catch {
          // Ignore
        }
        const blockPem = encodePem(block.label, block.bytes);
        chainBlocks.push({
          label: `${block.label} #${idx++}`,
          subject: subj || undefined,
          pem: blockPem,
        });
      }

      const formatted = chainBlocks
        .map((b) => `# ${b.label}${b.subject ? `\n# Subject: ${b.subject}` : ""}\n${b.pem}`)
        .join("\n\n");

      return {
        operation: "split-chain",
        detectedType: `Certificate Bundle / Chain (${chainBlocks.length} certificates)`,
        text: formatted,
        summary: `Split certificate chain containing ${chainBlocks.length} certificates.`,
        blocks: chainBlocks,
      };
    }
  }

  // Specific operations
  if (op === "extract-public-key") {
    if (isCert) {
      const cert = parseX509Certificate(der);
      return {
        operation: "extract-public-key",
        detectedType,
        text: cert.publicKey.spkiPem,
        bytes: cert.publicKey.spkiDer,
        summary: `Extracted ${cert.publicKey.algorithmName} public key (${cert.publicKey.details}) from certificate.`,
      };
    } else if (isCsr) {
      const csr = parseCsr(der);
      return {
        operation: "extract-public-key",
        detectedType,
        text: csr.publicKey.spkiPem,
        bytes: csr.publicKey.spkiDer,
        summary: `Extracted ${csr.publicKey.algorithmName} public key (${csr.publicKey.details}) from CSR.`,
      };
    }
    throw new Error("Cannot extract public key: input is not an X.509 certificate or CSR");
  }

  if (op === "pem-to-der") {
    return {
      operation: "pem-to-der",
      detectedType,
      bytes: der,
      summary: `Converted PEM ${detected.label ?? detectedType} to raw DER binary (${der.length} bytes).`,
    };
  }

  if (op === "der-to-pem") {
    const label = isCert
      ? "CERTIFICATE"
      : isCsr
        ? "CERTIFICATE REQUEST"
        : isPkcs7
          ? "PKCS7"
          : detected.label ?? "CERTIFICATE";
    const pemStr = encodePem(label, der);
    return {
      operation: "der-to-pem",
      detectedType,
      text: pemStr,
      summary: `Encoded binary DER (${der.length} bytes) to PEM formatted with ${label}.`,
    };
  }

  // Auto mode
  if (isPkcs7) {
    const certs = decodePkcs7CertBundle(input);
    const combinedPem = certs.map((c, i) => `# Certificate ${i + 1}\n${c.pem}`).join("\n\n");
    return {
      operation: "pkcs7-to-pem",
      detectedType: `PKCS#7 Bundle (${certs.length} certificates)`,
      text: combinedPem,
      summary: `Extracted ${certs.length} certificate(s) from PKCS#7 container into PEM format.`,
    };
  }

  if (isPkcs12) {
    const decoded = await decodePkcs12Archive(input, extra?.password ?? "");
    const parts: string[] = [];
    for (let i = 0; i < decoded.certs.length; i++) {
      parts.push(`# Certificate ${i + 1}\n${decoded.certs[i]!.pem}`);
    }
    if (decoded.privateKey) {
      parts.push(`# Private Key\n${decoded.privateKey.pem}`);
    }
    return {
      operation: "pkcs12-to-pem",
      detectedType: "PKCS#12 Archive",
      text: parts.join("\n\n"),
      summary: `Extracted ${decoded.certs.length} certificate(s)${decoded.privateKey ? " and private key" : ""} from PKCS#12 archive.`,
    };
  }

  if (detected.kind === "pem") {
    return {
      operation: "pem-to-der",
      detectedType,
      bytes: der,
      summary: `Decoded PEM ${detected.label ?? detectedType} into binary DER (${der.length} bytes).`,
    };
  } else {
    const label = isCert
      ? "CERTIFICATE"
      : isCsr
        ? "CERTIFICATE REQUEST"
        : "CERTIFICATE";
    const pemStr = encodePem(label, der);
    return {
      operation: "der-to-pem",
      detectedType,
      text: pemStr,
      summary: `Converted binary DER (${der.length} bytes) into formatted PEM with ${label}.`,
    };
  }
}
