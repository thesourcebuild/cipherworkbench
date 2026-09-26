import { parseAsn1, TagClass, UniversalTag } from "./asn1";
import {
  CSR_ATTRIBUTES,
  EXTENDED_KEY_USAGES,
  KEY_USAGE_FLAGS,
  SIGNATURE_ALGORITHMS,
} from "./oids";
import { detectInputBytes, encodePem } from "./pem";
import {
  formatHexColons,
  formatIpAddress,
  parseName,
  parseSpki,
  type ParsedName,
  type PublicKeyDetails,
} from "./x509";
import { verifyRsaPkcs1Sha3, verifyEcdsaSha3 } from "../crypto/keys";

export interface ParsedCsrAttribute {
  oid: string;
  name: string;
  raw: Uint8Array;
  valueString: string;
}

export interface ParsedCsr {
  version: number;
  subject: ParsedName;
  publicKey: PublicKeyDetails;
  signatureAlgorithmOid: string;
  signatureAlgorithmName: string;
  attributes: ParsedCsrAttribute[];
  requestedExtensions: {
    sans: string[];
    keyUsages: string[];
    extendedKeyUsages: string[];
  };
  signatureBytes: Uint8Array;
  rawDer: Uint8Array;
  pem: string;
  textDump: string;
  verifySelfSignature(): Promise<{ valid: boolean; error?: string }>;
}

/**
 * Parses a PKCS#10 Certificate Signing Request (PEM text or DER binary).
 */
export function parseCsr(input: Uint8Array | string): ParsedCsr {
  const der = detectInputBytes(input).der;
  const root = parseAsn1(der);
  if (root.tagNumber !== UniversalTag.Sequence || root.children.length < 3) {
    throw new Error("Invalid PKCS#10 CSR: root element is not a sequence with at least 3 elements");
  }

  const cri = root.children[0];
  const sigAlgSeq = root.children[1];
  const sigBitString = root.children[2];

  if (!cri || !sigAlgSeq || !sigBitString || cri.children.length < 3) {
    throw new Error("Invalid CertificationRequestInfo in CSR");
  }

  let criIdx = 0;
  const versionNode = cri.children[criIdx++];
  if (!versionNode) throw new Error("Missing version in CSR");
  const version = versionNode.asIntegerNumber();

  const subjectNode = cri.children[criIdx++];
  if (!subjectNode) throw new Error("Missing subject in CSR");
  const subject = parseName(subjectNode);

  const spkiNode = cri.children[criIdx++];
  if (!spkiNode) throw new Error("Missing public key in CSR");
  const publicKey = parseSpki(spkiNode);

  if (!sigAlgSeq.children[0]) throw new Error("Missing signature algorithm in CSR");
  const sigAlgOid = sigAlgSeq.children[0].asOid();
  const sigAlgMeta = SIGNATURE_ALGORITHMS[sigAlgOid];
  const signatureAlgorithmName = sigAlgMeta?.name ?? `OID ${sigAlgOid}`;
  const signatureBytes = sigBitString.asBitString().bytes;

  const attributes: ParsedCsrAttribute[] = [];
  const sans: string[] = [];
  const keyUsages: string[] = [];
  const extendedKeyUsages: string[] = [];

  // Parse attributes (tag [0])
  if (cri.children.length > criIdx) {
    const attrContainer = cri.children[criIdx];
    if (attrContainer && attrContainer.tagClass === TagClass.ContextSpecific && attrContainer.tagNumber === 0) {
      for (const attr of attrContainer.children) {
        if (attr.children.length < 2) continue;
        const attr0 = attr.children[0];
        const valSet = attr.children[1];
        if (!attr0 || !valSet) continue;
        const attrOid = attr0.asOid();
        const attrName = CSR_ATTRIBUTES[attrOid] ?? attrOid;
        let valStr = "";

        if (attrOid === "1.2.840.113549.1.9.14") {
          // Extension Request
          try {
            const extSeq = valSet.children[0] ?? valSet;
            for (const ext of extSeq.children) {
              if (ext.children.length < 2) continue;
              const ext0 = ext.children[0];
              if (!ext0) continue;
              const extOid = ext0.asOid();
              let valIdx = 1;
              const ext1 = ext.children[1];
              if (ext1 && ext1.tagNumber === UniversalTag.Boolean) valIdx = 2;
              const valNode = ext.children[valIdx];
              const valBytes = valNode?.valueBytes;
              if (!valBytes) continue;

              if (extOid === "2.5.29.17") {
                // SAN
                const sanAsn = parseAsn1(valBytes);
                for (const nameNode of sanAsn.children) {
                  const s = nameNode.asString();
                  if (nameNode.tagNumber === 2) sans.push(`DNS:${s}`);
                  else if (nameNode.tagNumber === 1) sans.push(`email:${s}`);
                  else if (nameNode.tagNumber === 6) sans.push(`URI:${s}`);
                  else if (nameNode.tagNumber === 7) {
                    sans.push(`IP:${formatIpAddress(nameNode.valueBytes)}`);
                  } else {
                    sans.push(`Other:${s}`);
                  }
                }
              } else if (extOid === "2.5.29.15") {
                // Key Usage
                const kuAsn = parseAsn1(valBytes);
                const { bytes } = kuAsn.asBitString();
                for (let b = 0; b < KEY_USAGE_FLAGS.length; b++) {
                  const byteIdx = Math.floor(b / 8);
                  const bitOffset = 7 - (b % 8);
                  const byteVal = bytes[byteIdx];
                  if (byteVal !== undefined && (byteVal & (1 << bitOffset)) !== 0) {
                    const flag = KEY_USAGE_FLAGS[b];
                    if (flag) keyUsages.push(flag);
                  }
                }
              } else if (extOid === "2.5.29.37") {
                // EKU
                const ekuAsn = parseAsn1(valBytes);
                for (const child of ekuAsn.children) {
                  const o = child.asOid();
                  extendedKeyUsages.push(EXTENDED_KEY_USAGES[o] ?? o);
                }
              }
            }
            valStr = [
              sans.length > 0 ? `SAN: ${sans.join(", ")}` : "",
              keyUsages.length > 0 ? `Key Usage: ${keyUsages.join(", ")}` : "",
              extendedKeyUsages.length > 0 ? `EKU: ${extendedKeyUsages.join(", ")}` : "",
            ]
              .filter(Boolean)
              .join("; ");
          } catch {
            valStr = formatHexColons(valSet.raw);
          }
        } else {
          valStr = valSet.children[0]?.asString() ?? formatHexColons(valSet.raw);
        }

        attributes.push({
          oid: attrOid,
          name: attrName,
          raw: valSet.raw,
          valueString: valStr,
        });
      }
    }
  }

  const pem = encodePem("CERTIFICATE REQUEST", der);

  // Generate OpenSSL text dump
  const textLines: string[] = [];
  textLines.push("Certificate Request:");
  textLines.push("    Data:");
  textLines.push(`        Version: ${version} (0x${version.toString(16)})`);
  textLines.push(`        Subject: ${subject.dn}`);
  textLines.push("        Subject Public Key Info:");
  textLines.push(`            Public Key Algorithm: ${publicKey.algorithmName}`);
  textLines.push(`            Details: ${publicKey.details}`);
  if (attributes.length > 0) {
    textLines.push("        Attributes:");
    for (const attr of attributes) {
      textLines.push(`            ${attr.name}: ${attr.valueString}`);
    }
  }
  if (sans.length > 0 || keyUsages.length > 0 || extendedKeyUsages.length > 0) {
    textLines.push("        Requested Extensions:");
    if (sans.length > 0) textLines.push(`            Subject Alternative Name: ${sans.join(", ")}`);
    if (keyUsages.length > 0) textLines.push(`            Key Usage: ${keyUsages.join(", ")}`);
    if (extendedKeyUsages.length > 0) textLines.push(`            Extended Key Usage: ${extendedKeyUsages.join(", ")}`);
  }
  textLines.push(`    Signature Algorithm: ${signatureAlgorithmName}`);
  textLines.push(`    Signature Value (${signatureBytes.length} bytes):`);
  textLines.push(`        ${formatHexColons(signatureBytes)}`);

  const textDump = textLines.join("\n");
  const criRaw = cri.raw;

  /**
   * Cryptographically verifies the CSR's self-signature against the embedded public key.
   */
  async function verifySelfSignature(): Promise<{ valid: boolean; error?: string }> {
    if (typeof globalThis.crypto?.subtle === "undefined") {
      return { valid: false, error: "WebCrypto API is not available in this environment" };
    }

    try {
      const dataToVerify = criRaw;

      if (publicKey.algorithmOid === "1.2.840.113549.1.1.1" && sigAlgMeta?.hash?.startsWith("SHA3-")) {
        const hashId =
          sigAlgMeta.hash === "SHA3-512"
            ? "sha3-512"
            : sigAlgMeta.hash === "SHA3-384"
              ? "sha3-384"
              : "sha3-256";
        const isValid = verifyRsaPkcs1Sha3(publicKey.spkiDer, hashId, dataToVerify, signatureBytes);
        return { valid: isValid, error: isValid ? undefined : "CSR RSA digital signature mismatch" };
      }

      if (publicKey.algorithmOid === "1.2.840.10045.2.1" && sigAlgMeta?.hash?.startsWith("SHA3-")) {
        const hashId =
          sigAlgMeta.hash === "SHA3-512"
            ? "sha3-512"
            : sigAlgMeta.hash === "SHA3-384"
              ? "sha3-384"
              : "sha3-256";
        const isValid = verifyEcdsaSha3(publicKey.spkiDer, publicKey.curveName, hashId, dataToVerify, signatureBytes);
        return { valid: isValid, error: isValid ? undefined : "CSR ECDSA digital signature mismatch" };
      }

      let webCryptoAlg: RsaHashedImportParams | EcKeyImportParams | AlgorithmIdentifier;

      if (publicKey.algorithmOid === "1.2.840.113549.1.1.1") {
        // RSA
        const hash = sigAlgMeta?.hash ?? "SHA-256";
        webCryptoAlg = { name: "RSASSA-PKCS1-v1_5", hash };
      } else if (publicKey.algorithmOid === "1.2.840.10045.2.1") {
        // ECDSA
        const namedCurve =
          publicKey.curveName?.includes("P-256") ? "P-256"
          : publicKey.curveName?.includes("P-384") ? "P-384"
          : publicKey.curveName?.includes("P-521") ? "P-521"
          : "P-256";
        webCryptoAlg = { name: "ECDSA", namedCurve };
      } else if (publicKey.algorithmOid === "1.3.101.112") {
        // Ed25519
        webCryptoAlg = { name: "Ed25519" };
      } else {
        return { valid: false, error: `Unsupported public key algorithm: ${publicKey.algorithmName}` };
      }

      const cryptoKey = await globalThis.crypto.subtle.importKey(
        "spki",
        publicKey.spkiDer as unknown as BufferSource,
        webCryptoAlg,
        false,
        ["verify"],
      );

      let verifyAlg: AlgorithmIdentifier | RsaPssParams | EcdsaParams = webCryptoAlg;
      if (publicKey.algorithmOid === "1.2.840.10045.2.1") {
        const hash = sigAlgMeta?.hash ?? "SHA-256";
        verifyAlg = { name: "ECDSA", hash };
      }

      // Convert DER signature to WebCrypto format for ECDSA if needed
      let signatureForVerify: Uint8Array = signatureBytes;
      if (publicKey.algorithmOid === "1.2.840.10045.2.1") {
        try {
          const sigAsn = parseAsn1(signatureBytes);
          if (sigAsn.children.length === 2) {
            const c0 = sigAsn.children[0];
            const c1 = sigAsn.children[1];
            if (c0 && c1) {
              let rBytes = c0.valueBytes;
              let sBytes = c1.valueBytes;
              if (rBytes.length > 32 && rBytes[0] === 0) rBytes = rBytes.slice(1);
              if (sBytes.length > 32 && sBytes[0] === 0) sBytes = sBytes.slice(1);
              const keyByteLen = publicKey.curveName?.includes("P-384") ? 48 : publicKey.curveName?.includes("P-521") ? 66 : 32;
              const p1363 = new Uint8Array(keyByteLen * 2);
              p1363.set(rBytes, keyByteLen - rBytes.length);
              p1363.set(sBytes, keyByteLen * 2 - sBytes.length);
              signatureForVerify = p1363;
            }
          }
        } catch {
          // Keep as is
        }
      }

      const isValid = await globalThis.crypto.subtle.verify(
        verifyAlg,
        cryptoKey,
        signatureForVerify as unknown as BufferSource,
        dataToVerify as unknown as BufferSource,
      );

      return { valid: isValid };
    } catch (err) {
      return { valid: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  return {
    version,
    subject,
    publicKey,
    signatureAlgorithmOid: sigAlgOid,
    signatureAlgorithmName,
    attributes,
    requestedExtensions: {
      sans,
      keyUsages,
      extendedKeyUsages,
    },
    signatureBytes,
    rawDer: der,
    pem,
    textDump,
    verifySelfSignature,
  };
}
