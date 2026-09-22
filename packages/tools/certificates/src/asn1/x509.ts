import { sha256 } from "@noble/hashes/sha2.js";
import { md5, sha1 } from "@noble/hashes/legacy.js";
import { parseAsn1, TagClass, UniversalTag, type Asn1Node } from "./asn1";
import {
  DN_LONG_NAMES,
  DN_SHORT_NAMES,
  EXTENSION_NAMES,
  EXTENDED_KEY_USAGES,
  KEY_USAGE_FLAGS,
  NAMED_CURVES,
  PUBLIC_KEY_ALGORITHMS,
  SIGNATURE_ALGORITHMS,
} from "./oids";
import { detectInputBytes, encodePem } from "./pem";

export interface DnAttribute {
  oid: string;
  name: string;
  shortName: string;
  value: string;
}

export interface ParsedName {
  dn: string;
  attributes: DnAttribute[];
  commonName?: string;
  organization?: string;
  country?: string;
  rawDer?: Uint8Array;
}

export interface ParsedExtension {
  oid: string;
  name: string;
  critical: boolean;
  raw: Uint8Array;
  valueString: string;
}

export interface PublicKeyDetails {
  algorithmOid: string;
  algorithmName: string;
  details: string;
  keyType: "rsa" | "ec" | "ed25519" | "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" | "unknown";
  rsaBits?: number;
  curveName?: string;
  spkiDer: Uint8Array;
  spkiPem: string;
  rawBytes?: Uint8Array;
}

export interface ParsedX509Certificate {
  version: number;
  serialNumber: string;
  signatureAlgorithmOid: string;
  signatureAlgorithmName: string;
  issuer: ParsedName;
  validity: {
    notBefore: Date;
    notAfter: Date;
    status: "valid" | "expired" | "not-yet-valid";
    statusLabel: string;
    daysRemaining: number;
  };
  subject: ParsedName;
  publicKey: PublicKeyDetails;
  extensions: {
    basicConstraints?: { isCa: boolean; pathLenConstraint?: number };
    sans: string[];
    keyUsages: string[];
    extendedKeyUsages: string[];
    subjectKeyIdentifier?: string;
    authorityKeyIdentifier?: string;
    ocspUrls: string[];
    caIssuerUrls: string[];
    crlUrls: string[];
    spiffeIds: string[];
    all: ParsedExtension[];
  };
  fingerprints: {
    sha256: string;
    sha1: string;
    md5: string;
  };
  tbsRaw: Uint8Array;
  signatureBytes: Uint8Array;
  rawDer: Uint8Array;
  pem: string;
  textDump: string;
}

/**
 * Parses an ASN.1 Name sequence into structured attributes and RFC 2253 formatted string.
 */
export function parseName(nameNode: Asn1Node): ParsedName {
  const attributes: DnAttribute[] = [];
  const parts: string[] = [];

  for (const rdnSet of nameNode.children) {
    for (const atv of rdnSet.children) {
      if (atv.children.length < 2) continue;
      const atv0 = atv.children[0];
      const atv1 = atv.children[1];
      if (!atv0 || !atv1) continue;
      const oid = atv0.asOid();
      const value = atv1.asString();
      const shortName = DN_SHORT_NAMES[oid] ?? oid;
      const name = DN_LONG_NAMES[oid] ?? shortName;
      attributes.push({ oid, name, shortName, value });
      parts.push(`${shortName}=${value}`);
    }
  }

  const commonName = attributes.find((a) => a.shortName === "CN")?.value;
  const organization = attributes.find((a) => a.shortName === "O")?.value;
  const country = attributes.find((a) => a.shortName === "C")?.value;

  return {
    dn: parts.join(", "),
    attributes,
    commonName,
    organization,
    country,
    rawDer: nameNode.raw,
  };
}

/**
 * Parses SubjectPublicKeyInfo.
 */
export function parseSpki(spkiNode: Asn1Node): PublicKeyDetails {
  const algSeq = spkiNode.children[0];
  const pubKeyBitString = spkiNode.children[1];
  if (!algSeq || !pubKeyBitString || !algSeq.children[0]) {
    throw new Error("Invalid SubjectPublicKeyInfo structure");
  }

  const algOid = algSeq.children[0].asOid();
  const algName = PUBLIC_KEY_ALGORITHMS[algOid] ?? `OID ${algOid}`;

  const spkiDer = spkiNode.raw;
  const spkiPem = encodePem("PUBLIC KEY", spkiDer);

  let keyType: PublicKeyDetails["keyType"] = "unknown";
  let details = algName;
  let rsaBits: number | undefined;
  let curveName: string | undefined;
  const rawBytes = pubKeyBitString.asBitString().bytes;

  if (algOid === "1.2.840.113549.1.1.1") {
    // RSA
    keyType = "rsa";
    try {
      const { bytes: rsaDer } = pubKeyBitString.asBitString();
      const rsaAsn = parseAsn1(rsaDer);
      if (rsaAsn.children.length >= 2) {
        const modulus = rsaAsn.children[0];
        const exponent = rsaAsn.children[1];
        if (modulus && exponent) {
          let modBytes = modulus.valueBytes;
          if (modBytes.length > 1 && modBytes[0] === 0) {
            modBytes = modBytes.slice(1);
          }
          rsaBits = modBytes.length * 8;
          const expNum = exponent.asIntegerNumber();
          details = `RSA ${rsaBits}-bit (e: ${expNum})`;
        }
      }
    } catch {
      details = "RSA Public Key";
    }
  } else if (algOid === "1.2.840.10045.2.1") {
    // EC
    keyType = "ec";
    if (algSeq.children.length >= 2 && algSeq.children[1]) {
      const curveOid = algSeq.children[1].asOid();
      curveName = NAMED_CURVES[curveOid] ?? curveOid;
      details = `EC Public Key, curve ${curveName}`;
    } else {
      details = "EC Public Key";
    }
  } else if (algOid === "1.3.101.112") {
    keyType = "ed25519";
    details = "Ed25519 256-bit Public Key";
  } else if (algOid === "2.16.840.1.101.3.4.3.17") {
    keyType = "ml-dsa-44";
    details = `Post-Quantum ML-DSA-44 (${rawBytes.length}-byte public key, NIST Security Level 2)`;
  } else if (algOid === "2.16.840.1.101.3.4.3.18") {
    keyType = "ml-dsa-65";
    details = `Post-Quantum ML-DSA-65 (${rawBytes.length}-byte public key, NIST Security Level 3)`;
  } else if (algOid === "2.16.840.1.101.3.4.3.19") {
    keyType = "ml-dsa-87";
    details = `Post-Quantum ML-DSA-87 (${rawBytes.length}-byte public key, NIST Security Level 5)`;
  }

  return {
    algorithmOid: algOid,
    algorithmName: algName,
    details,
    keyType,
    rsaBits,
    curveName,
    spkiDer,
    spkiPem,
    rawBytes,
  };
}

/**
 * Format bytes into colon-separated hex string.
 */
export function formatHexColons(bytes: Uint8Array): string {
  let res = "";
  for (let i = 0; i < bytes.length; i++) {
    if (i > 0) res += ":";
    const b = bytes[i];
    res += (b !== undefined ? b : 0).toString(16).padStart(2, "0").toUpperCase();
  }
  return res;
}

/**
 * Parses an X.509 Certificate (PEM text or DER binary).
 */
export function parseX509Certificate(input: Uint8Array): ParsedX509Certificate {
  let der: Uint8Array;
  try {
    der = detectInputBytes(input).der;
  } catch (err) {
    throw new Error(`Invalid X.509 certificate data (expected PEM or DER): ${err instanceof Error ? err.message : String(err)}`);
  }
  let root;
  try {
    root = parseAsn1(der);
  } catch (err) {
    throw new Error(`Invalid X.509 certificate ASN.1 DER: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (root.tagNumber !== UniversalTag.Sequence || root.children.length < 3) {
    throw new Error("Invalid X.509 certificate: root element is not a sequence with at least 3 elements");
  }

  const tbs = root.children[0];
  const sigAlgSeq = root.children[1];
  const sigBitString = root.children[2];
  if (!tbs || !sigAlgSeq || !sigBitString) {
    throw new Error("Invalid X.509 certificate structure");
  }

  let tbsIdx = 0;
  let version = 1; // Default v1
  const tbs0 = tbs.children[0];
  if (tbs0 && tbs0.tagClass === TagClass.ContextSpecific && tbs0.tagNumber === 0) {
    const versionNode = tbs0.children[0];
    if (versionNode) {
      version = versionNode.asIntegerNumber() + 1; // 0-based: 0=v1, 1=v2, 2=v3
    }
    tbsIdx++;
  }

  const serialNode = tbs.children[tbsIdx++];
  if (!serialNode) throw new Error("Missing serial number in certificate");
  const serialNumber = serialNode.asIntegerHex();

  // Signature algorithm in TBS
  const tbsSigAlg = tbs.children[tbsIdx++];
  if (!tbsSigAlg || !tbsSigAlg.children[0]) {
    throw new Error("Missing signature algorithm in certificate");
  }
  const sigAlgOid = tbsSigAlg.children[0].asOid();
  const sigAlgMeta = SIGNATURE_ALGORITHMS[sigAlgOid];
  const signatureAlgorithmName = sigAlgMeta?.name ?? `OID ${sigAlgOid}`;

  const issuerNode = tbs.children[tbsIdx++];
  if (!issuerNode) throw new Error("Missing issuer in certificate");
  const issuer = parseName(issuerNode);

  const validityNode = tbs.children[tbsIdx++];
  if (!validityNode || validityNode.children.length < 2 || !validityNode.children[0] || !validityNode.children[1]) {
    throw new Error("Missing validity dates in certificate");
  }
  const notBefore = validityNode.children[0].asDate();
  const notAfter = validityNode.children[1].asDate();

  const now = new Date();
  let status: "valid" | "expired" | "not-yet-valid" = "valid";
  let statusLabel = "";
  const msRemaining = notAfter.getTime() - now.getTime();
  const daysRemaining = Math.round(msRemaining / (1000 * 60 * 60 * 24));

  if (now.getTime() < notBefore.getTime()) {
    status = "not-yet-valid";
    statusLabel = `Not yet active (starts in ${Math.abs(Math.round((notBefore.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)))} days)`;
  } else if (now.getTime() > notAfter.getTime()) {
    status = "expired";
    const daysAgo = Math.abs(daysRemaining);
    statusLabel = `EXPIRED ${daysAgo} day${daysAgo === 1 ? "" : "s"} ago`;
  } else {
    status = "valid";
    statusLabel = `Valid (expires in ${daysRemaining} day${daysRemaining === 1 ? "" : "s"})`;
  }

  const subjectNode = tbs.children[tbsIdx++];
  if (!subjectNode) throw new Error("Missing subject in certificate");
  const subject = parseName(subjectNode);

  const spkiChildNode = tbs.children[tbsIdx++];
  if (!spkiChildNode) throw new Error("Missing public key in certificate");
  const publicKey = parseSpki(spkiChildNode);

  // Extensions (tag [3])
  const sans: string[] = [];
  const keyUsages: string[] = [];
  const extendedKeyUsages: string[] = [];
  let basicConstraints: { isCa: boolean; pathLenConstraint?: number } | undefined;
  let subjectKeyIdentifier: string | undefined;
  let authorityKeyIdentifier: string | undefined;
  const ocspUrls: string[] = [];
  const caIssuerUrls: string[] = [];
  const crlUrls: string[] = [];
  const spiffeIds: string[] = [];
  const allExtensions: ParsedExtension[] = [];

  for (let i = tbsIdx; i < tbs.children.length; i++) {
    const extContainer = tbs.children[i];
    if (extContainer && extContainer.tagClass === TagClass.ContextSpecific && extContainer.tagNumber === 3) {
      const extSeq = extContainer.children[0] ?? extContainer;
      for (const ext of extSeq.children) {
        if (ext.children.length < 2) continue;
        const ext0 = ext.children[0];
        if (!ext0) continue;
        const extOid = ext0.asOid();
        let isCritical = false;
        let valueIdx = 1;
        const ext1 = ext.children[1];
        if (ext1 && ext1.tagNumber === UniversalTag.Boolean) {
          isCritical = ext1.asBoolean();
          valueIdx = 2;
        }
        const valNode = ext.children[valueIdx];
        if (!valNode) continue;
        const valBytes = valNode.valueBytes;
        const extName = EXTENSION_NAMES[extOid] ?? extOid;

        let parsedValStr = "";

        try {
          if (extOid === "2.5.29.17") {
            // Subject Alternative Name
            const sanAsn = parseAsn1(valBytes);
            for (const nameNode of sanAsn.children) {
              const strVal = nameNode.asString();
              let sanItem = "";
              switch (nameNode.tagNumber) {
                case 1:
                  sanItem = `email:${strVal}`;
                  break;
                case 2:
                  sanItem = `DNS:${strVal}`;
                  break;
                case 6:
                  sanItem = `URI:${strVal}`;
                  if (strVal.toLowerCase().startsWith("spiffe://")) {
                    spiffeIds.push(strVal);
                  }
                  break;
                case 7: {
                  const b = nameNode.valueBytes;
                  if (b.length === 4) {
                    sanItem = `IP:${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
                  } else {
                    sanItem = `IP:${formatHexColons(b)}`;
                  }
                  break;
                }
                default:
                  sanItem = `Other:${strVal}`;
                  break;
              }
              if (sanItem) sans.push(sanItem);
            }
            parsedValStr = sans.join(", ");
          } else if (extOid === "2.5.29.19") {
            // Basic Constraints
            const bcAsn = parseAsn1(valBytes);
            let isCa = false;
            let pathLen: number | undefined;
            for (const child of bcAsn.children) {
              if (child.tagNumber === UniversalTag.Boolean) {
                isCa = child.asBoolean();
              } else if (child.tagNumber === UniversalTag.Integer) {
                pathLen = child.asIntegerNumber();
              }
            }
            basicConstraints = { isCa, pathLenConstraint: pathLen };
            parsedValStr = `CA:${isCa ? "TRUE" : "FALSE"}${pathLen !== undefined ? `, pathlen:${pathLen}` : ""}`;
          } else if (extOid === "2.5.29.15") {
            // Key Usage
            const kuAsn = parseAsn1(valBytes);
            const { bytes } = kuAsn.asBitString();
            for (let bitIdx = 0; bitIdx < KEY_USAGE_FLAGS.length; bitIdx++) {
              const byteIdx = Math.floor(bitIdx / 8);
              const bitOffset = 7 - (bitIdx % 8);
              const byteVal = bytes[byteIdx];
              if (byteVal !== undefined && (byteVal & (1 << bitOffset)) !== 0) {
                const flag = KEY_USAGE_FLAGS[bitIdx];
                if (flag) keyUsages.push(flag);
              }
            }
            parsedValStr = keyUsages.join(", ");
          } else if (extOid === "2.5.29.37") {
            // Extended Key Usage
            const ekuAsn = parseAsn1(valBytes);
            for (const child of ekuAsn.children) {
              const ekuOid = child.asOid();
              const ekuName = EXTENDED_KEY_USAGES[ekuOid] ?? ekuOid;
              extendedKeyUsages.push(ekuName);
            }
            parsedValStr = extendedKeyUsages.join(", ");
          } else if (extOid === "2.5.29.14") {
            // SKI
            const skiAsn = parseAsn1(valBytes);
            subjectKeyIdentifier = formatHexColons(skiAsn.valueBytes);
            parsedValStr = subjectKeyIdentifier;
          } else if (extOid === "2.5.29.35") {
            // AKI
            const akiAsn = parseAsn1(valBytes);
            const keyIdNode = akiAsn.findChild(0, TagClass.ContextSpecific);
            if (keyIdNode) {
              authorityKeyIdentifier = formatHexColons(keyIdNode.valueBytes);
              parsedValStr = `keyid:${authorityKeyIdentifier}`;
            }
          } else if (extOid === "1.3.6.1.5.5.7.1.1") {
            // AIA
            const aiaAsn = parseAsn1(valBytes);
            for (const desc of aiaAsn.children) {
              if (desc.children.length >= 2) {
                const desc0 = desc.children[0];
                const locNode = desc.children[1];
                if (desc0 && locNode) {
                  const methodOid = desc0.asOid();
                  const uri = locNode.asString();
                  if (methodOid === "1.3.6.1.5.5.7.48.1") {
                    ocspUrls.push(uri);
                  } else if (methodOid === "1.3.6.1.5.5.7.48.2") {
                    caIssuerUrls.push(uri);
                  }
                }
              }
            }
            parsedValStr = [...ocspUrls.map((u) => `OCSP: ${u}`), ...caIssuerUrls.map((u) => `CA: ${u}`)].join(", ");
          } else if (extOid === "2.5.29.31") {
            // CRL Distribution Points
            const crlAsn = parseAsn1(valBytes);
            for (const dp of crlAsn.children) {
              const str = dp.dump();
              const matches = [...str.matchAll(/http[^\s"]+/g)];
              for (const m of matches) crlUrls.push(m[0]);
            }
            parsedValStr = crlUrls.join(", ");
          } else {
            parsedValStr = formatHexColons(valBytes);
          }
        } catch {
          parsedValStr = formatHexColons(valBytes);
        }

        allExtensions.push({
          oid: extOid,
          name: extName,
          critical: isCritical,
          raw: valBytes,
          valueString: parsedValStr,
        });
      }
    }
  }

  // Compute fingerprints
  const sha256Bytes = sha256(der);
  const sha1Bytes = sha1(der);
  const md5Bytes = md5(der);

  const fingerprints = {
    sha256: formatHexColons(sha256Bytes),
    sha1: formatHexColons(sha1Bytes),
    md5: formatHexColons(md5Bytes),
  };

  const pem = encodePem("CERTIFICATE", der);

  // Generate OpenSSL text dump
  const textLines: string[] = [];
  textLines.push("Certificate:");
  textLines.push("    Data:");
  textLines.push(`        Version: ${version} (0x${(version - 1).toString(16)})`);
  textLines.push(`        Serial Number: ${serialNumber}`);
  textLines.push(`        Signature Algorithm: ${signatureAlgorithmName}`);
  textLines.push(`        Issuer: ${issuer.dn}`);
  textLines.push("        Validity");
  textLines.push(`            Not Before: ${notBefore.toUTCString()}`);
  textLines.push(`            Not After : ${notAfter.toUTCString()} [${statusLabel}]`);
  textLines.push(`        Subject: ${subject.dn}`);
  textLines.push("        Subject Public Key Info:");
  textLines.push(`            Public Key Algorithm: ${publicKey.algorithmName}`);
  textLines.push(`            Details: ${publicKey.details}`);
  if (allExtensions.length > 0) {
    textLines.push("        X509v3 extensions:");
    for (const ext of allExtensions) {
      textLines.push(`            ${ext.name}${ext.critical ? " (critical)" : ""}:`);
      textLines.push(`                ${ext.valueString}`);
    }
  }
  textLines.push(`    Signature Algorithm: ${signatureAlgorithmName}`);
  const sigBytes = sigBitString.asBitString().bytes;
  textLines.push(`    Signature Value (${sigBytes.length} bytes):`);
  const hexSig = formatHexColons(sigBytes);
  textLines.push(`        ${hexSig}`);
  textLines.push("    Fingerprints:");
  textLines.push(`        SHA-256: ${fingerprints.sha256}`);
  textLines.push(`        SHA-1:   ${fingerprints.sha1}`);
  textLines.push(`        MD5:     ${fingerprints.md5}`);

  return {
    version,
    serialNumber,
    signatureAlgorithmOid: sigAlgOid,
    signatureAlgorithmName,
    issuer,
    validity: {
      notBefore,
      notAfter,
      status,
      statusLabel,
      daysRemaining,
    },
    subject,
    publicKey,
    extensions: {
      basicConstraints,
      sans,
      keyUsages,
      extendedKeyUsages,
      subjectKeyIdentifier,
      authorityKeyIdentifier,
      ocspUrls,
      caIssuerUrls,
      crlUrls,
      spiffeIds,
      all: allExtensions,
    },
    fingerprints,
    tbsRaw: tbs.raw,
    signatureBytes: sigBytes,
    rawDer: der,
    pem,
    textDump: textLines.join("\n"),
  };
}
