import { parseAsn1, TagClass, UniversalTag, type Asn1Node } from "./asn1";
import {
  concatBytes,
  encodeDerContext,
  encodeDerInteger,
  encodeDerOid,
  encodeDerSequence,
  encodeDerSet,
} from "./encoder";
import { detectInputBytes, encodePem } from "./pem";

export interface Pkcs7CertBundleResult {
  pem: string;
  der: Uint8Array;
  count: number;
}

export interface ExtractedCert {
  pem: string;
  der: Uint8Array;
}

/**
 * Packages one or more X.509 certificates into an RFC 2315 / RFC 5652 PKCS#7 / CMS SignedData container.
 */
export function encodePkcs7CertBundle(certDers: Uint8Array[]): Pkcs7CertBundleResult {
  if (certDers.length === 0) {
    throw new Error("Cannot create PKCS#7 bundle: at least one certificate is required.");
  }

  // 1. Version 1
  const version = encodeDerInteger(1);

  // 2. Empty digest algorithms set: SET {}
  const digestAlgorithms = encodeDerSet([]);

  // 3. Encapsulated content info: SEQUENCE { OID 1.2.840.113549.1.7.1 (data) }
  const encapContentInfo = encodeDerSequence([encodeDerOid("1.2.840.113549.1.7.1")]);

  // 4. Certificates [0] IMPLICIT CertificateSet (SET OF Certificate)
  // Replaces SET tag (0x31) with constructed context tag 0 (0xA0)
  const certsContent = concatBytes(...certDers);
  const certsNode = encodeDerContext(0, certsContent, true);

  // 5. Empty signerInfos set: SET {}
  const signerInfos = encodeDerSet([]);

  // 6. SignedData sequence
  const signedData = encodeDerSequence([
    version,
    digestAlgorithms,
    encapContentInfo,
    certsNode,
    signerInfos,
  ]);

  // 7. Outer ContentInfo: SEQUENCE { OID 1.2.840.113549.1.7.2 (signedData), [0] EXPLICIT SignedData }
  const contentInfo = encodeDerSequence([
    encodeDerOid("1.2.840.113549.1.7.2"),
    encodeDerContext(0, signedData, true),
  ]);

  const pem = encodePem("PKCS7", contentInfo);

  return {
    pem,
    der: contentInfo,
    count: certDers.length,
  };
}

/**
 * Extracts all X.509 certificates from a PKCS#7 / CMS (.p7b / .p7c) container.
 */
export function decodePkcs7CertBundle(input: Uint8Array): ExtractedCert[] {
  const { der } = detectInputBytes(input);
  const root = parseAsn1(der);

  let signedDataNode: Asn1Node | undefined;

  if (root.tagNumber === UniversalTag.Sequence) {
    if (root.children.length >= 2 && root.children[0]?.asOid() === "1.2.840.113549.1.7.2") {
      // ContentInfo -> content [0]
      const expNode = root.children[1];
      if (expNode && expNode.children.length > 0) {
        signedDataNode = expNode.children[0];
      }
    } else if (
      root.children.length >= 4 &&
      root.children[0]?.tagNumber === UniversalTag.Integer
    ) {
      // Direct SignedData
      signedDataNode = root;
    }
  }

  if (!signedDataNode) {
    throw new Error("Invalid PKCS#7 data: unable to locate SignedData structure.");
  }

  // Look for certificates [0] IMPLICIT
  const certsSetNode = signedDataNode.children.find(
    (c) => c.tagClass === TagClass.ContextSpecific && c.tagNumber === 0,
  );

  if (!certsSetNode || certsSetNode.children.length === 0) {
    throw new Error("PKCS#7 bundle contains no embedded certificates.");
  }

  const results: ExtractedCert[] = [];
  for (const certNode of certsSetNode.children) {
    const certDer = certNode.raw;
    results.push({
      der: certDer,
      pem: encodePem("CERTIFICATE", certDer),
    });
  }

  return results;
}
