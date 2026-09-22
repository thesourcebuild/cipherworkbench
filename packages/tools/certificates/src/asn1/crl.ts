import { parseAsn1, UniversalTag, TagClass } from "./asn1";
import {
  encodeDerSequence,
  encodeDerInteger,
  encodeDerTime,
  encodeDerContext,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerEnumerated,
  encodeDerBitString,
} from "./encoder";
import { encodePem, detectInputBytes } from "./pem";
import { SIGNATURE_ALGORITHMS, DN_SHORT_NAMES } from "./oids";
import type { CaSigner } from "../crypto/keys";

export enum CrlReasonCode {
  Unspecified = 0,
  KeyCompromise = 1,
  CACompromise = 2,
  AffiliationChanged = 3,
  Superseded = 4,
  CessationOfOperation = 5,
  CertificateHold = 6,
  RemoveFromCRL = 8,
  PrivilegeWithdrawn = 9,
  AACompromise = 10,
}

export const CRL_REASON_NAMES: Record<number, string> = {
  0: "Unspecified",
  1: "Key Compromise",
  2: "CA Compromise",
  3: "Affiliation Changed",
  4: "Superseded",
  5: "Cessation of Operation",
  6: "Certificate Hold",
  8: "Remove from CRL",
  9: "Privilege Withdrawn",
  10: "AA Compromise",
};

export interface RevokedCertificateInput {
  serialNumber: bigint | number | string;
  revocationDate?: Date;
  reasonCode?: CrlReasonCode;
}

export interface CreateCrlOptions {
  signer: CaSigner;
  crlNumber?: number;
  thisUpdate?: Date;
  nextUpdate?: Date;
  revokedCertificates?: RevokedCertificateInput[];
}

export interface CreatedCrl {
  crlDer: Uint8Array;
  crlPem: string;
  crlNumber: number;
  thisUpdate: Date;
  nextUpdate: Date;
  revokedCount: number;
  issuerDn: string;
  signatureAlgorithm: string;
}

export interface ParsedRevokedCert {
  serialNumberHex: string;
  serialNumberDec: string;
  revocationDate: Date;
  reasonCode?: number;
  reasonText?: string;
}

export interface ParsedCrl {
  version: number;
  signatureAlgorithmOid: string;
  signatureAlgorithmName: string;
  issuerDn: string;
  thisUpdate: Date;
  nextUpdate?: Date;
  revokedCertificates: ParsedRevokedCert[];
  crlNumber?: number;
  authorityKeyIdentifierHex?: string;
  rawDer: Uint8Array;
  pem: string;
}

/**
 * Encodes an RFC 5280 X.509 v2 Certificate Revocation List (CRL).
 */
export async function createCrl(opts: CreateCrlOptions): Promise<CreatedCrl> {
  const crlNumber = opts.crlNumber ?? 1;
  const now = opts.thisUpdate ?? new Date();
  const thisUpdate = now;
  const nextUpdate =
    opts.nextUpdate ?? new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days default

  // 1. Revoked Certificates Sequence
  const revokedEntriesDer: Uint8Array[] = [];
  const revokedInputs = opts.revokedCertificates ?? [];

  for (const rev of revokedInputs) {
    let serialBigInt: bigint;
    if (typeof rev.serialNumber === "bigint") {
      serialBigInt = rev.serialNumber;
    } else if (typeof rev.serialNumber === "number") {
      serialBigInt = BigInt(rev.serialNumber);
    } else {
      const s = String(rev.serialNumber).trim();
      serialBigInt = s.startsWith("0x") || s.startsWith("0X") ? BigInt(s) : /^[0-9a-fA-F]+$/.test(s) && /[a-fA-F]/.test(s) ? BigInt("0x" + s) : BigInt(s);
    }

    const revDate = rev.revocationDate ?? now;
    const entryItems: Uint8Array[] = [
      encodeDerInteger(serialBigInt),
      encodeDerTime(revDate),
    ];

    if (rev.reasonCode !== undefined) {
      const reasonDer = encodeDerEnumerated(rev.reasonCode);
      const reasonExt = encodeDerSequence([
        encodeDerOid("2.5.29.21"), // id-ce-cRLReason
        encodeDerOctetString(reasonDer),
      ]);
      const entryExtensions = encodeDerSequence([reasonExt]);
      entryItems.push(entryExtensions);
    }

    revokedEntriesDer.push(encodeDerSequence(entryItems));
  }

  // 2. CRL Extensions (RFC 5280 Section 5.2)
  const crlExts: Uint8Array[] = [];

  // CRL Number (OID 2.5.29.20)
  const crlNumDer = encodeDerOctetString(encodeDerInteger(crlNumber));
  crlExts.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.20"),
      crlNumDer,
    ]),
  );

  // Authority Key Identifier (OID 2.5.29.35)
  if (opts.signer.issuerSki && opts.signer.issuerSki.length > 0) {
    const akiInner = encodeDerSequence([
      encodeDerContext(0, opts.signer.issuerSki, false),
    ]);
    crlExts.push(
      encodeDerSequence([
        encodeDerOid("2.5.29.35"),
        encodeDerOctetString(akiInner),
      ]),
    );
  }

  // 3. Assemble TBSCertList
  const tbsElements: Uint8Array[] = [
    encodeDerInteger(1), // v2 CRL (RFC 5280: value 1)
    opts.signer.signatureAlgorithmDer,
    opts.signer.issuerDnDer,
    encodeDerTime(thisUpdate),
    encodeDerTime(nextUpdate),
  ];

  if (revokedEntriesDer.length > 0) {
    tbsElements.push(encodeDerSequence(revokedEntriesDer));
  }

  if (crlExts.length > 0) {
    tbsElements.push(encodeDerContext(0, encodeDerSequence(crlExts), true));
  }

  const tbsDer = encodeDerSequence(tbsElements);

  // 4. Cryptographic Digital Signature
  const signatureBytes = await opts.signer.signTbs(tbsDer);
  const signatureBitString = encodeDerBitString(signatureBytes, 0);

  // 5. Final CertificateList DER
  const crlDer = encodeDerSequence([
    tbsDer,
    opts.signer.signatureAlgorithmDer,
    signatureBitString,
  ]);

  const crlPem = encodePem("X509 CRL", crlDer);

  return {
    crlDer,
    crlPem,
    crlNumber,
    thisUpdate,
    nextUpdate,
    revokedCount: revokedInputs.length,
    issuerDn: opts.signer.issuerDnString,
    signatureAlgorithm: "Signature Algorithm",
  };
}

/**
 * Parses an X.509 v2 CRL in PEM or DER format.
 */
export function parseX509Crl(input: Uint8Array | string): ParsedCrl {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const detected = detectInputBytes(bytes);
  const der = detected.der;

  const root = parseAsn1(der);
  if (root.tagNumber !== UniversalTag.Sequence || root.children.length < 3) {
    throw new Error("Invalid CRL ASN.1 structure: expected CertificateList SEQUENCE with at least 3 children");
  }

  const tbs = root.children[0]!;
  let idx = 0;

  // Version
  let version = 1;
  const first = tbs.children[0];
  if (first && first.tagNumber === UniversalTag.Integer) {
    version = first.asIntegerNumber() + 1;
    idx++;
  }

  // Signature Algorithm
  const sigAlgNode = tbs.children[idx++];
  const sigAlgOid = sigAlgNode?.children[0]?.asOid() ?? "";
  const sigAlgName = SIGNATURE_ALGORITHMS[sigAlgOid]?.name ?? sigAlgOid;

  // Issuer DN
  const issuerNode = tbs.children[idx++];
  let issuerDn = "";
  if (issuerNode) {
    const parts: string[] = [];
    for (const rdnSet of issuerNode.children) {
      for (const attrSeq of rdnSet.children) {
        const oid = attrSeq.children[0]?.asOid();
        const val = attrSeq.children[1]?.asString();
        if (oid && val) {
          const name = DN_SHORT_NAMES[oid] ?? oid;
          parts.push(`${name}=${val}`);
        }
      }
    }
    issuerDn = parts.join(", ");
  }

  // thisUpdate
  const thisUpdateNode = tbs.children[idx++];
  if (!thisUpdateNode) throw new Error("Invalid CRL: missing thisUpdate");
  const thisUpdate = thisUpdateNode.asDate();

  // nextUpdate (optional)
  let nextUpdate: Date | undefined;
  if (
    idx < tbs.children.length &&
    (tbs.children[idx]?.tagNumber === UniversalTag.UTCTime ||
      tbs.children[idx]?.tagNumber === UniversalTag.GeneralizedTime)
  ) {
    nextUpdate = tbs.children[idx++]?.asDate();
  }

  // revokedCertificates (optional SEQUENCE)
  const revokedCertificates: ParsedRevokedCert[] = [];
  if (
    idx < tbs.children.length &&
    tbs.children[idx]?.tagClass === TagClass.Universal &&
    tbs.children[idx]?.tagNumber === UniversalTag.Sequence
  ) {
    const revSeq = tbs.children[idx++]!;
    for (const entry of revSeq.children) {
      if (entry.children.length >= 2) {
        const serialBigInt = entry.children[0]!.asIntegerBigInt();
        const hex = serialBigInt.toString(16).toUpperCase();
        const dec = serialBigInt.toString(10);
        const revDate = entry.children[1]!.asDate();

        let reasonCode: number | undefined;
        let reasonText: string | undefined;

        if (entry.children.length >= 3) {
          const entryExts = entry.children[2]!;
          for (const ext of entryExts.children) {
            const extOid = ext.children[0]?.asOid();
            if (extOid === "2.5.29.21") {
              try {
                const octet = ext.children[ext.children.length - 1]?.asOctetString();
                if (octet) {
                  const reasonParsed = parseAsn1(octet);
                  reasonCode = reasonParsed.asIntegerNumber();
                  reasonText = CRL_REASON_NAMES[reasonCode] ?? `Reason(${reasonCode})`;
                }
              } catch {
                // Ignore failure parsing extension
              }
            }
          }
        }

        revokedCertificates.push({
          serialNumberHex: hex,
          serialNumberDec: dec,
          revocationDate: revDate,
          reasonCode,
          reasonText,
        });
      }
    }
  }

  // crlExtensions (optional [0] EXPLICIT)
  let crlNumber: number | undefined;
  let authorityKeyIdentifierHex: string | undefined;

  if (
    idx < tbs.children.length &&
    tbs.children[idx]?.tagClass === TagClass.ContextSpecific &&
    tbs.children[idx]?.tagNumber === 0
  ) {
    const extContainer = tbs.children[idx]!;
    const exts = extContainer.children[0]?.children ?? extContainer.children;
    for (const ext of exts) {
      const extOid = ext.children[0]?.asOid();
      if (extOid === "2.5.29.20") {
        try {
          const octet = ext.children[ext.children.length - 1]?.asOctetString();
          if (octet) {
            const numNode = parseAsn1(octet);
            crlNumber = numNode.asIntegerNumber();
          }
        } catch {
          // ignore
        }
      } else if (extOid === "2.5.29.35") {
        try {
          const octet = ext.children[ext.children.length - 1]?.asOctetString();
          if (octet) {
            const akiNode = parseAsn1(octet);
            const keyIdNode = akiNode.children[0];
            if (keyIdNode) {
              const rawKeyId = keyIdNode.valueBytes;
              authorityKeyIdentifierHex = Array.from(rawKeyId)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join(":")
                .toUpperCase();
            }
          }
        } catch {
          // ignore
        }
      }
    }
  }

  return {
    version,
    signatureAlgorithmOid: sigAlgOid,
    signatureAlgorithmName: sigAlgName,
    issuerDn,
    thisUpdate,
    nextUpdate,
    revokedCertificates,
    crlNumber,
    authorityKeyIdentifierHex,
    rawDer: der,
    pem: encodePem("X509 CRL", der),
  };
}
