import { sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { parseAsn1, TagClass, UniversalTag } from "./asn1";
import { detectInputBytes } from "./pem";
import { parseX509Certificate } from "./x509";
import {
  encodeDerContext,
  encodeDerEnumerated,
  encodeDerGeneralizedTime,
  encodeDerInteger,
  encodeDerNull,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  encodeDerBitString,
} from "./encoder";
import { buildVerificationScripts, type CommandScripts } from "../export/commands";

export interface CertIdInfo {
  hashAlgorithm: "sha1" | "sha256";
  hashAlgorithmOid: string;
  issuerNameHashHex: string;
  issuerKeyHashHex: string;
  serialNumberHex: string;
}

export interface BuildOcspRequestResult {
  requestDer: Uint8Array;
  requestB64: string;
  certId: CertIdInfo;
  ocspUrl?: string;
  opensslCommand: string;
  commands: CommandScripts;
}

export interface ParsedOcspSingleResponse {
  certStatus: "good" | "revoked" | "unknown";
  thisUpdate: Date;
  nextUpdate?: Date;
  revocationTime?: Date;
  revocationReason?: string;
  serialNumberHex: string;
}

export interface ParsedOcspResponse {
  responseStatus: string;
  responseStatusCode: number;
  responderId?: string;
  producedAt?: Date;
  signatureAlgorithm?: string;
  responses: ParsedOcspSingleResponse[];
  nonceHex?: string;
  summary: string;
  rawDer: Uint8Array;
  rawB64: string;
}

const OID_SHA1 = "1.3.14.3.2.26";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_BASIC_OCSP_RESPONSE = "1.3.6.1.5.5.7.48.1.1";
const _OID_NONCE = "1.3.6.1.5.5.7.48.1.2";

const CRL_REASONS: Record<number, string> = {
  0: "unspecified",
  1: "keyCompromise",
  2: "cACompromise",
  3: "affiliationChanged",
  4: "superseded",
  5: "cessationOfOperation",
  6: "certificateHold",
  8: "removeFromCRL",
  9: "privilegeWithdrawn",
  10: "aACompromise",
};

/**
 * Extracts the raw public key bit string bytes from an X.509 certificate SPKI structure.
 */
function extractPublicKeyBytes(certDer: Uint8Array): Uint8Array {
  const root = parseAsn1(certDer);
  const tbs = root.children[0];
  if (!tbs) throw new Error("Invalid certificate: missing TBSCertificate");

  let idx = 0;
  if (tbs.children[0]?.tagNumber === 0) idx++; // version
  idx++; // serial
  idx++; // signature
  idx++; // issuer
  idx++; // validity
  idx++; // subject
  const spki = tbs.children[idx];
  if (!spki || spki.children.length < 2) {
    throw new Error("Invalid certificate: missing SubjectPublicKeyInfo");
  }

  const pubBitString = spki.children[1]!;
  return pubBitString.asBitString().bytes;
}

/**
 * Encodes RFC 6960 CertID structure for a target certificate and its issuing CA certificate.
 */
export function buildCertId(
  targetCertDer: Uint8Array,
  issuerCertDer: Uint8Array,
  hashAlgorithm: "sha1" | "sha256" = "sha256",
): { der: Uint8Array; info: CertIdInfo } {
  const targetCert = parseX509Certificate(targetCertDer);
  const issuerCert = parseX509Certificate(issuerCertDer);

  const issuerSubjectDer = issuerCert.subject.rawDer;
  if (!issuerSubjectDer) {
    throw new Error("Could not extract raw Subject DN from issuer certificate");
  }

  const issuerPubBytes = extractPublicKeyBytes(issuerCertDer);

  const hasher = hashAlgorithm === "sha1" ? sha1 : sha256;
  const algOid = hashAlgorithm === "sha1" ? OID_SHA1 : OID_SHA256;

  const issuerNameHash = hasher(issuerSubjectDer);
  const issuerKeyHash = hasher(issuerPubBytes);

  const cleanSerial = targetCert.serialNumber.replace(/[^0-9a-fA-F]/g, "");
  const serialBigInt = BigInt("0x" + (cleanSerial || "0"));

  const algSeq = encodeDerSequence([encodeDerOid(algOid), encodeDerNull()]);

  const certIdDer = encodeDerSequence([
    algSeq,
    encodeDerOctetString(issuerNameHash),
    encodeDerOctetString(issuerKeyHash),
    encodeDerInteger(serialBigInt),
  ]);

  const info: CertIdInfo = {
    hashAlgorithm,
    hashAlgorithmOid: algOid,
    issuerNameHashHex: bytesToHex(issuerNameHash).toUpperCase(),
    issuerKeyHashHex: bytesToHex(issuerKeyHash).toUpperCase(),
    serialNumberHex: cleanSerial.toUpperCase(),
  };

  return { der: certIdDer, info };
}

/**
 * Encodes an RFC 6960 OCSPRequest DER structure.
 */
export function buildOcspRequest(opts: {
  certInput: string | Uint8Array;
  issuerCertInput: string | Uint8Array;
  hashAlgorithm?: "sha1" | "sha256";
}): BuildOcspRequestResult {
  const certDer = typeof opts.certInput === "string" ? detectInputBytes(opts.certInput).der : opts.certInput;
  const issuerDer = typeof opts.issuerCertInput === "string" ? detectInputBytes(opts.issuerCertInput).der : opts.issuerCertInput;

  const hashAlgorithm = opts.hashAlgorithm ?? "sha256";
  const { der: certIdDer, info } = buildCertId(certDer, issuerDer, hashAlgorithm);

  const requestSeq = encodeDerSequence([certIdDer]);
  const requestList = encodeDerSequence([requestSeq]);

  // TBSRequest: SEQUENCE { requestList SEQUENCE OF Request }
  const tbsRequest = encodeDerSequence([requestList]);

  // OCSPRequest: SEQUENCE { tbsRequest TBSRequest }
  const requestDer = encodeDerSequence([tbsRequest]);
  const requestB64 = base64.encode(requestDer);

  const parsedCert = parseX509Certificate(certDer);
  const ocspUrl = parsedCert.extensions.ocspUrls[0];

  const opensslCommand = ocspUrl
    ? `openssl ocsp -issuer ca.crt -cert cert.crt -url "${ocspUrl}" -respout ocsp.der -text`
    : `openssl ocsp -issuer ca.crt -cert cert.crt -text`;

  const commands = buildVerificationScripts({
    title: "OCSP Revocation Check",
    description: "Query online OCSP responder or verify offline OCSP staple response.",
    actions: [
      {
        id: "check-live",
        description: "Query live OCSP responder for revocation status",
        commands: [
          ...(ocspUrl
            ? [`openssl ocsp -issuer "ca.crt" -cert "cert.crt" -url "${ocspUrl}" -respout "ocsp.der" -text`]
            : ['echo "Note: Certificate does not contain an AIA OCSP responder URL."']),
        ],
      },
      {
        id: "inspect-staple",
        description: "Inspect downloaded or saved OCSP staple DER response",
        commands: ['openssl ocsp -respin "ocsp.der" -text'],
      },
    ],
  });

  return {
    requestDer,
    requestB64,
    certId: info,
    ocspUrl,
    opensslCommand,
    commands,
  };
}

/**
 * Parses and decodes an RFC 6960 OCSPResponse (DER or Base64 / PEM).
 */
export function parseOcspResponse(responseInput: Uint8Array | string): ParsedOcspResponse {
  const detected = detectInputBytes(responseInput);
  const der = detected.der;

  const root = parseAsn1(der);
  if (root.tagNumber !== UniversalTag.Sequence || root.children.length === 0) {
    throw new Error("Invalid OCSPResponse: root element is not an ASN.1 SEQUENCE");
  }

  const statusNode = root.children[0];
  if (!statusNode) throw new Error("Missing responseStatus in OCSPResponse");
  const statusCode = statusNode.asIntegerNumber();

  const STATUS_LABELS: Record<number, string> = {
    0: "successful (0)",
    1: "malformedRequest (1)",
    2: "internalError (2)",
    3: "tryLater (3)",
    5: "sigRequired (5)",
    6: "unauthorized (6)",
  };

  const responseStatus = STATUS_LABELS[statusCode] ?? `unknown (${statusCode})`;

  const responses: ParsedOcspSingleResponse[] = [];
  let responderId: string | undefined;
  let producedAt: Date | undefined;
  let signatureAlgorithm: string | undefined;
  let nonceHex: string | undefined;

  if (statusCode === 0 && root.children.length > 1) {
    const responseBytesNode = root.children[1];
    if (
      responseBytesNode &&
      responseBytesNode.tagClass === TagClass.ContextSpecific &&
      responseBytesNode.tagNumber === 0 &&
      responseBytesNode.children.length > 0
    ) {
      const respSeq = responseBytesNode.children[0]!;
      const respTypeOid = respSeq.children[0]?.asOid();
      const responseOctets = respSeq.children[1]?.asOctetString();

      if (respTypeOid === OID_BASIC_OCSP_RESPONSE && responseOctets) {
        const basicAsn = parseAsn1(responseOctets);
        const tbsResponseData = basicAsn.children[0];
        const sigAlgSeq = basicAsn.children[1];

        if (sigAlgSeq?.children[0]) {
          signatureAlgorithm = `OID ${sigAlgSeq.children[0].asOid()}`;
        }

        if (tbsResponseData) {
          let idx = 0;
          if (tbsResponseData.children[0]?.tagNumber === 0) idx++; // skip version if present
          const respIdNode = tbsResponseData.children[idx++];
          if (respIdNode) {
            responderId = respIdNode.dump().replace(/\s+/g, " ").trim();
          }

          const prodAtNode = tbsResponseData.children[idx++];
          if (prodAtNode) {
            try {
              producedAt = prodAtNode.asDate();
            } catch {
              // Ignore
            }
          }

          const responsesSeq = tbsResponseData.children[idx++];
          if (responsesSeq) {
            for (const single of responsesSeq.children) {
              if (single.children.length < 3) continue;
              const certIdSeq = single.children[0];
              const certStatusNode = single.children[1];
              const thisUpdateNode = single.children[2];
              const nextUpdateNode = single.children[3];

              let certStatus: "good" | "revoked" | "unknown" = "unknown";
              let revocationTime: Date | undefined;
              let revocationReason: string | undefined;

              if (certStatusNode) {
                if (certStatusNode.tagNumber === 0) {
                  certStatus = "good";
                } else if (certStatusNode.tagNumber === 1) {
                  certStatus = "revoked";
                  let revNode = certStatusNode;
                  if (certStatusNode.children.length === 1 && certStatusNode.children[0]?.tagNumber === UniversalTag.Sequence) {
                    revNode = certStatusNode.children[0]!;
                  }
                  if (revNode.children.length > 0) {
                    try {
                      revocationTime = revNode.children[0]?.asDate();
                    } catch {
                      // ignore
                    }
                    const reasonNode = revNode.children[1];
                    if (reasonNode) {
                      const codeNode = reasonNode.children.length > 0 ? reasonNode.children[0]! : reasonNode;
                      const code = codeNode.asIntegerNumber();
                      revocationReason = CRL_REASONS[code] ?? `Code ${code}`;
                    }
                  }
                } else {
                  certStatus = "unknown";
                }
              }

              let thisUpdate = new Date();
              try {
                if (thisUpdateNode) thisUpdate = thisUpdateNode.asDate();
              } catch {
                // ignore
              }

              let nextUpdate: Date | undefined;
              try {
                if (nextUpdateNode && nextUpdateNode.tagNumber === 0 && nextUpdateNode.children[0]) {
                  nextUpdate = nextUpdateNode.children[0].asDate();
                }
              } catch {
                // ignore
              }

              let serialNumberHex = "";
              if (certIdSeq && certIdSeq.children.length >= 4) {
                serialNumberHex = certIdSeq.children[3]?.asIntegerHex() ?? "";
              }

              responses.push({
                certStatus,
                thisUpdate,
                nextUpdate,
                revocationTime,
                revocationReason,
                serialNumberHex,
              });
            }
          }
        }
      }
    }
  }

  const primaryStatus = responses[0]?.certStatus ?? (statusCode === 0 ? "good" : "unknown");
  const summary = `OCSP Response: ${responseStatus.toUpperCase()} - Certificate Status: ${primaryStatus.toUpperCase()}`;

  return {
    responseStatus,
    responseStatusCode: statusCode,
    responderId,
    producedAt,
    signatureAlgorithm,
    responses,
    nonceHex,
    summary,
    rawDer: der,
    rawB64: base64.encode(der),
  };
}

/**
 * Creates an authentic RFC 6960 OCSP Response (e.g. for testing offline OCSP stapling).
 */
export function createMockOcspResponse(opts: {
  targetCertDer: Uint8Array;
  issuerCertDer: Uint8Array;
  certStatus?: "good" | "revoked" | "unknown";
  revocationReasonCode?: number;
  validityHours?: number;
}): { der: Uint8Array; b64: string } {
  const { der: certIdDer } = buildCertId(opts.targetCertDer, opts.issuerCertDer, "sha256");

  const now = new Date();
  const nextUpdate = new Date(now.getTime() + (opts.validityHours ?? 24) * 60 * 60 * 1000);

  // CertStatus CHOICE
  let statusNode: Uint8Array;
  if (opts.certStatus === "revoked") {
    const revTime = encodeDerGeneralizedTime(now);
    const revReason = opts.revocationReasonCode !== undefined
      ? encodeDerContext(0, encodeDerEnumerated(opts.revocationReasonCode), true)
      : new Uint8Array(0);
    const revInfo = encodeDerSequence([revTime, ...(revReason.length > 0 ? [revReason] : [])]);
    statusNode = encodeDerContext(1, revInfo, true);
  } else if (opts.certStatus === "unknown") {
    statusNode = encodeDerContext(2, encodeDerNull(), false);
  } else {
    // good: [0] IMPLICIT NULL
    statusNode = encodeDerContext(0, encodeDerNull(), false);
  }

  // SingleResponse: SEQUENCE { certId, certStatus, thisUpdate, nextUpdate [0] EXPLICIT }
  const singleResponse = encodeDerSequence([
    certIdDer,
    statusNode,
    encodeDerGeneralizedTime(now),
    encodeDerContext(0, encodeDerGeneralizedTime(nextUpdate), true),
  ]);

  const responsesList = encodeDerSequence([singleResponse]);

  // ResponderID: [1] EXPLICIT KeyHash
  const issuerPubBytes = extractPublicKeyBytes(opts.issuerCertDer);
  const keyHash = sha1(issuerPubBytes);
  const responderId = encodeDerContext(2, encodeDerOctetString(keyHash), true);

  // ResponseData
  const responseData = encodeDerSequence([
    responderId,
    encodeDerGeneralizedTime(now),
    responsesList,
  ]);

  // Mock signature
  const dummySigAlg = encodeDerSequence([encodeDerOid(OID_SHA256), encodeDerNull()]);
  const dummySignature = encodeDerBitString(new Uint8Array(64).fill(0x5a));

  // BasicOCSPResponse
  const basicOcsp = encodeDerSequence([responseData, dummySigAlg, dummySignature]);

  // ResponseBytes
  const responseBytes = encodeDerContext(
    0,
    encodeDerSequence([encodeDerOid(OID_BASIC_OCSP_RESPONSE), encodeDerOctetString(basicOcsp)]),
    true,
  );

  // OCSPResponse
  const ocspResponseDer = encodeDerSequence([
    encodeDerEnumerated(0), // successful (0)
    responseBytes,
  ]);

  return {
    der: ocspResponseDer,
    b64: base64.encode(ocspResponseDer),
  };
}
