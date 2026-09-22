import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  encodeDerBitString,
  encodeDerContext,
  encodeDerInteger,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  encodeDerTime,
  encodeDistinguishedName,
  type RdnEntry,
} from "../asn1/encoder";
import { encodePem } from "../asn1/pem";
import { encodeSanExtension, encodeKeyUsageBitString } from "../asn1/create-cert";
import { parseX509Certificate, type ParsedX509Certificate } from "../asn1/x509";
import { buildVerificationScripts, type CommandScripts } from "../export/commands";

export type PqcAlgorithm = "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87";

export const PQC_ALGORITHM_OIDS: Record<PqcAlgorithm, string> = {
  "ml-dsa-44": "2.16.840.1.101.3.4.3.17",
  "ml-dsa-65": "2.16.840.1.101.3.4.3.18",
  "ml-dsa-87": "2.16.840.1.101.3.4.3.19",
};

export const OID_TO_PQC_ALGORITHM: Record<string, PqcAlgorithm> = {
  "2.16.840.1.101.3.4.3.17": "ml-dsa-44",
  "2.16.840.1.101.3.4.3.18": "ml-dsa-65",
  "2.16.840.1.101.3.4.3.19": "ml-dsa-87",
};

export interface PqcKeyPair {
  algorithm: PqcAlgorithm;
  oid: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  spkiDer: Uint8Array;
  pkcs8Der: Uint8Array;
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface PqcCertParams {
  algorithm?: PqcAlgorithm;
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  san?: string;
  validityDays?: number;
  isCa?: boolean;
}

export interface PqcCertResult {
  algorithm: PqcAlgorithm;
  certPem: string;
  certDer: Uint8Array;
  privateKeyPem: string;
  privateKeyDer: Uint8Array;
  publicKeyPem: string;
  publicKeyDer: Uint8Array;
  parsed: ParsedX509Certificate;
  commands: CommandScripts;
}

function getPrimitive(alg: PqcAlgorithm) {
  switch (alg) {
    case "ml-dsa-44":
      return ml_dsa44;
    case "ml-dsa-65":
      return ml_dsa65;
    case "ml-dsa-87":
      return ml_dsa87;
  }
}

/**
 * Generates an ML-DSA Post-Quantum Key Pair and encodes SPKI and PKCS#8 DER/PEM structures.
 */
export function generatePqcKeyPair(algorithm: PqcAlgorithm = "ml-dsa-65"): PqcKeyPair {
  const primitive = getPrimitive(algorithm);
  const oid = PQC_ALGORITHM_OIDS[algorithm];

  const { publicKey, secretKey } = primitive.keygen();

  // In IETF draft-ietf-lamps-dilithium-certificates:
  // AlgorithmIdentifier parameters MUST be omitted
  const algId = encodeDerSequence([encodeDerOid(oid)]);

  // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  const spkiDer = encodeDerSequence([
    algId,
    encodeDerBitString(publicKey, 0),
  ]);

  // OneAsymmetricKey / PKCS#8: SEQUENCE { version INTEGER (0), privateKeyAlgorithm AlgorithmIdentifier, privateKey OCTET STRING }
  const pkcs8Der = encodeDerSequence([
    encodeDerInteger(0),
    algId,
    encodeDerOctetString(secretKey),
  ]);

  const publicKeyPem = encodePem("PUBLIC KEY", spkiDer);
  const privateKeyPem = encodePem("PRIVATE KEY", pkcs8Der);

  return {
    algorithm,
    oid,
    publicKey,
    secretKey,
    spkiDer,
    pkcs8Der,
    publicKeyPem,
    privateKeyPem,
  };
}

/**
 * Signs data using an ML-DSA private key.
 */
export function signWithPqc(
  algorithm: PqcAlgorithm,
  data: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  const primitive = getPrimitive(algorithm);
  return primitive.sign(data, secretKey);
}

/**
 * Verifies an ML-DSA signature against data and public key.
 */
export function verifyWithPqc(
  algorithm: PqcAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  const primitive = getPrimitive(algorithm);
  try {
    return primitive.verify(signature, data, publicKey);
  } catch {
    return false;
  }
}

/**
 * Creates a standards-compliant X.509 v3 Post-Quantum Certificate using NIST FIPS 204 ML-DSA.
 */
export async function createPqcCertificate(params: PqcCertParams): Promise<PqcCertResult> {
  const algorithm = params.algorithm ?? "ml-dsa-65";
  const keyPair = generatePqcKeyPair(algorithm);
  const oid = PQC_ALGORITHM_OIDS[algorithm];

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + (params.validityDays ?? 365) * 86400 * 1000);

  // Serial number (16 random bytes)
  const serialBytes = crypto.getRandomValues(new Uint8Array(16));
  serialBytes[0] = serialBytes[0]! & 0x7f; // positive
  let serialHex = "";
  for (const b of serialBytes) serialHex += b.toString(16).padStart(2, "0");
  const serialBigInt = BigInt("0x" + serialHex);

  // Distinguished Name
  const rdnEntries: RdnEntry[] = [
    { oid: "2.5.4.3", value: params.commonName },
    ...(params.organization ? [{ oid: "2.5.4.10", value: params.organization }] : []),
    ...(params.organizationalUnit ? [{ oid: "2.5.4.11", value: params.organizationalUnit }] : []),
    ...(params.country ? [{ oid: "2.5.4.6", value: params.country, isPrintable: true }] : []),
    ...(params.state ? [{ oid: "2.5.4.8", value: params.state }] : []),
    ...(params.locality ? [{ oid: "2.5.4.7", value: params.locality }] : []),
  ];

  const subjectDnDer = encodeDistinguishedName(rdnEntries);
  const issuerDnDer = subjectDnDer; // Self-signed root / leaf

  // Signature AlgorithmIdentifier (no parameters)
  const sigAlgId = encodeDerSequence([encodeDerOid(oid)]);

  // Extensions
  const extensions: Uint8Array[] = [];

  // 1. Basic Constraints
  const isCa = params.isCa ?? false;
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.19"),
      encodeDerOctetString(
        encodeDerSequence(isCa ? [new Uint8Array([0x01, 0x01, 0xff])] : []),
      ),
    ]),
  );

  // 2. Key Usage
  const kuBits = isCa ? [5, 6] : [0]; // keyCertSign, cRLSign OR digitalSignature
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.15"),
      encodeDerOctetString(encodeKeyUsageBitString(kuBits)),
    ]),
  );

  // 3. Subject Key Identifier (SHA-256 of public key bytes)
  const skiBytes = sha256(keyPair.publicKey).subarray(0, 20);
  extensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.14"),
      encodeDerOctetString(encodeDerOctetString(skiBytes)),
    ]),
  );

  // 4. SAN
  const sanDer = encodeSanExtension(params.san || params.commonName);
  if (sanDer) {
    extensions.push(
      encodeDerSequence([
        encodeDerOid("2.5.29.17"),
        encodeDerOctetString(sanDer),
      ]),
    );
  }

  // Extensions explicit container [3]
  const extContainer = encodeDerContext(3, encodeDerSequence(extensions), true);

  // TBSCertificate: SEQUENCE { version [0] EXPLICIT 2, serial, sigAlg, issuer, validity, subject, spki, extensions [3] }
  const validitySeq = encodeDerSequence([
    encodeDerTime(notBefore),
    encodeDerTime(notAfter),
  ]);

  const versionExplicit = new Uint8Array([0xa0, 0x03, 0x02, 0x01, 0x02]); // Version 3 (2)

  const tbsSequence = encodeDerSequence([
    versionExplicit,
    encodeDerInteger(serialBigInt),
    sigAlgId,
    issuerDnDer,
    validitySeq,
    subjectDnDer,
    keyPair.spkiDer,
    extContainer,
  ]);

  // Self-sign with ML-DSA
  const signatureBytes = signWithPqc(algorithm, tbsSequence, keyPair.secretKey);
  const sigBitString = encodeDerBitString(signatureBytes, 0);

  // Full Certificate
  const certDer = encodeDerSequence([
    tbsSequence,
    sigAlgId,
    sigBitString,
  ]);

  const certPem = encodePem("CERTIFICATE", certDer);
  const parsed = parseX509Certificate(certDer);

  const commands = buildVerificationScripts({
    title: `Post-Quantum X.509 Certificate (${algorithm.toUpperCase()})`,
    description: `Inspect and verify FIPS 204 ${algorithm.toUpperCase()} quantum-resistant certificate.`,
    actions: [
      {
        id: "inspect-cert",
        description: "Inspect certificate text, OID, and quantum-resistant public key",
        commands: ['openssl x509 -in "cert.crt" -text -noout'],
      },
    ],
  });

  return {
    algorithm,
    certPem,
    certDer,
    privateKeyPem: keyPair.privateKeyPem,
    privateKeyDer: keyPair.pkcs8Der,
    publicKeyPem: keyPair.publicKeyPem,
    publicKeyDer: keyPair.spkiDer,
    parsed,
    commands,
  };
}
