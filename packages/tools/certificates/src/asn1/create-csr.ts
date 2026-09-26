import {
  encodeDerBitString,
  encodeDerBoolean,
  encodeDerContext,
  encodeDerInteger,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  encodeDerSet,
  encodeDistinguishedName,
  type RdnEntry,
} from "./encoder";
import {
  generateKeyBundle,
  type KeyAlgorithmType,
  type HashAlgorithmType,
  type GeneratedKeyBundle,
} from "../crypto/keys";
import { encodePem } from "./pem";
import { encodeSanExtension, encodeKeyUsageBitString } from "./create-cert";
import { parseCsr, type ParsedCsr } from "./csr";
import { buildCsrOpenSslWorkflow } from "../export/openssl-workflow";

export interface CsrCreatorOptions {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  keyType: KeyAlgorithmType;
  hashType: HashAlgorithmType;
  san?: string;
  serverAuth?: boolean;
  clientAuth?: boolean;
  codeSigning?: boolean;
  emailProtection?: boolean;
}

export interface CreatedCsrResult {
  csrPem: string;
  csrDer: Uint8Array;
  privateKeyPem: string;
  publicKeyPem: string;
  subjectDn: string;
  signatureAlgorithm: string;
  verified: boolean;
  opensslCommand: string;
  parsedCsr: ParsedCsr;
  keyBundle: GeneratedKeyBundle;
}

/**
 * Generates a cryptographically valid, self-signed PKCS#10 Certificate Signing Request (CSR).
 */
export async function createCsr(opts: CsrCreatorOptions): Promise<CreatedCsrResult> {
  const keyBundle = await generateKeyBundle(opts.keyType, opts.hashType);

  // 1. Subject DN
  const rdnEntries: RdnEntry[] = [
    {
      oid: "2.5.4.6",
      value: (opts.country ?? "").slice(0, 2).toUpperCase(),
      isPrintable: true,
    }, // C
    { oid: "2.5.4.8", value: opts.state ?? "" }, // ST
    { oid: "2.5.4.7", value: opts.locality ?? "" }, // L
    { oid: "2.5.4.10", value: opts.organization ?? "" }, // O
    { oid: "2.5.4.11", value: opts.organizationalUnit ?? "" }, // OU
    { oid: "2.5.4.3", value: opts.commonName ?? "" }, // CN
  ].filter((e) => e.value.length > 0);

  const subjectDnDer = encodeDistinguishedName(rdnEntries);

  const dnStringParts: string[] = [];
  for (const entry of rdnEntries) {
    let name = entry.oid;
    if (entry.oid === "2.5.4.3") name = "CN";
    else if (entry.oid === "2.5.4.10") name = "O";
    else if (entry.oid === "2.5.4.11") name = "OU";
    else if (entry.oid === "2.5.4.6") name = "C";
    else if (entry.oid === "2.5.4.8") name = "ST";
    else if (entry.oid === "2.5.4.7") name = "L";
    dnStringParts.push(`${name}=${entry.value}`);
  }
  const subjectDnStr = dnStringParts.join(", ");

  // 2. Requested Extensions (extensionRequest attribute OID 1.2.840.113549.1.9.14)
  const requestedExtensions: Uint8Array[] = [];

  // 2a. SAN
  const sanDer = encodeSanExtension(opts.san || opts.commonName);
  if (sanDer) {
    requestedExtensions.push(
      encodeDerSequence([encodeDerOid("2.5.29.17"), encodeDerOctetString(sanDer)]),
    );
  }

  // 2b. Key Usage
  const kuBits = opts.keyType.startsWith("rsa-") ? [0, 2] : [0];
  const kuBitString = encodeKeyUsageBitString(kuBits);
  requestedExtensions.push(
    encodeDerSequence([
      encodeDerOid("2.5.29.15"),
      encodeDerBoolean(true),
      encodeDerOctetString(kuBitString),
    ]),
  );

  // 2c. Extended Key Usage
  const ekuOids: Uint8Array[] = [];
  if (opts.serverAuth !== false) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.1"));
  if (opts.clientAuth !== false) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.2"));
  if (opts.codeSigning) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.3"));
  if (opts.emailProtection) ekuOids.push(encodeDerOid("1.3.6.1.5.5.7.3.4"));

  if (ekuOids.length > 0) {
    requestedExtensions.push(
      encodeDerSequence([
        encodeDerOid("2.5.29.37"),
        encodeDerOctetString(encodeDerSequence(ekuOids)),
      ]),
    );
  }

  // Attributes [0] IMPLICIT Attributes
  let attributesNode: Uint8Array;
  if (requestedExtensions.length > 0) {
    const extRequestAttr = encodeDerSequence([
      encodeDerOid("1.2.840.113549.1.9.14"), // extensionRequest
      encodeDerSet([encodeDerSequence(requestedExtensions)]),
    ]);
    attributesNode = encodeDerContext(0, extRequestAttr, true);
  } else {
    attributesNode = encodeDerContext(0, new Uint8Array(0), true);
  }

  // 3. Assemble CertificationRequestInfo
  const criSequence = encodeDerSequence([
    encodeDerInteger(0), // Version 1 (0)
    subjectDnDer,
    keyBundle.spkiBytes,
    attributesNode,
  ]);

  // 4. Sign Request Info
  const signatureBytes = await keyBundle.signTbs(criSequence);
  const signatureBitString = encodeDerBitString(signatureBytes, 0);

  // 5. Assemble Full CSR
  const csrDer = encodeDerSequence([
    criSequence,
    keyBundle.signatureAlgorithmDer,
    signatureBitString,
  ]);

  const csrPem = encodePem("CERTIFICATE REQUEST", csrDer);

  // 6. Cross-verify with our own parser
  const parsedCsr = parseCsr(csrDer);
  const verifyResult = await parsedCsr.verifySelfSignature();

  // An equivalent CLI workflow, not the command used here: generation remains entirely in-process.
  const opensslCommand = buildCsrOpenSslWorkflow(opts);

  return {
    csrPem,
    csrDer,
    privateKeyPem: keyBundle.privateKeyPem,
    publicKeyPem: keyBundle.publicKeyPem,
    subjectDn: subjectDnStr,
    signatureAlgorithm: parsedCsr.signatureAlgorithmName,
    verified: verifyResult.valid,
    opensslCommand,
    parsedCsr,
    keyBundle,
  };
}
