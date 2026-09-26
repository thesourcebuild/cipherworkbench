import { ed25519 } from "@noble/curves/ed25519.js";
import { parseAsn1 } from "./asn1";
import { parseX509Certificate, type ParsedX509Certificate } from "./x509";
import { SIGNATURE_ALGORITHMS } from "./oids";
import { verifyWithPqc, OID_TO_PQC_ALGORITHM } from "../crypto/pqc";
import { verifyRsaPkcs1Sha3, verifyEcdsaSha3 } from "../crypto/keys";

export interface ChainNodeVerification {
  index: number;
  subjectDn: string;
  issuerDn: string;
  serialNumber: string;
  isCa: boolean;
  isRoot: boolean;
  validDates: boolean;
  datesMessage: string;
  signatureValid: boolean;
  signatureError?: string;
  akiSkiMatch?: boolean;
  ocspUrls?: string[];
  crlUrls?: string[];
  errors: string[];
  warnings: string[];
}

export interface ChainVerificationResult {
  isValid: boolean;
  chainDepth: number;
  leafSubject: string;
  rootSubject: string;
  isSelfSignedRoot: boolean;
  nodes: ChainNodeVerification[];
  summary: string;
  treeDiagram: string;
}

/**
 * Splits a concatenated PEM bundle into individual PEM certificate blocks.
 */
export function splitPemCertificates(pemText: string): string[] {
  const matches = pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches ? [...matches] : [];
}

/**
 * Cryptographically verifies that parent's public key signed child's TBSCertificate.
 */
export async function verifyCertificateSignature(
  child: ParsedX509Certificate,
  parent: ParsedX509Certificate,
): Promise<{ valid: boolean; error?: string }> {
  const subtle = globalThis.crypto?.subtle;

  // 1. Ed25519
  if (parent.publicKey.keyType === "ed25519") {
    try {
      const rawPub = parent.publicKey.spkiDer.slice(-32);
      const valid = ed25519.verify(child.signatureBytes, child.tbsRaw, rawPub);
      return { valid, error: valid ? undefined : "Ed25519 signature mismatch" };
    } catch (err) {
      return { valid: false, error: `Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  // 1b. ML-DSA Post-Quantum (FIPS 204)
  const pqcAlg = OID_TO_PQC_ALGORITHM[child.signatureAlgorithmOid];
  if (pqcAlg) {
    try {
      const rawPub = parent.publicKey.rawBytes ?? parent.publicKey.spkiDer.slice(-32);
      const valid = verifyWithPqc(pqcAlg, child.tbsRaw, child.signatureBytes, rawPub);
      return { valid, error: valid ? undefined : `${pqcAlg.toUpperCase()} signature mismatch` };
    } catch (err) {
      return { valid: false, error: `${pqcAlg.toUpperCase()} verification error: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  if (!subtle) {
    return { valid: false, error: "WebCrypto API (crypto.subtle) is not available" };
  }

  const sigAlgMeta = SIGNATURE_ALGORITHMS[child.signatureAlgorithmOid];

  // 2. RSA
  if (parent.publicKey.keyType === "rsa") {
    try {
      if (sigAlgMeta?.hash?.startsWith("SHA3-")) {
        const hashId =
          sigAlgMeta.hash === "SHA3-512"
            ? "sha3-512"
            : sigAlgMeta.hash === "SHA3-384"
              ? "sha3-384"
              : "sha3-256";
        const valid = verifyRsaPkcs1Sha3(
          parent.publicKey.spkiDer,
          hashId,
          child.tbsRaw,
          child.signatureBytes,
        );
        return { valid, error: valid ? undefined : "RSA digital signature mismatch" };
      }

      const hash = sigAlgMeta?.hash ?? "SHA-256";
      const cryptoKey = await subtle.importKey(
        "spki",
        parent.publicKey.spkiDer as unknown as BufferSource,
        { name: "RSASSA-PKCS1-v1_5", hash },
        false,
        ["verify"],
      );

      const valid = await subtle.verify(
        "RSASSA-PKCS1-v1_5",
        cryptoKey,
        child.signatureBytes as unknown as BufferSource,
        child.tbsRaw as unknown as BufferSource,
      );

      return { valid, error: valid ? undefined : "RSA digital signature mismatch" };
    } catch (err) {
      return { valid: false, error: `RSA verification error: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  // 3. ECDSA
  if (parent.publicKey.keyType === "ec") {
    try {
      if (sigAlgMeta?.hash?.startsWith("SHA3-")) {
        const hashId =
          sigAlgMeta.hash === "SHA3-512"
            ? "sha3-512"
            : sigAlgMeta.hash === "SHA3-384"
              ? "sha3-384"
              : "sha3-256";
        const valid = verifyEcdsaSha3(
          parent.publicKey.spkiDer,
          parent.publicKey.curveName,
          hashId,
          child.tbsRaw,
          child.signatureBytes,
        );
        return { valid, error: valid ? undefined : "ECDSA digital signature mismatch" };
      }

      const namedCurve =
        parent.publicKey.curveName?.includes("P-384") ? "P-384"
        : parent.publicKey.curveName?.includes("P-521") ? "P-521"
        : "P-256";
      const hash = sigAlgMeta?.hash ?? (namedCurve === "P-384" ? "SHA-384" : namedCurve === "P-521" ? "SHA-512" : "SHA-256");

      const cryptoKey = await subtle.importKey(
        "spki",
        parent.publicKey.spkiDer as unknown as BufferSource,
        { name: "ECDSA", namedCurve },
        false,
        ["verify"],
      );

      // Convert DER signature (SEQUENCE { INTEGER r, INTEGER s }) to IEEE P1363 raw signature (r || s)
      let signatureForVerify: Uint8Array = child.signatureBytes;
      try {
        const sigAsn = parseAsn1(child.signatureBytes);
        if (sigAsn.children.length === 2) {
          const c0 = sigAsn.children[0];
          const c1 = sigAsn.children[1];
          if (c0 && c1) {
            let rBytes = c0.valueBytes;
            let sBytes = c1.valueBytes;
            if (rBytes.length > 32 && rBytes[0] === 0) rBytes = rBytes.slice(1);
            if (sBytes.length > 32 && sBytes[0] === 0) sBytes = sBytes.slice(1);
            const keyByteLen = namedCurve === "P-384" ? 48 : namedCurve === "P-521" ? 66 : 32;
            const p1363 = new Uint8Array(keyByteLen * 2);
            p1363.set(rBytes, keyByteLen - rBytes.length);
            p1363.set(sBytes, keyByteLen * 2 - sBytes.length);
            signatureForVerify = p1363;
          }
        }
      } catch {
        // use raw
      }

      const valid = await subtle.verify(
        { name: "ECDSA", hash: { name: hash } },
        cryptoKey,
        signatureForVerify as unknown as BufferSource,
        child.tbsRaw as unknown as BufferSource,
      );

      return { valid, error: valid ? undefined : "ECDSA digital signature mismatch" };
    } catch (err) {
      return { valid: false, error: `ECDSA verification error: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  return { valid: false, error: `Unsupported public key algorithm: ${parent.publicKey.algorithmName}` };
}

/**
 * Builds an ordered certificate chain from leaf to root from an unordered list of certificates.
 */
export function buildCertificateChain(certs: ParsedX509Certificate[]): ParsedX509Certificate[] {
  if (certs.length <= 1) return [...certs];

  // Map by Subject DN
  const bySubject = new Map<string, ParsedX509Certificate>();
  for (const c of certs) {
    bySubject.set(c.subject.dn, c);
  }

  // Find candidate leaf: certificate whose Subject DN is not the Issuer of any other cert
  const issuerDns = new Set(certs.map((c) => c.issuer.dn));
  let leaf = certs.find((c) => !issuerDns.has(c.subject.dn) && !c.extensions.basicConstraints?.isCa);
  if (!leaf) {
    leaf = certs.find((c) => c.subject.dn !== c.issuer.dn) ?? certs[0]!;
  }

  const chain: ParsedX509Certificate[] = [leaf];
  const visited = new Set<string>([leaf.serialNumber]);

  let current = leaf;
  while (current.subject.dn !== current.issuer.dn) {
    const parent = bySubject.get(current.issuer.dn);
    if (!parent || visited.has(parent.serialNumber)) {
      break;
    }
    chain.push(parent);
    visited.add(parent.serialNumber);
    current = parent;
  }

  // Add any unvisited certs at the end
  for (const c of certs) {
    if (!visited.has(c.serialNumber)) {
      chain.push(c);
      visited.add(c.serialNumber);
    }
  }

  return chain;
}

/**
 * Validates a certificate chain, checking dates, basic constraints, key usages, AKI/SKI, and signatures.
 */
export async function verifyCertificateChain(
  input: string | Uint8Array | Uint8Array[],
): Promise<ChainVerificationResult> {
  const parsedCerts: ParsedX509Certificate[] = [];

  if (typeof input === "string") {
    const pems = splitPemCertificates(input);
    if (pems.length === 0) {
      // Single PEM or raw
      parsedCerts.push(parseX509Certificate(new TextEncoder().encode(input)));
    } else {
      for (const pem of pems) {
        parsedCerts.push(parseX509Certificate(new TextEncoder().encode(pem)));
      }
    }
  } else if (Array.isArray(input)) {
    for (const der of input) {
      parsedCerts.push(parseX509Certificate(der));
    }
  } else {
    // Check if input is a text buffer containing multiple PEMs
    const text = new TextDecoder().decode(input);
    const pems = splitPemCertificates(text);
    if (pems.length > 1) {
      for (const pem of pems) {
        parsedCerts.push(parseX509Certificate(new TextEncoder().encode(pem)));
      }
    } else {
      parsedCerts.push(parseX509Certificate(input));
    }
  }

  if (parsedCerts.length === 0) {
    throw new Error("No valid X.509 certificates found to verify");
  }

  const orderedChain = buildCertificateChain(parsedCerts);
  const now = new Date();
  const nodes: ChainNodeVerification[] = [];
  let chainValid = true;

  for (let i = 0; i < orderedChain.length; i++) {
    const cert = orderedChain[i]!;
    const isRoot = cert.subject.dn === cert.issuer.dn;
    const isCa = cert.extensions.basicConstraints?.isCa === true;
    const errors: string[] = [];
    const warnings: string[] = [];

    // 1. Validity Dates
    let validDates = true;
    let datesMessage = "Active";
    if (now < cert.validity.notBefore) {
      validDates = false;
      datesMessage = `Not valid yet (effective ${cert.validity.notBefore.toISOString()})`;
      errors.push(`Certificate is not yet valid (effective from ${cert.validity.notBefore.toISOString()})`);
    } else if (now > cert.validity.notAfter) {
      validDates = false;
      datesMessage = `Expired on ${cert.validity.notAfter.toISOString()}`;
      errors.push(`Certificate expired on ${cert.validity.notAfter.toISOString()}`);
    }

    // 2. Signature and Linkage verification
    let signatureValid = true;
    let signatureError: string | undefined;
    let akiSkiMatch: boolean | undefined;

    if (isRoot) {
      // Self-signed Root CA verification
      const sigRes = await verifyCertificateSignature(cert, cert);
      signatureValid = sigRes.valid;
      if (!sigRes.valid) {
        signatureError = sigRes.error ?? "Root CA self-signature verification failed";
        errors.push(signatureError);
      }
    } else {
      // Check signature from parent in chain (if available)
      const parent = orderedChain[i + 1];
      if (parent) {
        // AKI / SKI match
        if (cert.extensions.authorityKeyIdentifier && parent.extensions.subjectKeyIdentifier) {
          const aki = cert.extensions.authorityKeyIdentifier.replace(/^keyid:/, "").toLowerCase();
          const ski = parent.extensions.subjectKeyIdentifier.toLowerCase();
          akiSkiMatch = aki === ski;
          if (!akiSkiMatch) {
            warnings.push(`Authority Key Identifier (${aki}) does not match parent Subject Key Identifier (${ski})`);
          }
        }

        // Parent must be CA
        if (!parent.extensions.basicConstraints?.isCa) {
          errors.push(`Parent issuer (${parent.subject.dn}) does not have Basic Constraints CA:TRUE`);
        }

        // Parent must have keyCertSign
        if (parent.extensions.keyUsages.length > 0 && !parent.extensions.keyUsages.includes("keyCertSign")) {
          errors.push(`Parent issuer (${parent.subject.dn}) is missing keyCertSign in Key Usage`);
        }

        // Cryptographic signature check
        const sigRes = await verifyCertificateSignature(cert, parent);
        signatureValid = sigRes.valid;
        if (!sigRes.valid) {
          signatureError = sigRes.error ?? `Digital signature verification failed against issuer ${parent.subject.dn}`;
          errors.push(signatureError);
        }
      } else {
        warnings.push(`Issuer (${cert.issuer.dn}) certificate not provided in chain (incomplete chain)`);
      }
    }

    if (errors.length > 0) {
      chainValid = false;
    }

    nodes.push({
      index: i,
      subjectDn: cert.subject.dn,
      issuerDn: cert.issuer.dn,
      serialNumber: cert.serialNumber,
      isCa,
      isRoot,
      validDates,
      datesMessage,
      signatureValid,
      signatureError,
      akiSkiMatch,
      ocspUrls: cert.extensions.ocspUrls.length > 0 ? cert.extensions.ocspUrls : undefined,
      crlUrls: cert.extensions.crlUrls.length > 0 ? cert.extensions.crlUrls : undefined,
      errors,
      warnings,
    });
  }

  const leafCert = orderedChain[0]!;
  const rootCert = orderedChain[orderedChain.length - 1]!;
  const isSelfSignedRoot = rootCert.subject.dn === rootCert.issuer.dn;

  // Build tree diagram
  const treeLines: string[] = [];
  // Reverse so Root is printed at top, flowing down to Leaf
  const reversed = [...nodes].reverse();
  for (let j = 0; j < reversed.length; j++) {
    const node = reversed[j]!;
    const indent = "    ".repeat(j);
    const prefix = j === 0 ? " Root CA: " : `${indent}└── [Tier ${nodes.length - j}] `;
    const statusIcon = node.errors.length === 0 ? "[PASS]" : "[FAIL]";
    treeLines.push(`${prefix}${node.subjectDn} ${statusIcon}`);
    treeLines.push(`${indent}    - Serial: 0x${node.serialNumber} | Status: ${node.datesMessage}`);
    if (node.signatureError) {
      treeLines.push(`${indent}    - Signature: FAIL (${node.signatureError})`);
    } else {
      treeLines.push(`${indent}    - Signature: VALID`);
    }
  }

  const summary = chainValid
    ? `Certificate chain is valid and cryptographically verified (${nodes.length} certificates).`
    : `Certificate chain verification failed with ${nodes.reduce((acc, n) => acc + n.errors.length, 0)} error(s).`;

  return {
    isValid: chainValid,
    chainDepth: nodes.length,
    leafSubject: leafCert.subject.dn,
    rootSubject: rootCert.subject.dn,
    isSelfSignedRoot,
    nodes,
    summary,
    treeDiagram: treeLines.join("\n"),
  };
}
