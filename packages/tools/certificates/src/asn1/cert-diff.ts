import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { parseX509Certificate } from "./x509";
import { splitPemCertificates } from "./chain-verifier";
import { detectInputBytes } from "./pem";

export interface CertDiffAttribute {
  name: string;
  cert1Value: string;
  cert2Value: string;
  status: "identical" | "changed" | "added" | "removed" | "warning";
  note?: string;
}

export interface CertDiffResult {
  isIdentical: boolean;
  isCleanRenewal: boolean;
  keyRolledOver: boolean;
  attributes: CertDiffAttribute[];
  addedSans: string[];
  removedSans: string[];
  unchangedSans: string[];
  summary: string;
  markdownTable: string;
}

/**
 * Compares two X.509 certificates and produces a structured side-by-side diff.
 */
export function diffCertificates(
  cert1Input: string | Uint8Array,
  cert2Input?: string | Uint8Array,
): CertDiffResult {
  let cert1Der: Uint8Array | undefined;
  let cert2Der: Uint8Array | undefined;

  // 1. Separate combined PEMs if only one input was supplied
  if (!cert2Input || (typeof cert2Input === "string" && cert2Input.trim().length === 0)) {
    if (typeof cert1Input === "string") {
      const pems = splitPemCertificates(cert1Input);
      if (pems.length >= 2 && pems[0] && pems[1]) {
        cert1Der = detectInputBytes(pems[0]).der;
        cert2Der = detectInputBytes(pems[1]).der;
      }
    }
  } else {
    try {
      cert1Der = typeof cert1Input === "string" ? detectInputBytes(cert1Input).der : cert1Input;
    } catch {
      throw new Error("No valid X.509 Certificate found in primary input (expected PEM or DER).");
    }
    try {
      cert2Der = typeof cert2Input === "string" ? detectInputBytes(cert2Input).der : cert2Input;
    } catch {
      throw new Error("No valid X.509 Certificate found in comparison input (expected PEM or DER).");
    }
  }

  if (!cert1Der || !cert2Der) {
    throw new Error(
      "Certificate Diff requires two certificates to compare. Paste two PEM certificate blocks or provide both certificate inputs.",
    );
  }

  const c1 = parseX509Certificate(cert1Der);
  const c2 = parseX509Certificate(cert2Der);

  const attributes: CertDiffAttribute[] = [];

  // 1. Subject DN
  const subjectIdentical = c1.subject.dn === c2.subject.dn;
  attributes.push({
    name: "Subject DN",
    cert1Value: c1.subject.dn,
    cert2Value: c2.subject.dn,
    status: subjectIdentical ? "identical" : "changed",
    note: subjectIdentical ? undefined : "Subject DN differs between certificates",
  });

  // 2. Issuer DN
  const issuerIdentical = c1.issuer.dn === c2.issuer.dn;
  attributes.push({
    name: "Issuer DN",
    cert1Value: c1.issuer.dn,
    cert2Value: c2.issuer.dn,
    status: issuerIdentical ? "identical" : "changed",
    note: issuerIdentical ? undefined : "Issuing Certificate Authority has changed",
  });

  // 3. Serial Number
  const serialIdentical = c1.serialNumber === c2.serialNumber;
  attributes.push({
    name: "Serial Number",
    cert1Value: `0x${c1.serialNumber}`,
    cert2Value: `0x${c2.serialNumber}`,
    status: serialIdentical ? "identical" : "changed",
    note: serialIdentical ? "Warning: Same serial number reused" : "Unique serial numbers",
  });

  // 4. Validity Window & Expiration
  const notBefore1 = c1.validity.notBefore.toISOString();
  const notBefore2 = c2.validity.notBefore.toISOString();
  attributes.push({
    name: "Not Before (Effective)",
    cert1Value: notBefore1,
    cert2Value: notBefore2,
    status: notBefore1 === notBefore2 ? "identical" : "changed",
  });

  const notAfter1 = c1.validity.notAfter.toISOString();
  const notAfter2 = c2.validity.notAfter.toISOString();
  const daysDiff = Math.round(
    (c2.validity.notAfter.getTime() - c1.validity.notAfter.getTime()) / (1000 * 60 * 60 * 24),
  );
  attributes.push({
    name: "Not After (Expiry)",
    cert1Value: `${notAfter1} (${c1.validity.statusLabel})`,
    cert2Value: `${notAfter2} (${c2.validity.statusLabel})`,
    status: notAfter1 === notAfter2 ? "identical" : daysDiff > 0 ? "changed" : "warning",
    note:
      daysDiff > 0
        ? `Validity extended by +${daysDiff} days`
        : daysDiff < 0
          ? `Validity shortened by ${daysDiff} days`
          : "Identical expiration date",
  });

  // 5. Subject Alternative Names (SANs)
  const sans1 = new Set(c1.extensions.sans);
  const sans2 = new Set(c2.extensions.sans);
  const addedSans = c2.extensions.sans.filter((s) => !sans1.has(s));
  const removedSans = c1.extensions.sans.filter((s) => !sans2.has(s));
  const unchangedSans = c1.extensions.sans.filter((s) => sans2.has(s));

  const sansIdentical = addedSans.length === 0 && removedSans.length === 0;
  attributes.push({
    name: "Subject Alternative Names (SANs)",
    cert1Value: c1.extensions.sans.join(", ") || "(none)",
    cert2Value: c2.extensions.sans.join(", ") || "(none)",
    status: sansIdentical ? "identical" : "changed",
    note: sansIdentical
      ? "SAN list identical"
      : `Added: [${addedSans.join(", ") || "none"}], Removed: [${removedSans.join(", ") || "none"}]`,
  });

  // 6. Public Key & Algorithm
  const keyType1 = c1.publicKey.details;
  const keyType2 = c2.publicKey.details;
  const keyDetailsIdentical = keyType1 === keyType2;

  // Compare SPKI public key bytes to detect key rollover
  const spki1Hex = Array.from(c1.publicKey.spkiDer)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const spki2Hex = Array.from(c2.publicKey.spkiDer)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const keyRolledOver = spki1Hex !== spki2Hex;

  attributes.push({
    name: "Public Key Details",
    cert1Value: keyType1,
    cert2Value: keyType2,
    status: keyDetailsIdentical ? "identical" : "changed",
  });

  attributes.push({
    name: "Public Key Rollover",
    cert1Value: `SPKI: ${spki1Hex.slice(0, 16)}...`,
    cert2Value: `SPKI: ${spki2Hex.slice(0, 16)}...`,
    status: keyRolledOver ? "changed" : "identical",
    note: keyRolledOver ? "New keypair generated (Key Rollover)" : "Same public key reused across renewal",
  });

  // 7. Signature Algorithm
  const sigAlgIdentical = c1.signatureAlgorithmName === c2.signatureAlgorithmName;
  attributes.push({
    name: "Signature Algorithm",
    cert1Value: c1.signatureAlgorithmName,
    cert2Value: c2.signatureAlgorithmName,
    status: sigAlgIdentical ? "identical" : "changed",
  });

  // 8. Key Usage & Extended Key Usage
  const ku1 = c1.extensions.keyUsages.join(", ");
  const ku2 = c2.extensions.keyUsages.join(", ");
  attributes.push({
    name: "Key Usage",
    cert1Value: ku1 || "(none)",
    cert2Value: ku2 || "(none)",
    status: ku1 === ku2 ? "identical" : "changed",
  });

  const eku1 = c1.extensions.extendedKeyUsages.join(", ");
  const eku2 = c2.extensions.extendedKeyUsages.join(", ");
  attributes.push({
    name: "Extended Key Usage (EKU)",
    cert1Value: eku1 || "(none)",
    cert2Value: eku2 || "(none)",
    status: eku1 === eku2 ? "identical" : "changed",
  });

  // Public Key SPKI SHA-256
  const spkiSha1 = bytesToHex(sha256(c1.publicKey.spkiDer)).toUpperCase().match(/../g)?.join(":") ?? "";
  const spkiSha2 = bytesToHex(sha256(c2.publicKey.spkiDer)).toUpperCase().match(/../g)?.join(":") ?? "";
  attributes.push({
    name: "Public Key SHA-256",
    cert1Value: spkiSha1,
    cert2Value: spkiSha2,
    status: spkiSha1 === spkiSha2 ? "identical" : "changed",
    note: spkiSha1 === spkiSha2 ? "Reused key" : "New key (Key Rollover)",
  });

  // 9. SHA-256 Fingerprint
  attributes.push({
    name: "SHA-256 Fingerprint",
    cert1Value: c1.fingerprints.sha256,
    cert2Value: c2.fingerprints.sha256,
    status: c1.fingerprints.sha256 === c2.fingerprints.sha256 ? "identical" : "changed",
  });

  // 10. Is CA (Basic Constraints)
  const isCa1 = c1.extensions.basicConstraints?.isCa ? "CA: TRUE" : "Leaf Certificate (CA: FALSE)";
  const isCa2 = c2.extensions.basicConstraints?.isCa ? "CA: TRUE" : "Leaf Certificate (CA: FALSE)";
  attributes.push({
    name: "Is CA (Basic Constraints)",
    cert1Value: isCa1,
    cert2Value: isCa2,
    status: isCa1 === isCa2 ? "identical" : "changed",
  });

  const isIdentical = attributes.every((a) => a.status === "identical");
  const isCleanRenewal =
    subjectIdentical &&
    sansIdentical &&
    daysDiff > 0 &&
    !serialIdentical;

  let summary = "Certificates Compared.";
  if (isIdentical) {
    summary = "IDENTICAL: The two certificates are bit-for-bit identical.";
  } else if (isCleanRenewal) {
    summary = `CLEAN RENEWAL: Certificate 2 successfully renews Certificate 1 (Extended by +${daysDiff} days, ${keyRolledOver ? "Key Rolled Over" : "Same Key Reused"}).`;
  } else {
    const changes = attributes.filter((a) => a.status !== "identical").map((a) => a.name);
    summary = `DIFFERENCES DETECTED: Differences in ${changes.join(", ")}.`;
  }

  // Generate markdown table
  const tableRows = [
    "| Property | Certificate 1 (Base) | Certificate 2 (Target) | Status | Notes |",
    "| :--- | :--- | :--- | :---: | :--- |",
    ...attributes.map((a) => {
      const icon =
        a.status === "identical"
          ? "[OK]"
          : a.status === "warning"
            ? "[WARN]"
            : "[DIFF]";
      return `| **${a.name}** | \`${a.cert1Value}\` | \`${a.cert2Value}\` | ${icon} | ${a.note ?? "-"} |`;
    }),
  ];

  return {
    isIdentical,
    isCleanRenewal,
    keyRolledOver,
    attributes,
    addedSans,
    removedSans,
    unchangedSans,
    summary,
    markdownTable: tableRows.join("\n"),
  };
}
