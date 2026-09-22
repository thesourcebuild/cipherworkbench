export interface CertificateToolMeta {
  id: string;
  label: string;
  category: string;
  summary: string;
  tags: readonly string[];
}

export const CERTIFICATE_TOOLS: readonly CertificateToolMeta[] = [
  {
    id: "cert-creator",
    label: "Certificate Creator",
    category: "Creator",
    summary: "Generate self-signed or CA-signed X.509 v3 TLS/SSL certificates with custom Subject DN, SANs, key usages, and keys.",
    tags: ["tls", "ssl", "x509", "certificate", "creator", "generator", "self-signed", "pki", "san"],
  },
  {
    id: "csr-creator",
    label: "CSR Creator",
    category: "Creator",
    summary: "Generate PKCS#10 Certificate Signing Requests with custom Subject DN, SANs, and cryptographic self-signature.",
    tags: ["csr", "pkcs10", "creator", "generator", "pki", "request", "tls", "san"],
  },
  {
    id: "csr-signer",
    label: "CSR Signer (Micro-CA)",
    category: "Creator",
    summary: "Sign PKCS#10 CSRs in-browser using a custom CA or generate an ephemeral root CA to issue verified certificates.",
    tags: ["csr", "signer", "ca", "micro-ca", "pki", "issue", "tls", "x509"],
  },
  {
    id: "x509",
    label: "X.509 Certificate",
    category: "Parser",
    summary: "Inspect and parse X.509 TLS/SSL certificates in PEM or DER format.",
    tags: ["tls", "ssl", "x509", "certificate", "pki", "der", "pem", "crt"],
  },
  {
    id: "csr",
    label: "CSR (PKCS#10)",
    category: "Parser",
    summary: "Parse and verify PKCS#10 Certificate Signing Requests in PEM or DER format.",
    tags: ["csr", "pkcs10", "pki", "request", "tls", "pem", "der"],
  },
  {
    id: "crl",
    label: "CRL (Revocation List)",
    category: "Parser",
    summary: "Inspect and parse RFC 5280 X.509 v2 Certificate Revocation Lists (CRL) in PEM or DER format.",
    tags: ["crl", "revocation", "x509", "pki", "tls", "der", "pem"],
  },
  {
    id: "cert-converter",
    label: "Certificate Converter",
    category: "Conversion",
    summary: "Convert certificates and keys between PEM and DER formats, extract public keys, and inspect certificate chains.",
    tags: ["pem", "der", "convert", "x509", "spki", "chain", "bundle"],
  },
  {
    id: "cert-verifier",
    label: "Chain Verifier",
    category: "Verification",
    summary: "Verify full X.509 certificate chains, validate trust paths, digital signatures, validity dates, and AKI/SKI linkages.",
    tags: ["verify", "chain", "path", "pki", "trust", "x509", "tls", "root", "intermediate"],
  },
  {
    id: "cert-matcher",
    label: "Cert & Key Matcher",
    category: "Verification",
    summary: "Verify whether a private key mathematically and cryptographically matches an X.509 certificate or CSR.",
    tags: ["verify", "matcher", "keypair", "private-key", "certificate", "csr", "modulus"],
  },
  {
    id: "cert-diff",
    label: "Certificate Diff",
    category: "Analysis",
    summary: "Side-by-side visual comparison and audit of two X.509 certificates to verify renewals and inspect changes.",
    tags: ["diff", "compare", "renewal", "x509", "certificate", "sans", "audit"],
  },
  {
    id: "ocsp",
    label: "OCSP Inspector & Builder",
    category: "Protocols",
    summary: "Inspect RFC 6960 OCSP revocation responses, build OCSP queries, and generate offline OCSP staple bundles.",
    tags: ["ocsp", "revocation", "staple", "rfc6960", "tls", "pki", "x509"],
  },
  {
    id: "acme",
    label: "ACME Challenge Calculator",
    category: "Cloud-Native",
    summary: "Calculate RFC 8555 HTTP-01 and DNS-01 challenge digests, TXT records, and cross-platform verification scripts.",
    tags: ["acme", "letsencrypt", "dns01", "http01", "rfc8555", "tls", "zerossl", "challenge"],
  },
] as const;

export const CERTIFICATE_TOOL_IDS = CERTIFICATE_TOOLS.map((t) => t.id);

export function requireCertificateTool(id: string): CertificateToolMeta {
  const found = CERTIFICATE_TOOLS.find((t) => t.id === id);
  if (!found) throw new Error(`Unknown certificate tool: ${id}`);
  return found;
}
