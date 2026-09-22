export interface CertificateToolMeta {
  id: string;
  label: string;
  category: string;
  summary: string;
  tags: readonly string[];
}

export const CERTIFICATE_TOOLS: readonly CertificateToolMeta[] = [
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
    id: "cert-converter",
    label: "Certificate Converter",
    category: "Conversion",
    summary: "Convert certificates and keys between PEM and DER formats, extract public keys, and inspect certificate chains.",
    tags: ["pem", "der", "convert", "x509", "spki", "chain", "bundle"],
  },
  {
    id: "crl",
    label: "CRL (Revocation List)",
    category: "Parser",
    summary: "Inspect and parse RFC 5280 X.509 v2 Certificate Revocation Lists (CRL) in PEM or DER format.",
    tags: ["crl", "revocation", "x509", "pki", "tls", "der", "pem"],
  },
  {
    id: "cert-verifier",
    label: "Chain Verifier",
    category: "Verification",
    summary: "Verify full X.509 certificate chains, validate trust paths, digital signatures, validity dates, and AKI/SKI linkages.",
    tags: ["verify", "chain", "path", "pki", "trust", "x509", "tls", "root", "intermediate"],
  },
] as const;

export const CERTIFICATE_TOOL_IDS = CERTIFICATE_TOOLS.map((t) => t.id);

export function requireCertificateTool(id: string): CertificateToolMeta {
  const found = CERTIFICATE_TOOLS.find((t) => t.id === id);
  if (!found) throw new Error(`Unknown certificate tool: ${id}`);
  return found;
}
