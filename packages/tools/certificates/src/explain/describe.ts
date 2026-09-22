import { readConverterOp, readVerifyCsrSig } from "../pure";
import type { CertificateSpec } from "../spec";

export function describeSpec(spec: CertificateSpec): string {
  switch (spec.variant) {
    case "x509":
      return "Parses and inspects X.509 TLS/SSL certificates, extracting subject, issuer, validity, SANs, and key parameters.";
    case "csr": {
      const verify = readVerifyCsrSig(spec.options);
      return `Parses PKCS#10 Certificate Signing Request (CSR) data${verify ? " and cryptographically verifies its self-signature" : ""}.`;
    }
    case "cert-converter": {
      const op = readConverterOp(spec.options);
      switch (op) {
        case "pem-to-der":
          return "Converts PEM text into raw binary DER.";
        case "der-to-pem":
          return "Encodes binary DER into formatted PEM text.";
        case "pem-to-cer":
          return "Converts PEM certificate to binary DER (.cer) format.";
        case "cer-to-pem":
          return "Encodes binary (.cer) certificate into formatted PEM text.";
        case "pem-to-pkcs7":
          return "Packages certificate(s) into an RFC 2315 / RFC 5652 PKCS#7 (.p7b) container.";
        case "pkcs7-to-pem":
          return "Extracts all embedded certificates from a PKCS#7 (.p7b) container into PEM format.";
        case "pem-to-pkcs12":
          return "Packages certificate(s) and private key into a password-protected PKCS#12 (.pfx) archive.";
        case "pkcs12-to-pem":
          return "Extracts certificate(s) and private key from a PKCS#12 (.pfx / .p12) archive into PEM format.";
        case "extract-public-key":
          return "Extracts SubjectPublicKeyInfo (SPKI) from the certificate as PEM.";
        case "split-chain":
          return "Splits a certificate chain bundle into individual certificates.";
        default:
          return "Automatically converts between PEM, DER, PKCS#7, and PKCS#12 formats.";
      }
    }
    case "cert-creator":
      return "Generates a complete self-signed or CA-signed X.509 v3 TLS/SSL certificate and private key.";
    case "csr-creator":
      return "Generates a PKCS#10 Certificate Signing Request (CSR) with requested extensions and self-signature.";
    case "crl":
      return "Parses and inspects X.509 v2 Certificate Revocation Lists (CRL) and checks revoked serials.";
    case "cert-verifier":
      return "Verifies X.509 certificate chains, digital signatures, validity dates, and AKI/SKI linkages.";
    case "cert-matcher":
      return "Verifies whether a private key cryptographically matches an X.509 certificate or CSR.";
    case "cert-diff":
      return "Performs side-by-side visual comparison and audit of two X.509 certificates to verify renewals.";
    case "csr-signer":
      return "Signs a PKCS#10 Certificate Signing Request (CSR) using a custom CA or an ephemeral in-browser Root CA.";
    case "ocsp":
      return "Inspects and decodes RFC 6960 OCSP revocation responses, generates responder queries, and exports OCSP staple bundles.";
    case "acme":
      return "Calculates RFC 8555 HTTP-01 and DNS-01 challenge parameters, TXT record digests, and cross-platform verification scripts.";
    default:
      return "Certificate analysis and conversion tool.";
  }
}
