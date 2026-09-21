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
    default:
      return "Certificate analysis and conversion tool.";
  }
}
