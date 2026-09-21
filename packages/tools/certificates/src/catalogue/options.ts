import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
} from "@ocs/engine";
import {
  OPTION_CONVERTER_OP,
  OPTION_DETAIL_LEVEL,
  OPTION_INPUT_FORMAT,
  OPTION_VERIFY_CSR_SIG,
  OPTION_COMMON_NAME,
  OPTION_ORGANIZATION,
  OPTION_ORG_UNIT,
  OPTION_COUNTRY,
  OPTION_STATE,
  OPTION_LOCALITY,
  OPTION_KEY_TYPE,
  OPTION_HASH_TYPE,
  OPTION_VALIDITY_DAYS,
  OPTION_IS_CA,
  OPTION_SAN,
  OPTION_SERVER_AUTH,
  OPTION_CLIENT_AUTH,
  OPTION_CODE_SIGNING,
  OPTION_PASSWORD,
  OPTION_PRIVATE_KEY,
} from "../pure";
import type { CertificateOptionGroup } from "./groups";
import type { CertificateToolMeta } from "./tool-meta";

const INPUT_FORMAT: OptionDef<CertificateOptionGroup> = {
  id: OPTION_INPUT_FORMAT,
  label: "Input format",
  group: "format",
  kind: "enum",
  choices: [
    { value: "auto", label: "Auto-detect", summary: "Detects PEM, hex or binary DER automatically" },
    { value: "pem", label: "PEM", summary: "Base64 encoded text block with BEGIN/END header" },
    { value: "der", label: "DER", summary: "Raw binary ASN.1 DER" },
    { value: "hex", label: "Hex", summary: "Hex-encoded DER bytes" },
  ],
  summary: "How the input certificate data is encoded.",
  detail:
    "PEM is standard for files exported by OpenSSL and web servers; DER is the underlying binary ASN.1 encoding.",
  order: 10,
};

const DETAIL_LEVEL: OptionDef<CertificateOptionGroup> = {
  id: OPTION_DETAIL_LEVEL,
  label: "Detail view",
  group: "format",
  kind: "enum",
  choices: [
    { value: "summary", label: "Standard", summary: "Parsed fields, extensions and OpenSSL text dump" },
    { value: "full-dump", label: "ASN.1 Tree", summary: "Detailed hierarchical ASN.1 TLV structure dump" },
  ],
  summary: "How deeply to inspect the certificate data.",
  detail:
    "Standard displays decoded fields, extensions, and OpenSSL text format. ASN.1 Tree dumps the exact hierarchical TLV tag structure.",
  order: 20,
};

const VERIFY_CSR_SIG: OptionDef<CertificateOptionGroup> = {
  id: OPTION_VERIFY_CSR_SIG,
  label: "Verify self-signature",
  group: "verify",
  kind: "boolean",
  summary: "Cryptographically verify the CSR's signature using its embedded public key.",
  detail:
    "A PKCS#10 CSR is self-signed by the applicant's private key to prove possession (POP) of the corresponding public key.",
  order: 10,
};

const CONVERTER_OP: OptionDef<CertificateOptionGroup> = {
  id: OPTION_CONVERTER_OP,
  label: "Operation",
  group: "convert",
  kind: "enum",
  choices: [
    { value: "auto", label: "Auto Convert (PEM ↔ DER)", summary: "Converts PEM to DER or DER to PEM automatically" },
    { value: "pem-to-der", label: "PEM to DER", summary: "Decodes PEM text into raw binary DER" },
    { value: "der-to-pem", label: "DER to PEM", summary: "Encodes binary DER into formatted PEM text" },
    { value: "pem-to-cer", label: "PEM to CER", summary: "Exports certificate as binary DER (.cer)" },
    { value: "cer-to-pem", label: "CER to PEM", summary: "Encodes .cer certificate into PEM text" },
    { value: "pem-to-pkcs7", label: "PEM to PKCS#7 (.p7b)", summary: "Packages certificate(s) into PKCS#7 / P7B bundle" },
    { value: "pkcs7-to-pem", label: "PKCS#7 to PEM", summary: "Extracts certificates from PKCS#7 / P7B bundle into PEM" },
    { value: "pem-to-pkcs12", label: "PEM to PKCS#12 (.pfx / .p12)", summary: "Packages certificate + private key into PKCS#12 archive" },
    { value: "pkcs12-to-pem", label: "PKCS#12 to PEM", summary: "Extracts certificate and private key from PKCS#12 (.pfx) archive" },
    { value: "extract-public-key", label: "Extract Public Key", summary: "Extracts SubjectPublicKeyInfo (SPKI) as PEM" },
    { value: "split-chain", label: "Split Chain / Bundle", summary: "Splits multiple concatenated PEM certs into separate blocks" },
  ],
  summary: "Which conversion or extraction transformation to perform.",
  detail:
    "Select the desired output format or transformation for certificates, CSRs, and public keys.",
  order: 10,
};

const PASSWORD: OptionDef<CertificateOptionGroup> = {
  id: OPTION_PASSWORD,
  label: "Archive Password",
  group: "convert",
  kind: "password",
  secret: true,
  arg: { placeholder: "PKCS#12 password (optional)" },
  summary: "Password used to encrypt or decrypt PKCS#12 (.pfx / .p12) archives.",
  detail: "When exporting PKCS#12, encrypts the private key with PBES2 (AES-256-CBC). When importing, decrypts the archive.",
  order: 20,
};

const PRIVATE_KEY: OptionDef<CertificateOptionGroup> = {
  id: OPTION_PRIVATE_KEY,
  label: "Private Key (PEM)",
  group: "convert",
  kind: "text",
  arg: { placeholder: "-----BEGIN PRIVATE KEY----- ...", multiline: true },
  summary: "Optional separate private key to bundle into PKCS#12.",
  detail: "If not included in the main input box, paste the private key PEM here to bundle it with the certificate.",
  order: 30,
};

// Creator Options
const COMMON_NAME: OptionDef<CertificateOptionGroup> = {
  id: OPTION_COMMON_NAME,
  label: "Common Name (CN)",
  group: "subject",
  kind: "text",
  arg: { placeholder: "localhost" },
  summary: "Primary host or domain name.",
  detail: "Primary identity of the certificate or applicant (e.g. localhost, example.com).",
  order: 10,
};

const ORGANIZATION: OptionDef<CertificateOptionGroup> = {
  id: OPTION_ORGANIZATION,
  label: "Organization (O)",
  group: "subject",
  kind: "text",
  arg: { placeholder: "Cipher Workbench" },
  summary: "Organization or legal company name.",
  detail: "Legal company or organization name.",
  order: 20,
};

const ORG_UNIT: OptionDef<CertificateOptionGroup> = {
  id: OPTION_ORG_UNIT,
  label: "Organizational Unit (OU)",
  group: "subject",
  kind: "text",
  arg: { placeholder: "Security" },
  summary: "Department or organizational subdivision.",
  detail: "Department, team, or unit within the organization.",
  order: 30,
};

const COUNTRY: OptionDef<CertificateOptionGroup> = {
  id: OPTION_COUNTRY,
  label: "Country (C)",
  group: "subject",
  kind: "text",
  arg: { placeholder: "US" },
  summary: "Two-letter ISO country code.",
  detail: "Two-letter ISO 3166-1 alpha-2 country code (e.g. US, DE, GB).",
  order: 40,
};

const STATE: OptionDef<CertificateOptionGroup> = {
  id: OPTION_STATE,
  label: "State / Province (ST)",
  group: "subject",
  kind: "text",
  arg: { placeholder: "California" },
  summary: "State, province, or region name.",
  detail: "Full state or province name.",
  order: 50,
};

const LOCALITY: OptionDef<CertificateOptionGroup> = {
  id: OPTION_LOCALITY,
  label: "Locality / City (L)",
  group: "subject",
  kind: "text",
  arg: { placeholder: "San Francisco" },
  summary: "City or municipality.",
  detail: "City or municipal locality name.",
  order: 60,
};

const KEY_TYPE: OptionDef<CertificateOptionGroup> = {
  id: OPTION_KEY_TYPE,
  label: "Key Algorithm",
  group: "key",
  kind: "enum",
  choices: [
    { value: "ecdsa-p256", label: "ECDSA P-256", summary: "NIST P-256 (secp256r1) - Modern standard TLS default" },
    { value: "ecdsa-p384", label: "ECDSA P-384", summary: "NIST P-384 (secp384r1) - High security curve" },
    { value: "rsa-2048", label: "RSA 2048", summary: "RSA 2048-bit with PKCS#1 v1.5 padding" },
    { value: "rsa-4096", label: "RSA 4096", summary: "RSA 4096-bit - Extended security RSA" },
    { value: "ed25519", label: "Ed25519", summary: "Edwards-curve Ed25519 signature algorithm (RFC 8410)" },
  ],
  summary: "Cryptographic algorithm and key size.",
  detail: "Select ECDSA, RSA, or Ed25519 for key pair generation and digital signatures.",
  order: 10,
};

const HASH_TYPE: OptionDef<CertificateOptionGroup> = {
  id: OPTION_HASH_TYPE,
  label: "Signature Hash",
  group: "key",
  kind: "enum",
  choices: [
    { value: "sha256", label: "SHA-256", summary: "Standard SHA-256 cryptographic digest" },
    { value: "sha384", label: "SHA-384", summary: "High security SHA-384 digest" },
    { value: "sha512", label: "SHA-512", summary: "SHA-512 digest" },
  ],
  summary: "Cryptographic digest used for signing the certificate or request.",
  detail: "Hash algorithm paired with the key to produce the digital signature.",
  order: 20,
};

const VALIDITY_DAYS: OptionDef<CertificateOptionGroup> = {
  id: OPTION_VALIDITY_DAYS,
  label: "Validity (Days)",
  group: "extensions",
  kind: "text",
  arg: { placeholder: "365", unit: "days" },
  summary: "Certificate lifespan in days (default: 365).",
  detail: "Number of days from now that the certificate remains valid.",
  order: 10,
};

const IS_CA: OptionDef<CertificateOptionGroup> = {
  id: OPTION_IS_CA,
  label: "Is Certificate Authority (CA)",
  group: "extensions",
  kind: "boolean",
  summary: "Enable Basic Constraints cA=TRUE for Root or Intermediate CAs.",
  detail: "When enabled, sets cA=TRUE and KeyCertSign / CRLSign key usage flags.",
  order: 20,
};

const SAN: OptionDef<CertificateOptionGroup> = {
  id: OPTION_SAN,
  label: "Subject Alt Names (SAN)",
  group: "extensions",
  kind: "text",
  arg: { placeholder: "localhost, 127.0.0.1" },
  summary: "Comma-separated domain names or IP addresses.",
  detail: "Alternative identities (e.g. localhost, 127.0.0.1, example.com, admin@example.com).",
  order: 30,
};

const SERVER_AUTH: OptionDef<CertificateOptionGroup> = {
  id: OPTION_SERVER_AUTH,
  label: "Server Auth (TLS Web)",
  group: "extensions",
  kind: "boolean",
  summary: "Extended Key Usage: id-kp-serverAuth (1.3.6.1.5.5.7.3.1)",
  detail: "Enables TLS web server authentication.",
  order: 40,
};

const CLIENT_AUTH: OptionDef<CertificateOptionGroup> = {
  id: OPTION_CLIENT_AUTH,
  label: "Client Auth (mTLS)",
  group: "extensions",
  kind: "boolean",
  summary: "Extended Key Usage: id-kp-clientAuth (1.3.6.1.5.5.7.3.2)",
  detail: "Enables mutual TLS client authentication.",
  order: 50,
};

const CODE_SIGNING: OptionDef<CertificateOptionGroup> = {
  id: OPTION_CODE_SIGNING,
  label: "Code Signing",
  group: "extensions",
  kind: "boolean",
  summary: "Extended Key Usage: id-kp-codeSigning (1.3.6.1.5.5.7.3.3)",
  detail: "Enables digital software and code signing.",
  order: 60,
};

export const ALL_CERTIFICATE_OPTIONS: readonly OptionDef<CertificateOptionGroup>[] = [
  INPUT_FORMAT,
  DETAIL_LEVEL,
  VERIFY_CSR_SIG,
  CONVERTER_OP,
  PASSWORD,
  PRIVATE_KEY,
  COMMON_NAME,
  ORGANIZATION,
  ORG_UNIT,
  COUNTRY,
  STATE,
  LOCALITY,
  KEY_TYPE,
  HASH_TYPE,
  VALIDITY_DAYS,
  IS_CA,
  SAN,
  SERVER_AUTH,
  CLIENT_AUTH,
  CODE_SIGNING,
];

export function certificateCatalogueFor(meta: CertificateToolMeta): OptionCatalogue {
  const options: OptionDef<CertificateOptionGroup>[] = [];

  if (meta.id === "x509") {
    options.push(INPUT_FORMAT, DETAIL_LEVEL);
  } else if (meta.id === "csr") {
    options.push(INPUT_FORMAT, VERIFY_CSR_SIG, DETAIL_LEVEL);
  } else if (meta.id === "cert-converter") {
    options.push(CONVERTER_OP, INPUT_FORMAT, PASSWORD, PRIVATE_KEY);
  } else if (meta.id === "cert-creator") {
    options.push(
      COMMON_NAME,
      SAN,
      ORGANIZATION,
      ORG_UNIT,
      COUNTRY,
      STATE,
      LOCALITY,
      KEY_TYPE,
      HASH_TYPE,
      VALIDITY_DAYS,
      IS_CA,
      SERVER_AUTH,
      CLIENT_AUTH,
      CODE_SIGNING,
    );
  } else if (meta.id === "csr-creator") {
    options.push(
      COMMON_NAME,
      SAN,
      ORGANIZATION,
      ORG_UNIT,
      COUNTRY,
      STATE,
      LOCALITY,
      KEY_TYPE,
      HASH_TYPE,
      SERVER_AUTH,
      CLIENT_AUTH,
      CODE_SIGNING,
    );
  }

  return createOptionCatalogue(options);
}

