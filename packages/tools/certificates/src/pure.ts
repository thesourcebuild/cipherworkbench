import type { OptionValues } from "@ocs/contracts/options";
import { optBool, optString } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_INPUT_FORMAT = "inputFormat";
export const OPTION_DETAIL_LEVEL = "detailLevel";
export const OPTION_VERIFY_CSR_SIG = "verifyCsrSig";
export const OPTION_CONVERTER_OP = "converterOp";

// Creator Options
export const OPTION_COMMON_NAME = "commonName";
export const OPTION_ORGANIZATION = "organization";
export const OPTION_ORG_UNIT = "organizationalUnit";
export const OPTION_COUNTRY = "country";
export const OPTION_STATE = "state";
export const OPTION_LOCALITY = "locality";
export const OPTION_KEY_TYPE = "keyType";
export const OPTION_HASH_TYPE = "hashType";
export const OPTION_ROOT_KEY_TYPE = "rootKeyType";
export const OPTION_ROOT_HASH_TYPE = "rootHashType";
export const OPTION_INTERMEDIATE_KEY_TYPE = "intermediateKeyType";
export const OPTION_INTERMEDIATE_HASH_TYPE = "intermediateHashType";
export const OPTION_SERVER_KEY_TYPE = "serverKeyType";
export const OPTION_SERVER_HASH_TYPE = "serverHashType";
export const OPTION_CLIENT_KEY_TYPE = "clientKeyType";
export const OPTION_CLIENT_HASH_TYPE = "clientHashType";
export const OPTION_VALIDITY_DAYS = "validityDays";
export const OPTION_IS_CA = "isCa";
export const OPTION_SAN = "san";
export const OPTION_SERVER_AUTH = "serverAuth";
export const OPTION_CLIENT_AUTH = "clientAuth";
export const OPTION_CODE_SIGNING = "codeSigning";

export const OPTION_CREATOR_MODE = "creatorMode";
export const OPTION_WORKFLOW_LAYOUT = "workflowLayout";
export const OPTION_ISSUANCE_MODE = "issuanceMode";
export const OPTION_PKI_HIERARCHY = "pkiHierarchy";
export const OPTION_INTERMEDIATE_COMMON_NAME = "intermediateCommonName";
export const OPTION_CA_CERT = "caCert";
export const OPTION_CA_PRIVATE_KEY = "caPrivateKey";
export const OPTION_CLIENT_COMMON_NAME = "clientCommonName";
export const OPTION_CA_COMMON_NAME = "caCommonName";
export const OPTION_MTLS_P12_PASSWORD = "mtlsP12Password";

export const OPTION_PASSWORD = "password";
export const OPTION_PRIVATE_KEY = "privateKey";
export const OPTION_COMPARISON_CERT = "comparisonCert";

export type CreatorModeOption = "single-cert" | "mtls-suite";
export type WorkflowLayoutOption = "panels";
export type IssuanceModeOption = "self-signed" | "ca-signed";
export type PkiHierarchyOption = "2-tier" | "3-tier";

export function readWorkflowLayout(
  _options?: OptionValues,
  _fallback: WorkflowLayoutOption = "panels",
): WorkflowLayoutOption {
  return "panels";
}

export type InputFormatOption = "auto" | "pem" | "der" | "hex";
export type DetailLevelOption = "summary" | "full-dump";
export type ConverterOpOption =
  | "auto"
  | "pem-to-der"
  | "der-to-pem"
  | "pem-to-cer"
  | "cer-to-pem"
  | "pem-to-pkcs7"
  | "pkcs7-to-pem"
  | "pem-to-pkcs12"
  | "pkcs12-to-pem"
  | "pem-to-ppk"
  | "pkcs12-inspect"
  | "extract-public-key"
  | "split-chain";

export type KeyTypeOption =
  | "ecdsa-p256"
  | "ecdsa-p384"
  | "rsa-2048"
  | "rsa-4096"
  | "ed25519"
  | "ml-dsa-44"
  | "ml-dsa-65"
  | "ml-dsa-87";

export type HashTypeOption =
  "sha256" | "sha384" | "sha512" | "sha3-256" | "sha3-384" | "sha3-512";

export function readInputFormat(options: OptionValues): InputFormatOption {
  const val = optString(options, OPTION_INPUT_FORMAT);
  if (val === "pem" || val === "der" || val === "hex") return val;
  return "auto";
}

export function readDetailLevel(options: OptionValues): DetailLevelOption {
  const val = optString(options, OPTION_DETAIL_LEVEL);
  if (val === "full-dump") return "full-dump";
  return "summary";
}

export function readVerifyCsrSig(options: OptionValues): boolean {
  return optBool(options, OPTION_VERIFY_CSR_SIG) ?? true;
}

export function readConverterOp(options: OptionValues): ConverterOpOption {
  const val = optString(options, OPTION_CONVERTER_OP);
  if (
    val === "pem-to-der" ||
    val === "der-to-pem" ||
    val === "pem-to-cer" ||
    val === "cer-to-pem" ||
    val === "pem-to-pkcs7" ||
    val === "pkcs7-to-pem" ||
    val === "pem-to-pkcs12" ||
    val === "pkcs12-to-pem" ||
    val === "pem-to-ppk" ||
    val === "pkcs12-inspect" ||
    val === "extract-public-key" ||
    val === "split-chain"
  ) {
    return val;
  }
  return "auto";
}

export function readPassword(options: OptionValues): string {
  return optString(options, OPTION_PASSWORD) ?? "";
}

export function readPrivateKey(options: OptionValues): string {
  return optString(options, OPTION_PRIVATE_KEY) ?? "";
}

export function readCommonName(options: OptionValues, defaultVal = "localhost"): string {
  return optString(options, OPTION_COMMON_NAME) ?? defaultVal;
}

export function readOrganization(
  options: OptionValues,
  defaultVal = "Cipher Workbench",
): string {
  return optString(options, OPTION_ORGANIZATION) ?? defaultVal;
}

export function readOrgUnit(options: OptionValues, defaultVal = "Security"): string {
  return optString(options, OPTION_ORG_UNIT) ?? defaultVal;
}

export function readCountry(options: OptionValues, defaultVal = "US"): string {
  return optString(options, OPTION_COUNTRY) ?? defaultVal;
}

export function readState(options: OptionValues, defaultVal = "California"): string {
  return optString(options, OPTION_STATE) ?? defaultVal;
}

export function readLocality(options: OptionValues, defaultVal = "San Francisco"): string {
  return optString(options, OPTION_LOCALITY) ?? defaultVal;
}

function readKeyTypeOption(
  options: OptionValues,
  optionId: string,
  defaultVal: KeyTypeOption,
): KeyTypeOption {
  const val = optString(options, optionId);
  if (
    val === "ecdsa-p256" ||
    val === "ecdsa-p384" ||
    val === "rsa-2048" ||
    val === "rsa-4096" ||
    val === "ed25519" ||
    val === "ml-dsa-44" ||
    val === "ml-dsa-65" ||
    val === "ml-dsa-87"
  ) {
    return val;
  }
  return defaultVal;
}

function readHashTypeOption(
  options: OptionValues,
  optionId: string,
  defaultVal: HashTypeOption,
): HashTypeOption {
  const val = optString(options, optionId);
  if (
    val === "sha256" ||
    val === "sha384" ||
    val === "sha512" ||
    val === "sha3-256" ||
    val === "sha3-384" ||
    val === "sha3-512"
  ) {
    return val;
  }
  return defaultVal;
}

export function readKeyType(
  options: OptionValues,
  defaultVal: KeyTypeOption = "ecdsa-p256",
): KeyTypeOption {
  return readKeyTypeOption(options, OPTION_KEY_TYPE, defaultVal);
}

export function readHashType(
  options: OptionValues,
  defaultVal: HashTypeOption = "sha256",
): HashTypeOption {
  return readHashTypeOption(options, OPTION_HASH_TYPE, defaultVal);
}

export function readRootKeyType(
  options: OptionValues,
  defaultVal: KeyTypeOption = "ecdsa-p256",
): KeyTypeOption {
  return readKeyTypeOption(options, OPTION_ROOT_KEY_TYPE, defaultVal);
}

export function readRootHashType(
  options: OptionValues,
  defaultVal: HashTypeOption = "sha256",
): HashTypeOption {
  return readHashTypeOption(options, OPTION_ROOT_HASH_TYPE, defaultVal);
}

export function readIntermediateKeyType(
  options: OptionValues,
  defaultVal: KeyTypeOption = "ecdsa-p256",
): KeyTypeOption {
  return readKeyTypeOption(options, OPTION_INTERMEDIATE_KEY_TYPE, defaultVal);
}

export function readIntermediateHashType(
  options: OptionValues,
  defaultVal: HashTypeOption = "sha256",
): HashTypeOption {
  return readHashTypeOption(options, OPTION_INTERMEDIATE_HASH_TYPE, defaultVal);
}

export function readServerKeyType(
  options: OptionValues,
  defaultVal: KeyTypeOption = "ecdsa-p256",
): KeyTypeOption {
  return readKeyTypeOption(options, OPTION_SERVER_KEY_TYPE, defaultVal);
}

export function readServerHashType(
  options: OptionValues,
  defaultVal: HashTypeOption = "sha256",
): HashTypeOption {
  return readHashTypeOption(options, OPTION_SERVER_HASH_TYPE, defaultVal);
}

export function readClientKeyType(
  options: OptionValues,
  defaultVal: KeyTypeOption = "ecdsa-p256",
): KeyTypeOption {
  return readKeyTypeOption(options, OPTION_CLIENT_KEY_TYPE, defaultVal);
}

export function readClientHashType(
  options: OptionValues,
  defaultVal: HashTypeOption = "sha256",
): HashTypeOption {
  return readHashTypeOption(options, OPTION_CLIENT_HASH_TYPE, defaultVal);
}

export function readValidityDays(options: OptionValues, defaultVal = 365): number {
  const val = optString(options, OPTION_VALIDITY_DAYS);
  if (val) {
    const parsed = parseInt(val, 10);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }
  return defaultVal;
}

export function readIsCa(options: OptionValues, defaultVal = false): boolean {
  return optBool(options, OPTION_IS_CA) ?? defaultVal;
}

export function readSan(options: OptionValues, defaultVal = "localhost, 127.0.0.1"): string {
  return optString(options, OPTION_SAN) ?? defaultVal;
}

export function readServerAuth(options: OptionValues, defaultVal = true): boolean {
  return optBool(options, OPTION_SERVER_AUTH) ?? defaultVal;
}

export function readClientAuth(options: OptionValues, defaultVal = true): boolean {
  return optBool(options, OPTION_CLIENT_AUTH) ?? defaultVal;
}

export function readCodeSigning(options: OptionValues, defaultVal = false): boolean {
  return optBool(options, OPTION_CODE_SIGNING) ?? defaultVal;
}

export function readCreatorMode(options: OptionValues): CreatorModeOption {
  const val = optString(options, OPTION_CREATOR_MODE);
  if (val === "mtls-suite") return "mtls-suite";
  return "single-cert";
}

export function readIssuanceMode(options: OptionValues): IssuanceModeOption {
  const val = optString(options, OPTION_ISSUANCE_MODE);
  if (val === "ca-signed") return "ca-signed";
  return "self-signed";
}

export function readCaCert(options: OptionValues): string {
  return optString(options, OPTION_CA_CERT) ?? "";
}

export function readCaPrivateKey(options: OptionValues): string {
  return optString(options, OPTION_CA_PRIVATE_KEY) ?? "";
}

export function readClientCommonName(
  options: OptionValues,
  defaultVal = "client-app-01",
): string {
  return optString(options, OPTION_CLIENT_COMMON_NAME) ?? defaultVal;
}

export function readCaCommonName(
  options: OptionValues,
  defaultVal = "Internal Root CA",
): string {
  return optString(options, OPTION_CA_COMMON_NAME) ?? defaultVal;
}

export function readMtlsP12Password(options: OptionValues, defaultVal = "changeit"): string {
  return optString(options, OPTION_MTLS_P12_PASSWORD) ?? defaultVal;
}

export function readPkiHierarchy(options: OptionValues): PkiHierarchyOption {
  const val = optString(options, OPTION_PKI_HIERARCHY);
  if (val === "3-tier") return "3-tier";
  return "2-tier";
}

export function readIntermediateCommonName(
  options: OptionValues,
  defaultVal = "Internal Issuing CA",
): string {
  return optString(options, OPTION_INTERMEDIATE_COMMON_NAME) ?? defaultVal;
}

export function readComparisonCert(options: OptionValues): string {
  return optString(options, OPTION_COMPARISON_CERT) ?? "";
}

export const OPTION_CA_MODE = "caMode";
export type CaModeOption = "ephemeral-ca" | "custom-ca";

export function readCaMode(options: OptionValues): CaModeOption {
  const val = optString(options, OPTION_CA_MODE);
  if (val === "custom-ca") return "custom-ca";
  return "ephemeral-ca";
}

export const OPTION_OCSP_OP = "ocspOp";
export type OcspOpOption = "inspect-response" | "build-request" | "generate-staple";

export function readOcspOp(options: OptionValues): OcspOpOption {
  const val = optString(options, OPTION_OCSP_OP);
  if (val === "build-request") return "build-request";
  if (val === "generate-staple") return "generate-staple";
  return "inspect-response";
}

export const OPTION_ISSUER_CERT = "issuerCert";
export function readIssuerCert(options: OptionValues): string {
  return optString(options, OPTION_ISSUER_CERT) ?? "";
}

export const OPTION_ACME_DOMAIN = "acmeDomain";
export function readAcmeDomain(options: OptionValues): string {
  return optString(options, OPTION_ACME_DOMAIN) ?? "example.com";
}

export const OPTION_ACME_TOKEN = "acmeToken";
export function readAcmeToken(options: OptionValues): string {
  return optString(options, OPTION_ACME_TOKEN) ?? "";
}

export const OPTION_ACME_ACCOUNT_KEY = "acmeAccountKey";
export function readAcmeAccountKey(options: OptionValues): string {
  return optString(options, OPTION_ACME_ACCOUNT_KEY) ?? "";
}
